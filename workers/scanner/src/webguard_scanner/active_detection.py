"""Shared contract and safety plumbing for active (authorization-bound)
security detectors.

Active detectors send additional, crafted requests to an already-validated
target rather than only observing one passive response. That makes the
safety boundary more important, not less:

- every probe request goes through the same ``safe_http.fetch_once`` used
  by passive checks, so it inherits SSRF-validated addresses, TLS
  enforcement, redirect blocking, and response-size limits unmodified;
- probes are only ever sent to the origin (scheme + hostname + port) of the
  ``ValidatedTarget`` the caller already validated -- never a new host, and
  never a newly resolved address;
- callers may supply the same ``BeforeRequestHook``/``AfterRequestHook``
  pair used by ``passive_scan.run_passive_header_scan``, so rate limiting,
  TrustScan permit revalidation, and circuit breaking wired in by the
  executor apply identically to active probes;
- ``ActiveDetectionPolicy`` bounds how many probe requests one detector run
  may issue and enforces a minimum delay between them.

What this module deliberately does not do yet: wire a TrustScan permit's
``permitted_modes``/request budget into ``ActiveDetectionPolicy``
automatically. Today the caller must supply an already-approved,
conservative policy explicitly. Automatic permit-derived policy
construction is tracked as follow-up work, not implemented here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Tuple
from urllib.parse import urlencode, urlsplit

from .authentication import AuthenticationMaterial, apply_authentication
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .safe_http import FetchPolicy, SafeHttpResponse, SafeRequestError, fetch_once
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ActiveDetectionError(RuntimeError):
    """Controlled failure raised by the active-detection layer."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class DetectionCandidate:
    """One explicit, caller-approved place to attempt an injection.

    Candidates are never auto-discovered by this module. The caller is
    responsible for producing them (for example from an already-crawled,
    already-authorized page) and for ensuring only intended parameters are
    included. Only the GET method is supported by this slice; anything
    else is rejected rather than silently coerced.
    """

    url: str
    parameter: str
    method: str = "GET"
    original_value: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url.strip():
            raise ActiveDetectionError(
                "candidate_url_invalid",
                "A detection candidate requires a non-empty url.",
            )

        if not isinstance(self.parameter, str) or not self.parameter.strip():
            raise ActiveDetectionError(
                "candidate_parameter_invalid",
                "A detection candidate requires a non-empty parameter name.",
            )

        if not isinstance(self.method, str) or self.method.upper() != "GET":
            raise ActiveDetectionError(
                "unsupported_candidate_method",
                "Only GET-method candidates are supported by this detector "
                "generation.",
            )

        object.__setattr__(self, "method", "GET")


@dataclass(frozen=True, slots=True)
class ActiveDetectionPolicy:
    """Bounded execution policy for one active-detector run.

    This must be derived from, and must never exceed, the authorization or
    permit that approved the scan. This slice does not yet derive it
    automatically from a TrustScan permit; callers must supply an
    already-approved, conservative policy.
    """

    maximum_probe_requests: int = 5
    minimum_delay_seconds: float = 1.0
    fetch_policy: FetchPolicy = field(default_factory=FetchPolicy)

    def __post_init__(self) -> None:
        if (
            isinstance(self.maximum_probe_requests, bool)
            or not isinstance(self.maximum_probe_requests, int)
            or not (1 <= self.maximum_probe_requests <= 25)
        ):
            raise ActiveDetectionError(
                "maximum_probe_requests_invalid",
                "maximum_probe_requests must be an integer between 1 and 25.",
            )

        if (
            isinstance(self.minimum_delay_seconds, bool)
            or not isinstance(self.minimum_delay_seconds, (int, float))
            or not (0.0 <= float(self.minimum_delay_seconds) <= 30.0)
        ):
            raise ActiveDetectionError(
                "minimum_delay_seconds_invalid",
                "minimum_delay_seconds must be a number between 0 and 30.",
            )

        object.__setattr__(
            self,
            "minimum_delay_seconds",
            float(self.minimum_delay_seconds),
        )


@dataclass(frozen=True, slots=True)
class ActiveDetectionContext:
    """Authorization/permit provenance recorded on findings this layer
    produces.

    These fields are optional only because automatic TrustScan-permit
    wiring into active detection is not yet implemented; when absent, that
    absence is itself recorded on findings rather than silently omitted.
    The caller must have already validated the underlying authorization or
    permit before invoking any detector -- these fields are provenance for
    audit, not an authority check performed by this module.
    """

    scan_id: str
    authorization_id: str | None = None
    permit_id: str | None = None
    permit_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class ProbeAttempt:
    """One outbound probe request and its raw outcome, for audit purposes."""

    candidate: DetectionCandidate
    requested_url: str
    succeeded: bool
    error_code: str | None
    response: SafeHttpResponse | None


def _require_same_origin(base: ValidatedTarget, candidate_url: str) -> None:
    parsed = urlsplit(candidate_url)

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    if (
        parsed.scheme != base.scheme
        or (parsed.hostname or "").lower() != base.hostname
        or port != base.port
    ):
        raise ActiveDetectionError(
            "candidate_origin_mismatch",
            "The candidate URL is not on the authorized target's origin.",
        )


def _build_probe_target(
    base: ValidatedTarget,
    url_with_query: str,
) -> ValidatedTarget:
    """Build a request-only ValidatedTarget for one probe.

    Reuses ``base``'s already-validated identity -- hostname, port, scheme,
    and resolved addresses -- unchanged. No new DNS resolution occurs and
    no new address is introduced; the probe is always sent to
    ``base.resolved_addresses``. This intentionally bypasses
    ``validate_target_url``'s rejection of query strings: that rejection
    protects *registered scan targets*, not individual authorized probe
    requests against an origin that has already passed full scope
    validation.
    """

    return ValidatedTarget(
        original_url=url_with_query,
        normalised_url=url_with_query,
        scheme=base.scheme,
        hostname=base.hostname,
        port=base.port,
        resolved_addresses=base.resolved_addresses,
    )


def issue_probe(
    base_target: ValidatedTarget,
    candidate: DetectionCandidate,
    payload: str,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    authentication_material: AuthenticationMaterial | None = None,
) -> ProbeAttempt:
    """Send exactly one bounded GET probe request.

    ``payload`` replaces ``candidate.parameter``'s value. The request goes
    through ``safe_http.fetch_once`` with the caller's fetch policy, so
    response size, header, method, and TLS enforcement are unchanged from
    passive scanning.

    ``authentication_material`` (Slice 7), when supplied, is applied via
    the single shared ``authentication.apply_authentication`` mechanism
    -- this function never builds an Authorization/Cookie header itself.
    Every existing caller passes nothing here and probes exactly as
    before (unauthenticated).
    """

    _require_same_origin(base_target, candidate.url)

    parsed = urlsplit(candidate.url)
    query = urlencode({candidate.parameter: payload})
    url_with_query = (
        f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}?{query}"
    )

    probe_target = _build_probe_target(base_target, url_with_query)
    extra_headers = apply_authentication(
        url_with_query, authentication_material, now=_utc_now()
    )

    if before_request is not None:
        before_request(probe_target, "GET")

    try:
        response = fetch_once(
            probe_target,
            method="GET",
            policy=policy.fetch_policy,
            extra_headers=extra_headers,
        )
    except SafeRequestError as exc:
        if after_request is not None:
            after_request(probe_target, "GET", None, exc.code)
        return ProbeAttempt(
            candidate=candidate,
            requested_url=url_with_query,
            succeeded=False,
            error_code=exc.code,
            response=None,
        )

    if after_request is not None:
        after_request(probe_target, "GET", response, None)

    return ProbeAttempt(
        candidate=candidate,
        requested_url=url_with_query,
        succeeded=True,
        error_code=None,
        response=response,
    )


def fetch_same_origin_page(
    base_target: ValidatedTarget,
    page_url: str,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    authentication_material: AuthenticationMaterial | None = None,
) -> SafeHttpResponse | None:
    """Fetch one page's HTML for candidate discovery.

    Reuses the same same-origin enforcement and safety plumbing as
    ``issue_probe``, but fetches ``page_url`` unmodified rather than
    substituting a payload into a parameter. Returns None on any
    controlled failure rather than raising, since discovery is best-effort
    -- a page that fails to re-fetch simply yields no candidates from it.

    ``authentication_material`` (Slice 7): see ``issue_probe``. This is
    what lets an authenticated crawl/discovery pass reach pages an
    unauthenticated one cannot -- the fetch itself is otherwise identical.
    """

    _require_same_origin(base_target, page_url)
    probe_target = _build_probe_target(base_target, page_url)
    extra_headers = apply_authentication(
        page_url, authentication_material, now=_utc_now()
    )

    if before_request is not None:
        before_request(probe_target, "GET")

    try:
        response = fetch_once(
            probe_target,
            method="GET",
            policy=policy.fetch_policy,
            extra_headers=extra_headers,
        )
    except SafeRequestError as exc:
        if after_request is not None:
            after_request(probe_target, "GET", None, exc.code)
        return None

    if after_request is not None:
        after_request(probe_target, "GET", response, None)

    return response


def enforce_probe_budget(
    candidates: Tuple[DetectionCandidate, ...],
    policy: ActiveDetectionPolicy,
    *,
    requests_per_candidate: int = 1,
) -> None:
    """Fail closed if the candidate list would exceed the run's probe
    budget. requests_per_candidate lets a detector that issues more than
    one request per candidate (for example a baseline plus a diagnostic
    mutation) declare its real request cost so this check reflects actual
    outbound requests, not just candidate count."""

    total_requests = len(candidates) * requests_per_candidate
    if total_requests > policy.maximum_probe_requests:
        raise ActiveDetectionError(
            "candidate_budget_exceeded",
            f"{len(candidates)} candidates at {requests_per_candidate} "
            f"request(s) each ({total_requests} total) exceed the "
            f"maximum_probe_requests policy of "
            f"{policy.maximum_probe_requests}.",
        )


def throttle(policy: ActiveDetectionPolicy) -> None:
    """Sleep for the run's configured minimum inter-probe delay."""

    if policy.minimum_delay_seconds > 0:
        time.sleep(policy.minimum_delay_seconds)


__all__ = [
    "ActiveDetectionContext",
    "ActiveDetectionError",
    "ActiveDetectionPolicy",
    "DetectionCandidate",
    "ProbeAttempt",
    "enforce_probe_budget",
    "fetch_same_origin_page",
    "issue_probe",
    "throttle",
]
