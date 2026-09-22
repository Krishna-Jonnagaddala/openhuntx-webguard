"""Active missing-authentication detector (CWE-306, Missing
Authentication for Critical Function): compares one controlled test
identity's own access to an explicit, operator-asserted endpoint
against a plain, anonymous request to that same endpoint.

This is the concrete, safely-testable instance of the broader "broken
authentication" (CWE-287) request this project's own coverage registry
tracks: proving a genuine authentication *bypass* (a target that
accepts credentials it should reject) would require actually
completing an unauthorized login, which is destructive testing this
project's own ``ROADMAP.md`` excludes by design ("password attacks...
are not part of the current initial release scope"). Proving a
resource is reachable with *no* authentication at all requires no
password guessing, no session forgery, and no state change: it is a
single anonymous GET request, the same shape every other detector's
diagnostic probe already uses.

Detection methodology
----------------------
For each operator-supplied endpoint (never discovered, crawled for, or
enumerated by this module -- the identical discipline
``idor_authorization_detector.py`` already follows for its own
resource pairs), exactly two bounded GET requests are issued:

1. **baseline**: the referenced identity requests the endpoint. Must
   succeed with HTTP 200 to establish what the real, protected content
   looks like; anything else makes this endpoint INCONCLUSIVE, since
   there is nothing legitimate to compare against.
2. **probe**: the identical endpoint is requested again, with no
   authentication material at all -- no cookie header, no
   Authorization header, nothing. This must never be confused with the
   baseline request by sharing any state: this codebase's transport
   layer opens a fresh connection per request with no cookie jar or
   session object anywhere (verified directly against ``safe_http.py``
   before this detector was written), so there is no code path by
   which credentials could leak from one request to the other
   regardless of call order.

Both requests are issued with ``allow_redirect_status=True`` and a 3xx
response is classified from its status alone, before any body is ever
read or fingerprinted: a redirect (most commonly, to a login page) is
exactly what a correctly-gated endpoint is expected to do to an
anonymous request, and fingerprinting a redirect's own (usually
unrelated) body would be meaningless.

A finding requires more than a bare 200: unlike
``idor_authorization_detector.py``, which always has a *second*
identity's own baseline to rule out "this endpoint returns the same
thing to everyone" as a negative control, this detector has no second
identity, structurally. An exact content-fingerprint match between the
baseline and the probe proves the *same* bytes were served without
authentication, but not, by itself, that those bytes are genuinely
sensitive rather than a page that is legitimately, harmlessly identical
for every visitor (a CDN-cached static asset; an unpersonalized
single-page-app shell whose real per-account data loads separately via
an API call the operator never listed). For that reason CONFIRMED
requires both signals to agree: an exact fingerprint match *and* the
endpoint's own optional ``owner_marker`` (mirroring
``AuthorizationResource.owner_marker`` exactly, already opt-in there
too) present in the probe response. Either signal alone -- a fingerprint
match with no marker configured, or a marker match on a body that does
not exactly match the baseline (the common case when a page embeds a
per-request CSRF token, nonce, or timestamp) -- reaches only PROBABLE.

Confirmation levels
--------------------
- CONFIRMED: the anonymous probe succeeded with HTTP 200, its content
  fingerprint exactly matches the authenticated baseline's, and the
  endpoint's configured ``owner_marker`` is present in the probe's
  response body.
- PROBABLE: the anonymous probe succeeded with HTTP 200 and exactly one
  of the two CONFIRMED signals holds: either the fingerprint matches
  exactly but no marker was configured or found, or a configured marker
  is present despite the bodies not matching exactly.
- NOT_VULNERABLE: the anonymous probe was denied (a non-2xx status,
  including a 3xx redirect -- typically to a login page), or it
  succeeded with 200 but neither the fingerprint nor a configured
  marker corroborates that the real protected content was returned.
- INCONCLUSIVE: the authenticated baseline itself did not succeed with
  200 -- there is nothing legitimate established to compare against,
  so no claim is made either way.
- ERROR: the anonymous probe failed at the transport level, or this
  one endpoint's same-origin check failed. Deliberately scoped to
  exactly one endpoint: a single malformed or off-origin entry among up
  to ten never discards the other, valid entries' results.

v1 scope, stated plainly rather than left implicit:

- GET only. An anonymous probe against an operator-asserted "critical"
  endpoint must never be able to change state regardless of whether
  the target turns out to be vulnerable; enforced both by this
  project's own permit-claim validation (``MissingAuthenticationEndpoint``
  rejects any method but GET) and, independently, here.
- This module itself has no scan-mode restriction: it accepts any
  ``ValidatedTarget`` and endpoint list and runs the same two-request
  probe regardless of how the caller's scan was configured. The
  restriction to single-page scans lives one layer up, in
  ``executor._apply_missing_authentication_detection``, for a reason
  that is a contract limitation rather than a candidate-attribution
  one: ``webguard_contracts.CrawlScanResult`` (a crawl scan's report
  type) has no scan-wide ``findings`` field at all -- unlike
  ``ScanResult``, findings on a crawl report exist only inside each
  individual entry of its own ``pages`` tuple, each a
  ``CrawlPageScanResult``. ``active.authorization.idor``/
  ``active.ssrf.callback``/``active.xxe.callback`` all skip crawl-mode
  scans in the executor for the same underlying reason (their own
  docstrings describe it as page attribution, which is the visible
  symptom of this same contract gap for detectors that discover
  candidates from a page). This detector's candidates are never
  page-specific to begin with -- they come entirely from the signed
  permit's own ``missing_authentication_endpoints`` claim -- so there
  is not even a plausible single page to attribute a crawl-mode finding
  to. Extending ``CrawlScanResult`` with a scan-wide findings field
  would be required to support crawl mode honestly, and is tracked as
  follow-up work, not implemented here.
- No client-side (JavaScript-gated) SPA detection: if the real access
  control lives entirely in client-side routing, with the server
  serving the identical HTML shell to every visitor regardless of
  session and the actual protected data arriving through a separate
  API call, this detector cannot distinguish that from a genuine
  server-side authentication failure unless the operator supplies a
  marker specific to genuinely protected content. This is exactly why
  a marker-less match is capped at PROBABLE, never CONFIRMED: it is a
  named, structural limit of comparing a single identity against no
  identity at all, not an oversight.
- The authenticated identity itself is resolved and validated exactly
  once, by the caller, before any endpoint in this run is probed, and a
  failure there (an expired or revoked authentication context) must
  propagate as a scan-level failure, never be silently downgraded to a
  per-endpoint INCONCLUSIVE -- matching this project's own established
  pattern for every other authenticated active detector.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Tuple
from urllib.parse import urlsplit

from webguard_contracts import (
    Confidence,
    Evidence,
    ExternalIdentifier,
    FindingIdentity,
    NormalizedFinding,
    Severity,
)

from .active_detection import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    _build_probe_target,
    _require_same_origin,
)
from .authentication import AuthenticationMaterial, apply_authentication
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .safe_http import SafeRequestError, fetch_once
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


_DETECTOR_ID = "active.authentication.missing"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_MISSING_AUTH = ExternalIdentifier("CWE", "CWE-306")
_REQUESTS_PER_ENDPOINT = 2


class MissingAuthenticationOutcome(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"


_FINDING_OUTCOMES = frozenset(
    {MissingAuthenticationOutcome.CONFIRMED, MissingAuthenticationOutcome.PROBABLE}
)

_OUTCOME_CONFIDENCE = {
    MissingAuthenticationOutcome.CONFIRMED: Confidence.CONFIRMED,
    MissingAuthenticationOutcome.PROBABLE: Confidence.HIGH,
}

_OUTCOME_TITLE = {
    MissingAuthenticationOutcome.CONFIRMED: (
        "Missing Authentication for Critical Function (confirmed marker leak)"
    ),
    MissingAuthenticationOutcome.PROBABLE: (
        "Missing Authentication for Critical Function (probable content leak)"
    ),
}

_OUTCOME_DESCRIPTION = {
    MissingAuthenticationOutcome.CONFIRMED: (
        "An anonymous request to this endpoint, carrying no "
        "authentication credentials at all, succeeded (HTTP 200), "
        "returned a byte-for-byte match of the authenticated baseline's "
        "content, and contained the operator-configured marker known to "
        "appear only in this endpoint's genuinely protected content. The "
        "endpoint does not require authentication to access, despite "
        "being asserted as requiring it."
    ),
    MissingAuthenticationOutcome.PROBABLE: (
        "An anonymous request to this endpoint, carrying no "
        "authentication credentials at all, succeeded (HTTP 200) and "
        "either exactly matched the authenticated baseline's content or "
        "contained the operator-configured corroborating marker (though "
        "not both). This is consistent with the endpoint not requiring "
        "authentication, though (unlike a two-identity comparison) this "
        "detector has no second identity's own baseline to rule out a "
        "coincidentally identical, harmless public response."
    ),
}

_REMEDIATION = (
    "Require successful authentication before serving this endpoint's "
    "response to any client. Verify the check happens on every request "
    "path that can reach this resource (including alternate routes, "
    "cached responses, and any reverse proxy or CDN configuration), not "
    "only the primary navigation flow."
)

_REFERENCES = (
    "https://cwe.mitre.org/data/definitions/306.html",
    "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
)


@dataclass(frozen=True, slots=True)
class MissingAuthenticationObservation:
    """Bounded, non-sensitive characteristics of one probe response.
    Never stores the complete response body -- only whether it was
    present, its status, a content fingerprint, and whether the
    endpoint's own ``owner_marker`` (when configured) was found in it.
    ``marker_matched`` is ``None`` when no marker was configured, and a
    plain boolean otherwise, mirroring
    ``AuthorizationDifferentialObservation`` in
    ``idor_authorization_detector.py``. ``content_fingerprint`` is
    ``None`` for any non-200 status: a redirect or denial's body is
    never fingerprinted, since it carries no information about the
    protected content."""

    succeeded: bool
    status: int | None
    content_fingerprint: str | None
    marker_matched: bool | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class MissingAuthenticationRecord:
    """One probed endpoint's outcome, regardless of whether a finding
    was produced, so "no finding" is always distinguishable from "not
    tested"."""

    endpoint: str
    outcome: MissingAuthenticationOutcome
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class MissingAuthenticationDetectorRunResult:
    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[MissingAuthenticationRecord, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool = False


def _fetch_observation(
    base_target: ValidatedTarget,
    endpoint: str,
    material: AuthenticationMaterial | None,
    *,
    owner_marker: str,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None,
    after_request: AfterRequestHook | None,
) -> MissingAuthenticationObservation:
    """Issues exactly one bounded GET, with ``allow_redirect_status=True``
    so a 3xx (typically a login redirect) is returned intact instead of
    raising ``redirect_blocked``. ``material=None`` sends the request
    with no authentication headers at all --
    ``authentication.apply_authentication`` returns no headers for
    ``None``, so there is no header to omit or accidentally carry over
    by construction, not merely by care taken at this call site.
    """

    _require_same_origin(base_target, endpoint)
    probe_target = _build_probe_target(base_target, endpoint)
    extra_headers = apply_authentication(endpoint, material, now=_utc_now())

    if before_request is not None:
        before_request(probe_target, "GET")

    try:
        response = fetch_once(
            probe_target,
            method="GET",
            policy=policy.fetch_policy,
            extra_headers=extra_headers,
            allow_redirect_status=True,
        )
    except SafeRequestError as exc:
        if after_request is not None:
            after_request(probe_target, "GET", None, exc.code)
        return MissingAuthenticationObservation(
            succeeded=False,
            status=None,
            content_fingerprint=None,
            marker_matched=None,
            error_code=exc.code,
        )

    if after_request is not None:
        after_request(probe_target, "GET", response, None)

    if response.status != 200:
        # A redirect (commonly to a login page) or an outright denial --
        # either way, the body carries no information about the
        # protected content and is never fingerprinted.
        return MissingAuthenticationObservation(
            succeeded=True,
            status=response.status,
            content_fingerprint=None,
            marker_matched=None,
            error_code=None,
        )

    marker_matched = (
        owner_marker.encode("utf-8", errors="replace") in response.body
        if owner_marker
        else None
    )

    return MissingAuthenticationObservation(
        succeeded=True,
        status=response.status,
        content_fingerprint=hashlib.sha256(response.body).hexdigest(),
        marker_matched=marker_matched,
        error_code=None,
    )


def _classify(
    *,
    baseline: MissingAuthenticationObservation,
    probe: MissingAuthenticationObservation,
) -> MissingAuthenticationOutcome:
    if not baseline.succeeded or baseline.status != 200:
        return MissingAuthenticationOutcome.INCONCLUSIVE

    if not probe.succeeded:
        return MissingAuthenticationOutcome.ERROR

    if probe.status != 200:
        # Denied outright (401/403/etc), or a 3xx -- most commonly a
        # redirect to a login page -- either way correct gating.
        return MissingAuthenticationOutcome.NOT_VULNERABLE

    exact_match = probe.content_fingerprint == baseline.content_fingerprint
    marker_matched = bool(probe.marker_matched)

    if exact_match and marker_matched:
        return MissingAuthenticationOutcome.CONFIRMED

    if exact_match or marker_matched:
        return MissingAuthenticationOutcome.PROBABLE

    return MissingAuthenticationOutcome.NOT_VULNERABLE


def _build_finding(
    target: ValidatedTarget,
    *,
    endpoint: str,
    outcome: MissingAuthenticationOutcome,
    context: ActiveDetectionContext,
) -> NormalizedFinding:
    parsed = urlsplit(endpoint)

    identity = FindingIdentity(
        rule_id=f"{_DETECTOR_ID}.{outcome.value}",
        asset=f"{target.scheme}://{target.hostname}"
        + (f":{target.port}" if target.port not in (80, 443) else ""),
        path=parsed.path or "/",
        method="GET",
        parameter=None,
    )

    provenance = (
        f"Detector {_DETECTOR_ID} v{_DETECTOR_VERSION}. "
        f"Scan: {context.scan_id}. "
        f"Authorization: {context.authorization_id or 'not recorded'}. "
        f"Permit: {context.permit_id or 'not recorded'}. "
        f"An anonymous request to this endpoint returned the same "
        f"protected content an authenticated identity receives. "
        f"Outcome: {outcome.value}."
    )

    return NormalizedFinding(
        identity=identity,
        source=_SOURCE,
        title=_OUTCOME_TITLE[outcome],
        description=_OUTCOME_DESCRIPTION[outcome],
        severity=Severity.HIGH,
        confidence=_OUTCOME_CONFIDENCE[outcome],
        remediation=_REMEDIATION,
        source_rule_id=f"ACTIVE-AUTHENTICATION-MISSING-{outcome.value.upper()}",
        identifiers=(_CWE_MISSING_AUTH,),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("missing-authentication", "access-control", "active", f"outcome-{outcome.value}"),
    )


def run_missing_authentication_detector(
    target: ValidatedTarget,
    endpoints,
    context: ActiveDetectionContext,
    *,
    authentication_material: AuthenticationMaterial,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> MissingAuthenticationDetectorRunResult:
    """Run the missing-authentication detector across a bounded set of
    operator-supplied endpoints.

    ``target`` must already be scope-validated. ``endpoints`` must
    already be restricted to explicit, operator-controlled URLs (in
    practice, a permit's own ``missing_authentication_endpoints``
    claim, each a ``MissingAuthenticationEndpoint``) -- this function
    never discovers, crawls for, or enumerates one.
    ``authentication_material`` must already reference a live,
    validated identity: this function does not itself resolve or
    re-validate it, matching this project's existing pattern of
    resolving an authenticated identity once, up front, at the executor
    layer, and letting a resolution failure there propagate as a
    scan-level error rather than being caught per-endpoint here.

    Each endpoint costs two requests (authenticated baseline, anonymous
    probe); ``policy.maximum_probe_requests`` is enforced against that
    real cost before any request is sent. A single endpoint's same-
    origin or transport failure is recorded as that one endpoint's own
    ERROR outcome and does not discard results for any other endpoint
    in the same run.

    ``cancellation_check``, if supplied, is polled before every
    endpoint.
    """

    from .active_detection import ActiveDetectionError

    total_requests = len(endpoints) * _REQUESTS_PER_ENDPOINT
    if total_requests > policy.maximum_probe_requests:
        raise ActiveDetectionError(
            "candidate_budget_exceeded",
            f"{len(endpoints)} endpoints at {_REQUESTS_PER_ENDPOINT} "
            f"request(s) each ({total_requests} total) exceed the "
            f"maximum_probe_requests policy of "
            f"{policy.maximum_probe_requests}.",
        )

    findings: list[NormalizedFinding] = []
    records: list[MissingAuthenticationRecord] = []
    probe_errors: list[str] = []
    cancelled = False

    for endpoint in endpoints:
        if cancellation_check is not None and cancellation_check():
            cancelled = True
            break

        try:
            baseline = _fetch_observation(
                target,
                endpoint.endpoint,
                authentication_material,
                owner_marker=endpoint.owner_marker,
                policy=policy,
                before_request=before_request,
                after_request=after_request,
            )
            probe = _fetch_observation(
                target,
                endpoint.endpoint,
                None,
                owner_marker=endpoint.owner_marker,
                policy=policy,
                before_request=before_request,
                after_request=after_request,
            )
        except ActiveDetectionError as exc:
            # Scoped to exactly this one endpoint (e.g. an off-origin
            # URL among several): recorded as this endpoint's own
            # ERROR, never lets one bad entry discard every other,
            # valid endpoint's already-collected results.
            probe_errors.append(exc.code)
            records.append(
                MissingAuthenticationRecord(
                    endpoint=endpoint.endpoint,
                    outcome=MissingAuthenticationOutcome.ERROR,
                    detected_at=_utc_now(),
                )
            )
            continue

        if not baseline.succeeded:
            probe_errors.append(baseline.error_code or "unknown_probe_error")
        if not probe.succeeded:
            probe_errors.append(probe.error_code or "unknown_probe_error")

        outcome = _classify(baseline=baseline, probe=probe)
        records.append(
            MissingAuthenticationRecord(
                endpoint=endpoint.endpoint,
                outcome=outcome,
                detected_at=_utc_now(),
            )
        )

        if outcome in _FINDING_OUTCOMES:
            findings.append(
                _build_finding(
                    target,
                    endpoint=endpoint.endpoint,
                    outcome=outcome,
                    context=context,
                )
            )

    return MissingAuthenticationDetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "MissingAuthenticationDetectorRunResult",
    "MissingAuthenticationObservation",
    "MissingAuthenticationOutcome",
    "MissingAuthenticationRecord",
    "run_missing_authentication_detector",
]
