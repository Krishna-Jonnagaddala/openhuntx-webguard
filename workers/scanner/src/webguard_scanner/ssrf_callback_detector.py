"""Active SSRF detector (CWE-918): confirms Server-Side Request Forgery
by observing a genuine, out-of-band, server-side outbound request from
the target application to a WebGuard-controlled callback destination --
never by guessing from response text.

Detection methodology
----------------------
For each candidate request-template field whose parameter *name*
suggests it might carry a URL (a discovery-time filter only -- never
evidence by itself), this detector:

1. Registers a fresh, single-purpose ``CallbackToken`` (high-entropy,
   scan-bound and candidate-bound) through the injected
   ``CallbackBroker``.
2. Mutates *only* that one parameter to the resulting callback URL,
   preserving every other field of the request template unchanged
   (the same ``mutate()`` mutation engine XSS/SQLi detection already
   uses).
3. Issues exactly one bounded request via ``issue_templated_request``
   -- the same shared transport, same-origin enforcement, and
   authentication mechanism every other active detector in this
   codebase uses. No separate network stack is created.
4. Waits, bounded, for a callback observation correlated to that exact
   token -- never for an internal address, never for anything other
   than the token this detector itself just issued.

Confirmation levels
--------------------
- CONFIRMED: the probe request itself succeeded, and a callback
  observation for this exact token arrived within the policy's primary
  wait window. This is the only path to CONFIRMED -- a target response
  that merely reflects, mentions, or validates the callback URL is
  never sufficient on its own.
- PROBABLE: identical to CONFIRMED except the (still exactly
  token-correlated) observation only arrived during the secondary
  grace window -- weaker timing evidence, still never guessed.
- NOT_VULNERABLE: the probe request succeeded and no callback
  observation arrived even after the full wait+grace window elapsed.
- INCONCLUSIVE: callback registration itself failed (e.g. the
  broker's own registration budget was exhausted), or the wait for an
  observation was stopped early by cancellation -- in both cases this
  detector could not actually complete the test, so it makes no claim
  either way.
- ERROR: the probe request itself failed at the transport level.
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

from .active_detection import ActiveDetectionContext, ActiveDetectionPolicy, enforce_probe_budget, throttle
from .authentication import AuthenticationMaterial
from .callback_broker import CallbackBroker, CallbackBrokerError, CallbackObservation, CallbackPolicy
from .request_template import (
    MutatedRequest,
    RequestTemplate,
    RequestTemplateError,
    issue_templated_request,
    mutate,
)
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


_DETECTOR_ID = "active.ssrf.callback"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_SSRF = ExternalIdentifier("CWE", "CWE-918")
# OWASP Top 10 (2021) A10 is literally "Server-Side Request Forgery" --
# a direct, well-justified match, not a stretch the way a generic
# category would be. This is this project's second non-CWE identifier
# namespace addition (the first was OWASP-API, for IDOR, in Slice 8).
_OWASP_TOP10_SSRF = ExternalIdentifier("OWASP", "A10:2021")

_REQUESTS_PER_CANDIDATE = 1

# Discovery-time filter only (requirement 4): a parameter name matching
# one of these hints makes a request-template field *eligible* to be
# probed. It is never evidence of vulnerability by itself, and no
# finding this detector produces depends on it -- only a genuine
# callback observation does.
SSRF_PARAMETER_NAME_HINTS = frozenset(
    {
        "url",
        "uri",
        "callback",
        "webhook",
        "image",
        "avatar",
        "feed",
        "source",
        "redirect",
        "endpoint",
        "fetch",
        "import",
    }
)


class SsrfDetectionOutcome(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"


_FINDING_OUTCOMES = frozenset(
    {SsrfDetectionOutcome.CONFIRMED, SsrfDetectionOutcome.PROBABLE}
)

_OUTCOME_CONFIDENCE = {
    SsrfDetectionOutcome.CONFIRMED: Confidence.CONFIRMED,
    SsrfDetectionOutcome.PROBABLE: Confidence.HIGH,
}

_OUTCOME_TITLE = {
    SsrfDetectionOutcome.CONFIRMED: (
        "Server-Side Request Forgery (confirmed callback)"
    ),
    SsrfDetectionOutcome.PROBABLE: (
        "Server-Side Request Forgery (probable callback)"
    ),
}

_OUTCOME_DESCRIPTION = {
    SsrfDetectionOutcome.CONFIRMED: (
        "The application accepted a WebGuard-controlled callback URL as "
        "the value of a URL-shaped parameter and its own server made an "
        "outbound request to that exact, uniquely-tokenized destination "
        "within the expected time window -- direct evidence of a "
        "server-side outbound request the client never asked for and "
        "cannot see the response of."
    ),
    SsrfDetectionOutcome.PROBABLE: (
        "The application accepted a WebGuard-controlled callback URL as "
        "the value of a URL-shaped parameter and a correlated, uniquely "
        "-tokenized callback was observed, but only after the primary "
        "wait window elapsed -- still exactly token-correlated, but "
        "weaker timing evidence than an on-time callback."
    ),
}

_REMEDIATION = (
    "Never allow server-side code to fetch a URL supplied by an "
    "untrusted client without validation. Prefer an allowlist of "
    "permitted destination hosts/schemes, resolve and validate the "
    "destination before connecting, disable automatic redirect "
    "following, and block requests to internal/link-local/metadata "
    "address ranges at the network layer."
)

_REFERENCES = (
    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    "https://cwe.mitre.org/data/definitions/918.html",
)


def is_ssrf_candidate_parameter(name: str) -> bool:
    """Discovery-time name filter (requirement 4) -- never confirmation
    evidence. Substring match, case-insensitive: deliberately a little
    permissive (e.g. ``resource_id`` also matches "source") since
    over-inclusion here only costs one extra bounded probe request per
    candidate and can never itself produce a finding -- only a genuine
    callback observation can."""

    normalized = name.lower()
    return any(hint in normalized for hint in SSRF_PARAMETER_NAME_HINTS)


def select_ssrf_candidates(
    templates: Tuple[RequestTemplate, ...]
) -> Tuple[RequestTemplate, ...]:
    seen_candidate_ids: set[str] = set()
    selected: list[RequestTemplate] = []
    for template in templates:
        if not template.parameter or not is_ssrf_candidate_parameter(template.parameter):
            continue
        dedupe_key = template.source_candidate_id or (
            f"{template.endpoint}|{template.method}|{template.parameter}"
        )
        if dedupe_key in seen_candidate_ids:
            continue
        seen_candidate_ids.add(dedupe_key)
        selected.append(template)
    return tuple(selected)


@dataclass(frozen=True, slots=True)
class SsrfProbeRecord:
    """One candidate's outcome, regardless of whether a finding was
    produced -- so "not vulnerable" is always distinguishable from "not
    tested"."""

    candidate_endpoint: str
    method: str
    parameter: str
    outcome: SsrfDetectionOutcome
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class SsrfDetectorRunResult:
    detector_id: str
    records: Tuple[SsrfProbeRecord, ...]
    findings: Tuple[NormalizedFinding, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool


def _build_finding(
    target: ValidatedTarget,
    *,
    template: RequestTemplate,
    outcome: SsrfDetectionOutcome,
    context: ActiveDetectionContext,
    observation: CallbackObservation | None,
    token_fingerprint: str,
) -> NormalizedFinding:
    parsed = urlsplit(template.endpoint)

    identity = FindingIdentity(
        rule_id=f"{_DETECTOR_ID}.{outcome.value}",
        asset=f"{target.scheme}://{target.hostname}"
        + (f":{target.port}" if target.port not in (80, 443) else ""),
        path=parsed.path or "/",
        method=template.method,
        parameter=template.parameter,
    )

    # Bounded, non-sensitive evidence only (requirement 10): candidate
    # endpoint/method/parameter (via FindingIdentity), scan/authorization/
    # permit provenance, the callback observation's timestamp/method, and
    # a truncated fingerprint of the (WebGuard-generated, non-secret)
    # correlation token -- never the raw token/URL, never a header, never
    # a source IP, never any response body.
    provenance = (
        f"Detector {_DETECTOR_ID} v{_DETECTOR_VERSION}. "
        f"Scan: {context.scan_id}. "
        f"Authorization: {context.authorization_id or 'not recorded'}. "
        f"Permit: {context.permit_id or 'not recorded'}. "
        f"Parameter: {template.parameter} ({template.content_type or 'query'}). "
        f"Controlled destination class: webguard-callback. "
        f"Callback token fingerprint: {token_fingerprint}. "
        + (
            f"Callback observed at {observation.observed_at.isoformat()} "
            f"via {observation.method}. "
            if observation is not None
            else ""
        )
        + f"Outcome: {outcome.value}."
    )

    return NormalizedFinding(
        identity=identity,
        source=_SOURCE,
        title=_OUTCOME_TITLE[outcome],
        description=_OUTCOME_DESCRIPTION[outcome],
        severity=Severity.HIGH,
        confidence=_OUTCOME_CONFIDENCE[outcome],
        remediation=_REMEDIATION,
        source_rule_id=f"ACTIVE-SSRF-CALLBACK-{outcome.value.upper()}",
        identifiers=(_CWE_SSRF, _OWASP_TOP10_SSRF),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("ssrf", "callback", "active", f"outcome-{outcome.value}"),
    )


def run_ssrf_callback_detector(
    target: ValidatedTarget,
    candidates: Tuple[RequestTemplate, ...],
    context: ActiveDetectionContext,
    *,
    callback_broker: CallbackBroker,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    callback_policy: CallbackPolicy = CallbackPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    authentication_material: AuthenticationMaterial | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> SsrfDetectorRunResult:
    """Run the SSRF-callback detector across a bounded set of candidate
    request templates. ``candidates`` may be a mixed discovery result;
    this function itself narrows to URL-shaped parameter names via
    ``select_ssrf_candidates`` and never probes anything else.

    Enforces ``policy.maximum_probe_requests`` against the real request
    cost (one probe request per selected candidate; the callback wait
    itself issues no additional request from WebGuard's own client)
    before any request is sent.
    """

    ssrf_candidates = select_ssrf_candidates(candidates)
    enforce_probe_budget(
        ssrf_candidates, policy, requests_per_candidate=_REQUESTS_PER_CANDIDATE
    )

    records: list[SsrfProbeRecord] = []
    findings: list[NormalizedFinding] = []
    probe_errors: list[str] = []
    cancelled = False

    for template in ssrf_candidates:
        if cancellation_check is not None and cancellation_check():
            cancelled = True
            break

        try:
            token = callback_broker.register(
                scan_id=context.scan_id,
                candidate_fingerprint=(
                    template.source_candidate_id or template.parameter
                ),
            )
        except CallbackBrokerError as exc:
            probe_errors.append(exc.code)
            records.append(
                SsrfProbeRecord(
                    candidate_endpoint=template.endpoint,
                    method=template.method,
                    parameter=template.parameter,
                    outcome=SsrfDetectionOutcome.INCONCLUSIVE,
                    detected_at=_utc_now(),
                )
            )
            continue

        try:
            mutated: MutatedRequest = mutate(template, template.parameter, token.url)
        except RequestTemplateError as exc:
            probe_errors.append(exc.code)
            records.append(
                SsrfProbeRecord(
                    candidate_endpoint=template.endpoint,
                    method=template.method,
                    parameter=template.parameter,
                    outcome=SsrfDetectionOutcome.ERROR,
                    detected_at=_utc_now(),
                )
            )
            continue

        attempt = issue_templated_request(
            target,
            mutated,
            policy=policy,
            before_request=before_request,
            after_request=after_request,
            authentication_material=authentication_material,
        )

        if not attempt.succeeded:
            probe_errors.append(attempt.error_code or "unknown_probe_error")
            records.append(
                SsrfProbeRecord(
                    candidate_endpoint=template.endpoint,
                    method=template.method,
                    parameter=template.parameter,
                    outcome=SsrfDetectionOutcome.ERROR,
                    detected_at=_utc_now(),
                )
            )
            continue

        throttle(policy)

        try:
            observation, within_primary_window, was_cancelled = (
                callback_broker.wait_for_observation(
                    token,
                    policy=callback_policy,
                    cancellation_check=cancellation_check,
                )
            )
        except CallbackBrokerError as exc:
            # A callback-storage failure while waiting (e.g. the
            # backing database becomes unavailable mid-poll) must
            # degrade only this one candidate to INCONCLUSIVE -- the
            # identical treatment `register()`'s own CallbackBrokerError
            # already gets above -- never silently reclassified as
            # NOT_VULNERABLE (which would be indistinguishable from a
            # genuine negative result) and never left to propagate and
            # fail the whole scan job.
            probe_errors.append(exc.code)
            records.append(
                SsrfProbeRecord(
                    candidate_endpoint=template.endpoint,
                    method=template.method,
                    parameter=template.parameter,
                    outcome=SsrfDetectionOutcome.INCONCLUSIVE,
                    detected_at=_utc_now(),
                )
            )
            continue

        if was_cancelled:
            outcome = SsrfDetectionOutcome.INCONCLUSIVE
        elif observation is None:
            outcome = SsrfDetectionOutcome.NOT_VULNERABLE
        elif within_primary_window:
            outcome = SsrfDetectionOutcome.CONFIRMED
        else:
            outcome = SsrfDetectionOutcome.PROBABLE

        records.append(
            SsrfProbeRecord(
                candidate_endpoint=template.endpoint,
                method=template.method,
                parameter=template.parameter,
                outcome=outcome,
                detected_at=_utc_now(),
            )
        )

        if outcome in _FINDING_OUTCOMES:
            token_fingerprint = hashlib.sha256(token.value.encode()).hexdigest()[:16]
            findings.append(
                _build_finding(
                    target,
                    template=template,
                    outcome=outcome,
                    context=context,
                    observation=observation,
                    token_fingerprint=token_fingerprint,
                )
            )

    return SsrfDetectorRunResult(
        detector_id=_DETECTOR_ID,
        records=tuple(records),
        findings=tuple(findings),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "SSRF_PARAMETER_NAME_HINTS",
    "SsrfDetectionOutcome",
    "SsrfDetectorRunResult",
    "SsrfProbeRecord",
    "is_ssrf_candidate_parameter",
    "run_ssrf_callback_detector",
    "select_ssrf_candidates",
]
