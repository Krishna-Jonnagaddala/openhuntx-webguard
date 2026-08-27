"""Active reflected-XSS detector: GET-parameter marker reflection.

Detection methodology
----------------------
For each authorized candidate parameter, this detector sends exactly one
bounded GET request with the parameter value replaced by a unique,
non-guessable marker wrapped in angle brackets -- a syntactically
structural but semantically inert fake tag, for example
``<wgxss3f9a2c1b0e7d4a>``. It then inspects the *raw* response body text
for that exact marker.

This never executes any script and never renders the response in a
browser -- only bounded string matching against the HTTP response body
already fetched by ``safe_http``. It therefore cannot itself trigger the
vulnerability it looks for; it only establishes whether the server
reflects attacker-controlled input without HTML-entity-encoding, which is
the necessary (not sufficient) condition for reflected XSS.

Confirmation levels
--------------------
- CONFIRMED: the exact ``<marker>`` substring (both angle brackets intact)
  appears verbatim in the response body -- a complete, unescaped tag
  boundary was reflected.
- PROBABLE: one of the marker's two angle brackets survived unescaped
  (partial injection -- still demonstrates unescaped reflection, just not
  a complete tag boundary in this single probe).
- SUSPECTED: the marker text appears in the body, but neither angle
  bracket survived unescaped -- reflection is present but raw HTML
  injection was not demonstrated from this probe alone.
- INFORMATIONAL: the marker appears fully HTML-entity-encoded
  (``&lt;marker&gt;``) -- reflected, but safely escaped. This is a
  negative/positive-control result, not a vulnerability.
- INCONCLUSIVE: the marker does not appear in the response body at all.
  Produces no finding.

Only CONFIRMED, PROBABLE, SUSPECTED, and INFORMATIONAL produce a finding.
Every candidate probed -- including INCONCLUSIVE ones and probes that
failed outright -- is recorded in the returned ``DetectorRunResult`` for
audit purposes, so "no finding" is always distinguishable from "not
tested."
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, Tuple
from urllib.parse import urlsplit
from uuid import uuid4

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
    DetectionCandidate,
    enforce_probe_budget,
    issue_probe,
    throttle,
)
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    from datetime import timezone

    return datetime.now(timezone.utc)


_DETECTOR_ID = "active.xss.reflected"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_XSS = ExternalIdentifier("CWE", "CWE-79")


class DetectionOutcome(str, Enum):
    """Confirmation strength for one reflected-XSS probe."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    SUSPECTED = "suspected"
    INFORMATIONAL = "informational"
    INCONCLUSIVE = "inconclusive"


_FINDING_OUTCOMES = frozenset(
    {
        DetectionOutcome.CONFIRMED,
        DetectionOutcome.PROBABLE,
        DetectionOutcome.SUSPECTED,
        DetectionOutcome.INFORMATIONAL,
    }
)

_OUTCOME_SEVERITY = {
    DetectionOutcome.CONFIRMED: Severity.HIGH,
    DetectionOutcome.PROBABLE: Severity.HIGH,
    DetectionOutcome.SUSPECTED: Severity.MEDIUM,
    DetectionOutcome.INFORMATIONAL: Severity.INFORMATIONAL,
}

_OUTCOME_CONFIDENCE = {
    DetectionOutcome.CONFIRMED: Confidence.CONFIRMED,
    DetectionOutcome.PROBABLE: Confidence.HIGH,
    DetectionOutcome.SUSPECTED: Confidence.MEDIUM,
    DetectionOutcome.INFORMATIONAL: Confidence.CONFIRMED,
}

_OUTCOME_TITLE = {
    DetectionOutcome.CONFIRMED: (
        "Reflected Cross-Site Scripting (confirmed unescaped reflection)"
    ),
    DetectionOutcome.PROBABLE: (
        "Reflected Cross-Site Scripting (probable unescaped reflection)"
    ),
    DetectionOutcome.SUSPECTED: (
        "Parameter value reflected without full encoding confirmation"
    ),
    DetectionOutcome.INFORMATIONAL: (
        "Parameter value is reflected but HTML-encoded"
    ),
}

_OUTCOME_DESCRIPTION = {
    DetectionOutcome.CONFIRMED: (
        "A unique marker value containing angle brackets was submitted as "
        "this parameter and returned verbatim in the response body with "
        "both angle brackets intact, forming a complete, unescaped tag "
        "boundary. A browser rendering this response would parse the "
        "injected value as HTML, which means an attacker-supplied "
        "<script> or event-handler payload would also be parsed and "
        "potentially executed."
    ),
    DetectionOutcome.PROBABLE: (
        "A unique marker value containing angle brackets was submitted as "
        "this parameter and returned in the response body with one of its "
        "two angle brackets unescaped. This demonstrates unescaped "
        "reflection of attacker-controlled input, though a complete tag "
        "boundary was not observed from this single probe."
    ),
    DetectionOutcome.SUSPECTED: (
        "A unique marker value was submitted as this parameter and its "
        "text was observed in the response body, but neither angle "
        "bracket survived unescaped in this probe. Reflection of "
        "attacker-controlled input is present; unescaped HTML injection "
        "was not demonstrated from this probe alone."
    ),
    DetectionOutcome.INFORMATIONAL: (
        "A unique marker value containing angle brackets was submitted as "
        "this parameter and returned in the response body fully "
        "HTML-entity-encoded. The parameter is reflected, but the "
        "observed encoding would prevent this specific probe from "
        "executing as HTML."
    ),
}

_REMEDIATION = (
    "Apply context-appropriate output encoding to all reflected "
    "user-controlled input (HTML-entity encoding for HTML body context, "
    "attribute encoding for attribute context, JavaScript string escaping "
    "for script context). Deploy a Content-Security-Policy as defense in "
    "depth. Do not rely on blocklist-based input filtering alone."
)

_REFERENCES = (
    "https://owasp.org/www-community/attacks/xss/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
)


@dataclass(frozen=True, slots=True)
class DetectorRunRecord:
    """One probed candidate and its outcome, regardless of whether a
    finding was produced. Exists so "no finding" is always distinguishable
    from "not tested"."""

    candidate: DetectionCandidate
    outcome: DetectionOutcome
    requested_url: str
    marker: str
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class DetectorRunResult:
    """Complete, auditable output of one detector run."""

    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[DetectorRunRecord, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool = False


def _new_marker() -> str:
    return f"wgxss{uuid4().hex[:16]}"


def _classify_reflection(marker: str, body_text: str) -> DetectionOutcome:
    raw_tag = f"<{marker}>"
    if raw_tag in body_text:
        return DetectionOutcome.CONFIRMED

    left_open_unescaped = (
        f"<{marker}" in body_text and f"&lt;{marker}" not in body_text
    )
    right_close_unescaped = (
        f"{marker}>" in body_text and f"{marker}&gt;" not in body_text
    )
    if left_open_unescaped or right_close_unescaped:
        return DetectionOutcome.PROBABLE

    if marker not in body_text:
        return DetectionOutcome.INCONCLUSIVE

    encoded_tag = f"&lt;{marker}&gt;"
    if encoded_tag in body_text:
        return DetectionOutcome.INFORMATIONAL

    return DetectionOutcome.SUSPECTED


def _build_finding(
    target: ValidatedTarget,
    candidate: DetectionCandidate,
    outcome: DetectionOutcome,
    marker: str,
    requested_url: str,
    context: ActiveDetectionContext,
) -> NormalizedFinding:
    parsed = urlsplit(requested_url)

    identity = FindingIdentity(
        rule_id=f"{_DETECTOR_ID}.{outcome.value}",
        asset=f"{target.scheme}://{target.hostname}"
        + (f":{target.port}" if target.port not in (80, 443) else ""),
        path=parsed.path or "/",
        method="GET",
        parameter=candidate.parameter,
    )

    provenance = (
        f"Detector {_DETECTOR_ID} v{_DETECTOR_VERSION}. "
        f"Scan: {context.scan_id}. "
        f"Authorization: {context.authorization_id or 'not recorded'}. "
        f"Permit: {context.permit_id or 'not recorded'}. "
        f"Marker: {marker}. "
        f"Outcome: {outcome.value}."
    )

    identifiers = (
        (_CWE_XSS,)
        if outcome
        in (
            DetectionOutcome.CONFIRMED,
            DetectionOutcome.PROBABLE,
            DetectionOutcome.SUSPECTED,
        )
        else ()
    )

    return NormalizedFinding(
        identity=identity,
        source=_SOURCE,
        title=_OUTCOME_TITLE[outcome],
        description=_OUTCOME_DESCRIPTION[outcome],
        severity=_OUTCOME_SEVERITY[outcome],
        confidence=_OUTCOME_CONFIDENCE[outcome],
        remediation=_REMEDIATION,
        source_rule_id=f"ACTIVE-XSS-REFLECTED-{outcome.value.upper()}",
        identifiers=identifiers,
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES if identifiers else (),
        tags=("xss", "reflected", "active", f"outcome-{outcome.value}"),
    )


def run_reflected_xss_detector(
    target: ValidatedTarget,
    candidates: Tuple[DetectionCandidate, ...],
    context: ActiveDetectionContext,
    *,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> DetectorRunResult:
    """Run the reflected-XSS detector against a bounded set of candidates.

    ``target`` must already be scope-validated (the same ``ValidatedTarget``
    used for passive scanning of this origin). ``candidates`` must already
    be restricted to parameters the caller intends to test -- this
    function does not discover them. ``policy.maximum_probe_requests`` is
    enforced before any request is sent (fail closed on an oversized
    candidate list rather than truncating it silently).

    ``cancellation_check``, if supplied, is polled before every probe
    (including the first). When it returns True, no further probes are
    issued and the result's ``cancelled`` flag is set -- candidates not yet
    probed are simply absent from ``records``, never silently marked as any
    detection outcome.
    """

    enforce_probe_budget(candidates, policy)

    findings: list[NormalizedFinding] = []
    records: list[DetectorRunRecord] = []
    probe_errors: list[str] = []
    cancelled = False

    for index, candidate in enumerate(candidates):
        if cancellation_check is not None and cancellation_check():
            cancelled = True
            break

        if index > 0:
            throttle(policy)

        marker = _new_marker()
        payload = f"<{marker}>"

        attempt = issue_probe(
            target,
            candidate,
            payload,
            policy=policy,
            before_request=before_request,
            after_request=after_request,
        )

        if not attempt.succeeded:
            probe_errors.append(attempt.error_code or "unknown_probe_error")
            continue

        body_text = attempt.response.body.decode("utf-8", errors="replace")
        outcome = _classify_reflection(marker, body_text)

        records.append(
            DetectorRunRecord(
                candidate=candidate,
                outcome=outcome,
                requested_url=attempt.requested_url,
                marker=marker,
                detected_at=_utc_now(),
            )
        )

        if outcome not in _FINDING_OUTCOMES:
            continue

        findings.append(
            _build_finding(
                target,
                candidate,
                outcome,
                marker,
                attempt.requested_url,
                context,
            )
        )

    return DetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "DetectionOutcome",
    "DetectorRunRecord",
    "DetectorRunResult",
    "run_reflected_xss_detector",
]
