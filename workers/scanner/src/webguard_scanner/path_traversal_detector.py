"""Active path traversal detector (CWE-22): GET-parameter diagnostic
mutation with baseline comparison and file-content-signature matching.

Detection methodology
----------------------
For each authorized candidate parameter, this detector sends exactly two
bounded requests:

1. a **baseline** request, with the parameter set to a short, benign
   value (``candidate.original_value`` if non-empty, otherwise
   ``"baseline.txt"``);
2. a **diagnostic** request, with the parameter set to a single directory-
   traversal sequence targeting ``/etc/passwd``
   (``../../../../../../etc/passwd``, six levels deep), a read-only,
   world-readable file present on essentially every Unix/Linux host, so
   this probe cannot destroy or modify anything even against a genuinely
   vulnerable application. It reads exactly one file, once, and stops.

The diagnostic response is then checked for the file's own, highly
specific content signature (a ``root:`` /etc/passwd entry line, see
``_PASSWD_SIGNATURES`` below), and that signature is compared against the
baseline the same way the SQL-injection detector compares its own
signature set: a match that already existed in the baseline is not
attributable to the probe.

v1 scope, stated plainly rather than silently assumed: this detector only
probes for Unix/Linux-style traversal to ``/etc/passwd``. It does not
attempt a Windows-target variant (``..\\..\\windows\\win.ini``), does not
try alternate encodings (URL-encoded slashes, null-byte suffixes, or
absolute-path bypasses), and sends exactly one diagnostic payload per
candidate rather than a depth sweep, matching this project's existing
two-requests-per-candidate budget philosophy (see
``sqli_error_detector.py``'s identical choice). A target that requires a
different traversal depth, a different OS, or a different bypass
technique to reach a readable file will not be flagged as vulnerable by
this detector; that is a real, documented coverage limit, not a silent
gap.

Confirmation levels
--------------------
- CONFIRMED: the diagnostic response contains a ``/etc/passwd`` content
  signature that was absent from the baseline, and the response status
  code also changed from the baseline.
- PROBABLE: the same content signature appears, newly, in the diagnostic
  response, but the status code did not change (some applications return
  200 with the traversed file's content inlined into an otherwise-normal
  page).
- INCONCLUSIVE: everything else: no signature found; the probe failed;
  the response changed with no attributable signature; or the same
  signature already appeared in the baseline. Produces no finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
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
    DetectionCandidate,
    enforce_probe_budget,
    issue_probe,
    throttle,
)
from .request_template import (
    RequestTemplate,
    RequestTemplateError,
    get_template_parameter_value,
    issue_templated_request,
    mutate,
)
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    from datetime import timezone

    return datetime.now(timezone.utc)


_DETECTOR_ID = "active.pathtraversal.disclosure"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_PATH_TRAVERSAL = ExternalIdentifier("CWE", "CWE-22")
_REQUESTS_PER_CANDIDATE = 2
_DEFAULT_BASELINE_VALUE = "baseline.txt"
_DIAGNOSTIC_PAYLOAD = "../../../../../../etc/passwd"

# /etc/passwd's own root-entry line, in the two shapes actually seen
# across Linux distributions (some use "!" or "*" instead of "x" as the
# password placeholder). Both are specific enough to a real passwd file
# that they cannot plausibly appear in ordinary web content by chance.
_PASSWD_SIGNATURES: Tuple[str, ...] = (
    "root:x:0:0:",
    "root:!:0:0:",
    "root:*:0:0:",
)


class PathTraversalOutcome(str, Enum):
    """Confirmation strength for one path-traversal probe."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"


_FINDING_OUTCOMES = frozenset(
    {PathTraversalOutcome.CONFIRMED, PathTraversalOutcome.PROBABLE}
)

_OUTCOME_CONFIDENCE = {
    PathTraversalOutcome.CONFIRMED: Confidence.CONFIRMED,
    PathTraversalOutcome.PROBABLE: Confidence.HIGH,
}

_OUTCOME_TITLE = {
    PathTraversalOutcome.CONFIRMED: (
        "Path Traversal (confirmed /etc/passwd disclosure)"
    ),
    PathTraversalOutcome.PROBABLE: (
        "Path Traversal (probable /etc/passwd disclosure)"
    ),
}

_OUTCOME_DESCRIPTION = {
    PathTraversalOutcome.CONFIRMED: (
        "Submitting a directory-traversal sequence "
        "(../../../../../../etc/passwd) as this parameter's value "
        "produced a response containing the target host's own "
        "/etc/passwd content, which was not present in the baseline "
        "response for the same parameter, and the response status code "
        "also changed. This means the parameter is used to build a "
        "filesystem path without restricting it to an intended "
        "directory, letting an attacker read arbitrary files the "
        "server process can access."
    ),
    PathTraversalOutcome.PROBABLE: (
        "Submitting a directory-traversal sequence "
        "(../../../../../../etc/passwd) as this parameter's value "
        "produced a response containing the target host's own "
        "/etc/passwd content, which was not present in the baseline "
        "response. The status code did not change, one fewer "
        "corroborating signal than a confirmed finding, but the "
        "disclosed content is specific to the traversed file."
    ),
}

_REMEDIATION = (
    "Never build a filesystem path directly from user-controlled input. "
    "Resolve the requested value against an allowlist of permitted "
    "files or a fixed set of identifiers, or canonicalise the resulting "
    "path and reject anything that resolves outside the intended base "
    "directory before opening it."
)

_REFERENCES = (
    "https://owasp.org/www-community/attacks/Path_Traversal",
    "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
)


def _find_signature(body_text: str) -> str | None:
    for signature in _PASSWD_SIGNATURES:
        if signature in body_text:
            return signature
    return None


def _classify(
    *,
    baseline_text: str,
    diagnostic_text: str,
    baseline_status: int,
    diagnostic_status: int,
) -> tuple[PathTraversalOutcome, str | None]:
    baseline_signature = _find_signature(baseline_text)
    diagnostic_signature = _find_signature(diagnostic_text)

    if diagnostic_signature is None:
        return PathTraversalOutcome.INCONCLUSIVE, None

    if baseline_signature == diagnostic_signature:
        # The same passwd-shaped line already appears in the baseline,
        # not attributable to the diagnostic probe (a page that happens
        # to render that exact literal text for an unrelated reason).
        return PathTraversalOutcome.INCONCLUSIVE, None

    if baseline_status != diagnostic_status:
        return PathTraversalOutcome.CONFIRMED, diagnostic_signature

    return PathTraversalOutcome.PROBABLE, diagnostic_signature


@dataclass(frozen=True, slots=True)
class PathTraversalDetectorRunRecord:
    """One probed candidate and its outcome, regardless of whether a
    finding was produced, so "no finding" is always distinguishable
    from "not tested"."""

    candidate: DetectionCandidate | RequestTemplate
    outcome: PathTraversalOutcome
    baseline_url: str
    diagnostic_url: str
    matched_signature: str | None
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class PathTraversalDetectorRunResult:
    """Complete, auditable output of one detector run."""

    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[PathTraversalDetectorRunRecord, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool = False


def _build_finding(
    target: ValidatedTarget,
    parameter: str,
    method: str,
    outcome: PathTraversalOutcome,
    matched_signature: str,
    diagnostic_url: str,
    context: ActiveDetectionContext,
) -> NormalizedFinding:
    parsed = urlsplit(diagnostic_url)

    identity = FindingIdentity(
        rule_id=f"{_DETECTOR_ID}.{outcome.value}",
        asset=f"{target.scheme}://{target.hostname}"
        + (f":{target.port}" if target.port not in (80, 443) else ""),
        path=parsed.path or "/",
        method=method,
        parameter=parameter,
    )

    provenance = (
        f"Detector {_DETECTOR_ID} v{_DETECTOR_VERSION}. "
        f"Scan: {context.scan_id}. "
        f"Authorization: {context.authorization_id or 'not recorded'}. "
        f"Permit: {context.permit_id or 'not recorded'}. "
        f"Matched signature category: /etc/passwd content "
        f"(signature text not retained). "
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
        source_rule_id=f"ACTIVE-PATHTRAVERSAL-{outcome.value.upper()}",
        identifiers=(_CWE_PATH_TRAVERSAL,),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("path-traversal", "file-disclosure", "active", f"outcome-{outcome.value}"),
    )


def _issue_legacy_baseline_and_diagnostic(
    target: ValidatedTarget,
    candidate: DetectionCandidate,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None,
    after_request: AfterRequestHook | None,
    authentication_material=None,
):
    baseline_value = candidate.original_value or _DEFAULT_BASELINE_VALUE
    baseline_attempt = issue_probe(
        target,
        candidate,
        baseline_value,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
    )
    if not baseline_attempt.succeeded:
        return baseline_attempt, None, candidate.parameter, "GET"

    throttle(policy)

    diagnostic_attempt = issue_probe(
        target,
        candidate,
        _DIAGNOSTIC_PAYLOAD,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
    )
    return baseline_attempt, diagnostic_attempt, candidate.parameter, "GET"


def _issue_templated_baseline_and_diagnostic(
    target: ValidatedTarget,
    template: RequestTemplate,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None,
    after_request: AfterRequestHook | None,
    authentication_material=None,
):
    parameter = template.parameter
    try:
        current_value = get_template_parameter_value(template, parameter)
    except RequestTemplateError:
        current_value = ""
    baseline_value = current_value or _DEFAULT_BASELINE_VALUE

    baseline_mutated = mutate(template, parameter, baseline_value)
    baseline_attempt = issue_templated_request(
        target,
        baseline_mutated,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
    )
    if not baseline_attempt.succeeded:
        return baseline_attempt, None, parameter, template.method

    throttle(policy)

    diagnostic_mutated = mutate(template, parameter, _DIAGNOSTIC_PAYLOAD)
    diagnostic_attempt = issue_templated_request(
        target,
        diagnostic_mutated,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
    )
    return baseline_attempt, diagnostic_attempt, parameter, template.method


def run_path_traversal_detector(
    target: ValidatedTarget,
    candidates: Tuple[DetectionCandidate | RequestTemplate, ...],
    context: ActiveDetectionContext,
    *,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    authentication_material=None,
) -> PathTraversalDetectorRunResult:
    """Run the path-traversal detector against a bounded set of
    candidates.

    ``target`` must already be scope-validated. ``candidates`` must
    already be restricted to parameters the caller intends to test.
    Each candidate costs two requests (baseline + diagnostic);
    ``policy.maximum_probe_requests`` is enforced against that real cost
    before any request is sent. ``candidates`` may mix legacy
    ``DetectionCandidate`` items (GET query/form parameter) with
    ``RequestTemplate`` items (POST form or JSON body parameter),
    identical in spirit to ``run_sqli_error_detector``.

    ``cancellation_check``, if supplied, is polled before every
    candidate's baseline request.
    """

    enforce_probe_budget(
        candidates, policy, requests_per_candidate=_REQUESTS_PER_CANDIDATE
    )

    findings: list[NormalizedFinding] = []
    records: list[PathTraversalDetectorRunRecord] = []
    probe_errors: list[str] = []
    cancelled = False

    for index, candidate in enumerate(candidates):
        if cancellation_check is not None and cancellation_check():
            cancelled = True
            break

        if index > 0:
            throttle(policy)

        try:
            if isinstance(candidate, RequestTemplate):
                baseline_attempt, diagnostic_attempt, parameter, method = (
                    _issue_templated_baseline_and_diagnostic(
                        target,
                        candidate,
                        policy=policy,
                        before_request=before_request,
                        after_request=after_request,
                        authentication_material=authentication_material,
                    )
                )
            else:
                baseline_attempt, diagnostic_attempt, parameter, method = (
                    _issue_legacy_baseline_and_diagnostic(
                        target,
                        candidate,
                        policy=policy,
                        before_request=before_request,
                        after_request=after_request,
                        authentication_material=authentication_material,
                    )
                )
        except RequestTemplateError as exc:
            probe_errors.append(exc.code)
            continue

        if not baseline_attempt.succeeded:
            probe_errors.append(
                baseline_attempt.error_code or "unknown_probe_error"
            )
            continue

        if diagnostic_attempt is None or not diagnostic_attempt.succeeded:
            probe_errors.append(
                (diagnostic_attempt.error_code if diagnostic_attempt else None)
                or "unknown_probe_error"
            )
            continue

        baseline_text = baseline_attempt.response.body.decode(
            "utf-8", errors="replace"
        )
        diagnostic_text = diagnostic_attempt.response.body.decode(
            "utf-8", errors="replace"
        )
        outcome, matched_signature = _classify(
            baseline_text=baseline_text,
            diagnostic_text=diagnostic_text,
            baseline_status=baseline_attempt.response.status,
            diagnostic_status=diagnostic_attempt.response.status,
        )

        records.append(
            PathTraversalDetectorRunRecord(
                candidate=candidate,
                outcome=outcome,
                baseline_url=baseline_attempt.requested_url,
                diagnostic_url=diagnostic_attempt.requested_url,
                matched_signature=matched_signature,
                detected_at=_utc_now(),
            )
        )

        if outcome not in _FINDING_OUTCOMES:
            continue

        findings.append(
            _build_finding(
                target,
                parameter,
                method,
                outcome,
                matched_signature,
                diagnostic_attempt.requested_url,
                context,
            )
        )

    return PathTraversalDetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "PathTraversalOutcome",
    "PathTraversalDetectorRunRecord",
    "PathTraversalDetectorRunResult",
    "run_path_traversal_detector",
]
