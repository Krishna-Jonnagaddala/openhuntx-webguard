"""Active OS command injection detector (CWE-78): GET-parameter
diagnostic mutation with a unique, unforgeable marker.

Detection methodology
----------------------
For each authorized candidate parameter, this detector sends exactly two
bounded requests:

1. a **baseline** request, with the parameter set to a short, benign
   value (``candidate.original_value`` if non-empty, otherwise ``"1"``);
2. a **diagnostic** request, with the parameter set to that same
   baseline value followed by a POSIX shell command separator and a
   read-only, non-destructive command whose output is a freshly
   generated, unpredictable marker unique to this one probe:
   ``<baseline>; echo <marker> #``. ``echo`` prints its argument and
   exits; it reads no file, writes no file, and starts no other
   process. The trailing ``#`` comments out anything the calling code
   appends after the injection point in the same shell command, the
   same "neutralise the rest of the line" idea the SQL-injection
   detector's own single apostrophe uses to break a query with the
   smallest possible payload.

The diagnostic response is then checked for the exact marker string,
verbatim. Because the marker is generated fresh for this one probe (a
random 16-hex-character suffix, per ``_new_marker`` below), it cannot
already exist anywhere in the target's real content. Unlike the
SQL-injection and path-traversal detectors, there is no baseline-vs-
diagnostic ambiguity to resolve here: if the marker appears in the
diagnostic response at all, that is a request whose command output
appeared in a response, which could only happen if the shell run by the
target's process appended the response with our own echoed marker, i.e.
if the server executed the injected command.

v1 scope, stated plainly rather than silently assumed: this detector
only tests the POSIX ``;`` command-chaining separator with a trailing
``#`` comment terminator, targeting shells (``sh``/``bash``/``zsh``)
that treat this exact sequence as "end the original command, run mine,
ignore anything after." It does not test other separators (``|``,
``&&``, backticks, ``$()``), does not test Windows ``cmd.exe``/PowerShell
chaining (``&``), and does not attempt a quote-breaking prefix for
injection points nested inside a quoted string in the vulnerable
command line. A target vulnerable only through one of those other
mechanisms will not be flagged by this detector; that is a real,
documented coverage limit, matching the same one-payload-per-candidate
budget philosophy the path-traversal and SQL-injection detectors both
already use, not a silent gap.

Confirmation levels
--------------------
- CONFIRMED: the exact marker string appears in the diagnostic response
  body, and the full diagnostic payload string sent (baseline value +
  ``; echo <marker> #``) does *not* appear in the response. That second
  condition is the load-bearing check, not a formality: many
  applications reflect an invalid parameter value verbatim into an
  error message ("Invalid host: <value>"), which would put the marker
  right back into the response having executed nothing: the shell
  metacharacters and comment marker survived untouched, meaning no
  shell ever interpreted them. A genuine execution strips that syntax
  away and leaves only the marker (and whatever the baseline command's
  own real output was); the literal payload text does not survive
  intact. Checking for the marker's presence alone, without this
  check, was tried first and confirmed to false-positive on plain
  reflection before this distinction was added.
- INCONCLUSIVE: everything else: the marker did not appear; the
  marker appeared but so did the untouched raw payload (reflection, not
  execution); the probe failed. There is no PROBABLE/partial tier:
  unlike a database-error phrase or a file's own content, a freshly
  random marker either comes back on its own, as command output, or it
  does not, so there is no meaningful middle ground for this technique
  once reflection is ruled out.
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


_DETECTOR_ID = "active.cmdi.marker"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_CMDI = ExternalIdentifier("CWE", "CWE-78")
_REQUESTS_PER_CANDIDATE = 2
_DEFAULT_BASELINE_VALUE = "1"


def _new_marker() -> str:
    return f"wgcmdi{uuid4().hex[:16]}"


class CommandInjectionOutcome(str, Enum):
    """Confirmation strength for one command-injection probe."""

    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"


_FINDING_OUTCOMES = frozenset({CommandInjectionOutcome.CONFIRMED})

_OUTCOME_TITLE = "OS Command Injection (confirmed marker execution)"

_OUTCOME_DESCRIPTION = (
    "Appending a shell command separator (';') followed by a command to "
    "echo a freshly generated, unique marker as this parameter's value "
    "produced a response containing that exact marker. The marker is "
    "unpredictable and never sent to the target before this one probe, "
    "so its appearance in the response means the target's process "
    "passed this parameter's value to a shell and executed the injected "
    "command, not merely reflected the raw input back unmodified."
)

_REMEDIATION = (
    "Never pass user-controlled input to a shell (avoid os.system, "
    "subprocess with shell=True, or equivalent). Call the target "
    "program directly with an argument array instead of building a "
    "shell command line, and validate/allowlist any input that must "
    "influence which program or arguments are used."
)

_REFERENCES = (
    "https://owasp.org/www-community/attacks/Command_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
)


def _diagnostic_payload(baseline_value: str, marker: str) -> str:
    return f"{baseline_value}; echo {marker} #"


def _classify(
    marker: str, diagnostic_payload: str, diagnostic_text: str
) -> CommandInjectionOutcome:
    """The marker's mere presence in the response is not enough: many
    applications reflect an invalid parameter value verbatim into an
    error message (e.g. "Invalid host: <value>"), which would put the
    marker right back into the response having executed nothing at
    all, the payload string was echoed, not interpreted by a shell.
    A genuine execution strips the shell metacharacters and comment
    marker away and leaves only the marker itself (plus whatever the
    baseline command's own real output was) in the response; the raw
    payload's own literal text does not survive intact. So this only
    confirms when the marker is present *and* the exact payload string
    sent is absent: if the full, untouched payload can still be found
    verbatim, this is reflection, not command execution."""

    if marker not in diagnostic_text:
        return CommandInjectionOutcome.INCONCLUSIVE
    if diagnostic_payload in diagnostic_text:
        return CommandInjectionOutcome.INCONCLUSIVE
    return CommandInjectionOutcome.CONFIRMED


@dataclass(frozen=True, slots=True)
class CommandInjectionDetectorRunRecord:
    """One probed candidate and its outcome, regardless of whether a
    finding was produced, so "no finding" is always distinguishable
    from "not tested"."""

    candidate: DetectionCandidate | RequestTemplate
    outcome: CommandInjectionOutcome
    baseline_url: str
    diagnostic_url: str
    marker: str
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class CommandInjectionDetectorRunResult:
    """Complete, auditable output of one detector run."""

    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[CommandInjectionDetectorRunRecord, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool = False


def _build_finding(
    target: ValidatedTarget,
    parameter: str,
    method: str,
    diagnostic_url: str,
    context: ActiveDetectionContext,
) -> NormalizedFinding:
    parsed = urlsplit(diagnostic_url)

    identity = FindingIdentity(
        rule_id=f"{_DETECTOR_ID}.confirmed",
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
        f"Matched category: verbatim marker echo output "
        f"(marker text not retained). "
        f"Outcome: confirmed."
    )

    return NormalizedFinding(
        identity=identity,
        source=_SOURCE,
        title=_OUTCOME_TITLE,
        description=_OUTCOME_DESCRIPTION,
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        remediation=_REMEDIATION,
        source_rule_id="ACTIVE-CMDI-CONFIRMED",
        identifiers=(_CWE_CMDI,),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("command-injection", "rce", "active", "outcome-confirmed"),
    )


def _issue_legacy_baseline_and_diagnostic(
    target: ValidatedTarget,
    candidate: DetectionCandidate,
    marker: str,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None,
    after_request: AfterRequestHook | None,
    authentication_material=None,
):
    baseline_value = candidate.original_value or _DEFAULT_BASELINE_VALUE
    payload = _diagnostic_payload(baseline_value, marker)
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
        return baseline_attempt, None, candidate.parameter, "GET", payload

    throttle(policy)

    diagnostic_attempt = issue_probe(
        target,
        candidate,
        payload,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
    )
    return baseline_attempt, diagnostic_attempt, candidate.parameter, "GET", payload


def _issue_templated_baseline_and_diagnostic(
    target: ValidatedTarget,
    template: RequestTemplate,
    marker: str,
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
    payload = _diagnostic_payload(baseline_value, marker)

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
        return baseline_attempt, None, parameter, template.method, payload

    throttle(policy)

    diagnostic_mutated = mutate(template, parameter, payload)
    diagnostic_attempt = issue_templated_request(
        target,
        diagnostic_mutated,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
    )
    return baseline_attempt, diagnostic_attempt, parameter, template.method, payload


def run_command_injection_detector(
    target: ValidatedTarget,
    candidates: Tuple[DetectionCandidate | RequestTemplate, ...],
    context: ActiveDetectionContext,
    *,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    authentication_material=None,
) -> CommandInjectionDetectorRunResult:
    """Run the OS command injection detector against a bounded set of
    candidates.

    ``target`` must already be scope-validated. ``candidates`` must
    already be restricted to parameters the caller intends to test.
    Each candidate costs two requests (baseline + diagnostic);
    ``policy.maximum_probe_requests`` is enforced against that real cost
    before any request is sent. ``candidates`` may mix legacy
    ``DetectionCandidate`` items (GET query/form parameter) with
    ``RequestTemplate`` items (POST form or JSON body parameter).

    A fresh, unique marker is generated once per candidate (never
    reused across candidates in the same run), so a finding on one
    candidate can never be confused with evidence from another.

    ``cancellation_check``, if supplied, is polled before every
    candidate's baseline request.
    """

    enforce_probe_budget(
        candidates, policy, requests_per_candidate=_REQUESTS_PER_CANDIDATE
    )

    findings: list[NormalizedFinding] = []
    records: list[CommandInjectionDetectorRunRecord] = []
    probe_errors: list[str] = []
    cancelled = False

    for index, candidate in enumerate(candidates):
        if cancellation_check is not None and cancellation_check():
            cancelled = True
            break

        if index > 0:
            throttle(policy)

        marker = _new_marker()

        try:
            if isinstance(candidate, RequestTemplate):
                baseline_attempt, diagnostic_attempt, parameter, method, payload = (
                    _issue_templated_baseline_and_diagnostic(
                        target,
                        candidate,
                        marker,
                        policy=policy,
                        before_request=before_request,
                        after_request=after_request,
                        authentication_material=authentication_material,
                    )
                )
            else:
                baseline_attempt, diagnostic_attempt, parameter, method, payload = (
                    _issue_legacy_baseline_and_diagnostic(
                        target,
                        candidate,
                        marker,
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

        diagnostic_text = diagnostic_attempt.response.body.decode(
            "utf-8", errors="replace"
        )
        outcome = _classify(marker, payload, diagnostic_text)

        records.append(
            CommandInjectionDetectorRunRecord(
                candidate=candidate,
                outcome=outcome,
                baseline_url=baseline_attempt.requested_url,
                diagnostic_url=diagnostic_attempt.requested_url,
                marker=marker,
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
                diagnostic_attempt.requested_url,
                context,
            )
        )

    return CommandInjectionDetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "CommandInjectionOutcome",
    "CommandInjectionDetectorRunRecord",
    "CommandInjectionDetectorRunResult",
    "run_command_injection_detector",
]
