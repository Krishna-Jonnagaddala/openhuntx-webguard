"""Active error-based SQL injection detector (CWE-89): GET-parameter
diagnostic mutation with baseline comparison and database-error-signature
matching.

Detection methodology
----------------------
For each authorized candidate parameter, this detector sends exactly two
bounded GET requests:

1. a **baseline** request, with the parameter set to a short, benign
   value (``candidate.original_value`` if non-empty, otherwise ``"1"``);
2. a **diagnostic** request, with the parameter set to a single unescaped
   apostrophe (``'``) -- the minimal, non-destructive SQL metacharacter
   that breaks a string-literal query fragment if (and only if) the
   application concatenates the raw value into a SQL statement without
   parameterisation or escaping. It performs no UNION extraction, no
   stacked statements, no time delays, and modifies no data even against
   a genuinely vulnerable application: an unclosed quote produces a query
   *syntax* error, not an alternate executable statement.

The diagnostic response is then compared against the baseline. A finding
is only produced when a **specific, database-engine-attributable error
signature** appears in the diagnostic response and did **not** already
appear in the baseline. A generic status-code change alone (e.g. 200 to
500) is never sufficient evidence by itself -- this deliberately cannot
distinguish SQL injection from an unrelated application error, and the
brief for this detector is explicit that it must make that distinction
rather than flag any error page. Signature matching uses specific,
multi-token, database-engine-attributable phrases (never bare words like
"SQL", "syntax error", or a database product name alone), to avoid
matching ordinary application text.

Confirmation levels
--------------------
- CONFIRMED: a database-error signature appears in the diagnostic
  response, is absent from the baseline, and the response status code
  also changed from the baseline -- the strongest available corroboration
  from this technique (content and status both shifted together).
- PROBABLE: a database-error signature appears in the diagnostic
  response and is absent from the baseline, but the status code did not
  change (some applications render a caught database error inside a 200
  response) -- still specific, engine-attributable evidence, with one
  fewer corroborating signal than CONFIRMED.
- INCONCLUSIVE: everything else -- no signature found at all; the probe
  failed; the response changed but with no attributable signature (a
  generic error, a validation error, redirects, connection failures,
  reflection without interpretation); or the same signature already
  appeared in the baseline (pre-existing database-looking text in normal
  output, which cannot be attributed to this probe). Produces no finding.
  Per this detector's own design brief: ambiguous evidence is classified
  conservatively, or not at all -- there is no low-confidence catch-all
  finding tier here, unlike the reflected-XSS detector's INFORMATIONAL/
  SUSPECTED tiers, because this technique does not produce evidence with
  a genuine, distinguishable middle ground: either a specific signature
  newly appears, or nothing attributable is known to have happened.
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


_DETECTOR_ID = "active.sqli.error"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_SQLI = ExternalIdentifier("CWE", "CWE-89")
_REQUESTS_PER_CANDIDATE = 2
_DEFAULT_BASELINE_VALUE = "1"
_DIAGNOSTIC_PAYLOAD = "'"


class SqliDetectionOutcome(str, Enum):
    """Confirmation strength for one error-based SQLi probe."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"


_FINDING_OUTCOMES = frozenset(
    {SqliDetectionOutcome.CONFIRMED, SqliDetectionOutcome.PROBABLE}
)

_OUTCOME_CONFIDENCE = {
    SqliDetectionOutcome.CONFIRMED: Confidence.CONFIRMED,
    SqliDetectionOutcome.PROBABLE: Confidence.HIGH,
}

_OUTCOME_TITLE = {
    SqliDetectionOutcome.CONFIRMED: (
        "SQL Injection (confirmed database error signature)"
    ),
    SqliDetectionOutcome.PROBABLE: (
        "SQL Injection (probable database error signature)"
    ),
}

_OUTCOME_DESCRIPTION = {
    SqliDetectionOutcome.CONFIRMED: (
        "Submitting a single unescaped apostrophe as this parameter's "
        "value produced a response containing a database-engine error "
        "signature that was not present in the baseline response for "
        "the same parameter, and the response status code also changed. "
        "This is consistent with the parameter value being concatenated "
        "into a SQL statement without safe parameterisation or escaping."
    ),
    SqliDetectionOutcome.PROBABLE: (
        "Submitting a single unescaped apostrophe as this parameter's "
        "value produced a response containing a database-engine error "
        "signature that was not present in the baseline response for "
        "the same parameter. The response status code did not change, "
        "which is one fewer corroborating signal than a confirmed "
        "finding, but the signature itself is specific to database "
        "query-processing error output."
    ),
}

_REMEDIATION = (
    "Use parameterised queries or prepared statements for all "
    "database access built from user-controlled input; never "
    "concatenate raw input into SQL statements. Apply least-privilege "
    "database credentials and avoid exposing raw database error "
    "messages to clients."
)

_REFERENCES = (
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
)

# Specific, multi-token, database-engine-attributable error phrases.
# Deliberately not bare words like "SQL", "syntax error", or a bare
# product name -- each entry here is a phrase that, in practice, only
# appears in genuine database-driver/engine error output.
_DATABASE_ERROR_SIGNATURES: Tuple[str, ...] = (
    # PostgreSQL
    "unterminated quoted string",
    "syntax error at or near",
    "invalid input syntax for",
    "pg_query(): query failed",
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "warning: mysqli",
    "warning: mysql_",
    "check the manual that corresponds to your (mysql|mariadb) server version",
    # Microsoft SQL Server
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "microsoft odbc sql server driver",
    "system.data.sqlclient.sqlexception",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    "near \"'\": syntax error",
    "unrecognized token:",
)


@dataclass(frozen=True, slots=True)
class SqliDetectorRunRecord:
    """One probed candidate and its outcome, regardless of whether a
    finding was produced -- so "no finding" is always distinguishable
    from "not tested". ``candidate`` is either a legacy DetectionCandidate
    (GET query/form parameter) or a RequestTemplate (POST form / JSON
    body parameter, Slice 6) -- whichever transport actually probed it."""

    candidate: DetectionCandidate | RequestTemplate
    outcome: SqliDetectionOutcome
    baseline_url: str
    diagnostic_url: str
    matched_signature: str | None
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class SqliDetectorRunResult:
    """Complete, auditable output of one detector run."""

    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[SqliDetectorRunRecord, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool = False


def _find_signature(body_text: str) -> str | None:
    lowered = body_text.lower()
    for signature in _DATABASE_ERROR_SIGNATURES:
        if signature in lowered:
            return signature
    return None


def _classify(
    *,
    baseline_text: str,
    diagnostic_text: str,
    baseline_status: int,
    diagnostic_status: int,
) -> tuple[SqliDetectionOutcome, str | None]:
    baseline_signature = _find_signature(baseline_text)
    diagnostic_signature = _find_signature(diagnostic_text)

    if diagnostic_signature is None:
        return SqliDetectionOutcome.INCONCLUSIVE, None

    if baseline_signature == diagnostic_signature:
        # The same signature already appears in normal output for this
        # parameter -- pre-existing database-looking text, not evidence
        # attributable to the diagnostic probe.
        return SqliDetectionOutcome.INCONCLUSIVE, None

    if baseline_status != diagnostic_status:
        return SqliDetectionOutcome.CONFIRMED, diagnostic_signature

    return SqliDetectionOutcome.PROBABLE, diagnostic_signature


def _build_finding(
    target: ValidatedTarget,
    parameter: str,
    method: str,
    outcome: SqliDetectionOutcome,
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
        f"Matched signature category: database-engine error output "
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
        source_rule_id=f"ACTIVE-SQLI-ERROR-{outcome.value.upper()}",
        identifiers=(_CWE_SQLI,),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("sqli", "injection", "active", f"outcome-{outcome.value}"),
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
    """The original, unmodified GET-query issuance path (pre-Slice-6).
    Kept byte-for-byte in its own function so nothing about it changes
    for existing DetectionCandidate callers."""

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
    """Slice 6: POST-form / JSON-body issuance path via the shared
    mutation engine. The classification logic downstream is identical to
    the legacy path -- only how the two requests get built and sent
    differs by transport."""

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


def run_sqli_error_detector(
    target: ValidatedTarget,
    candidates: Tuple[DetectionCandidate | RequestTemplate, ...],
    context: ActiveDetectionContext,
    *,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    authentication_material=None,
) -> SqliDetectorRunResult:
    """Run the error-based SQL injection detector against a bounded set
    of candidates.

    ``target`` must already be scope-validated. ``candidates`` must
    already be restricted to parameters the caller intends to test --
    this function does not discover them. Each candidate costs two
    requests (baseline + diagnostic); ``policy.maximum_probe_requests`` is
    enforced against that real cost before any request is sent.

    As of Slice 6, ``candidates`` may mix legacy ``DetectionCandidate``
    items (GET query/form parameter, the only shape supported before this
    slice) with ``RequestTemplate`` items (POST form or JSON body
    parameter, built from attack-surface discovery via
    ``build_request_template``). Both are probed with the identical
    baseline-then-diagnostic-apostrophe methodology and the identical
    signature-based classification -- only how the two requests are
    constructed and sent differs by transport. This is deliberately one
    detector, not three, per input transport: GET/POST/JSON are input
    transports for the same underlying vulnerability class, not distinct
    detection methodologies.

    ``cancellation_check``, if supplied, is polled before every
    candidate's baseline request. When it returns True, no further
    candidates are probed and the result's ``cancelled`` flag is set.
    """

    enforce_probe_budget(
        candidates, policy, requests_per_candidate=_REQUESTS_PER_CANDIDATE
    )

    findings: list[NormalizedFinding] = []
    records: list[SqliDetectorRunRecord] = []
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
            # A malformed or unrepresentable template (e.g. invalid JSON,
            # a parameter path that no longer exists) is this candidate's
            # problem, not the whole run's -- skip it and keep going,
            # exactly like any other per-candidate probe failure.
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
            SqliDetectorRunRecord(
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

    return SqliDetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "SqliDetectionOutcome",
    "SqliDetectorRunRecord",
    "SqliDetectorRunResult",
    "run_sqli_error_detector",
]
