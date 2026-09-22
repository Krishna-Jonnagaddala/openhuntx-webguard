"""Active error-based LDAP injection detector (CWE-90): GET-parameter
diagnostic mutation with baseline comparison and directory-error-
signature matching. Structurally identical to ``sqli_error_detector.py``
(CWE-89): the same two-request baseline/diagnostic methodology, the
same "a specific, attributable signature must be new" classification
discipline, the same CONFIRMED/PROBABLE/INCONCLUSIVE tiers. Only the
payload and the signature list differ.

Detection methodology
----------------------
For each authorized candidate parameter, this detector sends exactly two
bounded requests:

1. a **baseline** request, with the parameter set to a short, benign
   value (``candidate.original_value`` if non-empty, otherwise ``"1"``);
2. a **diagnostic** request, with a single unescaped closing parenthesis
   (``)``) appended to that same baseline value.

LDAP filter strings (RFC 4515) are a fully-parenthesized grammar:
``(attr=value)``, or for compound filters, ``(&(objectClass=person)
(cn=value))``. String concatenation is additive: it can only ever add
characters, never remove an opening parenthesis the application's own
filter template already contributed. An unescaped, unmatched ``)``
appended to a value therefore pushes the close-paren count one further
past the open-paren count no matter how the value is embedded, whether
in a simple, wildcard-wrapped (``(cn=*value*)``), or deeply nested
compound filter: there is no surrounding shape that can structurally
absorb or cancel out an extra, unmatched close paren. Every mainstream
LDAP client library and directory server enforces a fully-balanced
filter grammar and rejects the result as a syntax error.

The diagnostic is appended to the baseline value, not a bare
replacement of it (unlike this detector's SQLi/path-traversal
siblings, which substitute a bare module-level constant for the whole
value): a value that still starts with a plausible-looking prefix is
less likely to be rejected by an application's own input-shape
validation (for example a loose "must start with a digit" check)
before it ever reaches the vulnerable filter-construction code, which
would otherwise mask a genuinely vulnerable parameter behind an
unrelated validation error rather than a directory error.

The diagnostic response is then compared against the baseline. A
finding is only produced when a **specific, library/directory-engine-
attributable error signature** appears in the diagnostic response and
did **not** already appear in the baseline, mirroring the SQLi
detector's own discipline exactly: a generic status-code change alone
is never sufficient, and signature matching uses specific,
implementation-attributable phrases (function names, fully-qualified
exception class names), never a bare word like "LDAP" or "filter"
alone.

Confirmation levels
--------------------
- CONFIRMED: a directory-error signature appears in the diagnostic
  response, is absent from the baseline, and the response status code
  also changed from the baseline.
- PROBABLE: the same signature appears and is absent from the
  baseline, but the status code did not change (some applications
  render a caught directory error inside a 200 response).
- INCONCLUSIVE: everything else: no signature found; the probe
  failed; the response changed but with no attributable signature; or
  the same signature already appeared in the baseline. Produces no
  finding.

Signature list, and what it does and does not cover
------------------------------------------------------
Verified before implementation against real client-library source and
real production incident reports (PHP's php-src, Oracle/UnboundID/
Novell/Apache Directory javadoc, Microsoft Learn, and GitHub issues
against python-ldap, ldap3, and ldapjs), not assumed from memory alone.

One entry, ``"bad search filter"`` (OpenLDAP's own ``ldap_err2string()``
text for result code 87), is the single signature in this list with no
implementation-attributable token (no function name, no namespaced
class name), kept because no evidence of it appearing in unrelated,
non-LDAP application content was found, but named here as the first
signature to suspect if a false positive is ever reported against it.
Several of the fully-qualified exception-class-name signatures (for
example ``system.directoryservices.directoryservicescomexception``)
match on *any* error of that class, not specifically a filter-syntax
one: an application that performs an unrelated, intermittently-
failing directory lookup on every request (for example an
authorization check) could in principle produce this signature on a
diagnostic request for an unrelated reason. This is not a new risk
this detector introduces: ``sqli_error_detector.py``'s own signatures
(``system.data.sqlclient.sqlexception``, ``sqlite3.operationalerror``)
carry the identical structural exposure, already accepted in that
already-shipped detector.

Real, safety-relevant risk, stated plainly rather than softened: on a
target built with ldapjs (a widely-used Node.js LDAP client), this
exact payload can produce a *synchronous, uncaught exception in the
target's own filter parser* rather than a normal error response.
Multiple documented ldapjs issues describe this crashing the entire
Node process when the application does not wrap its search call in
its own error handling, a materially larger blast radius than any
other diagnostic payload this project ships, none of which can crash
the target process outright. This is inherent to the paren-imbalance
technique itself against that specific library, not something this
detector can engineer around while still testing for this weakness;
it is disclosed here rather than hidden, and an operator issuing this
active check should know it before authorizing it against a target
that might be running ldapjs.

v1 scope, stated plainly rather than left implicit: this detector
tests only filter-syntax-error induction via one payload shape (a
single appended closing parenthesis). It does not attempt: a DN-
injection variant (a different LDAP injection sub-technique that
corrupts a distinguished name using different metacharacters,
``,``, ``+``, ``"``, ``\\``, ``<``, ``>``, ``;``, rather than a
search filter, structurally distinct from what this payload targets);
boolean-based blind detection (comparing an always-true vs. an
always-false filter injection to infer vulnerability without an
error signature); or time-based detection. A target that is vulnerable
only through one of those other techniques, or whose input validation
rejects the appended value before it ever reaches the vulnerable
concatenation point, will not be flagged by this detector; that is a
real, documented coverage limit, not a silent gap.
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


_DETECTOR_ID = "active.ldapi.error"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_LDAPI = ExternalIdentifier("CWE", "CWE-90")
_REQUESTS_PER_CANDIDATE = 2
_DEFAULT_BASELINE_VALUE = "1"


def _diagnostic_payload(baseline_value: str) -> str:
    """Appends a single unescaped closing parenthesis to the baseline
    value: see the module docstring for why append, rather than a
    bare replacement constant, is the deliberate choice here."""

    return f"{baseline_value})"


class LdapInjectionOutcome(str, Enum):
    """Confirmation strength for one error-based LDAP-injection probe."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"


_FINDING_OUTCOMES = frozenset(
    {LdapInjectionOutcome.CONFIRMED, LdapInjectionOutcome.PROBABLE}
)

_OUTCOME_CONFIDENCE = {
    LdapInjectionOutcome.CONFIRMED: Confidence.CONFIRMED,
    LdapInjectionOutcome.PROBABLE: Confidence.HIGH,
}

_OUTCOME_TITLE = {
    LdapInjectionOutcome.CONFIRMED: (
        "LDAP Injection (confirmed directory error signature)"
    ),
    LdapInjectionOutcome.PROBABLE: (
        "LDAP Injection (probable directory error signature)"
    ),
}

_OUTCOME_DESCRIPTION = {
    LdapInjectionOutcome.CONFIRMED: (
        "Appending a single unescaped closing parenthesis to this "
        "parameter's value produced a response containing a directory "
        "client-library or server error signature that was not "
        "present in the baseline response for the same parameter, and "
        "the response status code also changed. This is consistent "
        "with the parameter value being concatenated into an LDAP "
        "search filter without safe escaping."
    ),
    LdapInjectionOutcome.PROBABLE: (
        "Appending a single unescaped closing parenthesis to this "
        "parameter's value produced a response containing a directory "
        "client-library or server error signature that was not "
        "present in the baseline response. The response status code "
        "did not change, one fewer corroborating signal than a "
        "confirmed finding, but the signature itself is specific to "
        "LDAP filter-parsing error output."
    ),
}

_REMEDIATION = (
    "Escape every LDAP-reserved character (\\, *, (, ), NUL) in "
    "user-controlled input before it is concatenated into a search "
    "filter or distinguished name, using the escaping function your "
    "LDAP client library provides for exactly this purpose. Never "
    "build a filter string by directly interpolating raw input."
)

_REFERENCES = (
    "https://cwe.mitre.org/data/definitions/90.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
)

# Specific, implementation-attributable directory-error phrases: a
# function name, or a fully-qualified exception class name, never a
# bare word like "LDAP" or "filter" alone. Fact-checked before this
# detector was written against current library source and real
# production incident reports; see the module docstring for what each
# category covers and what it does not.
_LDAP_ERROR_SIGNATURES: Tuple[str, ...] = (
    # PHP (ldap_search()/ldap_read()/ldap_list()): all three delegate
    # to one shared C helper that unconditionally emits an E_WARNING
    # "Search: <text>", auto-prefixed by PHP with whichever function
    # was actually called.
    "ldap_search(): search:",
    "ldap_read(): search:",
    "ldap_list(): search:",
    # OpenLDAP's own ldap_err2string() text for LDAP_FILTER_ERROR
    # (result code 87); also surfaces verbatim through python-ldap.
    "bad search filter",
    # Java JNDI (javax.naming.directory)
    "javax.naming.directory.invalidsearchfilterexception",
    # Java (UnboundID/Ping Identity LDAP SDK; Novell/Micro Focus jLDAP)
    "com.unboundid.ldap.sdk.ldapexception",
    "com.novell.ldap.ldapexception",
    # Java (Apache Directory LDAP API / ApacheDS / Spring-LDAP)
    "org.apache.directory.api.ldap.model.exception.ldapinvalidsearchfilterexception",
    # .NET (System.DirectoryServices.Protocols, and the older ADSI/COM
    # System.DirectoryServices namespace)
    "system.directoryservices.protocols.directoryoperationexception",
    "system.directoryservices.directoryservicescomexception",
    # Python (python-ldap)
    "ldap.filter_error",
    # Python (ldap3)
    "ldap3.core.exceptions.ldapinvalidfiltererror",
    # Node.js (ldapjs): its bundled filter parser's own internal
    # paren-matching check, a distinctly different message shape from
    # every entry above.
    "unbalanced parentheses at matchparen",
)


@dataclass(frozen=True, slots=True)
class LdapInjectionDetectorRunRecord:
    """One probed candidate and its outcome, regardless of whether a
    finding was produced, so "no finding" is always distinguishable
    from "not tested"."""

    candidate: DetectionCandidate | RequestTemplate
    outcome: LdapInjectionOutcome
    baseline_url: str
    diagnostic_url: str
    matched_signature: str | None
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class LdapInjectionDetectorRunResult:
    """Complete, auditable output of one detector run."""

    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[LdapInjectionDetectorRunRecord, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool = False


def _find_signature(body_text: str) -> str | None:
    lowered = body_text.lower()
    for signature in _LDAP_ERROR_SIGNATURES:
        if signature in lowered:
            return signature
    return None


def _classify(
    *,
    baseline_text: str,
    diagnostic_text: str,
    baseline_status: int,
    diagnostic_status: int,
) -> tuple[LdapInjectionOutcome, str | None]:
    baseline_signature = _find_signature(baseline_text)
    diagnostic_signature = _find_signature(diagnostic_text)

    if diagnostic_signature is None:
        return LdapInjectionOutcome.INCONCLUSIVE, None

    if baseline_signature == diagnostic_signature:
        # The same signature already appears in normal output for
        # this parameter, pre-existing directory-looking text, not
        # evidence attributable to the diagnostic probe.
        return LdapInjectionOutcome.INCONCLUSIVE, None

    if baseline_status != diagnostic_status:
        return LdapInjectionOutcome.CONFIRMED, diagnostic_signature

    return LdapInjectionOutcome.PROBABLE, diagnostic_signature


def _build_finding(
    target: ValidatedTarget,
    parameter: str,
    method: str,
    outcome: LdapInjectionOutcome,
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
        f"Matched signature category: directory client-library/server "
        f"error output (signature text not retained). "
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
        source_rule_id=f"ACTIVE-LDAPI-{outcome.value.upper()}",
        identifiers=(_CWE_LDAPI,),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("ldap-injection", "injection", "active", f"outcome-{outcome.value}"),
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
        _diagnostic_payload(baseline_value),
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

    diagnostic_mutated = mutate(
        template, parameter, _diagnostic_payload(baseline_value)
    )
    diagnostic_attempt = issue_templated_request(
        target,
        diagnostic_mutated,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
    )
    return baseline_attempt, diagnostic_attempt, parameter, template.method


def run_ldap_injection_detector(
    target: ValidatedTarget,
    candidates: Tuple[DetectionCandidate | RequestTemplate, ...],
    context: ActiveDetectionContext,
    *,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    authentication_material=None,
) -> LdapInjectionDetectorRunResult:
    """Run the error-based LDAP injection detector against a bounded
    set of candidates.

    ``target`` must already be scope-validated. ``candidates`` must
    already be restricted to parameters the caller intends to test.
    Each candidate costs two requests (baseline + diagnostic);
    ``policy.maximum_probe_requests`` is enforced against that real
    cost before any request is sent. ``candidates`` may mix legacy
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
    records: list[LdapInjectionDetectorRunRecord] = []
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
            LdapInjectionDetectorRunRecord(
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

    return LdapInjectionDetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "LdapInjectionOutcome",
    "LdapInjectionDetectorRunRecord",
    "LdapInjectionDetectorRunResult",
    "run_ldap_injection_detector",
]
