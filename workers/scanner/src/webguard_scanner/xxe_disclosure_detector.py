"""Active in-band XXE file-disclosure detector (CWE-611): confirms XML
external entity injection by reading the disclosed file's own content
directly out of the response body, instead of waiting for an out-of-band
callback.

Why this exists alongside active.xxe.callback
------------------------------------------------
``xxe_callback_detector.py``'s ``active.xxe.callback`` only ever sends a
callback URL (http/https) as a SYSTEM identifier, and only ever confirms
by observing an inbound callback; it never reads response text. A live-
target investigation (see docs/audit/active-detection-phase13-xxe-
callback.md) found a real, anonymously-exploitable XXE that
``active.xxe.callback`` structurally cannot reach: the vulnerable parser
had filesystem access (``file://`` resolves) but no socket/network
capability at all, so a callback URL as the SYSTEM identifier never
resolves to anything and no callback ever arrives, even though the target
is genuinely vulnerable. This detector closes that half of the gap by
sending a ``file://`` SYSTEM identifier and checking the response body
for the disclosed file's own content, the same technique
``path_traversal_detector.py`` already uses for path traversal.

What this does not close, stated plainly rather than found out later: the
live vulnerability that motivated this detector was a genuine
``multipart/form-data`` file upload (an uploaded ``.xml`` file's own
content gets parsed, not the request's own body), and this scanner's
attack-surface discovery has no representation for that shape at all --
``InputLocation`` (``attack_surface.py``) has QUERY/PATH/FORM/JSON_BODY/
HEADER, no FILE or MULTIPART variant, so no ``RequestTemplate`` is ever
built for a multipart upload endpoint in the first place. Both this
detector and ``active.xxe.callback`` replace an existing FORM/JSON
request's entire body with a raw ``application/xml`` document; neither
constructs a multipart envelope. Consequently this detector cannot re-
confirm the specific live finding that motivated it. What it does
confirm: in-band XXE on any endpoint that accepts a form/JSON POST body
and also parses an ``application/xml`` body sent to that same URL and
method, the same candidate class ``active.xxe.callback`` already
targets, checked in-band instead of out-of-band. A genuine multipart-
upload XXE detector would need new discovery (a FILE input location) and
a new payload mechanic (a crafted multipart envelope); that is new
detector scope, not attempted here.

Detection methodology
----------------------
Candidate selection is a private, per-module copy of
``active.xxe.callback``'s own dedupe-by-(endpoint, method) plus
FORM_URLENCODED/JSON content-type restriction, not a cross-module import:
``select_ssrf_candidates`` and ``select_xxe_candidates`` are each already
defined independently in this codebase rather than one importing the
other, so this module follows the same precedent. Its candidate set is
never silently affected by a change made for the out-of-band detector's
own reasons.

For each selected candidate, exactly two requests, mirroring
``path_traversal_detector.py``'s baseline-plus-diagnostic *classification*
logic exactly, but not its *request-construction* technique:
path_traversal's baseline uses ``mutate()`` to change one parameter while
holding the template's real content type and shape constant, which does
not apply here since both requests must replace the content type itself
(from FORM_URLENCODED/JSON to XML), the same way ``active.xxe.callback``'s
own single probe already does. Both requests are built as a
``MutatedRequest`` directly:

1. a **baseline**: a well-formed, entity-free XML document
   (``<wgxxe>baseline</wgxxe>``, no DOCTYPE, resolves nothing);
2. a **diagnostic**: a single, non-recursive external general entity
   whose SYSTEM identifier is ``file:///etc/passwd``, the same safe,
   read-only, already-precedented disclosure target
   ``path_traversal_detector.py`` uses, referenced exactly once, never a
   parameter entity or an entity-referencing-entity chain.

The diagnostic response is checked for /etc/passwd's own content
signature (``path_traversal_detector.py``'s own ``_PASSWD_SIGNATURES``)
and compared against the baseline exactly as path traversal does: a
signature already present in the baseline is not attributable to the
probe; a new signature plus a status-code change is CONFIRMED; a new
signature with no status-code change is PROBABLE.

Honest limitation on stateful endpoints, not fixed this slice: this
comparison assumes the endpoint's behaviour for the same content type is
stable across two requests within a scan. A file-upload-style endpoint
gated by a one-time token, an upload quota, or duplicate-submission
detection can make the diagnostic fail, or its status change, for a
reason that has nothing to do with XXE. The /etc/passwd content signature
itself cannot appear in such an unrelated rejection, so this never
produces a false CONFIRMED/PROBABLE finding where no signature is
present; it can produce a false negative (INCONCLUSIVE) if the
diagnostic request is rejected before ever reaching the XML parser.
Retrying with a fresh token, or quota-aware pacing, is out of scope for
this two-request-per-candidate budget.

v1 scope, stated plainly: /etc/passwd only, one entity reference, no
Windows target, no alternate protocol wrapper (php://filter, expect://,
data://), no parameter-entity-based blind exfiltration, no multipart
file-upload payload delivery (see above). ``FindingIdentity.parameter``
is always ``None``, matching ``active.xxe.callback``'s own reasoning: the
whole body is replaced, and candidate selection dedupes to one template
per (endpoint, method), so no single parameter is the subject of the
evidence.
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
    throttle,
)
from .request_template import ContentType, MutatedRequest, RequestTemplate, issue_templated_request
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    from datetime import timezone

    return datetime.now(timezone.utc)


_DETECTOR_ID = "active.xxe.disclosure"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_XXE = ExternalIdentifier("CWE", "CWE-611")
_REQUESTS_PER_CANDIDATE = 2
_XML_DOCTYPE_NAME = "wgxxe"
_DISCLOSURE_TARGET = "file:///etc/passwd"

_BASELINE_XML_DOCUMENT = b'<?xml version="1.0" encoding="UTF-8"?>\n<wgxxe>baseline</wgxxe>'

_DIAGNOSTIC_XML_DOCUMENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b"<!DOCTYPE wgxxe [\n"
    b'  <!ENTITY wgxxe SYSTEM "file:///etc/passwd">\n'
    b"]>\n"
    b"<wgxxe>&wgxxe;</wgxxe>"
)

# /etc/passwd's own root-entry line, in the three shapes actually seen
# across Linux distributions. Copied from path_traversal_detector.py's
# own constant of the same name rather than imported, matching this
# codebase's convention of every detector owning its own small signature
# set.
_PASSWD_SIGNATURES: Tuple[str, ...] = (
    "root:x:0:0:",
    "root:!:0:0:",
    "root:*:0:0:",
)


class XxeDisclosureOutcome(str, Enum):
    """Confirmation strength for one in-band XXE disclosure probe."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"


_FINDING_OUTCOMES = frozenset(
    {XxeDisclosureOutcome.CONFIRMED, XxeDisclosureOutcome.PROBABLE}
)

_OUTCOME_CONFIDENCE = {
    XxeDisclosureOutcome.CONFIRMED: Confidence.CONFIRMED,
    XxeDisclosureOutcome.PROBABLE: Confidence.HIGH,
}

_OUTCOME_TITLE = {
    XxeDisclosureOutcome.CONFIRMED: "XML External Entity Injection (confirmed /etc/passwd disclosure)",
    XxeDisclosureOutcome.PROBABLE: "XML External Entity Injection (probable /etc/passwd disclosure)",
}

_OUTCOME_DESCRIPTION = {
    XxeDisclosureOutcome.CONFIRMED: (
        "Replacing this endpoint's request body with an XML document "
        "declaring a single external entity (SYSTEM \"file:///etc/passwd\") "
        "produced a response containing the target host's own /etc/passwd "
        "content, which was not present in the baseline response, and the "
        "response status code also changed. This means the XML parser "
        "behind this endpoint resolves external entities against the "
        "local filesystem, letting an attacker read arbitrary files the "
        "server process can access."
    ),
    XxeDisclosureOutcome.PROBABLE: (
        "Replacing this endpoint's request body with an XML document "
        "declaring a single external entity (SYSTEM \"file:///etc/passwd\") "
        "produced a response containing the target host's own /etc/passwd "
        "content, which was not present in the baseline response. The "
        "status code did not change, one fewer corroborating signal than "
        "a confirmed finding, but the disclosed content is specific to "
        "the requested file."
    ),
}

_REMEDIATION = (
    "Disable external entity resolution and DOCTYPE processing in "
    "every XML parser this application uses (for example, "
    "disallow-doctype-decl in Xerces/SAX, XMLConstants.FEATURE_SECURE_"
    "PROCESSING in Java, resolve_entities=False and no_network in "
    "libxml2/lxml, or a vetted library such as defusedxml in Python). "
    "Never rely on a blocklist of entity names or file paths."
)

_REFERENCES = (
    "https://cwe.mitre.org/data/definitions/611.html",
    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
)


def _select_candidates(
    candidates: Tuple[DetectionCandidate | RequestTemplate, ...]
) -> Tuple[RequestTemplate, ...]:
    """Narrow a mixed, page-wide candidate set to one RequestTemplate per
    (endpoint, method), restricted to a body-bearing content type. A
    private, per-module copy of active.xxe.callback's own
    select_xxe_candidates (see this module's docstring for why it is
    not a cross-module import)."""

    seen_keys: set[tuple[str, str]] = set()
    selected: list[RequestTemplate] = []
    for candidate in candidates:
        if not isinstance(candidate, RequestTemplate):
            continue
        if candidate.content_type not in (ContentType.FORM_URLENCODED, ContentType.JSON):
            continue
        key = (candidate.endpoint, candidate.method)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        selected.append(candidate)
    return tuple(selected)


def _build_probe(template: RequestTemplate, body: bytes) -> MutatedRequest:
    return MutatedRequest(
        url=template.endpoint,
        method=template.method,
        content_type=ContentType.XML,
        body=body,
        parameter="",
        source_candidate_id=template.source_candidate_id,
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
) -> tuple[XxeDisclosureOutcome, str | None]:
    baseline_signature = _find_signature(baseline_text)
    diagnostic_signature = _find_signature(diagnostic_text)

    if diagnostic_signature is None:
        return XxeDisclosureOutcome.INCONCLUSIVE, None

    if baseline_signature == diagnostic_signature:
        # The same passwd-shaped line already appears whether or not the
        # entity resolves: pre-existing content, not evidence of XXE.
        return XxeDisclosureOutcome.INCONCLUSIVE, None

    if baseline_status != diagnostic_status:
        return XxeDisclosureOutcome.CONFIRMED, diagnostic_signature

    return XxeDisclosureOutcome.PROBABLE, diagnostic_signature


@dataclass(frozen=True, slots=True)
class XxeDisclosureDetectorRunRecord:
    """One probed candidate and its outcome, regardless of whether a
    finding was produced, so "no finding" is always distinguishable from
    "not tested"."""

    candidate: RequestTemplate
    outcome: XxeDisclosureOutcome
    baseline_url: str
    diagnostic_url: str
    matched_signature: str | None
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class XxeDisclosureDetectorRunResult:
    """Complete, auditable output of one detector run."""

    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[XxeDisclosureDetectorRunRecord, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool = False


def _build_finding(
    target: ValidatedTarget,
    method: str,
    outcome: XxeDisclosureOutcome,
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
        # Deliberately None, not the discarded template's own parameter:
        # the whole body is replaced, so no single parameter is the
        # subject of this evidence. Matches active.xxe.callback's own
        # reasoning for the identical choice.
        parameter=None,
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
        source_rule_id=f"ACTIVE-XXE-DISCLOSURE-{outcome.value.upper()}",
        identifiers=(_CWE_XXE,),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("xxe", "file-disclosure", "active", f"outcome-{outcome.value}"),
    )


def run_xxe_disclosure_detector(
    target: ValidatedTarget,
    candidates: Tuple[DetectionCandidate | RequestTemplate, ...],
    context: ActiveDetectionContext,
    *,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    authentication_material=None,
) -> XxeDisclosureDetectorRunResult:
    """Run the in-band XXE disclosure detector against a bounded set of
    candidates.

    ``target`` must already be scope-validated. ``candidates`` is the
    same page-wide, mixed GET/POST/JSON candidate tuple every generic-
    registry detector receives; this function selects its own subset (see
    ``_select_candidates``) before enforcing the probe budget, since
    nothing upstream has narrowed it for this detector's own shape.

    ``cancellation_check``, if supplied, is polled before every
    candidate's baseline request.
    """

    selected = _select_candidates(candidates)
    enforce_probe_budget(
        selected, policy, requests_per_candidate=_REQUESTS_PER_CANDIDATE
    )

    findings: list[NormalizedFinding] = []
    records: list[XxeDisclosureDetectorRunRecord] = []
    probe_errors: list[str] = []
    cancelled = False

    for index, template in enumerate(selected):
        if cancellation_check is not None and cancellation_check():
            cancelled = True
            break

        if index > 0:
            throttle(policy)

        baseline_attempt = issue_templated_request(
            target,
            _build_probe(template, _BASELINE_XML_DOCUMENT),
            policy=policy,
            before_request=before_request,
            after_request=after_request,
            authentication_material=authentication_material,
        )
        if not baseline_attempt.succeeded:
            probe_errors.append(baseline_attempt.error_code or "unknown_probe_error")
            continue

        throttle(policy)

        diagnostic_attempt = issue_templated_request(
            target,
            _build_probe(template, _DIAGNOSTIC_XML_DOCUMENT),
            policy=policy,
            before_request=before_request,
            after_request=after_request,
            authentication_material=authentication_material,
        )
        if not diagnostic_attempt.succeeded:
            probe_errors.append(
                diagnostic_attempt.error_code or "unknown_probe_error"
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
            XxeDisclosureDetectorRunRecord(
                candidate=template,
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
                template.method,
                outcome,
                diagnostic_attempt.requested_url,
                context,
            )
        )

    return XxeDisclosureDetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "XxeDisclosureOutcome",
    "XxeDisclosureDetectorRunRecord",
    "XxeDisclosureDetectorRunResult",
    "run_xxe_disclosure_detector",
]
