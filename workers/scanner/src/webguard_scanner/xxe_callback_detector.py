"""Active XML External Entity detector (CWE-611): confirms blind/
out-of-band XXE by observing a genuine, server-side outbound request
from the target's own XML parser to a WebGuard-controlled callback
destination, never by inspecting the target's response text.

Why out-of-band only
---------------------
Every other content-based detector in this codebase (SQLi, path
traversal, command injection) holds the request's shape constant and
changes exactly one value, so a difference in the response is
attributable to that one value. XXE cannot use that recipe safely: it
has to replace the entire request body and content type, and a parser
that safely, correctly rejects an external entity (the modern secure
default for libxml2, .NET's XmlResolver, Java's
FEATURE_SECURE_PROCESSING, defusedxml) throws an error that routinely
uses the same vocabulary ("DOCTYPE", "external entity", "not
allowed") as a parser that is failing to resolve one because it *is*
vulnerable. There is no response-text signature this detector could
match on without risking flagging the safe case, which is the exact
failure this project's own command-injection detector had to be
corrected for (see its "Confirmation levels" docstring). Out-of-band
avoids the problem entirely: the response body is never read for
classification, so there is nothing for a reflected string, a generic
error page, or a hardened parser's own rejection message to fool.

This also means CWE-611's other classic techniques, in-band file
disclosure (the entity's resolved value echoed back into the
response) and parameter-entity-based two-stage exfiltration, are
deliberately not attempted this slice. Both remain real, named gaps,
not silently dropped: see "v1 scope limitations" below.

Detection methodology
----------------------
For each candidate request template already known to accept a POST
form or JSON request body (the same discovery this project's other
active detectors already use), deduped to one probe per (endpoint,
method) pair since the crafted document discards whatever parameter
suggested the endpoint:

1. Registers a fresh, single-purpose ``CallbackToken`` through the
   injected ``CallbackBroker``, the identical primitive
   ``ssrf_callback_detector.py`` already uses for CWE-918.
2. Builds a small XML document declaring exactly one external general
   entity, whose SYSTEM identifier is that token's callback URL, and
   sends it as the entire request body with ``Content-Type:
   application/xml``, replacing whatever form/JSON body the candidate
   originally had. This never touches ``mutate()`` (which only knows
   how to substitute one value into an existing FORM/JSON body); the
   ``MutatedRequest`` this module builds is constructed directly,
   which ``issue_templated_request`` accepts unmodified since nothing
   on that path validates ``content_type`` or requires ``mutate()``.
3. Issues exactly one bounded request via ``issue_templated_request``,
   the same shared transport, same-origin enforcement, and
   authentication mechanism every other active detector uses.
4. Waits, bounded, for a callback observation correlated to that exact
   token.

Confirmation levels
--------------------
- CONFIRMED: the probe request itself succeeded, and a callback
  observation for this exact token arrived within the policy's
  primary wait window. This is the only path to CONFIRMED: a
  response that rejects, ignores, or errors on the document is never
  sufficient on its own.
- PROBABLE: identical to CONFIRMED except the observation only arrived
  during the secondary grace window.
- NOT_VULNERABLE: the probe request succeeded and no callback
  observation arrived even after the full wait+grace window. This is
  also what a target with no XML parser at all, or a hardened one that
  safely declines the entity, produces: there is no in-band signal
  to misread either way.
- INCONCLUSIVE: callback registration itself failed, or the wait was
  stopped early by cancellation.
- ERROR: the probe request itself failed at the transport level.

Safety analysis
-----------------
Entity expansion / denial of service is structurally impossible with
this payload, not merely avoided by policy: the DOCTYPE declares
exactly one entity, referenced exactly once, with no parameter entity
and no nested or self-referential definition, so there is nothing
resembling a "billion laughs" chain for even a maximally naive parser
to expand. Arbitrary file read is equally impossible: the SYSTEM
identifier is always and only a WebGuard-issued ``http://``/``https://``
callback URL, never ``file://`` or any local path, so even a fully
vulnerable target can only be induced to make one outbound HTTP GET to
WebGuard's own receiver: it is never asked to open, read, or
transmit any of its own files. Response text is never inspected for
classification, so there is no exposure to the reflected-payload
false positive this project's command-injection detector had to guard
against.

v1 scope limitations
----------------------
- Out-of-band only. In-band file-disclosure and in-band error-based
  detection are both deliberately excluded (see "Why out-of-band
  only" above), not silently dropped.
- No parameter-entity-based two-stage exfiltration. That technique
  requires actually inducing the target to read and transmit one of
  its own files, exactly the file-read risk this detector is
  designed to never create.
- Exactly one payload shape: a single DOCTYPE, one general entity,
  referenced once in element content. No parameter entities, no
  nested DOCTYPE, no XInclude, no SOAP-envelope wrapping, no alternate
  encodings. A target that only resolves entities via one of these
  unattempted shapes is not flagged.
- Candidate selection reuses the existing POST-form/JSON-body
  discovery heuristic as a proxy for "this endpoint might also accept
  XML", as unproven as SSRF's own URL-shaped-parameter-name
  heuristic. A pure SOAP/XML-only endpoint never discovered as a
  POST-form or JSON-body candidate is not probed at all.
- Single-page scans only, matching the identical restriction
  ``_apply_ssrf_callback_detection`` already states for itself.
- No DNS-only out-of-band channel: only a completed inbound HTTP
  request at the WebGuard receiver counts as proof. A target whose
  egress permits DNS but blocks outbound HTTP is classified
  NOT_VULNERABLE, a false negative rather than a false positive,
  inherited from the CallbackBroker/receiver architecture this shares
  with SSRF.
- ``FindingIdentity.parameter`` is always ``None`` on a finding this
  detector produces, a deliberate deviation from every other active
  detector here (which always attaches a specific vulnerable
  parameter): XXE replaces the entire request body, so there is no
  single parameter the evidence is about.
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
from .request_template import ContentType, MutatedRequest, RequestTemplate, issue_templated_request
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


_DETECTOR_ID = "active.xxe.callback"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_XXE = ExternalIdentifier("CWE", "CWE-611")

_REQUESTS_PER_CANDIDATE = 1

_XML_DOCTYPE_NAME = "wgxxe"


class XxeDetectionOutcome(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"


_FINDING_OUTCOMES = frozenset(
    {XxeDetectionOutcome.CONFIRMED, XxeDetectionOutcome.PROBABLE}
)

_OUTCOME_CONFIDENCE = {
    XxeDetectionOutcome.CONFIRMED: Confidence.CONFIRMED,
    XxeDetectionOutcome.PROBABLE: Confidence.HIGH,
}

_OUTCOME_TITLE = {
    XxeDetectionOutcome.CONFIRMED: "XML External Entity injection (confirmed callback)",
    XxeDetectionOutcome.PROBABLE: "XML External Entity injection (probable callback)",
}

_OUTCOME_DESCRIPTION = {
    XxeDetectionOutcome.CONFIRMED: (
        "The endpoint accepted a crafted application/xml document "
        "declaring an external entity whose SYSTEM identifier was a "
        "WebGuard-controlled callback URL, and a genuine outbound "
        "request from the target's own XML parser was observed at "
        "that exact, uniquely-tokenized destination within the "
        "expected time window, direct evidence that the parser "
        "resolved an external reference it should not have."
    ),
    XxeDetectionOutcome.PROBABLE: (
        "The endpoint accepted a crafted application/xml document "
        "declaring an external entity whose SYSTEM identifier was a "
        "WebGuard-controlled callback URL, and a correlated, uniquely "
        "-tokenized callback was observed, but only after the primary "
        "wait window elapsed, still exactly token-correlated, but "
        "weaker timing evidence than an on-time callback."
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


def select_xxe_candidates(
    templates: Tuple[RequestTemplate, ...]
) -> Tuple[RequestTemplate, ...]:
    """Narrows a mixed discovery result to one candidate per (endpoint,
    method) pair, restricted to templates that already carry a POST
    form or JSON request body.

    A GET candidate (``ContentType.NONE``) carries no body at all, so
    sending an XML body there is a no-op most servers ignore, so it is
    never selected. Because the crafted document replaces the whole
    body regardless of which parameter the candidate was discovered
    on, several templates for the same endpoint (one per form field or
    JSON path) would otherwise produce byte-identical diagnostic
    requests; deduping by (endpoint, method) instead of by parameter
    is the one piece of selection logic this detector needs beyond
    what ``select_ssrf_candidates`` already does.
    """

    seen: set[tuple[str, str]] = set()
    selected: list[RequestTemplate] = []
    for template in templates:
        if template.content_type not in (ContentType.FORM_URLENCODED, ContentType.JSON):
            continue
        dedupe_key = (template.endpoint, template.method)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        selected.append(template)
    return tuple(selected)


def _build_xxe_document(callback_url: str) -> bytes:
    """One external general entity, declared once, referenced once:
    see the module docstring's "Safety analysis" for why this specific
    shape cannot expand or read a local file. ``callback_url`` is
    always a WebGuard-issued ``CallbackToken.url``: its token component
    is ``secrets.token_urlsafe`` output (URL-safe base64: letters,
    digits, ``-`` and ``_`` only) and its prefix is this codebase's own
    fixed base URL, so it can never contain an unescaped ``"`` or
    ``&`` that would break out of the attribute it is substituted
    into."""

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<!DOCTYPE {_XML_DOCTYPE_NAME} [\n"
        f'  <!ENTITY {_XML_DOCTYPE_NAME} SYSTEM "{callback_url}">\n'
        "]>\n"
        f"<{_XML_DOCTYPE_NAME}>&{_XML_DOCTYPE_NAME};</{_XML_DOCTYPE_NAME}>"
    ).encode("utf-8")


def _build_xxe_probe(template: RequestTemplate, xml_body: bytes) -> MutatedRequest:
    """Constructs the diagnostic request directly rather than through
    ``mutate()``: XXE replaces the entire body and content type, the
    opposite of what ``mutate()``'s single-value-substitution contract
    is for. ``MutatedRequest`` has no validation on ``content_type`` or
    ``body`` beyond its own field types, and ``issue_templated_request``
    never requires that a ``MutatedRequest`` came from ``mutate()``, so
    this is a legitimate, direct use of an already-public constructor,
    not a new primitive."""

    return MutatedRequest(
        url=template.endpoint,
        method=template.method,
        content_type=ContentType.XML,
        body=xml_body,
        parameter="",
        source_candidate_id=template.source_candidate_id,
    )


@dataclass(frozen=True, slots=True)
class XxeProbeRecord:
    """One candidate's outcome, regardless of whether a finding was
    produced. No ``parameter`` field: XXE replaces the whole request
    body, so no single parameter is ever the subject of the probe."""

    candidate_endpoint: str
    method: str
    outcome: XxeDetectionOutcome
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class XxeDetectorRunResult:
    detector_id: str
    records: Tuple[XxeProbeRecord, ...]
    findings: Tuple[NormalizedFinding, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool


def _build_finding(
    target: ValidatedTarget,
    *,
    template: RequestTemplate,
    outcome: XxeDetectionOutcome,
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
        # Deliberately None, not the discovering candidate's parameter
        # (see the module docstring's v1 scope limitations): this
        # detector replaces the whole request body, so no single
        # parameter is the subject of the evidence.
        parameter=None,
    )

    provenance = (
        f"Detector {_DETECTOR_ID} v{_DETECTOR_VERSION}. "
        f"Scan: {context.scan_id}. "
        f"Authorization: {context.authorization_id or 'not recorded'}. "
        f"Permit: {context.permit_id or 'not recorded'}. "
        f"Endpoint content type on discovery: {template.content_type}. "
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
        source_rule_id=f"ACTIVE-XXE-CALLBACK-{outcome.value.upper()}",
        identifiers=(_CWE_XXE,),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("xxe", "callback", "active", f"outcome-{outcome.value}"),
    )


def run_xxe_callback_detector(
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
) -> XxeDetectorRunResult:
    """Run the XXE-callback detector across a bounded set of candidate
    request templates. ``candidates`` may be a mixed discovery result;
    this function narrows to POST-form/JSON-body candidates, deduped by
    (endpoint, method), via ``select_xxe_candidates`` and never probes
    anything else.

    Enforces ``policy.maximum_probe_requests`` against the real
    request cost (one probe request per selected candidate; the
    callback wait itself issues no additional request from WebGuard's
    own client) before any request is sent.
    """

    xxe_candidates = select_xxe_candidates(candidates)
    enforce_probe_budget(
        xxe_candidates, policy, requests_per_candidate=_REQUESTS_PER_CANDIDATE
    )

    records: list[XxeProbeRecord] = []
    findings: list[NormalizedFinding] = []
    probe_errors: list[str] = []
    cancelled = False

    for template in xxe_candidates:
        if cancellation_check is not None and cancellation_check():
            cancelled = True
            break

        try:
            token = callback_broker.register(
                scan_id=context.scan_id,
                candidate_fingerprint=(
                    template.source_candidate_id or template.endpoint
                ),
            )
        except CallbackBrokerError as exc:
            probe_errors.append(exc.code)
            records.append(
                XxeProbeRecord(
                    candidate_endpoint=template.endpoint,
                    method=template.method,
                    outcome=XxeDetectionOutcome.INCONCLUSIVE,
                    detected_at=_utc_now(),
                )
            )
            continue

        xml_body = _build_xxe_document(token.url)
        mutated = _build_xxe_probe(template, xml_body)

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
                XxeProbeRecord(
                    candidate_endpoint=template.endpoint,
                    method=template.method,
                    outcome=XxeDetectionOutcome.ERROR,
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
            # A callback-storage failure while waiting must degrade
            # only this one candidate to INCONCLUSIVE, the identical
            # treatment `register()`'s own CallbackBrokerError already
            # gets above, never silently reclassified as
            # NOT_VULNERABLE and never left to propagate and fail the
            # whole scan job. Mirrors run_ssrf_callback_detector's
            # identical handling exactly.
            probe_errors.append(exc.code)
            records.append(
                XxeProbeRecord(
                    candidate_endpoint=template.endpoint,
                    method=template.method,
                    outcome=XxeDetectionOutcome.INCONCLUSIVE,
                    detected_at=_utc_now(),
                )
            )
            continue

        if was_cancelled:
            outcome = XxeDetectionOutcome.INCONCLUSIVE
        elif observation is None:
            outcome = XxeDetectionOutcome.NOT_VULNERABLE
        elif within_primary_window:
            outcome = XxeDetectionOutcome.CONFIRMED
        else:
            outcome = XxeDetectionOutcome.PROBABLE

        records.append(
            XxeProbeRecord(
                candidate_endpoint=template.endpoint,
                method=template.method,
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

    return XxeDetectorRunResult(
        detector_id=_DETECTOR_ID,
        records=tuple(records),
        findings=tuple(findings),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "XxeDetectionOutcome",
    "XxeDetectorRunResult",
    "XxeProbeRecord",
    "run_xxe_callback_detector",
    "select_xxe_candidates",
]
