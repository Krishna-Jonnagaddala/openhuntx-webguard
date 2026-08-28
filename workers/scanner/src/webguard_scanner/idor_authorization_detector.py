"""Active authorization-differential detector (CWE-639 / OWASP API BOLA):
compares authorization behaviour between two controlled test identities
to detect Insecure Direct Object Reference / Broken Object Level
Authorization.

Detection methodology
----------------------
For each supplied resource pair (a primary identity's own resource, a
secondary identity's own resource -- both explicitly supplied, never
generated or enumerated by this module), four bounded GET requests are
issued:

1. **baseline_primary**: the primary identity requests its own resource.
2. **baseline_secondary**: the secondary identity requests its own
   resource.
3. **cross_primary_to_secondary**: the primary identity requests the
   *secondary's* resource.
4. **cross_secondary_to_primary**: the secondary identity requests the
   *primary's* resource.

A finding requires a specific correlation, not a generic 200: a
cross-access response's bounded content fingerprint must match the
victim's own baseline fingerprint (proving the *actual* protected
content was returned, not a generic page, a login redirect, or a public
page that merely happens to also return 200), and must differ from the
requester's own baseline fingerprint (ruling out "this endpoint always
returns the same thing regardless of who or what is asked"). Fixture
markers, when present in test bodies, are read as auxiliary evidence
only -- production classification never depends on one.

Confirmation levels
--------------------
- CONFIRMED: both baselines succeeded (200), the cross-access response
  also succeeded (200), and its content fingerprint exactly matches the
  victim's baseline fingerprint while differing from the requester's own.
- PROBABLE: both baselines succeeded, the cross-access response
  succeeded (200), but fingerprint correlation is only partial (e.g. one
  direction's fixture-provided marker matches while the exact byte
  fingerprint does not -- content that varies slightly between requests
  for reasons unrelated to authorization).
- NOT_VULNERABLE: the cross-access request was denied (non-200, e.g.
  403/404), or it succeeded but its content does not correlate with the
  victim's own resource (a generic/public response) -- isolation is
  behaving as expected.
- INCONCLUSIVE: either baseline failed or errored (ownership access
  itself could not be established), the resource pair's
  ``expected_access`` is SHARED/PUBLIC (cross-access is expected by
  design, never reported as a vulnerability), or a cross-access probe
  itself errored.
- ERROR: a probe-level failure prevented any comparison from being made.
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
from .authorization_resource import AuthorizationResource, ResourceOwnership
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .safe_http import SafeRequestError, fetch_once
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


_DETECTOR_ID = "active.authorization.idor"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_IDOR = ExternalIdentifier("CWE", "CWE-639")
_OWASP_API_BOLA = ExternalIdentifier("OWASP-API", "API1:2023")
_REQUESTS_PER_RESOURCE_PAIR = 4

_BASELINE_HEADER_ALLOWLIST = frozenset({"content-type", "server", "cache-control"})


class IdorDetectionOutcome(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"


_FINDING_OUTCOMES = frozenset(
    {IdorDetectionOutcome.CONFIRMED, IdorDetectionOutcome.PROBABLE}
)

_OUTCOME_CONFIDENCE = {
    IdorDetectionOutcome.CONFIRMED: Confidence.CONFIRMED,
    IdorDetectionOutcome.PROBABLE: Confidence.HIGH,
}

_OUTCOME_TITLE = {
    IdorDetectionOutcome.CONFIRMED: (
        "Insecure Direct Object Reference (confirmed cross-identity access)"
    ),
    IdorDetectionOutcome.PROBABLE: (
        "Insecure Direct Object Reference (probable cross-identity access)"
    ),
}

_OUTCOME_DESCRIPTION = {
    IdorDetectionOutcome.CONFIRMED: (
        "One controlled test identity successfully retrieved another "
        "controlled test identity's own resource by supplying that "
        "resource's known identifier. The response's content fingerprint "
        "exactly matched the resource owner's own baseline access and "
        "differed from the requester's own resource, confirming genuine "
        "protected content was returned rather than a generic or public "
        "response."
    ),
    IdorDetectionOutcome.PROBABLE: (
        "One controlled test identity received a successful (200) "
        "response when requesting another controlled test identity's own "
        "resource. Corroborating evidence (a fixture-independent partial "
        "content correlation) supports that this was the resource "
        "owner's genuine content, though exact byte-for-byte fingerprint "
        "correlation was not established."
    ),
}

_REMEDIATION = (
    "Enforce object-level authorization on every request that accepts a "
    "user-controlled resource identifier: verify the authenticated "
    "identity is actually permitted to access the specific object "
    "requested, not merely that the identity is authenticated at all. "
    "Prefer indirect reference maps or server-side ownership checks over "
    "trusting a client-supplied identifier."
)

_REFERENCES = (
    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "https://cwe.mitre.org/data/definitions/639.html",
)


@dataclass(frozen=True, slots=True)
class AuthorizationResourcePair:
    """One pair of otherwise-equivalent resources, one owned by each
    identity, to cross-check for authorization isolation. Both resources
    must already carry a controlled ``ResourceSource`` provenance --
    this dataclass does not itself generate or validate identifiers."""

    primary_resource: AuthorizationResource
    secondary_resource: AuthorizationResource


@dataclass(frozen=True, slots=True)
class AuthorizationDifferentialObservation:
    """Bounded, non-sensitive characteristics of one probe response.
    Never stores the complete response body. ``marker_matched`` is
    ``None`` when the resource configured no ``owner_marker`` (the
    common, production case); otherwise it is a plain boolean recording
    whether that marker string was found -- the marker text itself is
    never retained here, only whether it was present."""

    succeeded: bool
    status: int | None
    response_length: int | None
    selected_headers: Tuple[Tuple[str, str], ...]
    content_fingerprint: str | None
    marker_matched: bool | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class IdorComparisonRecord:
    """One resource pair's outcome, regardless of whether a finding was
    produced -- so "not vulnerable" is always distinguishable from "not
    tested"."""

    resource_pair_id: Tuple[str, str]
    primary_identity: str
    secondary_identity: str
    outcome: IdorDetectionOutcome
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class IdorDetectorRunResult:
    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[IdorComparisonRecord, ...]
    probe_errors: Tuple[str, ...]
    cancelled: bool = False


def _selected_headers(
    headers: Tuple[Tuple[str, str], ...]
) -> Tuple[Tuple[str, str], ...]:
    return tuple(
        (name, value)
        for name, value in headers
        if name.lower() in _BASELINE_HEADER_ALLOWLIST
    )


def _fetch_resource(
    base_target: ValidatedTarget,
    resource: AuthorizationResource,
    material: AuthenticationMaterial,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None,
    after_request: AfterRequestHook | None,
) -> AuthorizationDifferentialObservation:
    _require_same_origin(base_target, resource.endpoint)
    probe_target = _build_probe_target(base_target, resource.endpoint)
    extra_headers = apply_authentication(resource.endpoint, material, now=_utc_now())

    if before_request is not None:
        before_request(probe_target, resource.method)

    try:
        response = fetch_once(
            probe_target,
            method=resource.method,
            policy=policy.fetch_policy,
            extra_headers=extra_headers,
        )
    except SafeRequestError as exc:
        if after_request is not None:
            after_request(probe_target, resource.method, None, exc.code)
        return AuthorizationDifferentialObservation(
            succeeded=False,
            status=None,
            response_length=None,
            selected_headers=(),
            content_fingerprint=None,
            marker_matched=None,
            error_code=exc.code,
        )

    if after_request is not None:
        after_request(probe_target, resource.method, response, None)

    marker_matched = (
        resource.owner_marker.encode("utf-8", errors="replace") in response.body
        if resource.owner_marker
        else None
    )

    return AuthorizationDifferentialObservation(
        succeeded=True,
        status=response.status,
        response_length=len(response.body),
        selected_headers=_selected_headers(response.headers),
        content_fingerprint=hashlib.sha256(response.body).hexdigest(),
        marker_matched=marker_matched,
        error_code=None,
    )


def _classify(
    *,
    baseline_primary: AuthorizationDifferentialObservation,
    baseline_secondary: AuthorizationDifferentialObservation,
    cross_primary_to_secondary: AuthorizationDifferentialObservation,
    expected_access: ResourceOwnership,
) -> IdorDetectionOutcome:
    if expected_access in (ResourceOwnership.SHARED, ResourceOwnership.PUBLIC):
        # Cross-access is expected by design -- never a finding, no
        # matter what the responses look like.
        return IdorDetectionOutcome.INCONCLUSIVE

    # Ownership access itself must be cleanly established (a real HTTP
    # 200, not merely "the transport didn't error") for both identities
    # before cross-access can mean anything. A baseline that errors out,
    # redirects, or itself returns a non-200 status leaves nothing
    # legitimate to correlate against.
    if not baseline_primary.succeeded or baseline_primary.status != 200:
        return IdorDetectionOutcome.INCONCLUSIVE
    if not baseline_secondary.succeeded or baseline_secondary.status != 200:
        return IdorDetectionOutcome.INCONCLUSIVE

    if not cross_primary_to_secondary.succeeded:
        return IdorDetectionOutcome.ERROR

    if cross_primary_to_secondary.status != 200:
        # Denied (403/404/etc) -- isolation is working as expected.
        return IdorDetectionOutcome.NOT_VULNERABLE

    cross_fingerprint = cross_primary_to_secondary.content_fingerprint
    secondary_fingerprint = baseline_secondary.content_fingerprint
    primary_fingerprint = baseline_primary.content_fingerprint

    if cross_fingerprint == primary_fingerprint:
        # The endpoint returned the same thing it always returns to the
        # primary identity -- a generic/constant response, not the
        # secondary's actual resource. Never a finding.
        return IdorDetectionOutcome.NOT_VULNERABLE

    if cross_fingerprint == secondary_fingerprint:
        return IdorDetectionOutcome.CONFIRMED

    # 200, differs from the requester's own baseline, and does not
    # exactly match the victim's baseline byte-for-byte either (e.g.
    # legitimate minor per-request variation). Exact fingerprint
    # correlation is the only signal that reaches CONFIRMED; anything
    # weaker (response length, headers) is deliberately never used here,
    # since either alone is easy to satisfy by coincidence -- see the
    # false-positive tests this rejected during development. The only
    # further corroborating evidence this detector accepts is an
    # explicit, operator-configured marker match, which is opt-in and
    # never assumed.
    if cross_primary_to_secondary.marker_matched:
        return IdorDetectionOutcome.PROBABLE

    return IdorDetectionOutcome.NOT_VULNERABLE


def _build_finding(
    target: ValidatedTarget,
    *,
    resource: AuthorizationResource,
    requesting_identity: str,
    owning_identity: str,
    outcome: IdorDetectionOutcome,
    context: ActiveDetectionContext,
) -> NormalizedFinding:
    parsed = urlsplit(resource.endpoint)

    identity = FindingIdentity(
        rule_id=f"{_DETECTOR_ID}.{outcome.value}",
        asset=f"{target.scheme}://{target.hostname}"
        + (f":{target.port}" if target.port not in (80, 443) else ""),
        path=parsed.path or "/",
        method=resource.method,
        parameter=resource.identifier_name or resource.resource_type,
    )

    provenance = (
        f"Detector {_DETECTOR_ID} v{_DETECTOR_VERSION}. "
        f"Scan: {context.scan_id}. "
        f"Authorization: {context.authorization_id or 'not recorded'}. "
        f"Permit: {context.permit_id or 'not recorded'}. "
        f"Requesting identity: {requesting_identity}. "
        f"Resource owner identity: {owning_identity}. "
        f"Expected authorization outcome: denied. Observed outcome: "
        f"cross-identity access succeeded. Outcome: {outcome.value}."
    )

    # Secondary classification (CWE-862) is deliberately never attached
    # automatically -- this detector's evidence establishes a specific
    # user-controlled-key bypass (CWE-639), not a general missing-
    # authorization condition, per this slice's own instruction.
    return NormalizedFinding(
        identity=identity,
        source=_SOURCE,
        title=_OUTCOME_TITLE[outcome],
        description=_OUTCOME_DESCRIPTION[outcome],
        severity=Severity.HIGH,
        confidence=_OUTCOME_CONFIDENCE[outcome],
        remediation=_REMEDIATION,
        source_rule_id=f"ACTIVE-AUTHORIZATION-IDOR-{outcome.value.upper()}",
        identifiers=(_CWE_IDOR, _OWASP_API_BOLA),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("idor", "bola", "authorization", "active", f"outcome-{outcome.value}"),
    )


def run_idor_authorization_detector(
    target: ValidatedTarget,
    resource_pairs: Tuple[AuthorizationResourcePair, ...],
    context: ActiveDetectionContext,
    *,
    primary_identity_label: str,
    primary_material: AuthenticationMaterial,
    secondary_identity_label: str,
    secondary_material: AuthenticationMaterial,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> IdorDetectorRunResult:
    """Run the authorization-differential (IDOR/BOLA) detector across a
    bounded set of resource pairs.

    ``resource_pairs`` must already be restricted to controlled,
    explicitly-supplied resources -- this function never generates,
    enumerates, or guesses a resource identifier. Each pair costs four
    requests (two baselines, two cross-checks);
    ``policy.maximum_probe_requests`` is enforced against that real cost
    before any request is sent.

    ``cancellation_check``, if supplied, is polled before every
    resource pair. When it returns True, no further pairs are compared
    and the result's ``cancelled`` flag is set.
    """

    total_requests = len(resource_pairs) * _REQUESTS_PER_RESOURCE_PAIR
    if total_requests > policy.maximum_probe_requests:
        from .active_detection import ActiveDetectionError

        raise ActiveDetectionError(
            "candidate_budget_exceeded",
            f"{len(resource_pairs)} resource pairs at "
            f"{_REQUESTS_PER_RESOURCE_PAIR} request(s) each "
            f"({total_requests} total) exceed the maximum_probe_requests "
            f"policy of {policy.maximum_probe_requests}.",
        )

    findings: list[NormalizedFinding] = []
    records: list[IdorComparisonRecord] = []
    probe_errors: list[str] = []
    cancelled = False

    for pair in resource_pairs:
        if cancellation_check is not None and cancellation_check():
            cancelled = True
            break

        baseline_primary = _fetch_resource(
            target,
            pair.primary_resource,
            primary_material,
            policy=policy,
            before_request=before_request,
            after_request=after_request,
        )
        if not baseline_primary.succeeded:
            probe_errors.append(baseline_primary.error_code or "unknown_probe_error")

        baseline_secondary = _fetch_resource(
            target,
            pair.secondary_resource,
            secondary_material,
            policy=policy,
            before_request=before_request,
            after_request=after_request,
        )
        if not baseline_secondary.succeeded:
            probe_errors.append(baseline_secondary.error_code or "unknown_probe_error")

        cross_primary_to_secondary = _fetch_resource(
            target,
            pair.secondary_resource,
            primary_material,
            policy=policy,
            before_request=before_request,
            after_request=after_request,
        )
        if not cross_primary_to_secondary.succeeded:
            probe_errors.append(
                cross_primary_to_secondary.error_code or "unknown_probe_error"
            )

        cross_secondary_to_primary = _fetch_resource(
            target,
            pair.primary_resource,
            secondary_material,
            policy=policy,
            before_request=before_request,
            after_request=after_request,
        )
        if not cross_secondary_to_primary.succeeded:
            probe_errors.append(
                cross_secondary_to_primary.error_code or "unknown_probe_error"
            )

        expected_access = pair.primary_resource.expected_access

        outcome_primary = _classify(
            baseline_primary=baseline_primary,
            baseline_secondary=baseline_secondary,
            cross_primary_to_secondary=cross_primary_to_secondary,
            expected_access=expected_access,
        )
        records.append(
            IdorComparisonRecord(
                resource_pair_id=(
                    pair.primary_resource.resource_id,
                    pair.secondary_resource.resource_id,
                ),
                primary_identity=primary_identity_label,
                secondary_identity=secondary_identity_label,
                outcome=outcome_primary,
                detected_at=_utc_now(),
            )
        )
        if outcome_primary in _FINDING_OUTCOMES:
            findings.append(
                _build_finding(
                    target,
                    resource=pair.secondary_resource,
                    requesting_identity=primary_identity_label,
                    owning_identity=secondary_identity_label,
                    outcome=outcome_primary,
                    context=context,
                )
            )

        outcome_secondary = _classify(
            baseline_primary=baseline_secondary,
            baseline_secondary=baseline_primary,
            cross_primary_to_secondary=cross_secondary_to_primary,
            expected_access=expected_access,
        )
        records.append(
            IdorComparisonRecord(
                resource_pair_id=(
                    pair.secondary_resource.resource_id,
                    pair.primary_resource.resource_id,
                ),
                primary_identity=secondary_identity_label,
                secondary_identity=primary_identity_label,
                outcome=outcome_secondary,
                detected_at=_utc_now(),
            )
        )
        if outcome_secondary in _FINDING_OUTCOMES:
            findings.append(
                _build_finding(
                    target,
                    resource=pair.primary_resource,
                    requesting_identity=secondary_identity_label,
                    owning_identity=primary_identity_label,
                    outcome=outcome_secondary,
                    context=context,
                )
            )

    return IdorDetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "AuthorizationDifferentialObservation",
    "AuthorizationResourcePair",
    "IdorComparisonRecord",
    "IdorDetectionOutcome",
    "IdorDetectorRunResult",
    "run_idor_authorization_detector",
]
