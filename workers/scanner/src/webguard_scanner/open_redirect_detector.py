"""Active open redirect detector (CWE-601): single-request diagnostic
that submits an absolute external URL as a parameter's value and checks
whether the target's own 3xx response redirects a browser there.

Detection methodology
----------------------
For each authorized candidate parameter, this detector sends exactly one
bounded diagnostic request, with the parameter set to
``https://<fresh-random-marker>.invalid/``. ``.invalid`` is the reserved
top-level domain RFC 2606 guarantees will never resolve; nothing ever
connects to it, because this detector requests the underlying transport
not follow the redirect (``allow_redirect_status=True``, an existing
``fetch_once`` parameter this module is the first candidate-based
detector to use) and reads only the response's status code and
``Location`` header, never its body.

CONFIRMED requires all of the following on the diagnostic response:

1. the status code is one of the five values a browser actually
   auto-follows without user interaction (301, 302, 303, 307, 308, the
   WHATWG Fetch spec's "redirect status" set; 300/305/306 are not in
   that set and are treated as NOT_VULNERABLE even though the parameter
   may still technically control the header, since the phishing-via-
   silent-redirect risk this detector reports does not hold for them);
2. exactly one ``Location`` header is present (a response with zero or
   more than one is classified NOT_VULNERABLE rather than guessing which
   of several conflicting values a real browser would honour); and
3. that header's value, parsed with ``urllib.parse.urlsplit``, resolves
   to a hostname exactly matching this probe's own marker host
   (case-insensitively, with one trailing "." stripped from each side
   to treat an absolute-FQDN-canonicalised host the same as its
   ordinary form).

Using ``urlsplit(...).hostname`` rather than a substring/``in`` check on
the raw header value is the load-bearing property here, not a style
choice: it is what correctly resolves the actual destination host of
``https://target.example.com@<marker>.invalid/`` to ``<marker>.invalid``
(a classic userinfo-prefix trick against naive string matching), and
what correctly resolves a *safe* pattern, an app redirecting to itself
while merely echoing our value back inside its own query string
(``Location: https://target.example.com/leaving?to=https://<marker>.invalid/``),
to ``target.example.com`` rather than being fooled by the marker
appearing as a substring somewhere in the header.

Why no baseline request: every other value-substitution detector in
this codebase (SQLi, path traversal, command injection) baselines
against the original value to rule out a signature that already existed
independent of the probe. That comparison protects against ambiguous,
content-based evidence. Here the evidence is structural, not content-
based: a fresh marker embedded in a hostname either is or is not the
resolved destination of an actual HTTP redirect, and a target cannot
produce that exact match by coincidence. There is nothing for a second,
baseline request to rule out.

v1 scope, stated directly rather than left implicit:

- Exactly one payload shape is sent: a bare absolute ``https://`` URL.
  Protocol-relative input, backslash tricks (``https:/\\evil.com``),
  double-encoding, and whitespace/control-character bypass encodings are
  not attempted.
- Only the HTTP ``Location`` header on a 3xx response is checked. The
  legacy HTTP ``Refresh`` response header (``Refresh: 0;url=...``, a
  second, real, non-JavaScript redirect mechanism distinct from the
  HTML ``<meta http-equiv="refresh">`` tag) is not checked. Client-side
  redirects via JavaScript (``window.location = ...``) are out of scope
  entirely: this is a black-box HTTP scanner with no JS execution.
- Single request only, no follow-up action: a "store now, redirect
  later" pattern, where a value submitted on one request (for example
  a login page's ``?next=``) is only used to build a ``Location``
  header on a later, separate request (for example after a successful
  login), is not observable by this detector and is reported
  NOT_VULNERABLE even when the underlying application is genuinely
  vulnerable. This is a real, common shape for this exact weakness
  (post-login/post-SSO redirect), not a rare corner case, and closing
  it would need a second, triggering request per candidate, a
  materially larger scope than this slice attempts.
- Severity is a flat MEDIUM for every CONFIRMED finding regardless of
  the parameter's role. An OAuth ``redirect_uri`` or SSO callback
  parameter controlling a redirect is a meaningfully worse finding than
  a cosmetic "share this page" link, but this detector does not attempt
  to tell them apart; that would need its own parameter/endpoint-name
  heuristic with its own false-positive surface, which this slice does
  not add.
- The diagnostic response's body is still read and bounded by
  ``fetch_once`` even though classification never inspects it (the same
  tradeoff ``login_workflow.py`` already accepts for its own
  ``allow_redirect_status=True`` use, inherited unchanged, not
  introduced here). A target whose redirect response carries an
  oversized interstitial page body (for example a "you are leaving this
  site" warning page some high-security sites render on the 3xx itself)
  can push a genuinely vulnerable candidate into a probe ERROR instead
  of CONFIRMED, since the body-size limit is enforced before this
  detector ever sees the status or headers.
- No cache-busting beyond the marker's own uniqueness: a CDN or shared
  cache keyed on path alone, ignoring the query string entirely, could
  in principle serve one candidate's cached diagnostic response to a
  different candidate probing the same endpoint path, masking a real
  finding as NOT_VULNERABLE. This is a false negative, never a false
  positive (a stray marker from an unrelated candidate will not match
  this candidate's own expected host), and it is treated as an
  inherited transport/infrastructure risk, not fixed here.
- Candidate reach is inherited unchanged from this codebase's existing
  discovery pipeline, which costs open redirect specifically more than
  it costs the other value-substitution detectors: redirect-controlling
  parameters are classically discovered via a link pointing at a
  *different* endpoint than the page that links to it (for example
  ``<a href="/logout?redirect_to=...">`` found on a dashboard page), or
  present only in the entry URL's own query string with no in-page
  repetition at all (for example a bookmarked ``?next=`` link). Crawl
  mode's per-page ``restrict_to_page_path`` filter and
  ``attack_surface.py``'s in-page-only discovery both drop these shapes
  before any detector, including this one, ever sees them; this is a
  shared, pre-existing property of the discovery architecture, not
  something this detector introduces, but it disproportionately affects
  this specific technique. Separately, ``attack_surface.py``'s
  ``_STATE_CHANGING_KEYWORDS`` safety classification (a deliberate
  safety boundary shared by every active detector, not a bug) means a
  POST-form logout or payment-callback redirect field, both classic
  real-world CWE-601 targets, is never projected into a
  ``RequestTemplate`` for any detector, including this one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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
    issue_templated_request,
    mutate,
)
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


_DETECTOR_ID = "active.openredirect.location"
_DETECTOR_VERSION = "1.0"
_SOURCE = "webguard-active"
_CWE_OPEN_REDIRECT = ExternalIdentifier("CWE", "CWE-601")
_REQUESTS_PER_CANDIDATE = 1

# The WHATWG Fetch spec's "redirect status" set: the only status codes a
# browser (or fetch()/XHR) actually auto-follows without the user seeing
# an intermediate page. 300 (Multiple Choices) and 305 (Use Proxy,
# removed from RFC 7231 for security reasons) are deliberately excluded:
# the parameter may still technically control the header on those
# statuses, but the silent-redirect-to-attacker-site risk this detector
# reports does not hold for a status a browser will not auto-follow.
_BROWSER_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _new_marker() -> str:
    return f"wgredirect{uuid4().hex[:16]}"


def _diagnostic_payload(marker: str) -> tuple[str, str]:
    """Returns ``(payload, expected_host)``: the URL sent as the
    parameter's value, and the hostname a vulnerable target's own
    Location header must resolve to for this candidate to be
    confirmed."""

    host = f"{marker}.invalid"
    return f"https://{host}/", host


def _resolve_redirect_host(location: str) -> str | None:
    """Returns the hostname a real browser would actually navigate to,
    or None if ``location`` cannot be parsed at all or carries no host
    (a relative reference, therefore same-origin and never evidence).

    ``urlsplit`` can raise ``ValueError`` on some malformed values
    (for example an unterminated IPv6 literal, ``http://[::1/broken``),
    caught here and folded into "no host", never allowed to propagate
    and crash the whole detector run over one candidate's malformed
    response.
    """

    try:
        return urlsplit(location).hostname
    except ValueError:
        return None


def _classify(
    status: int, headers: Tuple[Tuple[str, str], ...], expected_host: str
) -> "OpenRedirectOutcome":
    if status not in _BROWSER_REDIRECT_STATUSES:
        return OpenRedirectOutcome.NOT_VULNERABLE

    locations = [value for name, value in headers if name.lower() == "location"]
    if len(locations) != 1:
        # Zero Location headers on a 3xx is malformed but not evidence.
        # More than one is a genuine ambiguity (seen in practice from a
        # reverse proxy/WAF layer adding its own Location header on top
        # of the origin's own): which value a real browser would honour
        # is not something this detector can observe from the outside,
        # so it makes no claim either way rather than guessing.
        return OpenRedirectOutcome.NOT_VULNERABLE

    redirect_host = _resolve_redirect_host(locations[0])
    if redirect_host is None:
        return OpenRedirectOutcome.NOT_VULNERABLE

    if redirect_host.rstrip(".").lower() == expected_host.rstrip(".").lower():
        return OpenRedirectOutcome.CONFIRMED

    return OpenRedirectOutcome.NOT_VULNERABLE


class OpenRedirectOutcome(str, Enum):
    """Confirmation strength for one open-redirect probe. Binary by
    design: the check is structural (does the Location header resolve
    to a host this probe itself supplied), not a content signature with
    a weaker/stronger reading, so there is no PROBABLE tier the way
    SQLi/path traversal have one for a status-code-change signal."""

    CONFIRMED = "confirmed"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"


_FINDING_OUTCOMES = frozenset({OpenRedirectOutcome.CONFIRMED})

_TITLE = "Open Redirect (confirmed Location header)"

_DESCRIPTION = (
    "Submitting an absolute external URL as this parameter's value "
    "produced a response whose status code is one browsers "
    "auto-follow without any user interaction, and whose Location "
    "header resolved to that exact external host. An attacker can "
    "build a link that looks like it points at this trusted domain "
    "but silently redirects a victim's browser to an attacker-"
    "controlled site, useful for phishing and credential harvesting."
)

_REMEDIATION = (
    "Never redirect to a URL built directly from user-controlled "
    "input. Resolve the requested destination against an allowlist "
    "of permitted paths or hosts, or restrict it to a path-only, "
    "same-origin relative reference and reject anything that "
    "specifies a different scheme or host."
)

_REFERENCES = (
    "https://cwe.mitre.org/data/definitions/601.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
)


@dataclass(frozen=True, slots=True)
class OpenRedirectDetectorRunRecord:
    """One probed candidate and its outcome, regardless of whether a
    finding was produced, so "no finding" is always distinguishable
    from "not tested"."""

    candidate: DetectionCandidate | RequestTemplate
    outcome: OpenRedirectOutcome
    diagnostic_url: str
    expected_host: str
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class OpenRedirectDetectorRunResult:
    """Complete, auditable output of one detector run."""

    detector_id: str
    detector_version: str
    findings: Tuple[NormalizedFinding, ...]
    records: Tuple[OpenRedirectDetectorRunRecord, ...]
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
        rule_id=f"{_DETECTOR_ID}.{OpenRedirectOutcome.CONFIRMED.value}",
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
        f"Evidence: Location header resolved to a WebGuard-issued, "
        f"single-use probe host (host value not retained). "
        f"Outcome: {OpenRedirectOutcome.CONFIRMED.value}."
    )

    return NormalizedFinding(
        identity=identity,
        source=_SOURCE,
        title=_TITLE,
        description=_DESCRIPTION,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        remediation=_REMEDIATION,
        source_rule_id=f"ACTIVE-OPENREDIRECT-{OpenRedirectOutcome.CONFIRMED.value.upper()}",
        identifiers=(_CWE_OPEN_REDIRECT,),
        evidence=(Evidence(summary=provenance),),
        references=_REFERENCES,
        tags=("open-redirect", "active", f"outcome-{OpenRedirectOutcome.CONFIRMED.value}"),
    )


def _issue_legacy_diagnostic(
    target: ValidatedTarget,
    candidate: DetectionCandidate,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None,
    after_request: AfterRequestHook | None,
    authentication_material=None,
):
    marker = _new_marker()
    payload, expected_host = _diagnostic_payload(marker)
    attempt = issue_probe(
        target,
        candidate,
        payload,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
        allow_redirect_status=True,
    )
    return attempt, candidate.parameter, "GET", expected_host


def _issue_templated_diagnostic(
    target: ValidatedTarget,
    template: RequestTemplate,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None,
    after_request: AfterRequestHook | None,
    authentication_material=None,
):
    marker = _new_marker()
    payload, expected_host = _diagnostic_payload(marker)
    mutated = mutate(template, template.parameter, payload)
    attempt = issue_templated_request(
        target,
        mutated,
        policy=policy,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
        allow_redirect_status=True,
    )
    return attempt, template.parameter, template.method, expected_host


def run_open_redirect_detector(
    target: ValidatedTarget,
    candidates: Tuple[DetectionCandidate | RequestTemplate, ...],
    context: ActiveDetectionContext,
    *,
    policy: ActiveDetectionPolicy = ActiveDetectionPolicy(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    authentication_material=None,
) -> OpenRedirectDetectorRunResult:
    """Run the open-redirect detector against a bounded set of
    candidates.

    ``target`` must already be scope-validated. ``candidates`` must
    already be restricted to parameters the caller intends to test;
    unlike ``active.ssrf.callback``, no parameter-name heuristic is
    applied here, since the diagnostic costs only one request per
    candidate and is not structurally limited to URL-sounding field
    names. ``candidates`` may mix legacy ``DetectionCandidate`` items
    (GET query/form parameter) with ``RequestTemplate`` items (POST
    form or JSON body parameter), identical in spirit to
    ``run_sqli_error_detector``.

    Each candidate costs exactly one request (no baseline);
    ``policy.maximum_probe_requests`` is enforced against that real
    cost before any request is sent.

    ``cancellation_check``, if supplied, is polled before every
    candidate's diagnostic request.
    """

    enforce_probe_budget(
        candidates, policy, requests_per_candidate=_REQUESTS_PER_CANDIDATE
    )

    findings: list[NormalizedFinding] = []
    records: list[OpenRedirectDetectorRunRecord] = []
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
                attempt, parameter, method, expected_host = (
                    _issue_templated_diagnostic(
                        target,
                        candidate,
                        policy=policy,
                        before_request=before_request,
                        after_request=after_request,
                        authentication_material=authentication_material,
                    )
                )
            else:
                attempt, parameter, method, expected_host = (
                    _issue_legacy_diagnostic(
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

        if not attempt.succeeded:
            probe_errors.append(attempt.error_code or "unknown_probe_error")
            continue

        outcome = _classify(
            attempt.response.status, attempt.response.headers, expected_host
        )

        records.append(
            OpenRedirectDetectorRunRecord(
                candidate=candidate,
                outcome=outcome,
                diagnostic_url=attempt.requested_url,
                expected_host=expected_host,
                detected_at=_utc_now(),
            )
        )

        if outcome not in _FINDING_OUTCOMES:
            continue

        findings.append(
            _build_finding(
                target, parameter, method, attempt.requested_url, context
            )
        )

    return OpenRedirectDetectorRunResult(
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
        findings=tuple(findings),
        records=tuple(records),
        probe_errors=tuple(probe_errors),
        cancelled=cancelled,
    )


__all__ = [
    "OpenRedirectOutcome",
    "OpenRedirectDetectorRunRecord",
    "OpenRedirectDetectorRunResult",
    "run_open_redirect_detector",
]
