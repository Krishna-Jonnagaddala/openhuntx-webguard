"""Passive HTTP security-header analysis for OpenHuntX WebGuard."""

from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict, Iterable, Mapping, Tuple
from urllib.parse import urlsplit

from webguard_contracts import (
    Confidence,
    Evidence,
    ExternalIdentifier,
    FindingIdentity,
    NormalizedFinding,
    Severity,
)

from .safe_http import SafeHttpResponse
from .scope_validator import ValidatedTarget


_SOURCE = "webguard-passive"
_SOURCE_RULE_PREFIX = "HTTP-HEADER"


class HeaderAnalysisError(RuntimeError):
    """Controlled failure raised for inconsistent analysis inputs."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _header_map(
    headers: Iterable[tuple[str, str]],
) -> Mapping[str, Tuple[str, ...]]:
    """Return response headers grouped case-insensitively."""

    grouped: DefaultDict[str, list[str]] = defaultdict(list)

    for name, value in headers:
        grouped[name.strip().lower()].append(value.strip())

    return {
        name: tuple(values)
        for name, values in grouped.items()
    }


def _origin_and_path(
    target: ValidatedTarget,
) -> tuple[str, str]:
    """Return a canonical origin and path for finding identity."""

    parsed = urlsplit(target.normalised_url)

    if (
        parsed.scheme != target.scheme
        or parsed.hostname != target.hostname
    ):
        raise HeaderAnalysisError(
            "validated_target_mismatch",
            "Validated target fields do not match normalised_url.",
        )

    parsed_port = parsed.port
    default_port = 443 if target.scheme == "https" else 80
    port = parsed_port or default_port

    if port != target.port:
        raise HeaderAnalysisError(
            "validated_target_mismatch",
            "Validated target port does not match normalised_url.",
        )

    hostname = target.hostname
    formatted_hostname = (
        f"[{hostname}]"
        if ":" in hostname
        else hostname
    )

    origin = (
        f"{target.scheme}://{formatted_hostname}"
        if port == default_port
        else f"{target.scheme}://{formatted_hostname}:{port}"
    )

    return origin, parsed.path or "/"


def _csp_has_directive(
    csp_values: Iterable[str],
    directive_name: str,
) -> bool:
    """Return whether any enforced CSP contains the named directive."""

    expected = directive_name.lower()

    for policy in csp_values:
        for directive in policy.split(";"):
            parts = directive.strip().split()

            if parts and parts[0].lower() == expected:
                return True

    return False


def _finding(
    *,
    target: ValidatedTarget,
    rule_id: str,
    source_rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    remediation: str,
    evidence_summary: str,
    identifiers: tuple[ExternalIdentifier, ...] = (),
    references: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
) -> NormalizedFinding:
    """Create one validated passive-header finding."""

    origin, path = _origin_and_path(target)

    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule_id,
            asset=origin,
            path=path,
            method="GET",
        ),
        source=_SOURCE,
        source_rule_id=f"{_SOURCE_RULE_PREFIX}-{source_rule_id}",
        title=title,
        description=description,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        remediation=remediation,
        identifiers=identifiers,
        evidence=(
            Evidence(evidence_summary),
        ),
        references=references,
        tags=("http-headers", "passive") + tags,
    )


def analyze_security_headers(
    target: ValidatedTarget,
    response: SafeHttpResponse,
) -> tuple[NormalizedFinding, ...]:
    """Analyze one bounded HTTP response without sending new requests."""

    headers = _header_map(response.headers)
    findings: list[NormalizedFinding] = []

    hsts_values = headers.get("strict-transport-security", ())

    if target.scheme == "https" and not hsts_values:
        findings.append(
            _finding(
                target=target,
                rule_id="web.headers.hsts.missing",
                source_rule_id="001",
                title="Strict-Transport-Security header missing",
                description=(
                    "The HTTPS response does not include the "
                    "Strict-Transport-Security header. Browsers that have "
                    "not previously learned an HSTS policy may permit an "
                    "initial insecure HTTP connection."
                ),
                severity=Severity.MEDIUM,
                remediation=(
                    "After confirming that the entire site and required "
                    "subdomains support HTTPS, add a suitable "
                    "Strict-Transport-Security policy."
                ),
                evidence_summary=(
                    "No Strict-Transport-Security response header was "
                    "observed."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-319"),
                ),
                references=(
                    "https://owasp.org/www-project-secure-headers/",
                ),
                tags=("transport-security",),
            )
        )

    content_type_options = headers.get(
        "x-content-type-options",
        (),
    )

    if not content_type_options:
        findings.append(
            _finding(
                target=target,
                rule_id="web.headers.x_content_type_options.missing",
                source_rule_id="002",
                title="X-Content-Type-Options header missing",
                description=(
                    "The response does not instruct browsers to disable "
                    "MIME type sniffing."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Add the response header "
                    "'X-Content-Type-Options: nosniff'."
                ),
                evidence_summary=(
                    "No X-Content-Type-Options response header was "
                    "observed."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-16"),
                ),
                references=(
                    "https://owasp.org/www-project-secure-headers/",
                ),
                tags=("content-type",),
            )
        )
    elif not any(
        value.lower() == "nosniff"
        for value in content_type_options
    ):
        findings.append(
            _finding(
                target=target,
                rule_id="web.headers.x_content_type_options.invalid",
                source_rule_id="003",
                title="X-Content-Type-Options header is invalid",
                description=(
                    "The X-Content-Type-Options header is present but "
                    "does not contain the required 'nosniff' value."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Set the response header exactly to "
                    "'X-Content-Type-Options: nosniff'."
                ),
                evidence_summary=(
                    "Observed X-Content-Type-Options value(s): "
                    + ", ".join(content_type_options)
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-16"),
                ),
                references=(
                    "https://owasp.org/www-project-secure-headers/",
                ),
                tags=("content-type",),
            )
        )

    csp_values = headers.get("content-security-policy", ())

    if not csp_values:
        findings.append(
            _finding(
                target=target,
                rule_id="web.headers.csp.missing",
                source_rule_id="004",
                title="Content-Security-Policy header missing",
                description=(
                    "The response does not define a Content Security "
                    "Policy to restrict which resources the browser may "
                    "load or execute."
                ),
                severity=Severity.MEDIUM,
                remediation=(
                    "Deploy a tested Content-Security-Policy. Begin in "
                    "report-only mode where appropriate, review violations, "
                    "and then enforce the policy."
                ),
                evidence_summary=(
                    "No Content-Security-Policy response header was "
                    "observed."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-693"),
                ),
                references=(
                    "https://owasp.org/www-project-secure-headers/",
                ),
                tags=("content-security-policy",),
            )
        )

    referrer_policy_values = headers.get(
        "referrer-policy",
        (),
    )

    if not referrer_policy_values:
        findings.append(
            _finding(
                target=target,
                rule_id="web.headers.referrer_policy.missing",
                source_rule_id="005",
                title="Referrer-Policy header missing",
                description=(
                    "The response does not explicitly control how much "
                    "referrer information browsers send to other origins."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Set a Referrer-Policy value appropriate for the "
                    "application, such as 'strict-origin-when-cross-origin' "
                    "or a more restrictive policy."
                ),
                evidence_summary=(
                    "No Referrer-Policy response header was observed."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-200"),
                ),
                references=(
                    "https://owasp.org/www-project-secure-headers/",
                ),
                tags=("privacy",),
            )
        )

    frame_ancestors_present = _csp_has_directive(
        csp_values,
        "frame-ancestors",
    )

    x_frame_options_values = headers.get(
        "x-frame-options",
        (),
    )

    valid_x_frame_options = any(
        value.lower() in {"deny", "sameorigin"}
        for value in x_frame_options_values
    )

    if not frame_ancestors_present and not valid_x_frame_options:
        findings.append(
            _finding(
                target=target,
                rule_id="web.headers.frame_protection.missing",
                source_rule_id="006",
                title="Clickjacking frame protection missing",
                description=(
                    "The response does not contain a CSP frame-ancestors "
                    "directive or a valid X-Frame-Options fallback."
                ),
                severity=Severity.MEDIUM,
                remediation=(
                    "Define an appropriate Content-Security-Policy "
                    "frame-ancestors directive. Add X-Frame-Options as a "
                    "legacy-browser fallback when required."
                ),
                evidence_summary=(
                    "No CSP frame-ancestors directive or valid "
                    "X-Frame-Options value was observed."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-1021"),
                ),
                references=(
                    "https://owasp.org/www-community/attacks/Clickjacking",
                ),
                tags=("clickjacking",),
            )
        )

    return tuple(
        sorted(
            findings,
            key=lambda finding: finding.identity.rule_id,
        )
    )
