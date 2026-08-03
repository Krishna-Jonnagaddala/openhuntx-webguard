"""Passive HTTP information-disclosure header analysis."""

from __future__ import annotations

import re
from typing import Iterable
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
_SOURCE_RULE_PREFIX = "HTTP-DISCLOSURE"
_VERSION_TOKEN = re.compile(r"(?<![A-Za-z0-9])v?\d+(?:\.\d+){1,4}(?![A-Za-z0-9])")

DISCLOSURE_CHECKS = (
    "web.disclosure.aspnet",
    "web.disclosure.framework_headers",
    "web.disclosure.generator",
    "web.disclosure.powered_by",
    "web.disclosure.server",
    "web.disclosure.via",
)

_ASPNET_HEADERS = (
    "x-aspnet-version",
    "x-aspnetmvc-version",
)

_GENERATOR_HEADERS = (
    "generator",
    "x-generator",
)

_FRAMEWORK_HEADERS = (
    "x-backend-server",
    "x-cms",
    "x-drupal-cache",
    "x-drupal-dynamic-cache",
    "x-framework",
    "x-framework-version",
    "x-powered-cms",
    "x-rails-runtime",
    "x-runtime",
    "x-served-by",
    "x-umbraco-version",
    "x-version",
)

_NON_INFORMATIVE_SERVER_VALUES = frozenset(
    {
        "server",
        "web server",
        "webserver",
    }
)


class DisclosureAnalysisError(RuntimeError):
    """Controlled failure raised for inconsistent disclosure inputs."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _origin_and_path(
    target: ValidatedTarget,
) -> tuple[str, str]:
    """Return a canonical target origin and path."""

    parsed = urlsplit(target.normalised_url)

    if (
        parsed.scheme != target.scheme
        or parsed.hostname != target.hostname
    ):
        raise DisclosureAnalysisError(
            "validated_target_mismatch",
            "Validated target fields do not match normalised_url.",
        )

    parsed_port = parsed.port
    default_port = 443 if target.scheme == "https" else 80
    port = parsed_port or default_port

    if port != target.port:
        raise DisclosureAnalysisError(
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


def _header_values(
    headers: Iterable[tuple[str, str]],
    name: str,
) -> tuple[str, ...]:
    """Return non-empty values for one case-insensitive header name."""

    expected = name.lower()

    return tuple(
        value.strip()
        for header_name, value in headers
        if header_name.strip().lower() == expected
        and value.strip()
    )


def _contains_version(values: tuple[str, ...]) -> bool:
    """Return whether any value contains a bounded version-like token."""

    return any(
        _VERSION_TOKEN.search(value) is not None
        for value in values
    )


def _finding(
    *,
    target: ValidatedTarget,
    header_name: str,
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
    """Create one finding without retaining the raw header value."""

    origin, path = _origin_and_path(target)

    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule_id,
            asset=origin,
            path=path,
            method="GET",
            parameter=f"header:{header_name.lower()}",
        ),
        source=_SOURCE,
        source_rule_id=f"{_SOURCE_RULE_PREFIX}-{source_rule_id}",
        title=title,
        description=description,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        remediation=remediation,
        identifiers=identifiers,
        evidence=(Evidence(evidence_summary),),
        references=references,
        tags=("information-disclosure", "http-headers", "passive") + tags,
    )


def analyze_information_disclosure(
    target: ValidatedTarget,
    response: SafeHttpResponse,
) -> tuple[NormalizedFinding, ...]:
    """Report response headers that disclose implementation information.

    Raw values are deliberately excluded from evidence because proxy and
    framework headers can contain internal hostnames, deployment identifiers,
    or other environment-specific data.
    """

    _origin_and_path(target)
    findings: list[NormalizedFinding] = []

    server_values = _header_values(response.headers, "server")

    if server_values and not all(
        value.lower() in _NON_INFORMATIVE_SERVER_VALUES
        for value in server_values
    ):
        version_exposed = _contains_version(server_values)
        findings.append(
            _finding(
                target=target,
                header_name="server",
                rule_id=(
                    "web.disclosure.server.version"
                    if version_exposed
                    else "web.disclosure.server.technology"
                ),
                source_rule_id="001",
                title=(
                    "Server header exposes software version information"
                    if version_exposed
                    else "Server header exposes implementation information"
                ),
                description=(
                    "The Server response header identifies origin-server or "
                    "edge technology. Version details make product-specific "
                    "fingerprinting easier."
                ),
                severity=(
                    Severity.LOW
                    if version_exposed
                    else Severity.INFORMATIONAL
                ),
                remediation=(
                    "Remove the Server header where practical, or configure a "
                    "non-informative generic value without product or version "
                    "details."
                ),
                evidence_summary=(
                    "A Server header with a version-like token was observed; "
                    "the value was not retained."
                    if version_exposed
                    else (
                        "A product-identifying Server header was observed; "
                        "the value was not retained."
                    )
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-200"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server",
                ),
                tags=("server",) + (
                    ("version",)
                    if version_exposed
                    else ("technology",)
                ),
            )
        )

    powered_by_values = _header_values(
        response.headers,
        "x-powered-by",
    )

    if powered_by_values:
        version_exposed = _contains_version(powered_by_values)
        findings.append(
            _finding(
                target=target,
                header_name="x-powered-by",
                rule_id="web.disclosure.powered_by.present",
                source_rule_id="002",
                title="X-Powered-By exposes application technology",
                description=(
                    "The X-Powered-By response header identifies application "
                    "or framework technology and may include a product version."
                ),
                severity=Severity.LOW,
                remediation="Remove all X-Powered-By response headers.",
                evidence_summary=(
                    "X-Powered-By was observed"
                    + (
                        " with a version-like token"
                        if version_exposed
                        else ""
                    )
                    + "; the value was not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-200"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-powered-by",
                ),
                tags=("framework", "powered-by") + (
                    ("version",)
                    if version_exposed
                    else ()
                ),
            )
        )

    for header_name in _ASPNET_HEADERS:
        values = _header_values(response.headers, header_name)

        if not values:
            continue

        findings.append(
            _finding(
                target=target,
                header_name=header_name,
                rule_id="web.disclosure.aspnet_version.present",
                source_rule_id="003",
                title="ASP.NET version header is exposed",
                description=(
                    "The response exposes an ASP.NET or ASP.NET MVC version "
                    "header that can assist framework fingerprinting."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Disable ASP.NET and ASP.NET MVC version response headers "
                    "in the application and web-server configuration."
                ),
                evidence_summary=(
                    f"{header_name} was observed; the value was not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-200"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-aspnet-version",
                ),
                tags=("aspnet", "framework", "version"),
            )
        )

    for header_name in _GENERATOR_HEADERS:
        values = _header_values(response.headers, header_name)

        if not values:
            continue

        version_exposed = _contains_version(values)
        findings.append(
            _finding(
                target=target,
                header_name=header_name,
                rule_id="web.disclosure.generator.present",
                source_rule_id="004",
                title="Generator header exposes implementation information",
                description=(
                    "A generator response header identifies software used to "
                    "produce or serve the resource."
                ),
                severity=(
                    Severity.LOW
                    if version_exposed
                    else Severity.INFORMATIONAL
                ),
                remediation=(
                    "Remove generator-identification response headers unless "
                    "they are required for a documented operational purpose."
                ),
                evidence_summary=(
                    f"{header_name} was observed"
                    + (
                        " with a version-like token"
                        if version_exposed
                        else ""
                    )
                    + "; the value was not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-200"),),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
                ),
                tags=("generator",) + (
                    ("version",)
                    if version_exposed
                    else ()
                ),
            )
        )

    via_values = _header_values(response.headers, "via")

    if via_values:
        findings.append(
            _finding(
                target=target,
                header_name="via",
                rule_id="web.disclosure.via.present",
                source_rule_id="005",
                title="Via header exposes proxy information",
                description=(
                    "The Via response header discloses intermediary or proxy "
                    "routing information that may assist infrastructure "
                    "fingerprinting."
                ),
                severity=Severity.INFORMATIONAL,
                remediation=(
                    "Review whether the Via header is operationally required. "
                    "Where standards and architecture permit, suppress or "
                    "generalize identifying intermediary details."
                ),
                evidence_summary=(
                    "A Via response header was observed; the value was not "
                    "retained because it may contain internal identifiers."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-200"),),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
                ),
                tags=("proxy", "routing"),
            )
        )

    for header_name in _FRAMEWORK_HEADERS:
        values = _header_values(response.headers, header_name)

        if not values:
            continue

        version_exposed = _contains_version(values)
        findings.append(
            _finding(
                target=target,
                header_name=header_name,
                rule_id="web.disclosure.framework_header.present",
                source_rule_id="006",
                title="Framework or deployment header is exposed",
                description=(
                    "A framework-specific or deployment-identifying response "
                    "header was observed. Such headers can reveal application "
                    "technology, versions, cache layers, or internal topology."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Remove framework and deployment-identifying response "
                    "headers that are not required by clients or operations."
                ),
                evidence_summary=(
                    f"{header_name} was observed"
                    + (
                        " with a version-like token"
                        if version_exposed
                        else ""
                    )
                    + "; the value was not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-200"),),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
                ),
                tags=("framework",) + (
                    ("version",)
                    if version_exposed
                    else ()
                ),
            )
        )

    return tuple(
        sorted(
            findings,
            key=lambda item: (
                item.identity.rule_id,
                item.identity.parameter or "",
            ),
        )
    )
