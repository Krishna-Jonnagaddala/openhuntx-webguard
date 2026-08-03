"""Passive Set-Cookie security analysis for OpenHuntX WebGuard."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
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
_SOURCE_RULE_PREFIX = "HTTP-COOKIE"
_COOKIE_NAME = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$"
)
_ATTRIBUTE_NAME = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$"
)
_MAXIMUM_COOKIE_NAME_LENGTH = 128


COOKIE_CHECKS = (
    "web.cookies.domain",
    "web.cookies.httponly",
    "web.cookies.path",
    "web.cookies.prefix_host",
    "web.cookies.prefix_secure",
    "web.cookies.samesite",
    "web.cookies.secure",
    "web.cookies.transport",
)


class CookieAnalysisError(RuntimeError):
    """Controlled failure raised for inconsistent analysis inputs."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class _ParsedCookie:
    """Non-secret cookie metadata extracted from one Set-Cookie header."""

    name: str
    attributes: Mapping[str, Tuple[str | None, ...]]


def _origin_and_path(
    target: ValidatedTarget,
) -> tuple[str, str]:
    """Return a canonical origin and path for finding identity."""

    parsed = urlsplit(target.normalised_url)

    if (
        parsed.scheme != target.scheme
        or parsed.hostname != target.hostname
    ):
        raise CookieAnalysisError(
            "validated_target_mismatch",
            "Validated target fields do not match normalised_url.",
        )

    parsed_port = parsed.port
    default_port = 443 if target.scheme == "https" else 80
    port = parsed_port or default_port

    if port != target.port:
        raise CookieAnalysisError(
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


def _cookie_headers(
    headers: Iterable[tuple[str, str]],
) -> tuple[str, ...]:
    """Return Set-Cookie values without changing their order."""

    return tuple(
        value
        for name, value in headers
        if name.strip().lower() == "set-cookie"
    )


def _parse_cookie(
    raw_header: str,
) -> _ParsedCookie | None:
    """Parse only non-secret cookie metadata.

    The cookie value is deliberately discarded immediately and is never
    returned, logged, or placed in finding evidence.
    """

    segments = raw_header.split(";")

    if not segments:
        return None

    name_value = segments[0]
    name, separator, _discarded_value = name_value.partition("=")
    name = name.strip()

    if (
        not separator
        or not name
        or len(name) > _MAXIMUM_COOKIE_NAME_LENGTH
        or not _COOKIE_NAME.fullmatch(name)
    ):
        return None

    grouped: DefaultDict[str, list[str | None]] = defaultdict(list)

    for segment in segments[1:]:
        item = segment.strip()

        if not item:
            continue

        attribute_name, has_value, attribute_value = item.partition("=")
        attribute_name = attribute_name.strip().lower()

        if (
            not attribute_name
            or not _ATTRIBUTE_NAME.fullmatch(attribute_name)
        ):
            continue

        grouped[attribute_name].append(
            attribute_value.strip()
            if has_value
            else None
        )

    return _ParsedCookie(
        name=name,
        attributes={
            key: tuple(values)
            for key, values in grouped.items()
        },
    )


def _finding(
    *,
    target: ValidatedTarget,
    cookie_parameter: str,
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
    """Create one validated cookie finding without cookie values."""

    origin, path = _origin_and_path(target)

    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule_id,
            asset=origin,
            path=path,
            method="GET",
            parameter=cookie_parameter,
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
        tags=("cookies", "http-headers", "passive") + tags,
    )


def _cookie_finding(
    *,
    target: ValidatedTarget,
    cookie: _ParsedCookie,
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
    """Create a finding identified by cookie name, never cookie value."""

    return _finding(
        target=target,
        cookie_parameter=f"cookie:{cookie.name}",
        rule_id=rule_id,
        source_rule_id=source_rule_id,
        title=title,
        description=description,
        severity=severity,
        remediation=remediation,
        evidence_summary=(
            f"Cookie {cookie.name!r}: {evidence_summary} "
            "The cookie value was not retained."
        ),
        identifiers=identifiers,
        references=references,
        tags=tags,
    )


def _attribute_present(
    cookie: _ParsedCookie,
    name: str,
) -> bool:
    """Return whether an attribute name was present."""

    return name in cookie.attributes


def _single_attribute_value(
    cookie: _ParsedCookie,
    name: str,
) -> tuple[str | None, bool]:
    """Return one attribute value and whether its syntax is unambiguous."""

    values = cookie.attributes.get(name, ())

    if len(values) != 1:
        return None, False

    return values[0], True


def _domain_matches(
    hostname: str,
    domain: str,
) -> bool:
    """Return whether a Domain attribute domain-matches the target."""

    return (
        hostname == domain
        or hostname.endswith(f".{domain}")
    )


def _domain_findings(
    target: ValidatedTarget,
    cookie: _ParsedCookie,
) -> list[NormalizedFinding]:
    """Evaluate Domain scope without using a public-suffix guess."""

    if not _attribute_present(cookie, "domain"):
        return []

    raw_domain, unambiguous = _single_attribute_value(
        cookie,
        "domain",
    )

    if (
        not unambiguous
        or raw_domain is None
        or not raw_domain.strip()
    ):
        return [
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.domain.invalid",
                source_rule_id="007",
                title="Cookie Domain attribute is invalid",
                description=(
                    "The cookie contains an empty, repeated, or ambiguous "
                    "Domain attribute that may be rejected or interpreted "
                    "inconsistently."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Remove the Domain attribute for a host-only cookie, "
                    "or set one valid domain that intentionally matches "
                    "the target host."
                ),
                evidence_summary=(
                    "the Domain attribute was empty, repeated, or "
                    "ambiguous."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-16"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("cookie-scope",),
            )
        ]

    domain = raw_domain.strip().lower()
    had_trailing_dot = domain.endswith(".")

    if domain.startswith("."):
        domain = domain[1:]

    hostname = target.hostname.lower().rstrip(".")
    domain = domain.rstrip(".")

    invalid = (
        not domain
        or had_trailing_dot
    )

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        hostname_is_ip = False
    else:
        hostname_is_ip = True

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        domain_is_ip = False
    else:
        domain_is_ip = True

    if (
        invalid
        or hostname_is_ip
        or domain_is_ip
        or not _domain_matches(hostname, domain)
    ):
        return [
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.domain.invalid",
                source_rule_id="007",
                title="Cookie Domain attribute does not match the host",
                description=(
                    "The cookie Domain attribute does not validly "
                    "domain-match the response host and may be rejected "
                    "by user agents."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Remove the Domain attribute for a host-only cookie, "
                    "or set it to an intentional parent domain that "
                    "validly matches the response host."
                ),
                evidence_summary=(
                    "the Domain attribute did not validly match the "
                    "response host."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-16"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("cookie-scope",),
            )
        ]

    return [
        _cookie_finding(
            target=target,
            cookie=cookie,
            rule_id="web.cookies.domain.broad",
            source_rule_id="006",
            title="Cookie Domain attribute broadens host scope",
            description=(
                "The cookie includes a Domain attribute. This converts "
                "the cookie from host-only scope to domain scope and can "
                "make it available to matching subdomains."
            ),
            severity=Severity.LOW,
            remediation=(
                "Remove the Domain attribute unless the cookie must be "
                "shared deliberately with matching subdomains."
            ),
            evidence_summary=(
                "a valid Domain attribute broadened the cookie beyond "
                "host-only scope."
            ),
            identifiers=(
                ExternalIdentifier("CWE", "CWE-16"),
            ),
            references=(
                "https://datatracker.ietf.org/doc/"
                "draft-ietf-httpbis-rfc6265bis/",
            ),
            tags=("cookie-scope",),
        )
    ]


def _path_findings(
    target: ValidatedTarget,
    cookie: _ParsedCookie,
) -> list[NormalizedFinding]:
    """Evaluate explicit cookie path scope."""

    if not _attribute_present(cookie, "path"):
        return [
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.path.missing",
                source_rule_id="008",
                title="Cookie Path attribute missing",
                description=(
                    "The cookie does not define an explicit Path "
                    "attribute, so user-agent default-path processing "
                    "will determine where it is sent."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Set the narrowest explicit Path appropriate for the "
                    "cookie. Use Path=/ only when site-wide scope is "
                    "required."
                ),
                evidence_summary=(
                    "no explicit Path attribute was present."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-16"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("cookie-scope",),
            )
        ]

    raw_path, unambiguous = _single_attribute_value(
        cookie,
        "path",
    )

    if (
        not unambiguous
        or raw_path is None
        or not raw_path.startswith("/")
    ):
        return [
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.path.invalid",
                source_rule_id="010",
                title="Cookie Path attribute is invalid",
                description=(
                    "The cookie contains an empty, repeated, ambiguous, "
                    "or non-absolute Path attribute."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Set one explicit cookie Path beginning with '/'."
                ),
                evidence_summary=(
                    "the Path attribute was empty, repeated, ambiguous, "
                    "or did not begin with '/'."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-16"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("cookie-scope",),
            )
        ]

    _, request_path = _origin_and_path(target)

    if (
        raw_path == "/"
        and request_path != "/"
        and not cookie.name.lower().startswith("__host-")
    ):
        return [
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.path.broad",
                source_rule_id="009",
                title="Cookie Path attribute is broader than the response path",
                description=(
                    "The response set a site-wide cookie from a narrower "
                    "application path. This can expose the cookie to more "
                    "paths than necessary."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Use the narrowest Path that still supports the "
                    "cookie's intended application scope."
                ),
                evidence_summary=(
                    "Path=/ was set from a non-root response path."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-16"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("cookie-scope",),
            )
        ]

    return []


def _samesite_findings(
    target: ValidatedTarget,
    cookie: _ParsedCookie,
    *,
    secure_present: bool,
) -> list[NormalizedFinding]:
    """Evaluate SameSite presence, validity, and None/Secure coupling."""

    if not _attribute_present(cookie, "samesite"):
        return [
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.samesite.missing",
                source_rule_id="003",
                title="Cookie SameSite attribute missing",
                description=(
                    "The cookie does not explicitly define a SameSite "
                    "policy to limit cross-site attachment."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Set SameSite=Lax or SameSite=Strict where possible. "
                    "Use SameSite=None only when cross-site use is "
                    "required and also set Secure."
                ),
                evidence_summary=(
                    "no SameSite attribute was present."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-1275"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("cross-site",),
            )
        ]

    values = cookie.attributes["samesite"]
    normalised = tuple(
        value.lower()
        for value in values
        if value is not None
    )

    if (
        len(values) != 1
        or len(normalised) != 1
        or normalised[0] not in {"strict", "lax", "none"}
    ):
        return [
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.samesite.invalid",
                source_rule_id="005",
                title="Cookie SameSite attribute is invalid",
                description=(
                    "The cookie contains a missing-value, repeated, or "
                    "unsupported SameSite attribute."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Set exactly one SameSite value: Strict, Lax, or "
                    "None. Use None only together with Secure."
                ),
                evidence_summary=(
                    "the SameSite attribute was missing a value, "
                    "repeated, or unsupported."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-1275"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("cross-site",),
            )
        ]

    if normalised[0] == "none" and not secure_present:
        return [
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id=(
                    "web.cookies.samesite.none_without_secure"
                ),
                source_rule_id="004",
                title="SameSite=None cookie missing Secure",
                description=(
                    "The cookie requests cross-site delivery with "
                    "SameSite=None but does not include Secure."
                ),
                severity=Severity.MEDIUM,
                remediation=(
                    "Add Secure when SameSite=None is required, or use "
                    "Lax or Strict when cross-site delivery is not "
                    "required."
                ),
                evidence_summary=(
                    "SameSite=None was present without Secure."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-614"),
                    ExternalIdentifier("CWE", "CWE-1275"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("cross-site", "transport-security"),
            )
        ]

    return []


def _prefix_findings(
    target: ValidatedTarget,
    cookie: _ParsedCookie,
    *,
    secure_present: bool,
) -> list[NormalizedFinding]:
    """Evaluate case-insensitive __Secure- and __Host- requirements."""

    findings: list[NormalizedFinding] = []
    lowered_name = cookie.name.lower()

    if lowered_name.startswith("__secure-"):
        violations: list[str] = []

        if target.scheme != "https":
            violations.append("it was set from a non-HTTPS origin")

        if not secure_present:
            violations.append("the Secure attribute was missing")

        if violations:
            findings.append(
                _cookie_finding(
                    target=target,
                    cookie=cookie,
                    rule_id=(
                        "web.cookies.prefix_secure.invalid"
                    ),
                    source_rule_id="012",
                    title="__Secure- cookie prefix requirements violated",
                    description=(
                        "A __Secure- prefixed cookie must be set from a "
                        "secure origin and include the Secure attribute."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Set the cookie only over HTTPS and include the "
                        "Secure attribute, or remove the reserved prefix."
                    ),
                    evidence_summary="; ".join(violations) + ".",
                    identifiers=(
                        ExternalIdentifier("CWE", "CWE-16"),
                    ),
                    references=(
                        "https://datatracker.ietf.org/doc/"
                        "draft-ietf-httpbis-rfc6265bis/",
                    ),
                    tags=("cookie-prefix",),
                )
            )

    if lowered_name.startswith("__host-"):
        violations = []

        if target.scheme != "https":
            violations.append("it was set from a non-HTTPS origin")

        if not secure_present:
            violations.append("the Secure attribute was missing")

        if _attribute_present(cookie, "domain"):
            violations.append("a Domain attribute was present")

        path_value, path_unambiguous = _single_attribute_value(
            cookie,
            "path",
        )

        if not path_unambiguous or path_value != "/":
            violations.append("Path was not exactly '/'")

        if violations:
            findings.append(
                _cookie_finding(
                    target=target,
                    cookie=cookie,
                    rule_id="web.cookies.prefix_host.invalid",
                    source_rule_id="013",
                    title="__Host- cookie prefix requirements violated",
                    description=(
                        "A __Host- prefixed cookie must be set from a "
                        "secure origin, include Secure, omit Domain, and "
                        "set Path exactly to '/'."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Set the cookie over HTTPS with Secure and "
                        "Path=/, remove Domain, or remove the reserved "
                        "prefix."
                    ),
                    evidence_summary="; ".join(violations) + ".",
                    identifiers=(
                        ExternalIdentifier("CWE", "CWE-16"),
                    ),
                    references=(
                        "https://datatracker.ietf.org/doc/"
                        "draft-ietf-httpbis-rfc6265bis/",
                    ),
                    tags=("cookie-prefix",),
                )
            )

    return findings


def _cookie_findings(
    target: ValidatedTarget,
    cookie: _ParsedCookie,
) -> list[NormalizedFinding]:
    """Evaluate one parsed cookie."""

    findings: list[NormalizedFinding] = []
    secure_present = _attribute_present(cookie, "secure")
    httponly_present = _attribute_present(cookie, "httponly")

    if not secure_present:
        findings.append(
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.secure.missing",
                source_rule_id="001",
                title="Cookie missing Secure attribute",
                description=(
                    "The cookie is not marked Secure and could be sent "
                    "over an unencrypted connection if one becomes "
                    "available for its scope."
                ),
                severity=Severity.MEDIUM,
                remediation=(
                    "Set the Secure attribute and serve the application "
                    "exclusively over HTTPS."
                ),
                evidence_summary=(
                    "the Secure attribute was absent."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-614"),
                ),
                references=(
                    "https://owasp.org/www-community/controls/"
                    "SecureCookieAttribute",
                ),
                tags=("transport-security",),
            )
        )

    if not httponly_present:
        findings.append(
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.httponly.missing",
                source_rule_id="002",
                title="Cookie missing HttpOnly attribute",
                description=(
                    "The cookie is accessible to client-side scripts. "
                    "This can increase exposure if script execution is "
                    "compromised."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Set HttpOnly for cookies that do not require "
                    "client-side script access, especially session and "
                    "authentication cookies."
                ),
                evidence_summary=(
                    "the HttpOnly attribute was absent."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-1004"),
                ),
                references=(
                    "https://owasp.org/www-project-web-security-testing-"
                    "guide/",
                ),
                tags=("script-access",),
            )
        )

    if target.scheme == "http":
        findings.append(
            _cookie_finding(
                target=target,
                cookie=cookie,
                rule_id="web.cookies.transport.insecure",
                source_rule_id="011",
                title="Cookie set over an unencrypted HTTP response",
                description=(
                    "The cookie was observed in a response delivered over "
                    "HTTP, which does not provide transport encryption."
                ),
                severity=Severity.MEDIUM,
                remediation=(
                    "Serve the application over HTTPS, redirect HTTP "
                    "before setting cookies, and set Secure."
                ),
                evidence_summary=(
                    "the Set-Cookie header was received over HTTP."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-319"),
                ),
                references=(
                    "https://owasp.org/www-community/controls/"
                    "SecureCookieAttribute",
                ),
                tags=("transport-security",),
            )
        )

    findings.extend(
        _samesite_findings(
            target,
            cookie,
            secure_present=secure_present,
        )
    )
    findings.extend(_domain_findings(target, cookie))
    findings.extend(_path_findings(target, cookie))
    findings.extend(
        _prefix_findings(
            target,
            cookie,
            secure_present=secure_present,
        )
    )

    return findings


def analyze_cookies(
    target: ValidatedTarget,
    response: SafeHttpResponse,
) -> tuple[NormalizedFinding, ...]:
    """Analyze Set-Cookie headers without retaining cookie values."""

    _origin_and_path(target)
    findings_by_fingerprint: dict[str, NormalizedFinding] = {}

    for index, raw_header in enumerate(
        _cookie_headers(response.headers),
        start=1,
    ):
        cookie = _parse_cookie(raw_header)

        if cookie is None:
            finding = _finding(
                target=target,
                cookie_parameter=f"set-cookie:{index}",
                rule_id="web.cookies.syntax.malformed",
                source_rule_id="014",
                title="Set-Cookie header could not be safely parsed",
                description=(
                    "A Set-Cookie header did not contain a valid bounded "
                    "cookie name and could not be assessed reliably."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Emit one syntactically valid Set-Cookie header per "
                    "cookie using a valid cookie name and explicit "
                    "security attributes."
                ),
                evidence_summary=(
                    f"Set-Cookie header {index} was malformed. "
                    "Its cookie value was not retained."
                ),
                identifiers=(
                    ExternalIdentifier("CWE", "CWE-20"),
                ),
                references=(
                    "https://datatracker.ietf.org/doc/"
                    "draft-ietf-httpbis-rfc6265bis/",
                ),
                tags=("syntax",),
            )
            findings_by_fingerprint[finding.fingerprint] = finding
            continue

        for finding in _cookie_findings(target, cookie):
            findings_by_fingerprint[finding.fingerprint] = finding

    return tuple(
        sorted(
            findings_by_fingerprint.values(),
            key=lambda item: (
                item.identity.parameter or "",
                item.identity.rule_id,
            ),
        )
    )
