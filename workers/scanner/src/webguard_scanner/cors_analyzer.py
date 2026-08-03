"""Passive CORS response-header analysis for OpenHuntX WebGuard."""

from __future__ import annotations

import ipaddress
from typing import Iterable, Tuple
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
_SOURCE_RULE_PREFIX = "HTTP-CORS"

CORS_CHECKS = (
    "web.cors.credentials",
    "web.cors.dynamic_origin",
    "web.cors.null_origin",
    "web.cors.origin_syntax",
    "web.cors.wildcard_origin",
)


class CorsAnalysisError(RuntimeError):
    """Controlled failure raised for inconsistent CORS analysis inputs."""

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
        raise CorsAnalysisError(
            "validated_target_mismatch",
            "Validated target fields do not match normalised_url.",
        )

    parsed_port = parsed.port
    default_port = 443 if target.scheme == "https" else 80
    port = parsed_port or default_port

    if port != target.port:
        raise CorsAnalysisError(
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
    """Return values for one response header, preserving field order."""

    expected = name.lower()

    return tuple(
        value.strip()
        for header_name, value in headers
        if header_name.strip().lower() == expected
    )


def _vary_contains_origin(
    headers: Iterable[tuple[str, str]],
) -> bool:
    """Return whether Vary contains the Origin field name."""

    return any(
        token.strip().lower() == "origin"
        for value in _header_values(headers, "vary")
        for token in value.split(",")
    )


def _canonical_serialized_origin(
    value: str,
) -> str | None:
    """Return a canonical HTTP(S) origin, or None for invalid syntax."""

    if not value or any(character.isspace() for character in value):
        return None

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None

    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None

    hostname = parsed.hostname

    try:
        address = ipaddress.ip_address(hostname)
        formatted_hostname = (
            f"[{address.compressed}]"
            if isinstance(address, ipaddress.IPv6Address)
            else address.compressed
        )
    except ValueError:
        formatted_hostname = hostname.lower()

    default_port = 443 if parsed.scheme == "https" else 80

    return (
        f"{parsed.scheme.lower()}://{formatted_hostname}"
        if port in {None, default_port}
        else f"{parsed.scheme.lower()}://{formatted_hostname}:{port}"
    )


def _finding(
    *,
    target: ValidatedTarget,
    parameter: str,
    rule_id: str,
    source_rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    confidence: Confidence,
    remediation: str,
    evidence_summary: str,
    identifiers: tuple[ExternalIdentifier, ...] = (),
    references: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
) -> NormalizedFinding:
    """Create one normalized CORS finding."""

    origin, path = _origin_and_path(target)

    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule_id,
            asset=origin,
            path=path,
            method="GET",
            parameter=parameter,
        ),
        source=_SOURCE,
        source_rule_id=f"{_SOURCE_RULE_PREFIX}-{source_rule_id}",
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        remediation=remediation,
        identifiers=identifiers,
        evidence=(Evidence(evidence_summary),),
        references=references,
        tags=("cors", "http-headers", "passive") + tags,
    )


def _invalid_origin_finding(
    target: ValidatedTarget,
    *,
    reason: str,
) -> NormalizedFinding:
    return _finding(
        target=target,
        parameter="header:access-control-allow-origin",
        rule_id="web.cors.allow_origin.invalid",
        source_rule_id="001",
        title="Access-Control-Allow-Origin configuration is invalid",
        description=(
            "The response contains an Access-Control-Allow-Origin value "
            "that cannot be interpreted as one wildcard, null origin, or "
            "serialized HTTP(S) origin. Browsers may reject the CORS policy."
        ),
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        remediation=(
            "Return exactly one Access-Control-Allow-Origin value. Use '*', "
            "'null' only when explicitly required, or one serialized and "
            "allowlisted HTTP(S) origin."
        ),
        evidence_summary=reason,
        identifiers=(ExternalIdentifier("CWE", "CWE-16"),),
        references=("https://fetch.spec.whatwg.org/#http-new-header-syntax",),
        tags=("misconfiguration",),
    )


def analyze_cors(
    target: ValidatedTarget,
    response: SafeHttpResponse,
) -> tuple[NormalizedFinding, ...]:
    """Inspect CORS response headers without sending cross-origin probes.

    A specific origin combined with ``Vary: Origin`` is reported only as a
    medium-confidence dynamic-origin signal. Passive inspection cannot prove
    arbitrary origin reflection; active confirmation is intentionally out of
    scope for this analyser.
    """

    target_origin, _ = _origin_and_path(target)
    findings: list[NormalizedFinding] = []

    allow_origin_values = _header_values(
        response.headers,
        "access-control-allow-origin",
    )
    credentials_values = _header_values(
        response.headers,
        "access-control-allow-credentials",
    )

    credentials_enabled = (
        len(credentials_values) == 1
        and credentials_values[0] == "true"
    )

    if credentials_values and not credentials_enabled:
        reason = (
            "Multiple Access-Control-Allow-Credentials fields were observed."
            if len(credentials_values) > 1
            else (
                "Access-Control-Allow-Credentials is present but is not the "
                "case-sensitive value 'true'."
            )
        )
        findings.append(
            _finding(
                target=target,
                parameter="header:access-control-allow-credentials",
                rule_id="web.cors.credentials.invalid",
                source_rule_id="002",
                title="Access-Control-Allow-Credentials value is invalid",
                description=(
                    "The response contains an invalid credentialed-CORS "
                    "declaration. Browsers require the case-sensitive value "
                    "'true'; any other value should be omitted."
                ),
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                remediation=(
                    "Return exactly 'Access-Control-Allow-Credentials: true' "
                    "only for endpoints that intentionally support credentialed "
                    "cross-origin requests. Otherwise omit the header."
                ),
                evidence_summary=reason,
                identifiers=(ExternalIdentifier("CWE", "CWE-16"),),
                references=(
                    "https://fetch.spec.whatwg.org/#http-new-header-syntax",
                ),
                tags=("credentials", "misconfiguration"),
            )
        )

    if not allow_origin_values:
        if credentials_values:
            findings.append(
                _finding(
                    target=target,
                    parameter="header:access-control-allow-credentials",
                    rule_id="web.cors.credentials.without_origin",
                    source_rule_id="003",
                    title="CORS credentials header has no allowed origin",
                    description=(
                        "Access-Control-Allow-Credentials is present without "
                        "Access-Control-Allow-Origin. The credential setting is "
                        "inert and indicates an incomplete CORS policy."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        "Remove Access-Control-Allow-Credentials when CORS is "
                        "not enabled, or return a narrowly allowlisted origin "
                        "with the complete intended CORS policy."
                    ),
                    evidence_summary=(
                        "Access-Control-Allow-Credentials was observed but no "
                        "Access-Control-Allow-Origin field was present."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-16"),),
                    references=(
                        "https://fetch.spec.whatwg.org/#cors-protocol-and-credentials",
                    ),
                    tags=("credentials", "misconfiguration"),
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

    if len(allow_origin_values) != 1:
        findings.append(
            _invalid_origin_finding(
                target,
                reason=(
                    "More than one Access-Control-Allow-Origin response field "
                    "was observed."
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

    allow_origin = allow_origin_values[0]

    if "," in allow_origin:
        findings.append(
            _invalid_origin_finding(
                target,
                reason=(
                    "The Access-Control-Allow-Origin field contains a "
                    "comma-separated value, which is not valid CORS syntax."
                ),
            )
        )
    elif allow_origin == "*":
        if credentials_enabled:
            findings.append(
                _finding(
                    target=target,
                    parameter="header:access-control-allow-origin",
                    rule_id="web.cors.credentials.wildcard_origin",
                    source_rule_id="004",
                    title="Credentialed CORS is combined with a wildcard origin",
                    description=(
                        "The response combines Access-Control-Allow-Origin '*' "
                        "with credentialed CORS. Browsers do not permit the "
                        "wildcard origin for credentialed requests."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        "Replace the wildcard with an explicit allowlist of "
                        "trusted origins and emit only the validated request "
                        "origin. Include 'Vary: Origin' for dynamic selection."
                    ),
                    evidence_summary=(
                        "Wildcard Access-Control-Allow-Origin and "
                        "Access-Control-Allow-Credentials: true were both "
                        "observed."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-942"),),
                    references=(
                        "https://fetch.spec.whatwg.org/#cors-protocol-and-credentials",
                    ),
                    tags=("credentials", "wildcard"),
                )
            )
        else:
            findings.append(
                _finding(
                    target=target,
                    parameter="header:access-control-allow-origin",
                    rule_id="web.cors.allow_origin.wildcard",
                    source_rule_id="005",
                    title="CORS permits requests from any origin",
                    description=(
                        "The response uses a wildcard CORS origin. This permits "
                        "any website to read non-credentialed responses that "
                        "the browser makes available through CORS."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        "Confirm that the response is intentionally public. "
                        "For non-public data, replace '*' with a strict origin "
                        "allowlist."
                    ),
                    evidence_summary=(
                        "Access-Control-Allow-Origin is configured as '*'."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-942"),),
                    references=(
                        "https://fetch.spec.whatwg.org/#http-new-header-syntax",
                    ),
                    tags=("wildcard",),
                )
            )
    elif allow_origin == "null":
        rule_id = (
            "web.cors.credentials.null_origin"
            if credentials_enabled
            else "web.cors.allow_origin.null"
        )
        findings.append(
            _finding(
                target=target,
                parameter="header:access-control-allow-origin",
                rule_id=rule_id,
                source_rule_id="006",
                title=(
                    "Credentialed CORS permits the null origin"
                    if credentials_enabled
                    else "CORS permits the null origin"
                ),
                description=(
                    "The literal null origin can be used by sandboxed, local, "
                    "and other opaque-origin contexts. Trusting it may expose "
                    "a response to contexts that are difficult to identify or "
                    "allowlist safely."
                ),
                severity=(
                    Severity.MEDIUM
                    if credentials_enabled
                    else Severity.LOW
                ),
                confidence=Confidence.CONFIRMED,
                remediation=(
                    "Do not allow the literal null origin unless a documented "
                    "application requirement makes it unavoidable. Prefer an "
                    "explicit allowlist of trusted HTTP(S) origins."
                ),
                evidence_summary=(
                    "Access-Control-Allow-Origin is configured as 'null'"
                    + (
                        " with credentialed CORS enabled."
                        if credentials_enabled
                        else "."
                    )
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-942"),),
                references=(
                    "https://fetch.spec.whatwg.org/#http-new-header-syntax",
                ),
                tags=("null-origin",) + (
                    ("credentials",)
                    if credentials_enabled
                    else ()
                ),
            )
        )
    else:
        canonical_origin = _canonical_serialized_origin(allow_origin)

        if canonical_origin is None:
            findings.append(
                _invalid_origin_finding(
                    target,
                    reason=(
                        "Access-Control-Allow-Origin is neither '*', 'null', "
                        "nor a serialized HTTP(S) origin."
                    ),
                )
            )
        elif (
            canonical_origin != target_origin
            and _vary_contains_origin(response.headers)
        ):
            findings.append(
                _finding(
                    target=target,
                    parameter="header:access-control-allow-origin",
                    rule_id="web.cors.dynamic_origin.observed",
                    source_rule_id="007",
                    title="Dynamic CORS origin handling was observed",
                    description=(
                        "A specific non-target origin was returned together "
                        "with 'Vary: Origin'. This is consistent with dynamic "
                        "origin selection or reflection, but passive inspection "
                        "cannot determine whether arbitrary origins are trusted."
                    ),
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.MEDIUM,
                    remediation=(
                        "Confirm that the server compares the Origin request "
                        "header against an exact trusted allowlist and never "
                        "reflects arbitrary or suffix-matched origins."
                    ),
                    evidence_summary=(
                        "A specific non-target CORS origin and 'Vary: Origin' "
                        "were observed. The origin value was not retained."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-942"),),
                    references=(
                        "https://fetch.spec.whatwg.org/#cors-protocol-and-credentials",
                    ),
                    tags=("dynamic-origin", "requires-confirmation"),
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
