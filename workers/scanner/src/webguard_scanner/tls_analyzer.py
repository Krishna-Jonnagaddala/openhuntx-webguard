"""Passive TLS connection and certificate analysis for WebGuard."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from webguard_contracts import (
    Confidence,
    Evidence,
    ExternalIdentifier,
    FindingIdentity,
    NormalizedFinding,
    Severity,
)

from .safe_http import SafeHttpResponse, TlsConnectionInfo
from .scope_validator import ValidatedTarget


_SOURCE = "webguard-passive"
_SOURCE_RULE_PREFIX = "TLS"

CERTIFICATE_EXPIRY_WARNING_DAYS = 30
CERTIFICATE_EXPIRY_CRITICAL_DAYS = 7
MINIMUM_ACCEPTABLE_CIPHER_BITS = 128

TLS_CHECKS = (
    "web.tls.certificate.expiry",
    "web.tls.certificate.hostname",
    "web.tls.certificate.lifetime",
    "web.tls.certificate.validity",
    "web.tls.chain",
    "web.tls.cipher",
    "web.tls.protocol",
)

_DEPRECATED_PROTOCOLS = frozenset(
    {
        "SSLV2",
        "SSLV3",
        "TLSV1",
        "TLSV1.0",
        "TLSV1.1",
    }
)
_SUPPORTED_PROTOCOLS = frozenset({"TLSV1.2", "TLSV1.3"})
_WEAK_CIPHER_MARKERS = (
    "3DES",
    "DES-CBC",
    "DES40",
    "EXPORT",
    "IDEA",
    "NULL",
    "RC2",
    "RC4",
    "SEED",
)

# Current and scheduled CA/Browser Forum public TLS maximum validity periods.
_VALIDITY_LIMITS = (
    (datetime(2029, 3, 15, tzinfo=timezone.utc), 47),
    (datetime(2027, 3, 15, tzinfo=timezone.utc), 100),
    (datetime(2026, 3, 15, tzinfo=timezone.utc), 200),
)
_PRE_2026_VALIDITY_LIMIT_DAYS = 398


class TlsAnalysisError(RuntimeError):
    """Controlled failure raised for inconsistent TLS analysis input."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _origin_and_path(
    target: ValidatedTarget,
) -> tuple[str, str]:
    parsed = urlsplit(target.normalised_url)
    parsed_port = parsed.port
    default_port = 443 if target.scheme == "https" else 80
    port = parsed_port or default_port

    if (
        parsed.scheme != target.scheme
        or parsed.hostname != target.hostname
        or port != target.port
    ):
        raise TlsAnalysisError(
            "validated_target_mismatch",
            "Validated target fields do not match normalised_url.",
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
        evidence=(Evidence(evidence_summary),),
        identifiers=identifiers,
        references=references,
        tags=("tls", "passive") + tags,
    )


def _maximum_validity_days(not_before: datetime) -> int:
    for effective_at, maximum_days in _VALIDITY_LIMITS:
        if not_before >= effective_at:
            return maximum_days
    return _PRE_2026_VALIDITY_LIMIT_DAYS


def _validated_tls_info(
    target: ValidatedTarget,
    response: SafeHttpResponse,
) -> TlsConnectionInfo:
    _origin_and_path(target)

    if target.scheme != "https":
        raise TlsAnalysisError(
            "tls_target_not_https",
            "TLS analysis applies only to HTTPS targets.",
        )

    tls = response.tls
    if not isinstance(tls, TlsConnectionInfo):
        raise TlsAnalysisError(
            "tls_metadata_missing",
            "The HTTPS response does not contain validated TLS metadata.",
        )

    if tls.server_hostname != target.hostname:
        raise TlsAnalysisError(
            "tls_metadata_inconsistent",
            "TLS server_hostname does not match the validated target.",
        )

    for timestamp in (
        tls.certificate_not_before,
        tls.certificate_not_after,
    ):
        if (
            not isinstance(timestamp, datetime)
            or timestamp.tzinfo is None
            or timestamp.utcoffset() is None
        ):
            raise TlsAnalysisError(
                "tls_certificate_time_invalid",
                "TLS certificate timestamps must be timezone-aware.",
            )

    if (
        not isinstance(tls.protocol, str)
        or not tls.protocol.strip()
        or not isinstance(tls.cipher_name, str)
        or not tls.cipher_name.strip()
        or isinstance(tls.cipher_bits, bool)
        or not isinstance(tls.cipher_bits, int)
        or tls.cipher_bits < 0
        or not isinstance(tls.certificate_verified, bool)
        or not isinstance(tls.hostname_validated, bool)
        or (
            tls.verified_chain_length is not None
            and (
                isinstance(tls.verified_chain_length, bool)
                or not isinstance(tls.verified_chain_length, int)
                or tls.verified_chain_length < 0
            )
        )
    ):
        raise TlsAnalysisError(
            "tls_metadata_inconsistent",
            "TLS connection metadata contains an invalid field.",
        )

    if tls.certificate_not_after <= tls.certificate_not_before:
        raise TlsAnalysisError(
            "tls_certificate_time_invalid",
            "The certificate validity interval is inconsistent.",
        )

    return tls


def analyze_tls_security(
    target: ValidatedTarget,
    response: SafeHttpResponse,
) -> tuple[NormalizedFinding, ...]:
    """Analyse TLS metadata captured by the existing safe HTTPS request."""

    _origin_and_path(target)

    if target.scheme != "https":
        return ()

    tls = _validated_tls_info(target, response)
    now = _utc_now()
    findings: list[NormalizedFinding] = []

    if not tls.certificate_verified:
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.chain.unverified",
                source_rule_id="001",
                title="TLS certificate chain was not verified",
                description=(
                    "The connection metadata indicates that the peer "
                    "certificate chain was not verified against the configured "
                    "trust store."
                ),
                severity=Severity.CRITICAL,
                remediation=(
                    "Deploy a certificate chain that validates to a trusted root "
                    "and retain certificate verification in all clients."
                ),
                evidence_summary=(
                    "The bounded TLS connection reported an unverified "
                    "certificate chain. Certificate bodies were not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-295"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                tags=("certificate-chain",),
            )
        )
    elif tls.verified_chain_length == 0:
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.chain.empty",
                source_rule_id="002",
                title="Verified TLS certificate chain is empty",
                description=(
                    "The connection reports certificate verification but no "
                    "certificate in the verified chain projection."
                ),
                severity=Severity.HIGH,
                remediation=(
                    "Review the server certificate chain and ensure the leaf and "
                    "required intermediate certificates are presented correctly."
                ),
                evidence_summary=(
                    "The verified certificate-chain length was reported as zero."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-295"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                tags=("certificate-chain",),
            )
        )

    if not tls.hostname_validated:
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.certificate.hostname.unverified",
                source_rule_id="003",
                title="TLS certificate hostname was not validated",
                description=(
                    "The HTTPS connection metadata indicates that certificate "
                    "hostname validation was not enforced."
                ),
                severity=Severity.CRITICAL,
                remediation=(
                    "Require certificate verification and hostname checking for "
                    "the exact authorised target hostname."
                ),
                evidence_summary=(
                    "Hostname validation was reported as disabled for the TLS "
                    "connection."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-295"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                tags=("hostname-validation",),
            )
        )

    if now < tls.certificate_not_before:
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.certificate.validity.not_yet_valid",
                source_rule_id="004",
                title="TLS certificate is not yet valid",
                description=(
                    "The certificate validity period begins after the scan time."
                ),
                severity=Severity.HIGH,
                remediation=(
                    "Deploy a currently valid certificate and verify server and "
                    "certificate-authority clock synchronisation."
                ),
                evidence_summary=(
                    "The certificate not-before time is "
                    f"{tls.certificate_not_before.isoformat()}."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-295"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                tags=("certificate-validity",),
            )
        )
    elif now >= tls.certificate_not_after:
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.certificate.validity.expired",
                source_rule_id="005",
                title="TLS certificate has expired",
                description=(
                    "The certificate validity period ended before the scan time."
                ),
                severity=Severity.CRITICAL,
                remediation=(
                    "Replace the expired certificate immediately and automate "
                    "renewal with monitoring before future expiry."
                ),
                evidence_summary=(
                    "The certificate not-after time is "
                    f"{tls.certificate_not_after.isoformat()}."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-295"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                tags=("certificate-validity", "expired"),
            )
        )
    else:
        remaining_seconds = (
            tls.certificate_not_after - now
        ).total_seconds()
        remaining_days = remaining_seconds / 86_400
        if remaining_days <= CERTIFICATE_EXPIRY_WARNING_DAYS:
            severity = (
                Severity.HIGH
                if remaining_days <= CERTIFICATE_EXPIRY_CRITICAL_DAYS
                else Severity.MEDIUM
            )
            findings.append(
                _finding(
                    target=target,
                    rule_id="web.tls.certificate.expiry.imminent",
                    source_rule_id="006",
                    title="TLS certificate expires soon",
                    description=(
                        "The currently valid certificate is close to the end of "
                        "its validity period."
                    ),
                    severity=severity,
                    remediation=(
                        "Renew and deploy the certificate before expiry, then "
                        "confirm the complete chain and hostname coverage."
                    ),
                    evidence_summary=(
                        "The certificate expires in approximately "
                        f"{remaining_days:.1f} days at "
                        f"{tls.certificate_not_after.isoformat()}."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-295"),),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                    ),
                    tags=("certificate-expiry",),
                )
            )

    lifetime_seconds = (
        tls.certificate_not_after - tls.certificate_not_before
    ).total_seconds()
    lifetime_days = lifetime_seconds / 86_400
    maximum_days = _maximum_validity_days(
        tls.certificate_not_before
    )
    if lifetime_days > maximum_days:
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.certificate.lifetime.excessive",
                source_rule_id="007",
                title="TLS certificate validity period is unusually long",
                description=(
                    "The certificate lifetime exceeds the public TLS validity "
                    "limit applicable to its issuance date."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Use shorter-lived certificates and automated renewal. For "
                    "publicly trusted certificates, follow the current CA/Browser "
                    "Forum validity schedule."
                ),
                evidence_summary=(
                    "The certificate lifetime is approximately "
                    f"{lifetime_days:.1f} days; the applicable public TLS limit "
                    f"is {maximum_days} days."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-324"),),
                references=(
                    "https://cabforum.org/working-groups/server/baseline-requirements/requirements/",
                ),
                tags=("certificate-lifetime",),
            )
        )

    protocol = tls.protocol.upper()
    if protocol in _DEPRECATED_PROTOCOLS:
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.protocol.deprecated",
                source_rule_id="008",
                title="Deprecated TLS protocol negotiated",
                description=(
                    "The HTTPS connection negotiated a deprecated SSL/TLS "
                    "protocol version."
                ),
                severity=Severity.HIGH,
                remediation=(
                    "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Require TLS "
                    "1.2 or TLS 1.3 with modern cipher suites."
                ),
                evidence_summary=(
                    f"The negotiated protocol was {tls.protocol}."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-327"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                tags=("protocol",),
            )
        )
    elif protocol not in _SUPPORTED_PROTOCOLS:
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.protocol.unrecognised",
                source_rule_id="009",
                title="Unrecognised TLS protocol metadata",
                description=(
                    "The negotiated protocol value is not one of the recognised "
                    "TLS 1.2 or TLS 1.3 values."
                ),
                severity=Severity.MEDIUM,
                remediation=(
                    "Review the TLS endpoint and scanner runtime, and require a "
                    "recognised TLS 1.2 or TLS 1.3 negotiation."
                ),
                evidence_summary=(
                    f"The negotiated protocol was reported as {tls.protocol}."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-327"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                tags=("protocol",),
            )
        )

    cipher_upper = tls.cipher_name.upper()
    weak_marker = next(
        (
            marker
            for marker in _WEAK_CIPHER_MARKERS
            if marker in cipher_upper
        ),
        None,
    )
    if (
        weak_marker is not None
        or tls.cipher_bits < MINIMUM_ACCEPTABLE_CIPHER_BITS
    ):
        details = (
            f"matched weak marker {weak_marker}"
            if weak_marker is not None
            else (
                f"reported {tls.cipher_bits} secret bits, below the "
                f"{MINIMUM_ACCEPTABLE_CIPHER_BITS}-bit minimum"
            )
        )
        findings.append(
            _finding(
                target=target,
                rule_id="web.tls.cipher.weak",
                source_rule_id="010",
                title="Weak TLS cipher negotiated",
                description=(
                    "The HTTPS connection negotiated a cipher with weak or "
                    "legacy characteristics."
                ),
                severity=Severity.HIGH,
                remediation=(
                    "Configure modern authenticated-encryption cipher suites and "
                    "remove legacy, export, null, RC4, DES, and 3DES suites."
                ),
                evidence_summary=(
                    f"Cipher {tls.cipher_name} was negotiated and {details}."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-326"),),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                tags=("cipher",),
            )
        )

    return tuple(
        sorted(
            findings,
            key=lambda finding: finding.identity.rule_id,
        )
    )
