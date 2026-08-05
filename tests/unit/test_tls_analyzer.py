"""Unit tests for passive TLS and certificate analysis."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from webguard_contracts import Severity
from webguard_scanner import (
    SafeHttpResponse,
    TlsAnalysisError,
    TlsConnectionInfo,
    ValidatedTarget,
    analyze_tls_security,
)


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


def target(
    *,
    scheme: str = "https",
    url: str = "https://example.com/account",
    hostname: str = "example.com",
    port: int = 443,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_addresses=("93.184.216.34",),
    )


def tls_info(
    *,
    protocol: str = "TLSv1.3",
    cipher_name: str = "TLS_AES_256_GCM_SHA384",
    cipher_bits: int = 256,
    not_before: datetime = NOW - timedelta(days=30),
    not_after: datetime = NOW + timedelta(days=120),
    certificate_verified: bool = True,
    hostname_validated: bool = True,
    verified_chain_length: int | None = 3,
    server_hostname: str = "example.com",
) -> TlsConnectionInfo:
    return TlsConnectionInfo(
        protocol=protocol,
        cipher_name=cipher_name,
        cipher_bits=cipher_bits,
        server_hostname=server_hostname,
        certificate_not_before=not_before,
        certificate_not_after=not_after,
        certificate_sha256="a" * 64,
        subject_alt_names=("DNS:example.com",),
        certificate_verified=certificate_verified,
        hostname_validated=hostname_validated,
        verified_chain_length=verified_chain_length,
    )


def response(
    info: TlsConnectionInfo | None = None,
) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(("Content-Type", "text/html"),),
        body=b"<html></html>",
        connected_address="93.184.216.34",
        elapsed_milliseconds=10,
        tls=info,
    )


class TlsAnalyzerTests(unittest.TestCase):
    def analyse(
        self,
        info: TlsConnectionInfo | None = None,
    ):
        with patch(
            "webguard_scanner.tls_analyzer._utc_now",
            return_value=NOW,
        ):
            return analyze_tls_security(
                target(),
                response(info or tls_info()),
            )

    def test_http_target_is_not_analysed(self) -> None:
        http_target = target(
            scheme="http",
            url="http://example.com/account",
            port=80,
        )
        self.assertEqual(
            analyze_tls_security(http_target, response()),
            (),
        )

    def test_https_requires_tls_metadata(self) -> None:
        with self.assertRaises(TlsAnalysisError) as context:
            analyze_tls_security(target(), response())
        self.assertEqual(
            context.exception.code,
            "tls_metadata_missing",
        )

    def test_rejects_mismatched_server_hostname(self) -> None:
        with self.assertRaises(TlsAnalysisError) as context:
            self.analyse(
                tls_info(server_hostname="other.example")
            )
        self.assertEqual(
            context.exception.code,
            "tls_metadata_inconsistent",
        )

    def test_rejects_naive_certificate_timestamp(self) -> None:
        with self.assertRaises(TlsAnalysisError) as context:
            self.analyse(
                tls_info(
                    not_before=datetime(2026, 1, 1),
                    not_after=datetime(2026, 12, 1),
                )
            )
        self.assertEqual(
            context.exception.code,
            "tls_certificate_time_invalid",
        )

    def test_rejects_invalid_cipher_metadata(self) -> None:
        invalid = replace(tls_info(), cipher_bits=-1)
        with self.assertRaises(TlsAnalysisError) as context:
            self.analyse(invalid)
        self.assertEqual(
            context.exception.code,
            "tls_metadata_inconsistent",
        )

    def test_rejects_inverted_certificate_interval(self) -> None:
        with self.assertRaises(TlsAnalysisError) as context:
            self.analyse(
                tls_info(
                    not_before=NOW + timedelta(days=2),
                    not_after=NOW + timedelta(days=1),
                )
            )
        self.assertEqual(
            context.exception.code,
            "tls_certificate_time_invalid",
        )

    def test_modern_verified_connection_has_no_findings(self) -> None:
        self.assertEqual(self.analyse(), ())

    def test_certificate_expiring_within_thirty_days_is_medium(self) -> None:
        findings = self.analyse(
            tls_info(not_after=NOW + timedelta(days=20))
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.tls.certificate.expiry.imminent",
        )
        self.assertIs(findings[0].severity, Severity.MEDIUM)

    def test_certificate_expiring_within_seven_days_is_high(self) -> None:
        findings = self.analyse(
            tls_info(not_after=NOW + timedelta(days=6))
        )
        self.assertEqual(len(findings), 1)
        self.assertIs(findings[0].severity, Severity.HIGH)

    def test_expired_certificate_is_critical(self) -> None:
        findings = self.analyse(
            tls_info(
                not_before=NOW - timedelta(days=100),
                not_after=NOW - timedelta(seconds=1),
            )
        )
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.tls.certificate.validity.expired",
        )
        self.assertIs(findings[0].severity, Severity.CRITICAL)

    def test_not_yet_valid_certificate_is_high(self) -> None:
        findings = self.analyse(
            tls_info(
                not_before=NOW + timedelta(days=1),
                not_after=NOW + timedelta(days=100),
            )
        )
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.tls.certificate.validity.not_yet_valid",
        )
        self.assertIs(findings[0].severity, Severity.HIGH)

    def test_pre_2026_lifetime_above_398_days_is_reported(self) -> None:
        findings = self.analyse(
            tls_info(
                not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
                not_after=datetime(2026, 3, 1, tzinfo=timezone.utc),
            )
        )
        self.assertIn(
            "web.tls.certificate.lifetime.excessive",
            {item.identity.rule_id for item in findings},
        )

    def test_2026_lifetime_above_200_days_is_reported(self) -> None:
        findings = self.analyse(
            tls_info(
                not_before=datetime(2026, 3, 15, tzinfo=timezone.utc),
                not_after=datetime(2026, 10, 2, tzinfo=timezone.utc),
            )
        )
        self.assertIn(
            "web.tls.certificate.lifetime.excessive",
            {item.identity.rule_id for item in findings},
        )

    def test_2027_lifetime_above_100_days_is_reported(self) -> None:
        future_now = datetime(2027, 4, 1, tzinfo=timezone.utc)
        info = tls_info(
            not_before=datetime(2027, 3, 15, tzinfo=timezone.utc),
            not_after=datetime(2027, 6, 24, tzinfo=timezone.utc),
        )
        with patch(
            "webguard_scanner.tls_analyzer._utc_now",
            return_value=future_now,
        ):
            findings = analyze_tls_security(target(), response(info))
        self.assertIn(
            "web.tls.certificate.lifetime.excessive",
            {item.identity.rule_id for item in findings},
        )

    def test_2029_lifetime_above_47_days_is_reported(self) -> None:
        future_now = datetime(2029, 4, 1, tzinfo=timezone.utc)
        info = tls_info(
            not_before=datetime(2029, 3, 15, tzinfo=timezone.utc),
            not_after=datetime(2029, 5, 2, tzinfo=timezone.utc),
        )
        with patch(
            "webguard_scanner.tls_analyzer._utc_now",
            return_value=future_now,
        ):
            findings = analyze_tls_security(target(), response(info))
        self.assertIn(
            "web.tls.certificate.lifetime.excessive",
            {item.identity.rule_id for item in findings},
        )

    def test_exact_scheduled_validity_limits_are_accepted(self) -> None:
        cases = (
            (
                datetime(2025, 1, 1, tzinfo=timezone.utc),
                398,
                datetime(2025, 2, 1, tzinfo=timezone.utc),
            ),
            (
                datetime(2026, 3, 15, tzinfo=timezone.utc),
                200,
                datetime(2026, 4, 1, tzinfo=timezone.utc),
            ),
            (
                datetime(2027, 3, 15, tzinfo=timezone.utc),
                100,
                datetime(2027, 4, 1, tzinfo=timezone.utc),
            ),
            (
                datetime(2029, 3, 15, tzinfo=timezone.utc),
                47,
                datetime(2029, 4, 1, tzinfo=timezone.utc),
            ),
        )
        for issued, days, scan_time in cases:
            with self.subTest(issued=issued, days=days):
                info = tls_info(
                    not_before=issued,
                    not_after=issued + timedelta(days=days),
                )
                with patch(
                    "webguard_scanner.tls_analyzer._utc_now",
                    return_value=scan_time,
                ):
                    findings = analyze_tls_security(
                        target(),
                        response(info),
                    )
                self.assertNotIn(
                    "web.tls.certificate.lifetime.excessive",
                    {item.identity.rule_id for item in findings},
                )

    def test_deprecated_protocol_is_reported(self) -> None:
        for protocol in ("SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
            with self.subTest(protocol=protocol):
                findings = self.analyse(
                    tls_info(protocol=protocol)
                )
                self.assertIn(
                    "web.tls.protocol.deprecated",
                    {item.identity.rule_id for item in findings},
                )

    def test_unrecognised_protocol_is_reported(self) -> None:
        findings = self.analyse(
            tls_info(protocol="TLSv9.9")
        )
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.tls.protocol.unrecognised",
        )

    def test_weak_cipher_marker_is_reported(self) -> None:
        findings = self.analyse(
            tls_info(
                protocol="TLSv1.2",
                cipher_name="ECDHE-RSA-DES-CBC3-SHA",
                cipher_bits=168,
            )
        )
        self.assertIn(
            "web.tls.cipher.weak",
            {item.identity.rule_id for item in findings},
        )

    def test_low_cipher_bits_are_reported(self) -> None:
        findings = self.analyse(
            tls_info(
                protocol="TLSv1.2",
                cipher_name="TEST-CIPHER",
                cipher_bits=64,
            )
        )
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.tls.cipher.weak",
        )

    def test_unverified_chain_is_critical(self) -> None:
        findings = self.analyse(
            tls_info(certificate_verified=False)
        )
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.tls.chain.unverified",
        )
        self.assertIs(findings[0].severity, Severity.CRITICAL)

    def test_empty_verified_chain_is_reported(self) -> None:
        findings = self.analyse(
            tls_info(verified_chain_length=0)
        )
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.tls.chain.empty",
        )

    def test_unavailable_chain_length_is_not_false_positive(self) -> None:
        self.assertEqual(
            self.analyse(
                tls_info(verified_chain_length=None)
            ),
            (),
        )

    def test_disabled_hostname_validation_is_critical(self) -> None:
        findings = self.analyse(
            tls_info(hostname_validated=False)
        )
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.tls.certificate.hostname.unverified",
        )
        self.assertIs(findings[0].severity, Severity.CRITICAL)

    def test_findings_have_page_ownership_and_no_certificate_body(self) -> None:
        findings = self.analyse(
            tls_info(protocol="TLSv1.1")
        )
        finding = findings[0]
        self.assertEqual(
            finding.identity.asset,
            "https://example.com",
        )
        self.assertEqual(finding.identity.path, "/account")
        self.assertEqual(finding.identity.method, "GET")
        self.assertNotIn("a" * 64, repr(finding))

    def test_multiple_findings_are_sorted_by_rule_id(self) -> None:
        info = replace(
            tls_info(),
            protocol="TLSv1.1",
            cipher_name="RC4-MD5",
            cipher_bits=40,
            hostname_validated=False,
        )
        findings = self.analyse(info)
        rule_ids = tuple(item.identity.rule_id for item in findings)
        self.assertEqual(rule_ids, tuple(sorted(rule_ids)))


if __name__ == "__main__":
    unittest.main()
