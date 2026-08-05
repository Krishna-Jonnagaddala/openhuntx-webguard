"""Pipeline tests for TLS metadata capture and passive analysis."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from webguard_contracts import ScanStatus
from webguard_scanner import (
    PASSIVE_TLS_CHECKS,
    RetryPolicy,
    SafeHttpResponse,
    SafeRequestError,
    TlsConnectionInfo,
    ValidatedTarget,
    run_passive_header_scan,
)


START = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
END = START + timedelta(milliseconds=20)
SCAN_ID = "ac86c6bb-3d76-4ab7-8728-31118d93d030"


def target(*, https: bool = True) -> ValidatedTarget:
    if https:
        return ValidatedTarget(
            original_url="https://example.com/",
            normalised_url="https://example.com/",
            scheme="https",
            hostname="example.com",
            port=443,
            resolved_addresses=("93.184.216.34",),
        )
    return ValidatedTarget(
        original_url="http://127.0.0.1:3000/",
        normalised_url="http://127.0.0.1:3000/",
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=("127.0.0.1",),
    )


def tls_info(*, protocol: str = "TLSv1.3") -> TlsConnectionInfo:
    return TlsConnectionInfo(
        protocol=protocol,
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        server_hostname="example.com",
        certificate_not_before=START - timedelta(days=30),
        certificate_not_after=START + timedelta(days=120),
        certificate_sha256="b" * 64,
        subject_alt_names=("DNS:example.com",),
        certificate_verified=True,
        hostname_validated=True,
        verified_chain_length=3,
    )


def response(*, info: TlsConnectionInfo | None = None) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(
            ("Content-Type", "text/html"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("Content-Security-Policy", "frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ),
        body=b"<html></html>",
        connected_address="93.184.216.34",
        elapsed_milliseconds=10,
        tls=info,
    )


class TlsPipelineTests(unittest.TestCase):
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.tls_analyzer._utc_now",
        return_value=START,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_https_tls_checks_use_the_existing_response(
        self,
        fetch_mock,
        _tls_clock_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(info=tls_info())
        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )
        self.assertTrue(
            set(PASSIVE_TLS_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertEqual(result.coverage.skipped_checks, ())
        fetch_mock.assert_called_once()

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_http_target_skips_all_tls_checks(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = SafeHttpResponse(
            status=200,
            reason="OK",
            headers=(("Content-Type", "text/html"),),
            body=b"<html></html>",
            connected_address="127.0.0.1",
            elapsed_milliseconds=10,
        )
        result = run_passive_header_scan(
            target(https=False),
            scan_id=SCAN_ID,
            started_at=START,
        )
        skipped_ids = {
            item.check_id
            for item in result.coverage.skipped_checks
        }
        self.assertTrue(
            set(PASSIVE_TLS_CHECKS).issubset(skipped_ids)
        )
        self.assertFalse(
            set(PASSIVE_TLS_CHECKS).intersection(
                result.coverage.executed_checks
            )
        )

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.tls_analyzer._utc_now",
        return_value=START,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_tls_connection_metadata_is_not_serialised_in_report(
        self,
        fetch_mock,
        _tls_clock_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(info=tls_info())
        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )
        document = result.to_json()
        self.assertNotIn("certificate_sha256", document)
        self.assertNotIn("subject_alt_names", document)
        self.assertNotIn("TLS_AES_256_GCM_SHA384", document)
        self.assertNotIn("b" * 64, document)

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_invalid_certificate_remains_request_stage_failure(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = SafeRequestError(
            "tls_certificate_invalid",
            "Certificate verification failed.",
        )
        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(maximum_attempts=1),
            scan_id=SCAN_ID,
            started_at=START,
        )
        self.assertIs(result.status, ScanStatus.FAILED)
        self.assertEqual(result.errors[0].stage, "request")
        self.assertEqual(
            result.errors[0].code,
            "tls_certificate_invalid",
        )
        self.assertEqual(len(result.request_attempts), 1)

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_missing_https_tls_metadata_is_controlled_analysis_error(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(info=None)
        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )
        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(result.errors[0].stage, "analysis.tls")
        self.assertEqual(result.errors[0].code, "tls_metadata_missing")
        self.assertEqual(result.coverage.unaccounted_checks, ())

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.tls_analyzer._utc_now",
        return_value=START,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_deprecated_protocol_finding_is_reported(
        self,
        fetch_mock,
        _tls_clock_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            info=tls_info(protocol="TLSv1.1")
        )
        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )
        self.assertIn(
            "web.tls.protocol.deprecated",
            {item.identity.rule_id for item in result.findings},
        )

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_http_request_failure_preserves_https_only_skips(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = SafeRequestError(
            "connection_refused",
            "Connection refused.",
        )
        result = run_passive_header_scan(
            target(https=False),
            retry_policy=RetryPolicy(maximum_attempts=1),
            scan_id=SCAN_ID,
            started_at=START,
        )
        skipped_ids = {
            item.check_id
            for item in result.coverage.skipped_checks
        }
        self.assertTrue(
            set(PASSIVE_TLS_CHECKS).issubset(skipped_ids)
        )
        self.assertEqual(result.coverage.requests_succeeded, 0)

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.tls_analyzer._utc_now",
        return_value=START,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_tls_finding_has_no_response_body_evidence(
        self,
        fetch_mock,
        _tls_clock_mock,
        _clock_mock,
    ) -> None:
        secret_body = b"secret-body-value"
        item = response(info=tls_info(protocol="TLSv1.1"))
        fetch_mock.return_value = SafeHttpResponse(
            status=item.status,
            reason=item.reason,
            headers=item.headers,
            body=secret_body,
            connected_address=item.connected_address,
            elapsed_milliseconds=item.elapsed_milliseconds,
            tls=item.tls,
        )
        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )
        self.assertNotIn(
            secret_body.decode(),
            result.to_json(),
        )


if __name__ == "__main__":
    unittest.main()
