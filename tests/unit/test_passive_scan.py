"""Tests for passive header scan orchestration."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from webguard_contracts import ScanResult, ScanStatus

from webguard_scanner import (
    FetchPolicy,
    HeaderAnalysisError,
    SafeHttpResponse,
    SafeRequestError,
    ValidatedTarget,
    run_passive_header_scan,
)


STARTED_AT = datetime(
    2026,
    8,
    3,
    1,
    45,
    tzinfo=timezone.utc,
)
COMPLETED_AT = STARTED_AT + timedelta(milliseconds=20)
SCAN_ID = "eb2f2bf7-e28a-4aa4-bb22-42930c77b474"


def target(
    *,
    scheme: str = "http",
    url: str = "http://127.0.0.1:3000/",
    hostname: str = "127.0.0.1",
    port: int = 3000,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_addresses=("127.0.0.1",),
    )


def response(
    *headers: tuple[str, str],
) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=tuple(headers),
        body=b"<html></html>",
        connected_address="127.0.0.1",
        elapsed_milliseconds=10,
    )


class PassiveScanTests(unittest.TestCase):
    """Verify passive scan orchestration and ScanResult output."""

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_http_scan_returns_validated_scan_result(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            (
                "X-Content-Type-Options",
                "nosniff",
            ),
            (
                "X-Frame-Options",
                "DENY",
            ),
        )

        result = run_passive_header_scan(
            target(),
            fetch_policy=FetchPolicy(
                timeout_seconds=5,
            ),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIsInstance(result, ScanResult)
        self.assertIs(
            result.status,
            ScanStatus.COMPLETED,
        )
        self.assertEqual(result.scan_id, SCAN_ID)
        self.assertEqual(
            result.target,
            "http://127.0.0.1:3000/",
        )
        self.assertEqual(
            result.connected_addresses,
            ("127.0.0.1",),
        )
        self.assertEqual(result.http_statuses, (200,))
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(
            {
                finding.identity.rule_id
                for finding in result.findings
            },
            {
                "web.headers.csp.missing",
                "web.headers.referrer_policy.missing",
            },
        )

        fetch_mock.assert_called_once()

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_http_scan_skips_hsts_and_accounts_for_coverage(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response()

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertEqual(
            result.coverage.unaccounted_checks,
            (),
        )
        self.assertEqual(
            result.coverage.completion_percent,
            80.0,
        )
        self.assertEqual(
            result.coverage.skipped_checks[0].check_id,
            "web.headers.hsts",
        )

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_https_scan_executes_all_header_checks(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = SafeHttpResponse(
            status=200,
            reason="OK",
            headers=(
                (
                    "Strict-Transport-Security",
                    "max-age=31536000",
                ),
                (
                    "X-Content-Type-Options",
                    "nosniff",
                ),
                (
                    "Content-Security-Policy",
                    "frame-ancestors 'none'",
                ),
                (
                    "Referrer-Policy",
                    "no-referrer",
                ),
            ),
            body=b"<html></html>",
            connected_address="93.184.216.34",
            elapsed_milliseconds=10,
        )

        https_target = ValidatedTarget(
            original_url="https://example.com/",
            normalised_url="https://example.com/",
            scheme="https",
            hostname="example.com",
            port=443,
            resolved_addresses=("93.184.216.34",),
        )

        result = run_passive_header_scan(
            https_target,
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertEqual(
            result.coverage.completion_percent,
            100.0,
        )
        self.assertEqual(
            result.coverage.skipped_checks,
            (),
        )
        self.assertEqual(result.findings, ())

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_request_failure_returns_failed_scan_result(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = SafeRequestError(
            "connection_failed",
            "The authorised target refused the connection.",
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.FAILED,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.connected_addresses, ())
        self.assertEqual(result.http_statuses, ())
        self.assertEqual(
            result.coverage.requests_attempted,
            1,
        )
        self.assertEqual(
            result.coverage.requests_succeeded,
            0,
        )
        self.assertEqual(
            result.coverage.executed_checks,
            (),
        )
        self.assertEqual(
            result.coverage.unaccounted_checks,
            (
                "web.headers.csp",
                "web.headers.frame_protection",
                "web.headers.referrer_policy",
                "web.headers.x_content_type_options",
            ),
        )
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(
            result.errors[0].code,
            "connection_failed",
        )
        self.assertEqual(
            result.errors[0].stage,
            "request",
        )
        self.assertFalse(result.errors[0].retryable)

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.analyze_security_headers",
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_analysis_failure_preserves_response_metadata(
        self,
        fetch_mock,
        analyze_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response()
        analyze_mock.side_effect = HeaderAnalysisError(
            "analysis_input_inconsistent",
            "The response metadata was inconsistent.",
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.FAILED,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.connected_addresses,
            ("127.0.0.1",),
        )
        self.assertEqual(result.http_statuses, (200,))
        self.assertEqual(
            result.coverage.requests_attempted,
            1,
        )
        self.assertEqual(
            result.coverage.requests_succeeded,
            1,
        )
        self.assertEqual(
            result.coverage.executed_checks,
            (),
        )
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(
            result.errors[0].code,
            "analysis_input_inconsistent",
        )
        self.assertEqual(
            result.errors[0].stage,
            "analysis",
        )
        self.assertFalse(result.errors[0].retryable)


if __name__ == "__main__":
    unittest.main()
