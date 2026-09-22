"""Tests for passive header scan orchestration."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import call, patch

from webguard_contracts import (
    RequestAttemptOutcome,
    ScanResult,
    ScanStatus,
)

from webguard_scanner import (
    CookieAnalysisError,
    CorsAnalysisError,
    DisclosureAnalysisError,
    FetchPolicy,
    HeaderAnalysisError,
    PASSIVE_CHECKS,
    PASSIVE_COOKIE_CHECKS,
    PASSIVE_CORS_CHECKS,
    PASSIVE_DISCLOSURE_CHECKS,
    PASSIVE_HEADER_CHECKS,
    PASSIVE_TLS_CHECKS,
    RetryPolicy,
    SafeHttpResponse,
    TlsAnalysisError,
    TlsConnectionInfo,
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


def tls_info(
    *,
    protocol: str = "TLSv1.3",
    cipher_name: str = "TLS_AES_256_GCM_SHA384",
    cipher_bits: int = 256,
) -> TlsConnectionInfo:
    return TlsConnectionInfo(
        protocol=protocol,
        cipher_name=cipher_name,
        cipher_bits=cipher_bits,
        server_hostname="example.com",
        certificate_not_before=(
            STARTED_AT - timedelta(days=30)
        ),
        certificate_not_after=(
            STARTED_AT + timedelta(days=120)
        ),
        certificate_sha256="a" * 64,
        subject_alt_names=("DNS:example.com",),
        certificate_verified=True,
        hostname_validated=True,
        verified_chain_length=3,
    )


def response(
    *headers: tuple[str, str],
    tls: TlsConnectionInfo | None = None,
) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=tuple(headers),
        body=b"<html></html>",
        connected_address="127.0.0.1",
        elapsed_milliseconds=10,
        tls=tls,
    )


class PassiveScanTests(unittest.TestCase):
    """Verify passive scan orchestration and retry behaviour."""

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
        self.assertEqual(
            result.coverage.requests_attempted,
            1,
        )
        self.assertEqual(
            result.coverage.requests_succeeded,
            1,
        )
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(len(result.request_attempts), 1)
        self.assertIs(
            result.request_attempts[0].outcome,
            RequestAttemptOutcome.SUCCEEDED,
        )
        self.assertFalse(
            result.request_attempts[0].retry_scheduled
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
            80.49,
        )
        skipped_ids = {
            item.check_id
            for item in result.coverage.skipped_checks
        }
        self.assertIn("web.headers.hsts", skipped_ids)
        self.assertTrue(
            set(PASSIVE_TLS_CHECKS).issubset(skipped_ids)
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
            tls=tls_info(),
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
        "webguard_scanner.passive_scan.time.sleep",
    )
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_default_policy_does_not_retry(
        self,
        fetch_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.side_effect = SafeRequestError(
            "connection_timeout",
            "The connection timed out.",
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
        self.assertTrue(result.errors[0].retryable)
        self.assertEqual(
            result.coverage.requests_attempted,
            1,
        )
        self.assertEqual(len(result.request_attempts), 1)
        self.assertIs(
            result.request_attempts[0].outcome,
            RequestAttemptOutcome.FAILED,
        )
        self.assertFalse(
            result.request_attempts[0].retry_scheduled
        )
        fetch_mock.assert_called_once()
        sleep_mock.assert_not_called()

    @patch(
        "webguard_scanner.passive_scan.time.sleep",
    )
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_retryable_failure_can_succeed_on_second_attempt(
        self,
        fetch_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.side_effect = [
            SafeRequestError(
                "connection_timeout",
                "The connection timed out.",
            ),
            response(),
        ]

        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(
                maximum_attempts=2,
                initial_backoff_seconds=0.1,
                maximum_backoff_seconds=0.1,
            ),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED,
        )
        self.assertEqual(
            result.coverage.requests_attempted,
            2,
        )
        self.assertEqual(
            result.coverage.requests_succeeded,
            1,
        )
        self.assertEqual(fetch_mock.call_count, 2)
        self.assertEqual(
            tuple(
                item.outcome
                for item in result.request_attempts
            ),
            (
                RequestAttemptOutcome.FAILED,
                RequestAttemptOutcome.SUCCEEDED,
            ),
        )
        self.assertTrue(
            result.request_attempts[0].retry_scheduled
        )
        self.assertEqual(
            result.request_attempts[0].backoff_seconds,
            0.1,
        )
        sleep_mock.assert_called_once_with(0.1)

    @patch(
        "webguard_scanner.passive_scan.time.sleep",
    )
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_retry_exhaustion_preserves_final_error(
        self,
        fetch_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.side_effect = [
            SafeRequestError(
                "connection_timeout",
                "Attempt one timed out.",
            ),
            SafeRequestError(
                "connection_refused",
                "Attempt two was refused.",
            ),
            SafeRequestError(
                "connection_interrupted",
                "Attempt three was interrupted.",
            ),
        ]

        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(
                maximum_attempts=3,
                initial_backoff_seconds=0.1,
                backoff_multiplier=2,
                maximum_backoff_seconds=0.15,
            ),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.FAILED,
        )
        self.assertEqual(
            result.coverage.requests_attempted,
            3,
        )
        self.assertEqual(
            result.coverage.requests_succeeded,
            0,
        )
        self.assertEqual(
            result.errors[0].code,
            "connection_interrupted",
        )
        self.assertTrue(result.errors[0].retryable)
        self.assertEqual(
            tuple(
                item.error_code
                for item in result.request_attempts
            ),
            (
                "connection_timeout",
                "connection_refused",
                "connection_interrupted",
            ),
        )
        self.assertEqual(
            tuple(
                item.retry_scheduled
                for item in result.request_attempts
            ),
            (True, True, False),
        )
        self.assertEqual(
            sleep_mock.call_args_list,
            [
                call(0.1),
                call(0.15),
            ],
        )

    @patch(
        "webguard_scanner.passive_scan.time.sleep",
    )
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_non_retryable_failure_stops_immediately(
        self,
        fetch_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.side_effect = SafeRequestError(
            "redirect_blocked",
            "Automatic redirects are disabled.",
        )

        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(
                maximum_attempts=3,
            ),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.FAILED,
        )
        self.assertFalse(result.errors[0].retryable)
        self.assertEqual(
            result.coverage.requests_attempted,
            1,
        )
        self.assertEqual(len(result.request_attempts), 1)
        self.assertFalse(
            result.request_attempts[0].retry_scheduled
        )
        self.assertEqual(
            result.request_attempts[0].backoff_seconds,
            0.0,
        )
        fetch_mock.assert_called_once()
        sleep_mock.assert_not_called()

    @patch(
        "webguard_scanner.passive_scan.time.sleep",
    )
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
    def test_analysis_failure_is_not_retried(
        self,
        fetch_mock,
        analyze_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.return_value = response()
        analyze_mock.side_effect = HeaderAnalysisError(
            "validated_target_mismatch",
            "The response metadata was inconsistent.",
        )

        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(maximum_attempts=3),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(result.coverage.requests_attempted, 1)
        self.assertEqual(result.coverage.requests_succeeded, 1)
        self.assertEqual(result.errors[0].stage, "analysis.headers")
        self.assertFalse(result.errors[0].retryable)
        self.assertEqual(result.coverage.unaccounted_checks, ())
        self.assertTrue(
            set(PASSIVE_HEADER_CHECKS).issubset(
                {
                    item.check_id
                    for item in result.coverage.skipped_checks
                }
            )
        )
        self.assertTrue(
            set(PASSIVE_COOKIE_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        fetch_mock.assert_called_once()
        analyze_mock.assert_called_once()
        sleep_mock.assert_not_called()

    @patch(
        "webguard_scanner.passive_scan.time.sleep",
    )
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
    def test_analysis_failure_after_retry_tracks_attempts(
        self,
        fetch_mock,
        analyze_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.side_effect = [
            SafeRequestError(
                "connection_timeout",
                "The first attempt timed out.",
            ),
            response(),
        ]
        analyze_mock.side_effect = HeaderAnalysisError(
            "validated_target_mismatch",
            "The response metadata was inconsistent.",
        )

        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(
                maximum_attempts=2,
                initial_backoff_seconds=0,
                maximum_backoff_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(result.coverage.requests_attempted, 2)
        self.assertEqual(result.coverage.requests_succeeded, 1)
        self.assertEqual(result.errors[0].stage, "analysis.headers")
        self.assertEqual(fetch_mock.call_count, 2)
        self.assertEqual(len(result.request_attempts), 2)
        self.assertIs(
            result.request_attempts[-1].outcome,
            RequestAttemptOutcome.SUCCEEDED,
        )
        self.assertEqual(result.coverage.unaccounted_checks, ())
        analyze_mock.assert_called_once()
        sleep_mock.assert_not_called()

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_cookie_findings_are_included_in_scan_result(
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
            (
                "Set-Cookie",
                "session=secret; Path=/",
            ),
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        result_rules = {
            item.identity.rule_id
            for item in result.findings
        }

        self.assertIn(
            "web.cookies.secure.missing",
            result_rules,
        )
        self.assertIn(
            "web.cookies.httponly.missing",
            result_rules,
        )
        self.assertIn(
            "web.cookies.samesite.missing",
            result_rules,
        )
        self.assertIn(
            "web.cookies.transport.insecure",
            result_rules,
        )
        self.assertTrue(
            set(PASSIVE_COOKIE_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertEqual(
            result.coverage.planned_checks,
            tuple(sorted(PASSIVE_CHECKS)),
        )

    @patch(
        "webguard_scanner.passive_scan.time.sleep",
    )
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.analyze_cookies",
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_cookie_analysis_failure_is_not_retried(
        self,
        fetch_mock,
        cookie_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.return_value = response()
        cookie_mock.side_effect = CookieAnalysisError(
            "validated_target_mismatch",
            "The cookie analysis input was inconsistent.",
        )

        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(maximum_attempts=3),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(result.coverage.requests_attempted, 1)
        self.assertEqual(result.coverage.requests_succeeded, 1)
        self.assertEqual(result.errors[0].stage, "analysis.cookies")
        self.assertEqual(result.coverage.unaccounted_checks, ())
        self.assertTrue(
            set(PASSIVE_COOKIE_CHECKS).issubset(
                {
                    item.check_id
                    for item in result.coverage.skipped_checks
                }
            )
        )
        self.assertTrue(result.findings)
        fetch_mock.assert_called_once()
        cookie_mock.assert_called_once()
        sleep_mock.assert_not_called()

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_cors_findings_are_included_in_scan_result(
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
            (
                "Access-Control-Allow-Origin",
                "*",
            ),
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        result_rules = {
            item.identity.rule_id
            for item in result.findings
        }

        self.assertIn(
            "web.cors.allow_origin.wildcard",
            result_rules,
        )
        self.assertTrue(
            set(PASSIVE_CORS_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_disclosure_findings_are_included_in_scan_result(
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
            (
                "Server",
                "nginx/1.25.4",
            ),
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        result_rules = {
            item.identity.rule_id
            for item in result.findings
        }

        self.assertIn(
            "web.disclosure.server.version",
            result_rules,
        )
        self.assertTrue(
            set(PASSIVE_DISCLOSURE_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )

    @patch(
        "webguard_scanner.passive_scan.time.sleep",
    )
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.analyze_cors",
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_cors_analysis_failure_is_not_retried(
        self,
        fetch_mock,
        cors_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.return_value = response()
        cors_mock.side_effect = CorsAnalysisError(
            "validated_target_mismatch",
            "The CORS analysis input was inconsistent.",
        )

        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(maximum_attempts=3),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(result.coverage.requests_attempted, 1)
        self.assertEqual(result.coverage.requests_succeeded, 1)
        self.assertEqual(result.errors[0].stage, "analysis.cors")
        self.assertEqual(result.coverage.unaccounted_checks, ())
        self.assertTrue(
            set(PASSIVE_CORS_CHECKS).issubset(
                {
                    item.check_id
                    for item in result.coverage.skipped_checks
                }
            )
        )
        fetch_mock.assert_called_once()
        cors_mock.assert_called_once()
        sleep_mock.assert_not_called()

    @patch(
        "webguard_scanner.passive_scan.time.sleep",
    )
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.analyze_information_disclosure",
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_disclosure_analysis_failure_is_not_retried(
        self,
        fetch_mock,
        disclosure_mock,
        _clock_mock,
        sleep_mock,
    ) -> None:
        fetch_mock.return_value = response()
        disclosure_mock.side_effect = DisclosureAnalysisError(
            "validated_target_mismatch",
            "The disclosure analysis input was inconsistent.",
        )

        result = run_passive_header_scan(
            target(),
            retry_policy=RetryPolicy(maximum_attempts=3),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(result.coverage.requests_attempted, 1)
        self.assertEqual(result.coverage.requests_succeeded, 1)
        self.assertEqual(result.errors[0].stage, "analysis.disclosure")
        self.assertEqual(result.coverage.unaccounted_checks, ())
        self.assertTrue(
            set(PASSIVE_DISCLOSURE_CHECKS).issubset(
                {
                    item.check_id
                    for item in result.coverage.skipped_checks
                }
            )
        )
        fetch_mock.assert_called_once()
        disclosure_mock.assert_called_once()
        sleep_mock.assert_not_called()


    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.analyze_cors",
    )
    @patch(
        "webguard_scanner.passive_scan.analyze_cookies",
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_multiple_controlled_failures_are_isolated(
        self,
        fetch_mock,
        cookie_mock,
        cors_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response()
        cookie_mock.side_effect = CookieAnalysisError(
            "validated_target_mismatch",
            "Cookie analysis failed.",
        )
        cors_mock.side_effect = CorsAnalysisError(
            "validated_target_mismatch",
            "CORS analysis failed.",
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(
            {error.stage for error in result.errors},
            {"analysis.cookies", "analysis.cors"},
        )
        self.assertEqual(result.coverage.unaccounted_checks, ())
        self.assertTrue(
            set(PASSIVE_DISCLOSURE_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )

    @patch(
        "webguard_scanner.passive_scan.analyze_cookies",
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_unexpected_analysis_exception_surfaces(
        self,
        fetch_mock,
        cookie_mock,
    ) -> None:
        fetch_mock.return_value = response()
        cookie_mock.side_effect = RuntimeError(
            "unexpected programming failure"
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "unexpected programming failure",
        ):
            run_passive_header_scan(
                target(),
                scan_id=SCAN_ID,
                started_at=STARTED_AT,
            )


    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.tls_analyzer._utc_now",
        return_value=STARTED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_tls_findings_are_included_in_https_scan(
        self,
        fetch_mock,
        _tls_clock_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            ("Strict-Transport-Security", "max-age=31536000"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "frame-ancestors 'none'"),
            ("Referrer-Policy", "no-referrer"),
            tls=tls_info(protocol="TLSv1.1"),
        )
        result = run_passive_header_scan(
            target(
                scheme="https",
                url="https://example.com/",
                hostname="example.com",
                port=443,
            ),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )
        self.assertIn(
            "web.tls.protocol.deprecated",
            {item.identity.rule_id for item in result.findings},
        )
        self.assertTrue(
            set(PASSIVE_TLS_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertEqual(result.coverage.completion_percent, 100.0)

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=COMPLETED_AT,
    )
    @patch(
        "webguard_scanner.passive_scan.analyze_tls_security",
    )
    @patch(
        "webguard_scanner.passive_scan.fetch_once",
    )
    def test_tls_analysis_failure_is_isolated(
        self,
        fetch_mock,
        tls_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            tls=tls_info(),
        )
        tls_mock.side_effect = TlsAnalysisError(
            "tls_metadata_inconsistent",
            "TLS metadata was inconsistent.",
        )
        result = run_passive_header_scan(
            target(
                scheme="https",
                url="https://example.com/",
                hostname="example.com",
                port=443,
            ),
            scan_id=SCAN_ID,
            started_at=STARTED_AT,
        )
        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(result.errors[0].stage, "analysis.tls")
        self.assertTrue(
            set(PASSIVE_TLS_CHECKS).issubset(
                {item.check_id for item in result.coverage.skipped_checks}
            )
        )
        self.assertEqual(result.coverage.unaccounted_checks, ())


if __name__ == "__main__":
    unittest.main()
