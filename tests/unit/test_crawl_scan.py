from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from webguard_contracts import (
    CrawlTerminationReason,
    RequestAttempt,
    RequestAttemptOutcome,
    ScanStatus,
)
from webguard_scanner import (
    CrawlExecution,
    CrawlPageOutcome,
    CrawlPageRecord,
    CrawlPolicy,
    CrawlSkipReason,
    CrawlSkipSummary,
    HeaderAnalysisError,
    PassiveAnalyzer,
    SafeHttpResponse,
    TlsConnectionInfo,
    ValidatedTarget,
    run_passive_crawl_scan,
)
from webguard_scanner.passive_scan import DEFAULT_PASSIVE_ANALYZERS

START = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
END = START + timedelta(seconds=1)
SCAN_ID = "eb2f2bf7-e28a-4aa4-bb22-42930c77b474"


def target() -> ValidatedTarget:
    return ValidatedTarget(
        original_url="http://127.0.0.1:3000/",
        normalised_url="http://127.0.0.1:3000/",
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=("127.0.0.1",),
    )


def https_target() -> ValidatedTarget:
    return ValidatedTarget(
        original_url="https://example.com/",
        normalised_url="https://example.com/",
        scheme="https",
        hostname="example.com",
        port=443,
        resolved_addresses=("93.184.216.34",),
    )


def tls_info(
    *,
    protocol: str = "TLSv1.3",
) -> TlsConnectionInfo:
    return TlsConnectionInfo(
        protocol=protocol,
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        server_hostname="example.com",
        certificate_not_before=START - timedelta(days=30),
        certificate_not_after=START + timedelta(days=120),
        certificate_sha256="a" * 64,
        subject_alt_names=("DNS:example.com",),
        certificate_verified=True,
        hostname_validated=True,
        verified_chain_length=3,
    )


def attempt(
    *,
    succeeded: bool = True,
    number: int = 1,
) -> RequestAttempt:
    if succeeded:
        return RequestAttempt(
            attempt_number=number,
            started_at=START + timedelta(milliseconds=10),
            completed_at=START + timedelta(milliseconds=20),
            outcome=RequestAttemptOutcome.SUCCEEDED,
            connected_address="127.0.0.1",
            http_status=200,
        )
    return RequestAttempt(
        attempt_number=number,
        started_at=START + timedelta(milliseconds=30),
        completed_at=START + timedelta(milliseconds=40),
        outcome=RequestAttemptOutcome.FAILED,
        error_code="connection_refused",
        retryable=True,
    )


def response(
    *,
    tls: TlsConnectionInfo | None = None,
    connected_address: str = "127.0.0.1",
) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(
            ("Content-Type", "text/html; charset=utf-8"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("Content-Security-Policy", "frame-ancestors 'none'"),
            ("Referrer-Policy", "no-referrer"),
        ),
        body=b"<html></html>",
        connected_address=connected_address,
        elapsed_milliseconds=10,
        tls=tls,
    )


def success_execution(*, child: CrawlPageRecord | None = None) -> CrawlExecution:
    pages = [
        CrawlPageRecord(
            url="http://127.0.0.1:3000/",
            depth=0,
            parent_url=None,
            outcome=CrawlPageOutcome.SUCCEEDED,
            attempts=(attempt(),),
            content_type="text/html",
            connected_address="127.0.0.1",
            http_status=200,
            discovered_links=1 if child is not None else 0,
            queued_links=1 if child is not None else 0,
        )
    ]
    if child is not None:
        pages.append(child)
    return CrawlExecution(
        root_url="http://127.0.0.1:3000/",
        pages=tuple(pages),
        skipped_links=(
            CrawlSkipSummary(CrawlSkipReason.EXTERNAL_ORIGIN, 1),
        ),
    )


class CrawlScanTests(unittest.TestCase):
    @patch("webguard_scanner.crawl_scan._utc_now", return_value=END)
    @patch("webguard_scanner.crawl_scan.crawl_same_origin")
    def test_successful_page_is_analysed_without_second_fetch(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        execution = success_execution()

        def run(_root, *, on_page, **_kwargs):
            on_page(target(), response(), 0, None)
            return execution

        crawl_mock.side_effect = run
        result = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertIs(result.status, ScanStatus.COMPLETED)
        self.assertEqual(len(result.pages), 1)
        self.assertEqual(result.coverage.pages_succeeded, 1)
        self.assertEqual(result.coverage.requests_attempted, 1)
        self.assertEqual(result.coverage.check_executions_planned, 40)
        self.assertEqual(result.coverage.check_executions_executed, 32)
        self.assertEqual(result.coverage.check_executions_skipped, 8)
        self.assertEqual(result.findings, ())
        crawl_mock.assert_called_once()

    @patch("webguard_scanner.crawl_scan._utc_now", return_value=END)
    @patch("webguard_scanner.crawl_scan.crawl_same_origin")
    def test_controlled_analyzer_failure_is_page_local(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        def fail_headers(_target, _response):
            raise HeaderAnalysisError(
                "validated_target_mismatch",
                "simulated controlled failure",
            )

        analyzers = (
            replace(
                DEFAULT_PASSIVE_ANALYZERS[0],
                analyze=fail_headers,
            ),
            *DEFAULT_PASSIVE_ANALYZERS[1:],
        )

        def run(_root, *, on_page, **_kwargs):
            on_page(target(), response(), 0, None)
            return success_execution()

        crawl_mock.side_effect = run
        result = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            analyzers=analyzers,
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertIs(result.status, ScanStatus.COMPLETED_WITH_ERRORS)
        self.assertIs(
            result.pages[0].status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(result.pages[0].errors[0].stage, "analysis.headers")
        self.assertEqual(len(result.pages[0].coverage.skipped_checks), 12)

    @patch("webguard_scanner.crawl_scan._utc_now", return_value=END)
    @patch("webguard_scanner.crawl_scan.crawl_same_origin")
    def test_child_request_failure_is_isolated(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        child = CrawlPageRecord(
            url="http://127.0.0.1:3000/a",
            depth=1,
            parent_url="http://127.0.0.1:3000/",
            outcome=CrawlPageOutcome.FAILED,
            attempts=(attempt(succeeded=False),),
            error_code="connection_refused",
            retryable=True,
        )
        execution = success_execution(child=child)

        def run(_root, *, on_page, **_kwargs):
            on_page(target(), response(), 0, None)
            return execution

        crawl_mock.side_effect = run
        result = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=2,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertIs(result.status, ScanStatus.COMPLETED_WITH_ERRORS)
        self.assertEqual(result.coverage.pages_succeeded, 1)
        self.assertEqual(result.coverage.pages_failed, 1)
        self.assertIs(result.pages[1].status, ScanStatus.FAILED)
        self.assertEqual(result.pages[1].errors[0].code, "connection_refused")

    @patch("webguard_scanner.crawl_scan._utc_now", return_value=END)
    @patch("webguard_scanner.crawl_scan.crawl_same_origin")
    def test_root_request_failure_returns_failed_report(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        crawl_mock.return_value = CrawlExecution(
            root_url="http://127.0.0.1:3000/",
            pages=(
                CrawlPageRecord(
                    url="http://127.0.0.1:3000/",
                    depth=0,
                    parent_url=None,
                    outcome=CrawlPageOutcome.FAILED,
                    attempts=(attempt(succeeded=False),),
                    error_code="connection_refused",
                    retryable=True,
                ),
            ),
            skipped_links=(),
            termination_reason=(
                CrawlTerminationReason.ROOT_REQUEST_FAILED
            ),
        )
        result = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=START,
        )
        self.assertIs(result.status, ScanStatus.FAILED)
        self.assertEqual(result.coverage.pages_failed, 1)

    @patch("webguard_scanner.crawl_scan._utc_now", return_value=END)
    @patch("webguard_scanner.crawl_scan.crawl_same_origin")
    def test_unexpected_analyzer_exception_surfaces(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        def explode(_target, _response):
            raise RuntimeError("unexpected")

        analyzer = PassiveAnalyzer(
            analyzer_id="unexpected",
            checks=("web.unexpected.check",),
            finding_namespace="web.unexpected",
            analyze=explode,
            controlled_error=HeaderAnalysisError,
        )

        def run(_root, *, on_page, **_kwargs):
            on_page(target(), response(), 0, None)
            return success_execution()

        crawl_mock.side_effect = run
        with self.assertRaisesRegex(RuntimeError, "unexpected"):
            run_passive_crawl_scan(
                target(),
                crawl_policy=CrawlPolicy(
                    maximum_depth=0,
                    minimum_delay_seconds=0,
                ),
                analyzers=(analyzer,),
                scan_id=SCAN_ID,
                started_at=START,
            )


    @patch("webguard_scanner.crawl_scan._utc_now", return_value=END)
    @patch("webguard_scanner.tls_analyzer._utc_now", return_value=START)
    @patch("webguard_scanner.crawl_scan.crawl_same_origin")
    def test_https_page_uses_existing_tls_metadata_without_second_fetch(
        self,
        crawl_mock,
        _tls_clock_mock,
        _clock_mock,
    ) -> None:
        page = CrawlPageRecord(
            url="https://example.com/",
            depth=0,
            parent_url=None,
            outcome=CrawlPageOutcome.SUCCEEDED,
            attempts=(
                RequestAttempt(
                    attempt_number=1,
                    started_at=START + timedelta(milliseconds=10),
                    completed_at=START + timedelta(milliseconds=20),
                    outcome=RequestAttemptOutcome.SUCCEEDED,
                    connected_address="93.184.216.34",
                    http_status=200,
                ),
            ),
            content_type="text/html",
            connected_address="93.184.216.34",
            http_status=200,
        )
        execution = CrawlExecution(
            root_url="https://example.com/",
            pages=(page,),
            skipped_links=(),
        )

        def run(_root, *, on_page, **_kwargs):
            on_page(
                https_target(),
                response(
                    tls=tls_info(protocol="TLSv1.1"),
                    connected_address="93.184.216.34",
                ),
                0,
                None,
            )
            return execution

        crawl_mock.side_effect = run
        result = run_passive_crawl_scan(
            https_target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=START,
        )
        self.assertIn(
            "web.tls.protocol.deprecated",
            {item.identity.rule_id for item in result.findings},
        )
        self.assertEqual(
            result.pages[0].coverage.completion_percent,
            100.0,
        )
        self.assertEqual(
            result.coverage.check_executions_planned,
            40,
        )
        crawl_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
