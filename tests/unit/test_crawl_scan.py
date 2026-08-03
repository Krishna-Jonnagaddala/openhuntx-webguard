from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from webguard_contracts import (
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


def response() -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(
            ("Content-Type", "text/html; charset=utf-8"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ),
        body=b"<html></html>",
        connected_address="127.0.0.1",
        elapsed_milliseconds=10,
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
        self.assertEqual(result.coverage.check_executions_planned, 24)
        self.assertEqual(result.coverage.check_executions_executed, 23)
        self.assertEqual(result.coverage.check_executions_skipped, 1)
        self.assertTrue(result.findings)
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
        self.assertEqual(len(result.pages[0].coverage.skipped_checks), 5)

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


if __name__ == "__main__":
    unittest.main()
