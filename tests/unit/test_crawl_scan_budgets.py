"""Crawl-scan orchestration tests for budget termination."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from webguard_contracts import (
    CrawlTerminationReason,
    ScanStatus,
)
from webguard_scanner import (
    CrawlCancellationToken,
    CrawlExecution,
    CrawlPageOutcome,
    CrawlPageRecord,
    CrawlPolicy,
    SafeHttpResponse,
    ValidatedTarget,
    run_passive_crawl_scan,
)
from webguard_contracts import (
    RequestAttempt,
    RequestAttemptOutcome,
)


START = datetime(2026, 8, 3, 21, 0, tzinfo=timezone.utc)
END = START + timedelta(seconds=1)
SCAN_ID = "8ad566c8-e58e-4c58-ae6b-48061285191e"


def target() -> ValidatedTarget:
    return ValidatedTarget(
        original_url="http://127.0.0.1:3000/",
        normalised_url="http://127.0.0.1:3000/",
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=("127.0.0.1",),
    )


def response() -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(
            ("Content-Type", "text/html"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ),
        body=b"",
        connected_address="127.0.0.1",
        elapsed_milliseconds=1,
    )


def page_record() -> CrawlPageRecord:
    return CrawlPageRecord(
        url="http://127.0.0.1:3000/",
        depth=0,
        parent_url=None,
        outcome=CrawlPageOutcome.SUCCEEDED,
        attempts=(
            RequestAttempt(
                attempt_number=1,
                started_at=START + timedelta(milliseconds=10),
                completed_at=START + timedelta(milliseconds=20),
                outcome=RequestAttemptOutcome.SUCCEEDED,
                connected_address="127.0.0.1",
                http_status=200,
            ),
        ),
        content_type="text/html",
        connected_address="127.0.0.1",
        http_status=200,
    )


class CrawlBudgetOrchestrationTests(unittest.TestCase):
    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.crawl_scan.crawl_same_origin",
    )
    def test_pre_request_cancellation_returns_empty_cancelled_report(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        crawl_mock.return_value = CrawlExecution(
            root_url="http://127.0.0.1:3000/",
            pages=(),
            skipped_links=(),
            termination_reason=CrawlTerminationReason.CANCELLED,
            pages_pending=1,
        )

        result = run_passive_crawl_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertIs(result.status, ScanStatus.CANCELLED)
        self.assertEqual(result.pages, ())
        self.assertEqual(result.coverage.pages_pending, 1)
        self.assertEqual(result.errors[0].code, "crawl_cancelled")

    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.crawl_scan.crawl_same_origin",
    )
    def test_request_budget_preserves_analysed_root(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        execution = CrawlExecution(
            root_url="http://127.0.0.1:3000/",
            pages=(page_record(),),
            skipped_links=(),
            termination_reason=(
                CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED
            ),
            pages_pending=1,
        )

        def run(_root, *, on_page, **_kwargs):
            on_page(target(), response(), 0, None)
            return execution

        crawl_mock.side_effect = run

        result = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=2,
                maximum_request_attempts=1,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(len(result.pages), 1)
        self.assertEqual(result.coverage.pages_pending, 1)
        self.assertEqual(
            result.errors[-1].code,
            "crawl_request_attempt_limit_reached",
        )

    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.crawl_scan.crawl_same_origin",
    )
    def test_page_limit_is_normal_completed_report(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        execution = CrawlExecution(
            root_url="http://127.0.0.1:3000/",
            pages=(page_record(),),
            skipped_links=(),
            termination_reason=(
                CrawlTerminationReason.PAGE_LIMIT_REACHED
            ),
        )

        def run(_root, *, on_page, **_kwargs):
            on_page(target(), response(), 0, None)
            return execution

        crawl_mock.side_effect = run

        result = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=1,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertIs(result.status, ScanStatus.COMPLETED)
        self.assertEqual(result.errors, ())
        self.assertIs(
            result.termination.reason,
            CrawlTerminationReason.PAGE_LIMIT_REACHED,
        )

    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.crawl_scan.crawl_same_origin",
    )
    def test_cancellation_token_is_forwarded_to_crawler(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        token = CrawlCancellationToken()
        crawl_mock.return_value = CrawlExecution(
            root_url="http://127.0.0.1:3000/",
            pages=(),
            skipped_links=(),
            termination_reason=CrawlTerminationReason.CANCELLED,
            pages_pending=1,
        )

        run_passive_crawl_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
            cancellation_token=token,
        )

        self.assertIs(
            crawl_mock.call_args.kwargs["cancellation_token"],
            token,
        )

    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.crawl_scan.crawl_same_origin",
    )
    def test_policy_snapshot_includes_execution_budgets(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        execution = CrawlExecution(
            root_url="http://127.0.0.1:3000/",
            pages=(page_record(),),
            skipped_links=(),
        )

        def run(_root, *, on_page, **_kwargs):
            on_page(target(), response(), 0, None)
            return execution

        crawl_mock.side_effect = run
        result = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_execution_seconds=45,
                maximum_request_attempts=7,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertEqual(
            result.policy.maximum_execution_seconds,
            45.0,
        )
        self.assertEqual(
            result.policy.maximum_request_attempts,
            7,
        )


if __name__ == "__main__":
    unittest.main()
