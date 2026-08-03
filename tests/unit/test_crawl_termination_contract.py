"""Contract tests for crawl termination and execution budgets."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from webguard_contracts import (
    DEFAULT_CRAWL_REPORT_EXECUTION_SECONDS,
    DEFAULT_CRAWL_REPORT_REQUEST_ATTEMPTS,
    CrawlPageScanResult,
    CrawlScanPolicy,
    CrawlScanResult,
    CrawlScanTermination,
    CrawlTerminationReason,
    MalformedScanReportError,
    RequestAttempt,
    RequestAttemptOutcome,
    ScanContractValidationError,
    ScanCoverage,
    ScanStatus,
    load_crawl_scan_result,
)


START = datetime(2026, 8, 3, 20, 0, tzinfo=timezone.utc)
END = START + timedelta(seconds=2)
SCAN_ID = "f0dd8f3e-7950-4e1d-a111-6512c99b4071"


def policy(
    *,
    maximum_pages: int = 10,
) -> CrawlScanPolicy:
    return CrawlScanPolicy(
        maximum_pages=maximum_pages,
        maximum_depth=1,
        maximum_links_per_page=100,
        maximum_url_length=2048,
        minimum_delay_seconds=0.1,
        query_mode="drop",
        allowed_content_types=("text/html",),
        blocked_path_segments=("delete",),
    )


def page(
    url: str = "http://127.0.0.1:3000/",
) -> CrawlPageScanResult:
    attempt = RequestAttempt(
        attempt_number=1,
        started_at=START + timedelta(milliseconds=10),
        completed_at=START + timedelta(milliseconds=20),
        outcome=RequestAttemptOutcome.SUCCEEDED,
        connected_address="127.0.0.1",
        http_status=200,
    )
    return CrawlPageScanResult(
        url=url,
        depth=0,
        parent_url=None,
        status=ScanStatus.COMPLETED,
        coverage=ScanCoverage(
            planned_checks=("web.headers.csp",),
            executed_checks=("web.headers.csp",),
            requests_attempted=1,
            requests_succeeded=1,
        ),
        request_attempts=(attempt,),
        content_type="text/html",
        connected_address="127.0.0.1",
        http_status=200,
    )


def completed_result() -> CrawlScanResult:
    return CrawlScanResult(
        scan_id=SCAN_ID,
        scan_type="passive-http-crawl",
        status=ScanStatus.COMPLETED,
        target="http://127.0.0.1:3000/",
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=START,
        completed_at=END,
        policy=policy(),
        pages=(page(),),
    )


class CrawlTerminationContractTests(unittest.TestCase):
    def test_current_schema_serializes_budgets_and_termination(self) -> None:
        result = completed_result()
        document = result.to_dict()

        self.assertEqual(result.schema_version, "1.1")
        self.assertEqual(
            document["policy"]["maximum_execution_seconds"],
            DEFAULT_CRAWL_REPORT_EXECUTION_SECONDS,
        )
        self.assertEqual(
            document["policy"]["maximum_request_attempts"],
            DEFAULT_CRAWL_REPORT_REQUEST_ATTEMPTS,
        )
        self.assertEqual(
            document["termination"],
            {
                "reason": "completed",
                "pages_pending": 0,
            },
        )
        self.assertEqual(document["coverage"]["pages_pending"], 0)

    def test_pre_request_cancellation_is_contract_valid(self) -> None:
        result = CrawlScanResult(
            scan_id=SCAN_ID,
            scan_type="passive-http-crawl",
            status=ScanStatus.CANCELLED,
            target="http://127.0.0.1:3000/",
            engine="webguard-native",
            engine_version="0.1.0",
            started_at=START,
            completed_at=END,
            policy=policy(),
            pages=(),
            termination=CrawlScanTermination(
                reason=CrawlTerminationReason.CANCELLED,
                pages_pending=1,
            ),
        )

        self.assertEqual(result.coverage.pages_attempted, 0)
        self.assertEqual(result.coverage.pages_pending, 1)
        self.assertIsNone(result.coverage.completion_percent)
        self.assertEqual(result.errors[0].code, "crawl_cancelled")
        self.assertEqual(result.request_attempt_count, 0)

    def test_time_limit_with_preserved_page_is_completed_with_errors(
        self,
    ) -> None:
        result = replace(
            completed_result(),
            status=ScanStatus.COMPLETED_WITH_ERRORS,
            termination=CrawlScanTermination(
                reason=CrawlTerminationReason.TIME_LIMIT_REACHED,
                pages_pending=1,
            ),
        )

        self.assertEqual(
            result.errors[-1].code,
            "crawl_time_limit_reached",
        )
        self.assertEqual(result.coverage.pages_succeeded, 1)
        self.assertEqual(result.coverage.pages_pending, 1)

    def test_request_budget_exhaustion_adds_top_level_error(
        self,
    ) -> None:
        result = replace(
            completed_result(),
            status=ScanStatus.COMPLETED_WITH_ERRORS,
            termination=CrawlScanTermination(
                reason=(
                    CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED
                ),
            ),
        )

        self.assertEqual(
            result.errors[-1].code,
            "crawl_request_attempt_limit_reached",
        )

    def test_rejects_empty_normally_completed_report(self) -> None:
        with self.assertRaises(ScanContractValidationError) as context:
            replace(completed_result(), pages=())

        self.assertEqual(
            context.exception.code,
            "crawl_scan_empty_pages_invalid",
        )

    def test_rejects_status_inconsistent_with_cancellation(self) -> None:
        with self.assertRaises(ScanContractValidationError) as context:
            replace(
                completed_result(),
                termination=CrawlScanTermination(
                    reason=CrawlTerminationReason.CANCELLED,
                ),
            )

        self.assertEqual(
            context.exception.code,
            "crawl_scan_status_inconsistent",
        )

    def test_rejects_attempted_and_pending_pages_above_policy(
        self,
    ) -> None:
        with self.assertRaises(ScanContractValidationError) as context:
            CrawlScanResult(
                scan_id=SCAN_ID,
                scan_type="passive-http-crawl",
                status=ScanStatus.COMPLETED_WITH_ERRORS,
                target="http://127.0.0.1:3000/",
                engine="webguard-native",
                engine_version="0.1.0",
                started_at=START,
                completed_at=END,
                policy=policy(maximum_pages=1),
                pages=(page(),),
                termination=CrawlScanTermination(
                    reason=CrawlTerminationReason.TIME_LIMIT_REACHED,
                    pages_pending=1,
                ),
            )

        self.assertEqual(
            context.exception.code,
            "crawl_scan_pending_page_limit_exceeded",
        )

    def test_migrates_crawl_schema_1_0_without_mutating_input(
        self,
    ) -> None:
        legacy = completed_result().to_dict()
        legacy["schema_version"] = "1.0"
        legacy.pop("termination")
        legacy["policy"].pop("maximum_execution_seconds")
        legacy["policy"].pop("maximum_request_attempts")
        legacy["coverage"].pop("pages_pending")
        original = copy.deepcopy(legacy)

        loaded = load_crawl_scan_result(legacy)

        self.assertEqual(legacy, original)
        self.assertEqual(loaded.schema_version, "1.1")
        self.assertEqual(
            loaded.policy.maximum_execution_seconds,
            DEFAULT_CRAWL_REPORT_EXECUTION_SECONDS,
        )
        self.assertIs(
            loaded.termination.reason,
            CrawlTerminationReason.COMPLETED,
        )

    def test_loader_rejects_tampered_termination_projection(
        self,
    ) -> None:
        report = completed_result().to_dict()
        report["termination"]["reason"] = "cancelled"

        with self.assertRaises(MalformedScanReportError):
            load_crawl_scan_result(report)

    def test_completed_termination_cannot_retain_pending_pages(
        self,
    ) -> None:
        with self.assertRaises(ScanContractValidationError) as context:
            CrawlScanTermination(
                reason=CrawlTerminationReason.COMPLETED,
                pages_pending=1,
            )

        self.assertEqual(
            context.exception.code,
            "crawl_termination_pending_pages_invalid",
        )


if __name__ == "__main__":
    unittest.main()
