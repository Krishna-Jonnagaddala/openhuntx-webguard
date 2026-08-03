from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from webguard_contracts import (
    CrawlLinkSkip,
    CrawlPageScanResult,
    CrawlScanPolicy,
    CrawlScanResult,
    MalformedScanReportError,
    RequestAttempt,
    RequestAttemptOutcome,
    ScanContractValidationError,
    ScanCoverage,
    ScanError,
    ScanStatus,
    SkippedCheck,
    load_crawl_scan_result,
    load_crawl_scan_result_json,
    load_webguard_report_json,
)

START = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
END = START + timedelta(seconds=1)
SCAN_ID = "4a4574be-54c9-46f8-a4da-93c36fc0f7bb"


def policy() -> CrawlScanPolicy:
    return CrawlScanPolicy(
        maximum_pages=10,
        maximum_depth=1,
        maximum_links_per_page=100,
        maximum_url_length=2048,
        minimum_delay_seconds=0.1,
        query_mode="drop",
        allowed_content_types=("application/xhtml+xml", "text/html"),
        blocked_path_segments=("delete", "logout"),
    )


def success_attempt(
    number: int = 1,
    *,
    start_ms: int = 10,
    end_ms: int = 20,
) -> RequestAttempt:
    return RequestAttempt(
        attempt_number=number,
        started_at=START + timedelta(milliseconds=start_ms),
        completed_at=START + timedelta(milliseconds=end_ms),
        outcome=RequestAttemptOutcome.SUCCEEDED,
        connected_address="127.0.0.1",
        http_status=200,
    )


def failed_attempt(number: int = 1) -> RequestAttempt:
    return RequestAttempt(
        attempt_number=number,
        started_at=START + timedelta(milliseconds=30),
        completed_at=START + timedelta(milliseconds=40),
        outcome=RequestAttemptOutcome.FAILED,
        error_code="connection_refused",
        retryable=True,
    )


def completed_page(
    url: str = "http://127.0.0.1:3000/",
    *,
    depth: int = 0,
    parent_url: str | None = None,
    start_ms: int = 10,
    end_ms: int = 20,
) -> CrawlPageScanResult:
    return CrawlPageScanResult(
        url=url,
        depth=depth,
        parent_url=parent_url,
        status=ScanStatus.COMPLETED,
        coverage=ScanCoverage(
            planned_checks=("web.headers.csp", "web.headers.hsts"),
            executed_checks=("web.headers.csp",),
            skipped_checks=(
                SkippedCheck(
                    "web.headers.hsts",
                    "HSTS applies only to HTTPS.",
                ),
            ),
            requests_attempted=1,
            requests_succeeded=1,
        ),
        request_attempts=(success_attempt(start_ms=start_ms, end_ms=end_ms),),
        content_type="text/html",
        connected_address="127.0.0.1",
        http_status=200,
        discovered_links=1 if depth == 0 else 0,
        queued_links=1 if depth == 0 else 0,
    )


def failed_page() -> CrawlPageScanResult:
    return CrawlPageScanResult(
        url="http://127.0.0.1:3000/a",
        depth=1,
        parent_url="http://127.0.0.1:3000/",
        status=ScanStatus.FAILED,
        coverage=ScanCoverage(
            planned_checks=("web.headers.csp", "web.headers.hsts"),
            skipped_checks=(
                SkippedCheck(
                    "web.headers.hsts",
                    "HSTS applies only to HTTPS.",
                ),
            ),
            requests_attempted=1,
            requests_succeeded=0,
        ),
        request_attempts=(failed_attempt(),),
        errors=(
            ScanError(
                code="connection_refused",
                message="The page request was refused.",
                stage="request",
                retryable=True,
            ),
        ),
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
        pages=(completed_page(),),
        skipped_links=(CrawlLinkSkip("external_origin", 2),),
    )


class CrawlScanContractTests(unittest.TestCase):
    def test_completed_report_is_deterministic(self) -> None:
        result = completed_result()
        self.assertEqual(result.report_type, "crawl_scan")
        self.assertEqual(result.schema_version, "1.0")
        self.assertEqual(result.coverage.pages_attempted, 1)
        self.assertEqual(result.coverage.completion_percent, 50.0)
        self.assertEqual(result.request_attempt_count, 1)
        self.assertEqual(result.to_json(), result.to_json())

    def test_combined_attempt_projection_contains_page_context(self) -> None:
        attempt = completed_result().to_dict()["request_attempts"][0]
        self.assertEqual(attempt["sequence"], 1)
        self.assertEqual(attempt["page_url"], "http://127.0.0.1:3000/")
        self.assertEqual(attempt["page_attempt_number"], 1)

    def test_child_failure_makes_result_completed_with_errors(self) -> None:
        result = CrawlScanResult(
            scan_id=SCAN_ID,
            scan_type="passive-http-crawl",
            status=ScanStatus.COMPLETED_WITH_ERRORS,
            target="http://127.0.0.1:3000/",
            engine="webguard-native",
            engine_version="0.1.0",
            started_at=START,
            completed_at=END,
            policy=policy(),
            pages=(completed_page(), failed_page()),
        )
        self.assertEqual(result.coverage.pages_succeeded, 1)
        self.assertEqual(result.coverage.pages_failed, 1)
        self.assertEqual(result.coverage.unaccounted_check_executions, 1)

    def test_failed_root_requires_failed_overall_status(self) -> None:
        root = replace(
            failed_page(),
            url="http://127.0.0.1:3000/",
            depth=0,
            parent_url=None,
        )
        result = CrawlScanResult(
            scan_id=SCAN_ID,
            scan_type="passive-http-crawl",
            status=ScanStatus.FAILED,
            target="http://127.0.0.1:3000/",
            engine="webguard-native",
            engine_version="0.1.0",
            started_at=START,
            completed_at=END,
            policy=policy(),
            pages=(root,),
        )
        self.assertIs(result.status, ScanStatus.FAILED)

    def test_rejects_inconsistent_overall_status(self) -> None:
        with self.assertRaises(ScanContractValidationError) as context:
            replace(completed_result(), status=ScanStatus.FAILED)
        self.assertEqual(context.exception.code, "crawl_scan_status_inconsistent")

    def test_rejects_child_before_parent(self) -> None:
        child = completed_page(
            "http://127.0.0.1:3000/a",
            depth=1,
            parent_url="http://127.0.0.1:3000/missing",
            start_ms=30,
            end_ms=40,
        )
        with self.assertRaises(ScanContractValidationError) as context:
            replace(completed_result(), pages=(completed_page(), child))
        self.assertEqual(context.exception.code, "crawl_scan_parent_invalid")

    def test_rejects_duplicate_pages(self) -> None:
        with self.assertRaises(ScanContractValidationError) as context:
            replace(
                completed_result(),
                pages=(completed_page(), completed_page()),
            )
        self.assertEqual(context.exception.code, "crawl_scan_page_duplicate")

    def test_rejects_multiple_depth_zero_pages(self) -> None:
        second_root = completed_page(
            "http://127.0.0.1:3000/second",
            start_ms=30,
            end_ms=40,
        )
        with self.assertRaises(ScanContractValidationError) as context:
            replace(completed_result(), pages=(completed_page(), second_root))
        self.assertEqual(context.exception.code, "crawl_scan_multiple_roots")

    def test_rejects_mismatched_page_check_plan(self) -> None:
        child = completed_page(
            "http://127.0.0.1:3000/a",
            depth=1,
            parent_url="http://127.0.0.1:3000/",
            start_ms=30,
            end_ms=40,
        )
        child = replace(
            child,
            coverage=ScanCoverage(
                planned_checks=("web.headers.csp",),
                executed_checks=("web.headers.csp",),
                requests_attempted=1,
                requests_succeeded=1,
            ),
        )
        with self.assertRaises(ScanContractValidationError) as context:
            replace(completed_result(), pages=(completed_page(), child))
        self.assertEqual(context.exception.code, "crawl_scan_check_plan_mismatch")

    def test_rejects_non_breadth_first_depth_order(self) -> None:
        first_child = completed_page(
            "http://127.0.0.1:3000/a",
            depth=1,
            parent_url="http://127.0.0.1:3000/",
            start_ms=30,
            end_ms=40,
        )
        grandchild = completed_page(
            "http://127.0.0.1:3000/a/child",
            depth=2,
            parent_url="http://127.0.0.1:3000/a",
            start_ms=50,
            end_ms=60,
        )
        later_sibling = completed_page(
            "http://127.0.0.1:3000/b",
            depth=1,
            parent_url="http://127.0.0.1:3000/",
            start_ms=70,
            end_ms=80,
        )
        deeper_policy = replace(policy(), maximum_depth=2)
        with self.assertRaises(ScanContractValidationError) as context:
            replace(
                completed_result(),
                policy=deeper_policy,
                pages=(completed_page(), first_child, grandchild, later_sibling),
            )
        self.assertEqual(context.exception.code, "crawl_scan_page_order_invalid")

    def test_rejects_overlapping_page_attempts(self) -> None:
        child = completed_page(
            "http://127.0.0.1:3000/a",
            depth=1,
            parent_url="http://127.0.0.1:3000/",
            start_ms=15,
            end_ms=25,
        )
        with self.assertRaises(ScanContractValidationError) as context:
            replace(completed_result(), pages=(completed_page(), child))
        self.assertEqual(
            context.exception.code,
            "crawl_scan_page_attempt_order_invalid",
        )

    def test_loader_round_trip(self) -> None:
        original = completed_result()
        loaded = load_crawl_scan_result_json(original.to_json())
        self.assertEqual(loaded, original)
        self.assertEqual(load_webguard_report_json(original.to_json()), original)

    def test_loader_does_not_mutate_input(self) -> None:
        report = completed_result().to_dict()
        original = copy.deepcopy(report)
        load_crawl_scan_result(report)
        self.assertEqual(report, original)

    def test_loader_rejects_tampered_aggregate_coverage(self) -> None:
        report = completed_result().to_dict()
        report["coverage"]["pages_succeeded"] = 0
        with self.assertRaises(MalformedScanReportError) as context:
            load_crawl_scan_result(report)
        self.assertEqual(context.exception.code, "crawl_scan_report_non_canonical")

    def test_loader_rejects_tampered_combined_attempt(self) -> None:
        report = completed_result().to_dict()
        report["request_attempts"][0]["page_url"] = "http://127.0.0.1:3000/x"
        with self.assertRaises(MalformedScanReportError) as context:
            load_crawl_scan_result(report)
        self.assertEqual(context.exception.code, "crawl_scan_report_non_canonical")


if __name__ == "__main__":
    unittest.main()
