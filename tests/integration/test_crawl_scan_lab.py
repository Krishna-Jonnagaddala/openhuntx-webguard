"""Authorised OWASP Juice Shop crawl-scan integration test."""

from __future__ import annotations

import os
import unittest
from urllib.parse import urlsplit

from webguard_contracts import (
    CrawlScanResult,
    ScanStatus,
    load_crawl_scan_result_json,
)
from webguard_scanner import (
    CrawlPolicy,
    FetchPolicy,
    PASSIVE_CHECKS,
    ValidationMode,
    ValidationPolicy,
    run_passive_crawl_scan,
    validate_target_url,
)


RUN_INTEGRATION = os.getenv(
    "WEBGUARD_RUN_INTEGRATION"
) == "1"
LAB_TARGET = os.getenv(
    "WEBGUARD_LAB_TARGET",
    "http://127.0.0.1:3000/",
)


@unittest.skipUnless(
    RUN_INTEGRATION,
    "Set WEBGUARD_RUN_INTEGRATION=1 to run network integration tests.",
)
class CrawlScanLabIntegrationTests(unittest.TestCase):
    """Persist a page-aware report only for the authorised lab origin."""

    def test_crawls_analyses_and_round_trips_juice_shop(self) -> None:
        parsed = urlsplit(LAB_TARGET)
        if parsed.hostname is None:
            self.fail(
                "WEBGUARD_LAB_TARGET must contain a hostname."
            )

        target = validate_target_url(
            LAB_TARGET,
            ValidationPolicy(
                mode=ValidationMode.LAB,
                allowed_lab_hosts=frozenset(
                    {
                        parsed.hostname,
                        "127.0.0.1",
                        "localhost",
                    }
                ),
            ),
        )

        result = run_passive_crawl_scan(
            target,
            crawl_policy=CrawlPolicy(
                maximum_pages=5,
                maximum_depth=1,
                maximum_links_per_page=100,
                minimum_delay_seconds=0,
            ),
            fetch_policy=FetchPolicy(
                timeout_seconds=5,
                maximum_body_bytes=2_097_152,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
            ),
        )

        self.assertIsInstance(result, CrawlScanResult)
        self.assertIs(result.status, ScanStatus.COMPLETED)
        self.assertEqual(result.report_type, "crawl_scan")
        self.assertEqual(result.schema_version, "1.0")
        self.assertGreaterEqual(len(result.pages), 1)
        self.assertLessEqual(len(result.pages), 5)
        self.assertEqual(result.pages[0].url, result.target)
        self.assertEqual(result.pages[0].depth, 0)
        self.assertEqual(result.pages[0].parent_url, None)
        self.assertEqual(result.errors, ())

        self.assertEqual(
            result.coverage.pages_attempted,
            len(result.pages),
        )
        self.assertEqual(
            result.coverage.pages_succeeded,
            len(result.pages),
        )
        self.assertEqual(result.coverage.pages_failed, 0)
        self.assertEqual(
            result.coverage.requests_attempted,
            result.request_attempt_count,
        )
        self.assertEqual(
            result.coverage.requests_succeeded,
            len(result.pages),
        )
        self.assertEqual(
            result.coverage.unaccounted_check_executions,
            0,
        )
        self.assertEqual(
            result.coverage.completion_percent,
            95.83,
        )

        root_origin = (
            target.scheme,
            target.hostname,
            target.port,
        )
        planned_checks = tuple(sorted(PASSIVE_CHECKS))

        for page in result.pages:
            page_url = urlsplit(page.url)
            page_port = page_url.port
            if page_port is None:
                page_port = 443 if page_url.scheme == "https" else 80

            self.assertEqual(
                (
                    page_url.scheme,
                    page_url.hostname,
                    page_port,
                ),
                root_origin,
            )
            self.assertEqual(page_url.query, "")
            self.assertEqual(page_url.fragment, "")
            self.assertIs(page.status, ScanStatus.COMPLETED)
            self.assertEqual(
                page.coverage.planned_checks,
                planned_checks,
            )
            self.assertEqual(
                page.coverage.unaccounted_checks,
                (),
            )

        loaded = load_crawl_scan_result_json(
            result.to_json()
        )
        self.assertEqual(loaded, result)
        self.assertEqual(loaded.to_json(), result.to_json())


if __name__ == "__main__":
    unittest.main()
