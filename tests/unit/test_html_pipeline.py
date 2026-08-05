"""Pipeline integration tests for passive HTML analysis."""

from __future__ import annotations

import unittest
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
    HtmlAnalysisError,
    PASSIVE_HTML_CHECKS,
    SafeHttpResponse,
    ValidatedTarget,
    run_passive_crawl_scan,
    run_passive_header_scan,
)


START = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
END = START + timedelta(milliseconds=20)
SCAN_ID = "499cb7ea-c35e-4cee-a78b-2cc98abb18de"


def target() -> ValidatedTarget:
    return ValidatedTarget(
        original_url="http://127.0.0.1:3000/",
        normalised_url="http://127.0.0.1:3000/",
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=("127.0.0.1",),
    )


def response(
    body: bytes = b"<html></html>",
    *,
    content_type: str = "text/html; charset=utf-8",
) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(
            ("Content-Type", content_type),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ),
        body=body,
        connected_address="127.0.0.1",
        elapsed_milliseconds=10,
    )


class HtmlPipelineTests(unittest.TestCase):
    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_single_scan_includes_html_finding_without_second_fetch(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            b"<form><input type='password'></form>"
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertIn(
            "web.html.password_transport.insecure",
            {
                item.identity.rule_id
                for item in result.findings
            },
        )
        self.assertTrue(
            set(PASSIVE_HTML_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        fetch_mock.assert_called_once()

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch(
        "webguard_scanner.passive_scan.analyze_html_security",
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_controlled_html_failure_is_isolated(
        self,
        fetch_mock,
        html_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response()
        html_mock.side_effect = HtmlAnalysisError(
            "html_body_limit_exceeded",
            "The HTML body limit was exceeded.",
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertIs(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertIn(
            "analysis.html",
            {item.stage for item in result.errors},
        )
        skipped = {
            item.check_id
            for item in result.coverage.skipped_checks
        }
        self.assertTrue(set(PASSIVE_HTML_CHECKS).issubset(skipped))
        self.assertEqual(result.coverage.unaccounted_checks, ())
        fetch_mock.assert_called_once()
        html_mock.assert_called_once()

    @patch(
        "webguard_scanner.passive_scan._utc_now",
        return_value=END,
    )
    @patch("webguard_scanner.passive_scan.fetch_once")
    def test_non_html_response_accounts_for_html_checks(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            b'{"status":"ok"}',
            content_type="application/json",
        )

        result = run_passive_header_scan(
            target(),
            scan_id=SCAN_ID,
            started_at=START,
        )

        self.assertTrue(
            set(PASSIVE_HTML_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertFalse(
            any(
                item.identity.rule_id.startswith("web.html.")
                for item in result.findings
            )
        )

    @patch("webguard_scanner.crawl_scan._utc_now", return_value=END)
    @patch("webguard_scanner.crawl_scan.crawl_same_origin")
    def test_crawl_page_includes_html_finding_without_refetch(
        self,
        crawl_mock,
        _clock_mock,
    ) -> None:
        page_response = response(
            b"<form><input type='password'></form>"
        )
        attempt = RequestAttempt(
            attempt_number=1,
            started_at=START,
            completed_at=END,
            outcome=RequestAttemptOutcome.SUCCEEDED,
            connected_address="127.0.0.1",
            http_status=200,
        )
        execution = CrawlExecution(
            root_url=target().normalised_url,
            pages=(
                CrawlPageRecord(
                    url=target().normalised_url,
                    depth=0,
                    parent_url=None,
                    outcome=CrawlPageOutcome.SUCCEEDED,
                    attempts=(attempt,),
                    content_type="text/html",
                    connected_address="127.0.0.1",
                    http_status=200,
                ),
            ),
            skipped_links=(),
        )

        def run(_root, *, on_page, **_kwargs):
            on_page(target(), page_response, 0, None)
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

        self.assertIn(
            "web.html.password_transport.insecure",
            {
                item.identity.rule_id
                for item in result.pages[0].findings
            },
        )
        self.assertTrue(
            set(PASSIVE_HTML_CHECKS).issubset(
                result.pages[0].coverage.executed_checks
            )
        )
        crawl_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
