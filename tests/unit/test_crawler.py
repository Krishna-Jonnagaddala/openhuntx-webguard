"""Tests for bounded same-origin crawling."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import call, patch

from webguard_contracts import RequestAttemptOutcome

from webguard_scanner.crawler import (
    CrawlExecution,
    CrawlPageOutcome,
    CrawlPolicy,
    CrawlPolicyError,
    CrawlQueryMode,
    CrawlSkipReason,
    MAXIMUM_CRAWL_PAGES,
    crawl_same_origin,
)
from webguard_scanner.retry_policy import RetryPolicy
from webguard_scanner.safe_http import (
    FetchPolicy,
    SafeHttpResponse,
    SafeRequestError,
)
from webguard_scanner.scope_validator import ValidatedTarget


NOW = datetime(2026, 8, 3, 18, 0, tzinfo=timezone.utc)


def target(
    url: str = "http://127.0.0.1:3000/",
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=("127.0.0.1",),
    )


def response(
    body: str = "",
    *,
    content_type: str | None = "text/html; charset=utf-8",
    status: int = 200,
) -> SafeHttpResponse:
    headers = (
        ()
        if content_type is None
        else (("Content-Type", content_type),)
    )

    return SafeHttpResponse(
        status=status,
        reason="OK",
        headers=headers,
        body=body.encode(),
        connected_address="127.0.0.1",
        elapsed_milliseconds=1,
    )


class CrawlPolicyTests(unittest.TestCase):
    def test_defaults_are_bounded(self) -> None:
        policy = CrawlPolicy()

        self.assertEqual(policy.maximum_pages, 10)
        self.assertEqual(policy.maximum_depth, 1)
        self.assertEqual(policy.query_mode, CrawlQueryMode.DROP)

    def test_rejects_page_limit_above_hard_maximum(self) -> None:
        with self.assertRaises(CrawlPolicyError) as context:
            CrawlPolicy(maximum_pages=MAXIMUM_CRAWL_PAGES + 1)

        self.assertEqual(
            context.exception.code,
            "maximum_pages_invalid",
        )

    def test_rejects_invalid_query_mode(self) -> None:
        with self.assertRaises(CrawlPolicyError) as context:
            CrawlPolicy(query_mode="drop")  # type: ignore[arg-type]

        self.assertEqual(
            context.exception.code,
            "query_mode_invalid",
        )

    def test_rejects_negative_delay(self) -> None:
        with self.assertRaises(CrawlPolicyError) as context:
            CrawlPolicy(minimum_delay_seconds=-1)

        self.assertEqual(
            context.exception.code,
            "minimum_delay_invalid",
        )


class SameOriginCrawlerTests(unittest.TestCase):
    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_fetches_root_and_same_origin_links_breadth_first(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = [
            response(
                '<a href="/b">B</a>'
                '<a href="/a">A</a>'
            ),
            response(),
            response(),
        ]

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=3,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(
            tuple(page.url for page in result.pages),
            (
                "http://127.0.0.1:3000/",
                "http://127.0.0.1:3000/a",
                "http://127.0.0.1:3000/b",
            ),
        )
        self.assertEqual(result.requests_attempted, 3)
        self.assertEqual(result.requests_succeeded, 3)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_deduplicates_normalised_urls(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = [
            response(
                '<a href="/a">one</a>'
                '<a href="/x/../a#part">two</a>'
                '<a href="/a?token=secret">three</a>'
            ),
            response(),
        ]

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=5,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 2)
        self.assertEqual(
            result.pages[1].url,
            "http://127.0.0.1:3000/a",
        )
        skipped = {
            item.reason: item.count
            for item in result.skipped_links
        }
        self.assertEqual(
            skipped[CrawlSkipReason.DUPLICATE],
            2,
        )

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_does_not_follow_external_or_unsupported_links(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            '<a href="https://example.com/">external</a>'
            '<a href="mailto:test@example.com">mail</a>'
            '<a href="javascript:alert(1)">script</a>'
        )

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=2,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 1)
        skipped = {
            item.reason: item.count
            for item in result.skipped_links
        }
        self.assertEqual(
            skipped[CrawlSkipReason.EXTERNAL_ORIGIN],
            1,
        )
        self.assertEqual(
            skipped[CrawlSkipReason.UNSUPPORTED_SCHEME],
            2,
        )

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_blocks_destructive_paths(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            '<a href="/logout">logout</a>'
            '<a href="/account/delete-account">delete</a>'
            '<a href="/checkout">checkout</a>'
        )

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 1)
        self.assertEqual(
            result.skipped_links[0].reason,
            CrawlSkipReason.DESTRUCTIVE_PATH,
        )
        self.assertEqual(result.skipped_links[0].count, 3)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_query_drop_removes_sensitive_values(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        secret = "super-secret-token"
        fetch_mock.side_effect = [
            response(
                f'<a href="/profile?token={secret}">profile</a>'
            ),
            response(),
        ]

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertNotIn(secret, repr(result))
        self.assertEqual(
            result.pages[1].url,
            "http://127.0.0.1:3000/profile",
        )

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_query_reject_mode_does_not_queue_query_urls(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            '<a href="/search?q=secret">search</a>'
        )

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                query_mode=CrawlQueryMode.REJECT,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 1)
        self.assertEqual(
            result.skipped_links[0].reason,
            CrawlSkipReason.QUERY_REJECTED,
        )

    def test_reject_query_mode_rejects_query_root(self) -> None:
        with self.assertRaises(CrawlPolicyError) as context:
            crawl_same_origin(
                target(
                    "http://127.0.0.1:3000/?token=secret"
                ),
                crawl_policy=CrawlPolicy(
                    query_mode=CrawlQueryMode.REJECT,
                ),
            )

        self.assertEqual(
            context.exception.code,
            "root_query_rejected",
        )

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_only_discovers_from_allowed_html_content(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            '<a href="/should-not-run">link</a>',
            content_type="application/json",
        )

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=2,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 1)
        self.assertEqual(result.pages[0].discovered_links, 0)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_ignores_forms_scripts_and_images(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            '<form action="/delete-account"></form>'
            '<script src="/script.js"></script>'
            '<img src="/image.png">'
        )

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=2,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 1)
        self.assertEqual(result.pages[0].discovered_links, 0)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.time.sleep",
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_retryable_failure_can_succeed(
        self,
        fetch_mock,
        sleep_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = [
            SafeRequestError(
                "connection_timeout",
                "timed out",
            ),
            response(),
        ]

        result = crawl_same_origin(
            target(),
            retry_policy=RetryPolicy(
                maximum_attempts=2,
                initial_backoff_seconds=0.25,
                maximum_backoff_seconds=0.25,
            ),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
        )

        page = result.pages[0]
        self.assertIs(
            page.outcome,
            CrawlPageOutcome.SUCCEEDED,
        )
        self.assertEqual(len(page.attempts), 2)
        self.assertIs(
            page.attempts[0].outcome,
            RequestAttemptOutcome.FAILED,
        )
        sleep_mock.assert_called_once_with(0.25)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_nonretryable_root_failure_is_recorded(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = SafeRequestError(
            "redirect_blocked",
            "redirect blocked",
        )

        result = crawl_same_origin(
            target(),
            retry_policy=RetryPolicy(maximum_attempts=3),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.failed_pages), 1)
        page = result.failed_pages[0]
        self.assertEqual(page.error_code, "redirect_blocked")
        self.assertFalse(page.retryable)
        self.assertEqual(len(page.attempts), 1)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_child_failure_does_not_stop_other_queued_pages(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = [
            response(
                '<a href="/a">a</a>'
                '<a href="/b">b</a>'
            ),
            SafeRequestError(
                "connection_refused",
                "refused",
            ),
            response(),
        ]

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=3,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 3)
        self.assertEqual(len(result.failed_pages), 1)
        self.assertEqual(len(result.successful_pages), 2)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.time.sleep",
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_applies_minimum_delay_between_pages(
        self,
        fetch_mock,
        sleep_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = [
            response('<a href="/a">a</a>'),
            response(),
        ]

        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=1,
                minimum_delay_seconds=0.2,
            ),
        )

        sleep_mock.assert_called_once_with(0.2)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_page_callback_receives_response_without_storing_body(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        secret = "body-secret-that-must-not-be-retained"
        fetch_mock.return_value = response(secret)
        observed = []

        def visitor(page_target, page_response, depth, parent):
            observed.append(
                (
                    page_target.normalised_url,
                    page_response.body,
                    depth,
                    parent,
                )
            )

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            on_page=visitor,
        )

        self.assertEqual(observed[0][1], secret.encode())
        self.assertNotIn(secret, repr(result))
        self.assertFalse(
            hasattr(result.pages[0], "body")
        )

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_page_limit_is_enforced_before_queue_growth(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = [
            response(
                "".join(
                    f'<a href="/p{index}">p</a>'
                    for index in range(10)
                )
            ),
            response(),
            response(),
        ]

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=3,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 3)
        skipped = {
            item.reason: item.count
            for item in result.skipped_links
        }
        self.assertEqual(
            skipped[CrawlSkipReason.PAGE_LIMIT],
            8,
        )

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_link_limit_is_enforced(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = [
            response(
                "".join(
                    f'<a href="/p{index}">p</a>'
                    for index in range(5)
                )
            ),
            response(),
            response(),
        ]

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=10,
                maximum_depth=1,
                maximum_links_per_page=2,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(result.pages), 3)
        skipped = {
            item.reason: item.count
            for item in result.skipped_links
        }
        self.assertEqual(
            skipped[CrawlSkipReason.LINK_LIMIT],
            3,
        )

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_fragment_only_links_are_not_requested(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            '<a href="#section">section</a>'
        )

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        fetch_mock.assert_called_once()
        self.assertEqual(
            result.skipped_links[0].reason,
            CrawlSkipReason.FRAGMENT_ONLY,
        )

    def test_rejects_inconsistent_validated_root(self) -> None:
        inconsistent = ValidatedTarget(
            original_url="http://127.0.0.1:3000/",
            normalised_url="http://example.com/",
            scheme="http",
            hostname="127.0.0.1",
            port=3000,
            resolved_addresses=("127.0.0.1",),
        )

        with self.assertRaises(CrawlPolicyError) as context:
            crawl_same_origin(inconsistent)

        self.assertEqual(
            context.exception.code,
            "validated_target_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
