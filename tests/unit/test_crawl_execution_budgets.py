"""Tests for crawl cancellation and execution budgets."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from webguard_contracts import (
    CrawlTerminationReason,
    RequestAttemptOutcome,
)

from webguard_scanner.crawler import (
    DEFAULT_CRAWL_EXECUTION_SECONDS,
    DEFAULT_CRAWL_REQUEST_ATTEMPTS,
    MAXIMUM_CRAWL_EXECUTION_SECONDS,
    MAXIMUM_CRAWL_REQUEST_ATTEMPTS,
    CrawlCancellationToken,
    CrawlPageOutcome,
    CrawlPolicy,
    CrawlPolicyError,
    CrawlSkipReason,
    crawl_same_origin,
)
from webguard_scanner.retry_policy import RetryPolicy
from webguard_scanner.safe_http import (
    SafeHttpResponse,
    SafeRequestError,
)
from webguard_scanner.scope_validator import ValidatedTarget


NOW = datetime(2026, 8, 3, 19, 0, tzinfo=timezone.utc)


def target() -> ValidatedTarget:
    return ValidatedTarget(
        original_url="http://127.0.0.1:3000/",
        normalised_url="http://127.0.0.1:3000/",
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=("127.0.0.1",),
    )


def response(body: str = "") -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(("Content-Type", "text/html"),),
        body=body.encode(),
        connected_address="127.0.0.1",
        elapsed_milliseconds=1,
    )


class CrawlBudgetPolicyTests(unittest.TestCase):
    def test_defaults_preserve_existing_bounded_behaviour(self) -> None:
        policy = CrawlPolicy()

        self.assertEqual(
            policy.maximum_execution_seconds,
            DEFAULT_CRAWL_EXECUTION_SECONDS,
        )
        self.assertEqual(
            policy.maximum_request_attempts,
            DEFAULT_CRAWL_REQUEST_ATTEMPTS,
        )

    def test_rejects_nonpositive_execution_time(self) -> None:
        with self.assertRaises(CrawlPolicyError) as context:
            CrawlPolicy(maximum_execution_seconds=0)

        self.assertEqual(
            context.exception.code,
            "maximum_execution_seconds_invalid",
        )

    def test_rejects_execution_time_above_hard_limit(self) -> None:
        with self.assertRaises(CrawlPolicyError):
            CrawlPolicy(
                maximum_execution_seconds=(
                    MAXIMUM_CRAWL_EXECUTION_SECONDS + 1
                )
            )

    def test_rejects_request_budget_outside_hard_limit(self) -> None:
        for value in (0, MAXIMUM_CRAWL_REQUEST_ATTEMPTS + 1):
            with self.subTest(value=value):
                with self.assertRaises(CrawlPolicyError) as context:
                    CrawlPolicy(maximum_request_attempts=value)

                self.assertEqual(
                    context.exception.code,
                    "maximum_request_attempts_invalid",
                )


class CrawlExecutionBudgetTests(unittest.TestCase):
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_pre_cancelled_token_starts_no_request(
        self,
        fetch_mock,
    ) -> None:
        token = CrawlCancellationToken()
        token.cancel()

        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                minimum_delay_seconds=0,
            ),
            cancellation_token=token,
        )

        self.assertEqual(execution.pages, ())
        self.assertEqual(execution.pages_pending, 1)
        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.CANCELLED,
        )
        fetch_mock.assert_not_called()

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_cancellation_after_root_prevents_child_request(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        token = CrawlCancellationToken()
        fetch_mock.return_value = response(
            '<a href="/child">child</a>'
        )

        def visitor(*_args) -> None:
            token.cancel()

        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=2,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
            on_page=visitor,
            cancellation_token=token,
        )

        self.assertEqual(len(execution.pages), 1)
        self.assertEqual(execution.pages_pending, 1)
        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.CANCELLED,
        )
        fetch_mock.assert_called_once()

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_request_budget_prevents_child_request(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.return_value = response(
            '<a href="/child">child</a>'
        )

        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=2,
                maximum_depth=1,
                maximum_request_attempts=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(len(execution.pages), 1)
        self.assertEqual(execution.pages_pending, 1)
        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
        )
        fetch_mock.assert_called_once()

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_request_budget_prevents_retry_and_fixes_audit(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        fetch_mock.side_effect = SafeRequestError(
            "connection_timeout",
            "timeout",
        )

        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_request_attempts=1,
                minimum_delay_seconds=0,
            ),
            retry_policy=RetryPolicy(
                maximum_attempts=3,
                initial_backoff_seconds=0.25,
            ),
        )

        self.assertEqual(len(execution.pages), 1)
        page = execution.pages[0]
        self.assertIs(page.outcome, CrawlPageOutcome.FAILED)
        self.assertEqual(len(page.attempts), 1)
        self.assertFalse(page.attempts[0].retry_scheduled)
        self.assertEqual(page.attempts[0].backoff_seconds, 0.0)
        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
        )
        fetch_mock.assert_called_once()

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
        return_value=response(),
    )
    def test_exact_request_budget_can_complete(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_request_attempts=1,
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
        )

        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.COMPLETED,
        )
        self.assertEqual(execution.pages_pending, 0)
        fetch_mock.assert_called_once()

    @patch(
        "webguard_scanner.crawler.time.monotonic",
        side_effect=(0.0, 2.0),
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_expired_deadline_starts_no_request(
        self,
        fetch_mock,
        _monotonic_mock,
    ) -> None:
        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_execution_seconds=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertEqual(execution.pages, ())
        self.assertEqual(execution.pages_pending, 1)
        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.TIME_LIMIT_REACHED,
        )
        fetch_mock.assert_not_called()

    @patch(
        "webguard_scanner.crawler.time.sleep",
    )
    @patch(
        "webguard_scanner.crawler.time.monotonic",
        side_effect=(0.0, 0.0, 0.0, 0.9, 0.9),
    )
    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
        side_effect=SafeRequestError(
            "connection_timeout",
            "timeout",
        ),
    )
    def test_deadline_blocks_retry_backoff_and_second_request(
        self,
        fetch_mock,
        _clock_mock,
        _monotonic_mock,
        sleep_mock,
    ) -> None:
        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_execution_seconds=1,
                maximum_request_attempts=3,
                minimum_delay_seconds=0,
            ),
            retry_policy=RetryPolicy(
                maximum_attempts=3,
                initial_backoff_seconds=0.25,
            ),
        )

        page = execution.pages[0]
        self.assertFalse(page.attempts[0].retry_scheduled)
        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.TIME_LIMIT_REACHED,
        )
        fetch_mock.assert_called_once()
        sleep_mock.assert_not_called()

    @patch(
        "webguard_scanner.crawler.time.monotonic",
        return_value=0.0,
    )
    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
        side_effect=SafeRequestError(
            "connection_timeout",
            "timeout",
        ),
    )
    def test_cancellation_during_backoff_prevents_retry(
        self,
        fetch_mock,
        _clock_mock,
        _monotonic_mock,
    ) -> None:
        token = CrawlCancellationToken()

        with patch(
            "webguard_scanner.crawler.time.sleep",
            side_effect=lambda _seconds: token.cancel(),
        ) as sleep_mock:
            execution = crawl_same_origin(
                target(),
                crawl_policy=CrawlPolicy(
                    maximum_request_attempts=3,
                    minimum_delay_seconds=0,
                ),
                retry_policy=RetryPolicy(
                    maximum_attempts=3,
                    initial_backoff_seconds=0.25,
                ),
                cancellation_token=token,
            )

        page = execution.pages[0]
        self.assertFalse(page.attempts[0].retry_scheduled)
        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.CANCELLED,
        )
        fetch_mock.assert_called_once()
        sleep_mock.assert_called_once_with(0.25)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
        return_value=response(
            '<a href="/child">child</a>'
        ),
    )
    def test_page_limit_has_explicit_normal_termination(
        self,
        _fetch_mock,
        _clock_mock,
    ) -> None:
        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=1,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
        )

        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.PAGE_LIMIT_REACHED,
        )
        skips = {
            item.reason: item.count
            for item in execution.skipped_links
        }
        self.assertEqual(skips[CrawlSkipReason.PAGE_LIMIT], 1)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
        side_effect=SafeRequestError(
            "connection_refused",
            "refused",
        ),
    )
    def test_root_failure_has_explicit_termination(
        self,
        _fetch_mock,
        _clock_mock,
    ) -> None:
        execution = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                minimum_delay_seconds=0,
            ),
        )

        self.assertIs(
            execution.termination_reason,
            CrawlTerminationReason.ROOT_REQUEST_FAILED,
        )
        self.assertEqual(execution.pages_pending, 0)
        self.assertIs(
            execution.pages[0].attempts[0].outcome,
            RequestAttemptOutcome.FAILED,
        )


if __name__ == "__main__":
    unittest.main()
