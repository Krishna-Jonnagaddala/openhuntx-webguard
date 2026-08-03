
"""Tests for crawler checkpoint snapshots and safe resume state."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from webguard_contracts import CrawlTerminationReason

from webguard_scanner import (
    CrawlCancellationToken,
    CrawlPolicy,
    CrawlPolicyError,
    CrawlResumeState,
    SafeHttpResponse,
    ValidatedTarget,
    crawl_same_origin,
)


NOW = datetime(2026, 8, 3, 22, 30, tzinfo=timezone.utc)


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


def response(body: str = "") -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(("Content-Type", "text/html"),),
        body=body.encode(),
        connected_address="127.0.0.1",
        elapsed_milliseconds=1,
    )


class CrawlResumeTests(unittest.TestCase):
    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_cancelled_crawl_can_resume_pending_breadth_first_queue(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        token = CrawlCancellationToken()
        snapshots: list[CrawlResumeState] = []
        fetch_mock.side_effect = [
            response(
                '<a href="/b">b</a>'
                '<a href="/a">a</a>'
            ),
        ]

        def observe(state: CrawlResumeState) -> None:
            snapshots.append(state)
            if len(state.pages) == 1 and len(state.pending_pages) == 2:
                token.cancel()

        first = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=3,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
            cancellation_token=token,
            on_checkpoint=observe,
        )

        self.assertIs(
            first.termination_reason,
            CrawlTerminationReason.CANCELLED,
        )
        self.assertEqual(first.pages_pending, 2)
        resume = snapshots[-1]
        self.assertEqual(
            tuple(item.url for item in resume.pending_pages),
            (
                "http://127.0.0.1:3000/a",
                "http://127.0.0.1:3000/b",
            ),
        )
        self.assertEqual(resume.attempts_used, 1)

        fetch_mock.reset_mock()
        fetch_mock.side_effect = [response(), response()]
        second_snapshots: list[CrawlResumeState] = []

        second = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=3,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
            resume_state=resume,
            on_checkpoint=second_snapshots.append,
        )

        self.assertIs(
            second.termination_reason,
            CrawlTerminationReason.COMPLETED,
        )
        self.assertEqual(
            tuple(item.url for item in second.pages),
            (
                "http://127.0.0.1:3000/",
                "http://127.0.0.1:3000/a",
                "http://127.0.0.1:3000/b",
            ),
        )
        self.assertEqual(fetch_mock.call_count, 2)
        self.assertEqual(second.requests_attempted, 3)
        self.assertEqual(second_snapshots[-1].pending_pages, ())
        self.assertEqual(second_snapshots[-1].attempts_used, 3)

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_resumed_request_budget_counts_prior_attempts(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        token = CrawlCancellationToken()
        snapshots: list[CrawlResumeState] = []
        fetch_mock.return_value = response(
            '<a href="/a">a</a><a href="/b">b</a>'
        )

        def observe(state: CrawlResumeState) -> None:
            snapshots.append(state)
            if len(state.pages) == 1:
                token.cancel()

        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=3,
                maximum_depth=1,
                maximum_request_attempts=2,
                minimum_delay_seconds=0,
            ),
            cancellation_token=token,
            on_checkpoint=observe,
        )
        resume = snapshots[-1]

        fetch_mock.reset_mock()
        fetch_mock.return_value = response()

        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=3,
                maximum_depth=1,
                maximum_request_attempts=2,
                minimum_delay_seconds=0,
            ),
            resume_state=resume,
        )

        self.assertIs(
            result.termination_reason,
            CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
        )
        self.assertEqual(fetch_mock.call_count, 1)
        self.assertEqual(result.requests_attempted, 2)
        self.assertEqual(result.pages_pending, 1)

    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_cancelled_resume_sends_no_new_request(
        self,
        fetch_mock,
    ) -> None:
        token = CrawlCancellationToken()
        token.cancel()

        initial: list[CrawlResumeState] = []
        # Obtain canonical initial state without sending a request.
        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            cancellation_token=token,
            on_checkpoint=initial.append,
        )

        fetch_mock.reset_mock()
        token2 = CrawlCancellationToken()
        token2.cancel()
        result = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            cancellation_token=token2,
            resume_state=initial[-1],
        )

        fetch_mock.assert_not_called()
        self.assertIs(
            result.termination_reason,
            CrawlTerminationReason.CANCELLED,
        )
        self.assertEqual(result.pages_pending, 1)

    def test_resume_rejects_different_root(self) -> None:
        token = CrawlCancellationToken()
        token.cancel()
        states: list[CrawlResumeState] = []

        crawl_same_origin(
            target(),
            cancellation_token=token,
            on_checkpoint=states.append,
        )

        with self.assertRaises(CrawlPolicyError) as context:
            crawl_same_origin(
                target("http://127.0.0.1:3000/other"),
                resume_state=states[-1],
            )

        self.assertEqual(
            context.exception.code,
            "resume_root_mismatch",
        )

    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_checkpoint_state_never_contains_response_body(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        secret = "secret-response-body"
        fetch_mock.return_value = response(secret)
        states: list[CrawlResumeState] = []

        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            on_checkpoint=states.append,
        )

        self.assertTrue(states)
        self.assertNotIn(secret, repr(states))
        self.assertFalse(
            any(hasattr(page, "body") for state in states for page in state.pages)
        )


if __name__ == "__main__":
    unittest.main()
