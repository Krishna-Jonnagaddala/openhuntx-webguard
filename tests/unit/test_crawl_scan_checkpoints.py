
"""Tests for crawl-scan checkpoint creation and safe resume orchestration."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from webguard_contracts import (
    CrawlCheckpoint,
    CrawlCheckpointResumeError,
    CrawlTerminationReason,
    ScanStatus,
)

from webguard_scanner import (
    CrawlCancellationToken,
    CrawlPolicy,
    SafeHttpResponse,
    ValidatedTarget,
    run_passive_crawl_scan,
)


NOW = datetime(2026, 8, 3, 23, 0, tzinfo=timezone.utc)
SCAN_ID = "7214e74c-7633-472c-8b83-555c7d59419d"


def target(
    *,
    address: str = "127.0.0.1",
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url="http://127.0.0.1:3000/",
        normalised_url="http://127.0.0.1:3000/",
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=(address,),
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


class CrawlScanCheckpointTests(unittest.TestCase):
    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_cancelled_checkpoint_resumes_without_refetching_completed_page(
        self,
        fetch_mock,
        _crawler_clock,
        _scan_clock,
    ) -> None:
        token = CrawlCancellationToken()
        checkpoints: list[CrawlCheckpoint] = []
        fetch_mock.return_value = response('<a href="/a">a</a>')

        def save(checkpoint: CrawlCheckpoint) -> None:
            checkpoints.append(checkpoint)
            if checkpoint.pages and checkpoint.pending_pages:
                token.cancel()

        first = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=2,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=NOW,
            cancellation_token=token,
            checkpoint_callback=save,
        )

        self.assertIs(first.status, ScanStatus.CANCELLED)
        resume = checkpoints[-1]
        self.assertEqual(len(resume.pages), 1)
        self.assertEqual(len(resume.pending_pages), 1)
        root_findings = resume.pages[0].findings
        self.assertTrue(root_findings)

        fetch_mock.reset_mock()
        fetch_mock.return_value = response()
        resumed_checkpoints: list[CrawlCheckpoint] = []

        second = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=2,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
            resume_checkpoint=resume,
            checkpoint_callback=resumed_checkpoints.append,
        )

        self.assertIs(second.status, ScanStatus.COMPLETED)
        self.assertIs(
            second.termination.reason,
            CrawlTerminationReason.COMPLETED,
        )
        self.assertEqual(second.scan_id, SCAN_ID)
        self.assertEqual(second.started_at, NOW)
        self.assertEqual(len(second.pages), 2)
        self.assertEqual(second.pages[0].findings, root_findings)
        self.assertEqual(fetch_mock.call_count, 1)
        self.assertEqual(second.request_attempt_count, 2)
        self.assertEqual(
            resumed_checkpoints[-1].pending_pages,
            (),
        )
        self.assertNotIn(
            "response_body",
            resumed_checkpoints[-1].to_json(b"k" * 32),
        )

    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_pre_request_cancellation_writes_resumable_root_checkpoint(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        token = CrawlCancellationToken()
        token.cancel()
        checkpoints: list[CrawlCheckpoint] = []

        result = run_passive_crawl_scan(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_depth=0,
                minimum_delay_seconds=0,
            ),
            scan_id=SCAN_ID,
            started_at=NOW,
            cancellation_token=token,
            checkpoint_callback=checkpoints.append,
        )

        fetch_mock.assert_not_called()
        self.assertIs(result.status, ScanStatus.CANCELLED)
        self.assertTrue(checkpoints)
        self.assertEqual(checkpoints[-1].pages, ())
        self.assertEqual(len(checkpoints[-1].pending_pages), 1)
        self.assertEqual(checkpoints[-1].attempts_used, 0)

    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_resume_rejects_changed_policy(
        self,
        fetch_mock,
        _crawler_clock,
        _scan_clock,
    ) -> None:
        token = CrawlCancellationToken()
        token.cancel()
        checkpoints: list[CrawlCheckpoint] = []
        policy = CrawlPolicy(
            maximum_pages=2,
            maximum_depth=1,
            minimum_delay_seconds=0,
        )

        run_passive_crawl_scan(
            target(),
            crawl_policy=policy,
            scan_id=SCAN_ID,
            started_at=NOW,
            cancellation_token=token,
            checkpoint_callback=checkpoints.append,
        )

        with self.assertRaises(CrawlCheckpointResumeError):
            run_passive_crawl_scan(
                target(),
                crawl_policy=CrawlPolicy(
                    maximum_pages=3,
                    maximum_depth=1,
                    minimum_delay_seconds=0,
                ),
                resume_checkpoint=checkpoints[-1],
            )

        fetch_mock.assert_not_called()

    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_resume_rejects_revalidated_address_change(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        token = CrawlCancellationToken()
        token.cancel()
        checkpoints: list[CrawlCheckpoint] = []

        run_passive_crawl_scan(
            target(),
            cancellation_token=token,
            scan_id=SCAN_ID,
            started_at=NOW,
            checkpoint_callback=checkpoints.append,
        )

        with self.assertRaises(Exception):
            run_passive_crawl_scan(
                target(address="127.0.0.2"),
                resume_checkpoint=checkpoints[-1],
            )

        fetch_mock.assert_not_called()

    @patch(
        "webguard_scanner.crawl_scan._utc_now",
        return_value=NOW,
    )
    @patch(
        "webguard_scanner.crawler.fetch_once",
    )
    def test_resume_rejects_different_scan_id(
        self,
        fetch_mock,
        _clock_mock,
    ) -> None:
        token = CrawlCancellationToken()
        token.cancel()
        checkpoints: list[CrawlCheckpoint] = []

        run_passive_crawl_scan(
            target(),
            cancellation_token=token,
            scan_id=SCAN_ID,
            started_at=NOW,
            checkpoint_callback=checkpoints.append,
        )

        with self.assertRaises(ValueError):
            run_passive_crawl_scan(
                target(),
                resume_checkpoint=checkpoints[-1],
                scan_id="dc976a91-5ad1-4177-8479-eb43764ad1c3",
            )

        fetch_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
