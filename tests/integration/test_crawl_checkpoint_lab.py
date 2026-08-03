
"""Authorised OWASP Juice Shop signed-checkpoint resume integration test."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from webguard_contracts import (
    CrawlCheckpoint,
    CrawlTerminationReason,
    ScanStatus,
    load_crawl_checkpoint_file,
    write_crawl_checkpoint_file,
)

from webguard_scanner import (
    CrawlCancellationToken,
    CrawlPolicy,
    FetchPolicy,
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
KEY = b"authorised-lab-checkpoint-key-" + b"k" * 16


@unittest.skipUnless(
    RUN_INTEGRATION,
    "Set WEBGUARD_RUN_INTEGRATION=1 to run network integration tests.",
)
class CrawlCheckpointLabIntegrationTests(unittest.TestCase):
    def test_pre_request_checkpoint_resumes_juice_shop(self) -> None:
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
        policy = CrawlPolicy(
            maximum_pages=5,
            maximum_depth=1,
            maximum_links_per_page=100,
            minimum_delay_seconds=0,
            maximum_execution_seconds=30,
            maximum_request_attempts=10,
        )

        token = CrawlCancellationToken()
        token.cancel()
        checkpoints: list[CrawlCheckpoint] = []

        cancelled = run_passive_crawl_scan(
            target,
            crawl_policy=policy,
            fetch_policy=FetchPolicy(
                timeout_seconds=5,
                maximum_body_bytes=2_097_152,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
            ),
            cancellation_token=token,
            checkpoint_callback=checkpoints.append,
        )

        self.assertIs(cancelled.status, ScanStatus.CANCELLED)
        self.assertEqual(cancelled.request_attempt_count, 0)
        self.assertTrue(checkpoints)
        self.assertEqual(len(checkpoints[-1].pending_pages), 1)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "juice-shop.checkpoint.json"
            write_crawl_checkpoint_file(
                checkpoints[-1],
                path,
                KEY,
                overwrite=False,
            )
            loaded = load_crawl_checkpoint_file(path, KEY)

        resumed_checkpoints: list[CrawlCheckpoint] = []
        resumed = run_passive_crawl_scan(
            target,
            crawl_policy=policy,
            fetch_policy=FetchPolicy(
                timeout_seconds=5,
                maximum_body_bytes=2_097_152,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
            ),
            resume_checkpoint=loaded,
            checkpoint_callback=resumed_checkpoints.append,
        )

        self.assertIs(resumed.status, ScanStatus.COMPLETED)
        self.assertIs(
            resumed.termination.reason,
            CrawlTerminationReason.COMPLETED,
        )
        self.assertEqual(resumed.scan_id, loaded.scan_id)
        self.assertGreaterEqual(len(resumed.pages), 1)
        self.assertGreaterEqual(resumed.request_attempt_count, 1)
        self.assertEqual(
            resumed_checkpoints[-1].pending_pages,
            (),
        )
        self.assertEqual(
            resumed_checkpoints[-1].target,
            target.normalised_url,
        )


if __name__ == "__main__":
    unittest.main()
