
"""Tests for signed crawl checkpoint contracts and atomic persistence."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_contracts import (
    CrawlCheckpoint,
    CrawlCheckpointFetchPolicy,
    CrawlCheckpointIntegrityError,
    CrawlCheckpointLoadError,
    CrawlCheckpointPendingPage,
    CrawlCheckpointResumeError,
    CrawlCheckpointRetryPolicy,
    CrawlLinkSkip,
    CrawlPageScanResult,
    CrawlScanPolicy,
    RequestAttempt,
    RequestAttemptOutcome,
    ScanCoverage,
    ScanStatus,
    load_crawl_checkpoint_file,
    load_crawl_checkpoint_json,
    load_crawl_checkpoint_key_file,
    validate_crawl_checkpoint_resume,
    write_crawl_checkpoint_file,
)


START = datetime(2026, 8, 3, 22, 0, tzinfo=timezone.utc)
UPDATED = START + timedelta(seconds=2)
KEY = b"k" * 32
OTHER_KEY = b"x" * 32
SCAN_ID = "35ff91b9-a63a-46be-ac4c-b0f10054e8e1"


def crawl_policy() -> CrawlScanPolicy:
    return CrawlScanPolicy(
        maximum_pages=5,
        maximum_depth=1,
        maximum_links_per_page=100,
        maximum_url_length=2048,
        minimum_delay_seconds=0.1,
        maximum_execution_seconds=300,
        maximum_request_attempts=20,
        query_mode="drop",
        allowed_content_types=("application/xhtml+xml", "text/html"),
        blocked_path_segments=("delete", "logout"),
    )


def fetch_policy() -> CrawlCheckpointFetchPolicy:
    return CrawlCheckpointFetchPolicy(
        timeout_seconds=10,
        maximum_body_bytes=1_048_576,
        maximum_header_bytes=65_536,
        maximum_header_count=100,
    )


def retry_policy() -> CrawlCheckpointRetryPolicy:
    return CrawlCheckpointRetryPolicy(
        maximum_attempts=1,
        initial_backoff_seconds=0.25,
        backoff_multiplier=2,
        maximum_backoff_seconds=2,
    )


def successful_page() -> CrawlPageScanResult:
    attempt = RequestAttempt(
        attempt_number=1,
        started_at=START + timedelta(milliseconds=10),
        completed_at=START + timedelta(milliseconds=20),
        outcome=RequestAttemptOutcome.SUCCEEDED,
        connected_address="127.0.0.1",
        http_status=200,
    )
    return CrawlPageScanResult(
        url="http://127.0.0.1:3000/",
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
        discovered_links=1,
        queued_links=1,
    )


def checkpoint(*, with_page: bool = True) -> CrawlCheckpoint:
    pages = (successful_page(),) if with_page else ()
    pending = (
        (
            CrawlCheckpointPendingPage(
                url="http://127.0.0.1:3000/a",
                depth=1,
                parent_url="http://127.0.0.1:3000/",
            ),
        )
        if with_page
        else (
            CrawlCheckpointPendingPage(
                url="http://127.0.0.1:3000/",
                depth=0,
                parent_url=None,
            ),
        )
    )
    visited = tuple(sorted(
        [item.url for item in pages]
        + [item.url for item in pending]
    ))
    return CrawlCheckpoint(
        scan_id=SCAN_ID,
        target="http://127.0.0.1:3000/",
        resolved_addresses=("127.0.0.1",),
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=START,
        updated_at=UPDATED,
        policy=crawl_policy(),
        fetch_policy=fetch_policy(),
        retry_policy=retry_policy(),
        pages=pages,
        pending_pages=pending,
        visited_urls=visited,
        skipped_links=(CrawlLinkSkip("external_origin", 2),),
        elapsed_execution_seconds=2,
        attempts_used=sum(
            len(page.request_attempts)
            for page in pages
        ),
    )


class CrawlCheckpointContractTests(unittest.TestCase):
    def test_signed_json_round_trip_is_deterministic(self) -> None:
        original = checkpoint()
        loaded = load_crawl_checkpoint_json(
            original.to_json(KEY),
            KEY,
        )
        self.assertEqual(loaded, original)
        self.assertEqual(
            loaded.to_json(KEY),
            original.to_json(KEY),
        )

    def test_wrong_key_is_rejected(self) -> None:
        document = checkpoint().to_json(KEY)
        with self.assertRaises(CrawlCheckpointIntegrityError):
            load_crawl_checkpoint_json(document, OTHER_KEY)

    def test_payload_modification_is_rejected(self) -> None:
        document = json.loads(checkpoint().to_json(KEY))
        document["payload"]["attempts_used"] = 0
        with self.assertRaises(CrawlCheckpointIntegrityError):
            load_crawl_checkpoint_json(
                json.dumps(document),
                KEY,
            )

    def test_integrity_digest_modification_is_rejected(self) -> None:
        document = json.loads(checkpoint().to_json(KEY))
        document["integrity"]["digest"] = "0" * 64
        with self.assertRaises(CrawlCheckpointIntegrityError):
            load_crawl_checkpoint_json(
                json.dumps(document),
                KEY,
            )

    def test_initial_pending_root_checkpoint_is_valid(self) -> None:
        result = checkpoint(with_page=False)
        self.assertEqual(result.pages, ())
        self.assertEqual(len(result.pending_pages), 1)
        self.assertEqual(result.attempts_used, 0)

    def test_rejects_inconsistent_visited_projection(self) -> None:
        with self.assertRaises(Exception):
            replace(
                checkpoint(),
                visited_urls=("http://127.0.0.1:3000/",),
            )

    def test_rejects_attempt_count_mismatch(self) -> None:
        with self.assertRaises(Exception):
            replace(checkpoint(), attempts_used=0)

    def test_rejects_pending_parent_not_attempted(self) -> None:
        item = CrawlCheckpointPendingPage(
            url="http://127.0.0.1:3000/a",
            depth=1,
            parent_url="http://127.0.0.1:3000/missing",
        )
        with self.assertRaises(Exception):
            replace(
                checkpoint(),
                pending_pages=(item,),
                visited_urls=(
                    "http://127.0.0.1:3000/",
                    "http://127.0.0.1:3000/a",
                ),
            )

    def test_resume_validation_accepts_matching_state(self) -> None:
        validate_crawl_checkpoint_resume(
            checkpoint(),
            target="http://127.0.0.1:3000/",
            resolved_addresses=("127.0.0.1",),
            policy=crawl_policy(),
            fetch_policy=fetch_policy(),
            retry_policy=retry_policy(),
            engine="webguard-native",
            engine_version="0.1.0",
        )

    def test_resume_rejects_changed_addresses(self) -> None:
        with self.assertRaises(Exception):
            validate_crawl_checkpoint_resume(
                checkpoint(),
                target="http://127.0.0.1:3000/",
                resolved_addresses=("127.0.0.2",),
                policy=crawl_policy(),
                fetch_policy=fetch_policy(),
                retry_policy=retry_policy(),
                engine="webguard-native",
                engine_version="0.1.0",
            )

    def test_resume_rejects_changed_policy(self) -> None:
        changed = replace(crawl_policy(), maximum_pages=4)
        with self.assertRaises(Exception):
            validate_crawl_checkpoint_resume(
                checkpoint(),
                target="http://127.0.0.1:3000/",
                resolved_addresses=("127.0.0.1",),
                policy=changed,
                fetch_policy=fetch_policy(),
                retry_policy=retry_policy(),
                engine="webguard-native",
                engine_version="0.1.0",
            )

    def test_resume_rejects_checkpoint_without_pending_pages(self) -> None:
        complete = replace(
            checkpoint(),
            pending_pages=(),
            visited_urls=("http://127.0.0.1:3000/",),
        )
        with self.assertRaises(CrawlCheckpointResumeError):
            validate_crawl_checkpoint_resume(
                complete,
                target="http://127.0.0.1:3000/",
                resolved_addresses=("127.0.0.1",),
                policy=crawl_policy(),
                fetch_policy=fetch_policy(),
                retry_policy=retry_policy(),
                engine="webguard-native",
                engine_version="0.1.0",
            )

    def test_atomic_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crawl.checkpoint.json"
            write_crawl_checkpoint_file(
                checkpoint(),
                path,
                KEY,
                overwrite=False,
            )
            loaded = load_crawl_checkpoint_file(path, KEY)
            self.assertEqual(loaded, checkpoint())
            self.assertFalse(
                any(
                    item.name.endswith(".tmp")
                    for item in Path(directory).iterdir()
                )
            )

    def test_no_overwrite_rejects_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crawl.checkpoint.json"
            write_crawl_checkpoint_file(
                checkpoint(),
                path,
                KEY,
            )
            with self.assertRaises(CrawlCheckpointLoadError):
                write_crawl_checkpoint_file(
                    checkpoint(),
                    path,
                    KEY,
                    overwrite=False,
                )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_checkpoint_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real.json"
            link = Path(directory) / "link.json"
            real.write_text("{}", encoding="utf-8")
            link.symlink_to(real)
            with self.assertRaises(CrawlCheckpointLoadError):
                load_crawl_checkpoint_file(link, KEY)

    def test_private_key_file_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.key"
            path.write_bytes(KEY + b"\n")
            if os.name == "posix":
                path.chmod(0o600)
            self.assertEqual(
                load_crawl_checkpoint_key_file(path),
                KEY,
            )

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_insecure_key_permissions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.key"
            path.write_bytes(KEY)
            path.chmod(0o644)
            with self.assertRaises(CrawlCheckpointLoadError):
                load_crawl_checkpoint_key_file(path)


if __name__ == "__main__":
    unittest.main()
