
"""CLI tests for signed crawl checkpoints and safe resume."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from webguard_contracts import (
    CrawlCheckpoint,
    CrawlCheckpointFetchPolicy,
    CrawlCheckpointPendingPage,
    CrawlCheckpointRetryPolicy,
    CrawlScanPolicy,
    CrawlScanResult,
    CrawlScanTermination,
    CrawlTerminationReason,
    ScanStatus,
    load_crawl_checkpoint_file,
    write_crawl_checkpoint_file,
)

from webguard_scanner import ValidatedTarget
from webguard_scanner import cli


NOW = datetime(2026, 8, 3, 23, 30, tzinfo=timezone.utc)
SCAN_ID = "596e74ed-4c49-42d2-b967-113e4ded23b8"
KEY = b"k" * 32

TARGET = ValidatedTarget(
    original_url="https://example.com/",
    normalised_url="https://example.com/",
    scheme="https",
    hostname="example.com",
    port=443,
    resolved_addresses=("93.184.216.34",),
)


def policy() -> CrawlScanPolicy:
    return CrawlScanPolicy(
        maximum_pages=5,
        maximum_depth=1,
        maximum_links_per_page=100,
        maximum_url_length=2048,
        minimum_delay_seconds=0.1,
        maximum_execution_seconds=300,
        maximum_request_attempts=150,
        query_mode="drop",
        allowed_content_types=("application/xhtml+xml", "text/html"),
        blocked_path_segments=(
            "checkout",
            "close-account",
            "confirm-order",
            "delete",
            "delete-account",
            "destroy",
            "log-out",
            "logout",
            "pay",
            "payment",
            "place-order",
            "purchase",
            "remove",
            "sign-out",
            "signout",
            "terminate-account",
            "unsubscribe",
        ),
    )


def initial_checkpoint() -> CrawlCheckpoint:
    return CrawlCheckpoint(
        scan_id=SCAN_ID,
        target="https://example.com/",
        resolved_addresses=("93.184.216.34",),
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=NOW,
        updated_at=NOW,
        policy=policy(),
        fetch_policy=CrawlCheckpointFetchPolicy(
            timeout_seconds=10,
            maximum_body_bytes=1_048_576,
            maximum_header_bytes=65_536,
            maximum_header_count=100,
        ),
        retry_policy=CrawlCheckpointRetryPolicy(
            maximum_attempts=1,
            initial_backoff_seconds=0.25,
            backoff_multiplier=2,
            maximum_backoff_seconds=2,
        ),
        pending_pages=(
            CrawlCheckpointPendingPage(
                url="https://example.com/",
                depth=0,
                parent_url=None,
            ),
        ),
        visited_urls=("https://example.com/",),
    )


def cancelled_result(scan_id: str) -> CrawlScanResult:
    return CrawlScanResult(
        scan_id=scan_id,
        scan_type="passive-http-crawl",
        status=ScanStatus.CANCELLED,
        target="https://example.com/",
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=NOW,
        completed_at=NOW,
        policy=policy(),
        pages=(),
        termination=CrawlScanTermination(
            reason=CrawlTerminationReason.CANCELLED,
            pages_pending=1,
        ),
    )


class CrawlCheckpointCliTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = cli.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _key_file(self, directory: str) -> Path:
        path = Path(directory) / "checkpoint.key"
        path.write_bytes(KEY)
        if os.name == "posix":
            path.chmod(0o600)
        return path

    def test_checkpoint_requires_crawl(self) -> None:
        exit_code, _, stderr = self._run(
            [
                "scan",
                "https://example.com/",
                "--checkpoint",
                "crawl.checkpoint.json",
            ]
        )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("checkpoint_option_requires_crawl", stderr)

    def test_checkpoint_requires_key_file(self) -> None:
        exit_code, _, stderr = self._run(
            [
                "scan",
                "https://example.com/",
                "--crawl",
                "--checkpoint",
                "crawl.checkpoint.json",
            ]
        )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("checkpoint_key_required", stderr)

    def test_key_file_without_checkpoint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = self._key_file(directory)
            exit_code, _, stderr = self._run(
                [
                    "scan",
                    "https://example.com/",
                    "--crawl",
                    "--checkpoint-key-file",
                    str(key),
                ]
            )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("checkpoint_key_without_checkpoint", stderr)

    def test_existing_fresh_checkpoint_requires_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = self._key_file(directory)
            checkpoint_path = Path(directory) / "crawl.checkpoint.json"
            checkpoint_path.write_text("existing", encoding="utf-8")
            output = Path(directory) / "report.json"

            exit_code, _, stderr = self._run(
                [
                    "scan",
                    "https://example.com/",
                    "--crawl",
                    "--checkpoint",
                    str(checkpoint_path),
                    "--checkpoint-key-file",
                    str(key),
                    "-o",
                    str(output),
                ]
            )

        self.assertEqual(exit_code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("checkpoint_exists", stderr)

    def test_fresh_crawl_persists_signed_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = self._key_file(directory)
            checkpoint_path = Path(directory) / "crawl.checkpoint.json"
            output = Path(directory) / "report.json"

            def run(*_args, **kwargs):
                checkpoint = initial_checkpoint()
                kwargs["checkpoint_callback"](checkpoint)
                return cancelled_result(kwargs["scan_id"])

            with patch.object(
                cli,
                "validate_target_url",
                return_value=TARGET,
            ), patch.object(
                cli,
                "run_passive_crawl_scan",
                side_effect=run,
            ):
                exit_code, stdout, stderr = self._run(
                    [
                        "scan",
                        "https://example.com/",
                        "--lab",
                        "--allow-host",
                        "example.com",
                        "--crawl",
                        "--crawl-max-pages",
                        "5",
                        "--checkpoint",
                        str(checkpoint_path),
                        "--checkpoint-key-file",
                        str(key),
                        "-o",
                        str(output),
                    ]
                )

            loaded = load_crawl_checkpoint_file(
                checkpoint_path,
                KEY,
            )

        self.assertEqual(exit_code, cli.EXIT_SCAN_FAILED)
        self.assertEqual(stderr, "")
        self.assertEqual(loaded.target, "https://example.com/")
        self.assertIn("Saved checkpoint:", stdout)

    def test_resume_uses_checkpoint_scan_id_and_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = self._key_file(directory)
            checkpoint_path = Path(directory) / "crawl.checkpoint.json"
            write_crawl_checkpoint_file(
                initial_checkpoint(),
                checkpoint_path,
                KEY,
            )
            output = Path(directory) / "report.json"

            with patch.object(
                cli,
                "validate_target_url",
                return_value=TARGET,
            ), patch.object(
                cli,
                "run_passive_crawl_scan",
                side_effect=lambda *_args, **kwargs: cancelled_result(
                    kwargs["resume_checkpoint"].scan_id
                ),
            ) as run:
                exit_code, stdout, stderr = self._run(
                    [
                        "scan",
                        "https://example.com/",
                        "--lab",
                        "--allow-host",
                        "example.com",
                        "--crawl",
                        "--resume-from",
                        str(checkpoint_path),
                        "--checkpoint-key-file",
                        str(key),
                        "-o",
                        str(output),
                    ]
                )

        self.assertEqual(exit_code, cli.EXIT_SCAN_FAILED)
        self.assertEqual(stderr, "")
        self.assertEqual(
            run.call_args.kwargs["resume_checkpoint"].scan_id,
            SCAN_ID,
        )
        self.assertEqual(
            run.call_args.kwargs["crawl_policy"].maximum_pages,
            5,
        )
        self.assertIn(f"Scan ID: {SCAN_ID}", stdout)

    def test_wrong_resume_key_is_rejected_before_target_validation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = self._key_file(directory)
            checkpoint_path = Path(directory) / "crawl.checkpoint.json"
            write_crawl_checkpoint_file(
                initial_checkpoint(),
                checkpoint_path,
                KEY,
            )
            wrong = Path(directory) / "wrong.key"
            wrong.write_bytes(b"x" * 32)
            if os.name == "posix":
                wrong.chmod(0o600)

            with patch.object(
                cli,
                "validate_target_url",
            ) as validate:
                exit_code, _, stderr = self._run(
                    [
                        "scan",
                        "https://example.com/",
                        "--crawl",
                        "--resume-from",
                        str(checkpoint_path),
                        "--checkpoint-key-file",
                        str(wrong),
                    ]
                )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("checkpoint_integrity_failed", stderr)
        validate.assert_not_called()

    def test_checkpoint_and_report_path_cannot_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = self._key_file(directory)
            path = Path(directory) / "same.json"

            exit_code, _, stderr = self._run(
                [
                    "scan",
                    "https://example.com/",
                    "--crawl",
                    "--checkpoint",
                    str(path),
                    "--checkpoint-key-file",
                    str(key),
                    "-o",
                    str(path),
                ]
            )

        self.assertEqual(exit_code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("checkpoint_report_path_conflict", stderr)


if __name__ == "__main__":
    unittest.main()
