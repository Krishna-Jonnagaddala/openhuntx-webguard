"""CLI tests for crawl execution budgets and graceful cancellation."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from webguard_contracts import (
    CrawlScanPolicy,
    CrawlScanResult,
    CrawlScanTermination,
    CrawlTerminationReason,
    ScanStatus,
    load_webguard_report_file,
)
from webguard_scanner import (
    CrawlCancellationToken,
    ValidatedTarget,
)
from webguard_scanner import cli


NOW = datetime(2026, 8, 3, 22, 0, tzinfo=timezone.utc)
TARGET = ValidatedTarget(
    original_url="https://example.com/",
    normalised_url="https://example.com/",
    scheme="https",
    hostname="example.com",
    port=443,
    resolved_addresses=("93.184.216.34",),
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
        policy=CrawlScanPolicy(
            maximum_pages=5,
            maximum_depth=1,
            maximum_links_per_page=50,
            maximum_url_length=2048,
            minimum_delay_seconds=0.1,
            query_mode="drop",
            allowed_content_types=("text/html",),
            blocked_path_segments=("delete",),
            maximum_execution_seconds=45,
            maximum_request_attempts=7,
        ),
        pages=(),
        termination=CrawlScanTermination(
            reason=CrawlTerminationReason.CANCELLED,
            pages_pending=1,
        ),
    )


class CrawlBudgetCliTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = cli.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_budget_options_are_passed_to_crawl_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "crawl.json"

            with patch.object(
                cli,
                "validate_target_url",
                return_value=TARGET,
            ), patch.object(
                cli,
                "run_passive_crawl_scan",
                side_effect=lambda *args, **kwargs: cancelled_result(
                    kwargs["scan_id"]
                ),
            ) as crawl_scan:
                exit_code, stdout, stderr = self._run(
                    [
                        "scan",
                        "https://example.com",
                        "--crawl",
                        "--crawl-time-limit",
                        "45",
                        "--crawl-request-budget",
                        "7",
                        "-o",
                        str(output),
                    ]
                )

        self.assertEqual(exit_code, cli.EXIT_SCAN_FAILED)
        self.assertEqual(stderr, "")
        policy = crawl_scan.call_args.kwargs["crawl_policy"]
        self.assertEqual(policy.maximum_execution_seconds, 45.0)
        self.assertEqual(policy.maximum_request_attempts, 7)
        self.assertIsInstance(
            crawl_scan.call_args.kwargs["cancellation_token"],
            CrawlCancellationToken,
        )
        self.assertIn("Termination: cancelled", stdout)
        self.assertIn("1 pending", stdout)

    def test_time_limit_without_crawl_is_rejected(self) -> None:
        exit_code, stdout, stderr = self._run(
            [
                "scan",
                "https://example.com",
                "--crawl-time-limit",
                "30",
            ]
        )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertEqual(stdout, "")
        self.assertIn("crawl_option_requires_crawl", stderr)

    def test_request_budget_without_crawl_is_rejected(self) -> None:
        exit_code, _, stderr = self._run(
            [
                "scan",
                "https://example.com",
                "--crawl-request-budget",
                "5",
            ]
        )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("crawl_option_requires_crawl", stderr)

    def test_invalid_time_limit_is_controlled_preflight_error(self) -> None:
        exit_code, _, stderr = self._run(
            [
                "scan",
                "https://example.com",
                "--crawl",
                "--crawl-time-limit",
                "0",
            ]
        )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn(
            "maximum_execution_seconds_invalid",
            stderr,
        )

    def test_invalid_request_budget_is_controlled_preflight_error(
        self,
    ) -> None:
        exit_code, _, stderr = self._run(
            [
                "scan",
                "https://example.com",
                "--crawl",
                "--crawl-request-budget",
                "151",
            ]
        )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn(
            "maximum_request_attempts_invalid",
            stderr,
        )

    def test_cancelled_report_is_saved_and_strictly_loadable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "cancelled.json"

            with patch.object(
                cli,
                "validate_target_url",
                return_value=TARGET,
            ), patch.object(
                cli,
                "run_passive_crawl_scan",
                side_effect=lambda *args, **kwargs: cancelled_result(
                    kwargs["scan_id"]
                ),
            ):
                exit_code, stdout, stderr = self._run(
                    [
                        "scan",
                        "https://example.com",
                        "--crawl",
                        "-o",
                        str(output),
                    ]
                )

            loaded = load_webguard_report_file(output)

        self.assertEqual(exit_code, cli.EXIT_SCAN_FAILED)
        self.assertEqual(stderr, "")
        self.assertIs(loaded.status, ScanStatus.CANCELLED)
        self.assertIs(
            loaded.termination.reason,
            CrawlTerminationReason.CANCELLED,
        )
        self.assertIn("Status: cancelled", stdout)

    def test_sigint_handler_requests_token_cancellation(self) -> None:
        token = CrawlCancellationToken()
        installed = []

        def fake_signal(_signal_number, handler):
            installed.append(handler)

        with patch.object(
            cli.signal,
            "getsignal",
            return_value="previous",
        ), patch.object(
            cli.signal,
            "signal",
            side_effect=fake_signal,
        ):
            with cli._graceful_crawl_cancellation(token):
                handler = installed[0]
                handler(None, None)
                self.assertTrue(token.is_cancelled)

        self.assertEqual(installed[-1], "previous")


if __name__ == "__main__":
    unittest.main()
