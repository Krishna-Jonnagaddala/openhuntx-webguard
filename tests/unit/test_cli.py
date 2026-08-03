from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from webguard_contracts import (
    ScanCoverage,
    ScanError,
    ScanResult,
    ScanStatus,
    load_scan_result_file,
)
from webguard_scanner import cli
from webguard_scanner.scope_validator import ValidatedTarget, ValidationMode


_NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
_TARGET = ValidatedTarget(
    original_url="https://example.com/",
    normalised_url="https://example.com/",
    scheme="https",
    hostname="example.com",
    port=443,
    resolved_addresses=("93.184.216.34",),
)


def _completed_result(scan_id: str) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-headers",
        status=ScanStatus.COMPLETED,
        target="https://example.com/",
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=_NOW,
        completed_at=_NOW,
        coverage=ScanCoverage(),
    )


def _failed_result(scan_id: str) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-headers",
        status=ScanStatus.FAILED,
        target="https://example.com/",
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=_NOW,
        completed_at=_NOW,
        coverage=ScanCoverage(),
        errors=(
            ScanError(
                code="connection_timeout",
                message="The connection timed out.",
                stage="request",
                retryable=True,
            ),
        ),
    )


class CliTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_version_uses_engine_version(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                cli.main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(stdout.getvalue(), "webguard 0.1.0\n")

    def test_scan_uses_commercial_mode_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"

            with patch.object(
                cli,
                "validate_target_url",
                return_value=_TARGET,
            ) as validate, patch.object(
                cli,
                "run_passive_header_scan",
                side_effect=lambda *args, **kwargs: _completed_result(
                    kwargs["scan_id"]
                ),
            ) as scan:
                exit_code, stdout, stderr = self._run(
                    ["scan", "https://example.com", "-o", str(output)]
                )

            self.assertEqual(exit_code, cli.EXIT_SUCCESS)
            self.assertEqual(stderr, "")
            self.assertIn("Status: completed", stdout)
            self.assertTrue(output.exists())
            self.assertEqual(
                load_scan_result_file(output).status,
                ScanStatus.COMPLETED,
            )

            policy = validate.call_args.args[1]
            self.assertEqual(policy.mode, ValidationMode.COMMERCIAL)
            self.assertEqual(policy.allowed_lab_hosts, frozenset())
            self.assertEqual(scan.call_count, 1)

    def test_lab_mode_requires_explicit_allowlist(self) -> None:
        with patch.object(cli, "validate_target_url") as validate:
            exit_code, stdout, stderr = self._run(
                ["scan", "http://127.0.0.1:3000/", "--lab"]
            )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertEqual(stdout, "")
        self.assertIn("lab_allowlist_required", stderr)
        validate.assert_not_called()

    def test_allow_host_is_rejected_without_lab_mode(self) -> None:
        exit_code, _, stderr = self._run(
            [
                "scan",
                "https://example.com",
                "--allow-host",
                "example.com",
            ]
        )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("allow_host_requires_lab_mode", stderr)

    def test_lab_mode_passes_only_configured_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"

            with patch.object(
                cli,
                "validate_target_url",
                return_value=_TARGET,
            ) as validate, patch.object(
                cli,
                "run_passive_header_scan",
                side_effect=lambda *args, **kwargs: _completed_result(
                    kwargs["scan_id"]
                ),
            ):
                exit_code, _, _ = self._run(
                    [
                        "scan",
                        "http://127.0.0.1:3000/",
                        "--lab",
                        "--allow-host",
                        "127.0.0.1",
                        "--allow-host",
                        "localhost",
                        "-o",
                        str(output),
                    ]
                )

            self.assertEqual(exit_code, cli.EXIT_SUCCESS)
            policy = validate.call_args.args[1]
            self.assertEqual(policy.mode, ValidationMode.LAB)
            self.assertEqual(
                policy.allowed_lab_hosts,
                frozenset({"127.0.0.1", "localhost"}),
            )

    def test_existing_output_is_rejected_before_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("existing", encoding="utf-8")

            with patch.object(cli, "validate_target_url") as validate, patch.object(
                cli,
                "run_passive_header_scan",
            ) as scan:
                exit_code, _, stderr = self._run(
                    ["scan", "https://example.com", "-o", str(output)]
                )

            self.assertEqual(exit_code, cli.EXIT_OUTPUT_FAILED)
            self.assertIn("output_exists", stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing")
            validate.assert_not_called()
            scan.assert_not_called()

    def test_overwrite_replaces_existing_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("existing", encoding="utf-8")

            with patch.object(
                cli,
                "validate_target_url",
                return_value=_TARGET,
            ), patch.object(
                cli,
                "run_passive_header_scan",
                side_effect=lambda *args, **kwargs: _completed_result(
                    kwargs["scan_id"]
                ),
            ):
                exit_code, _, stderr = self._run(
                    [
                        "scan",
                        "https://example.com",
                        "-o",
                        str(output),
                        "--overwrite",
                    ]
                )

            self.assertEqual(exit_code, cli.EXIT_SUCCESS)
            self.assertEqual(stderr, "")
            self.assertEqual(
                load_scan_result_file(output).status,
                ScanStatus.COMPLETED,
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_output_symlink_is_always_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            real_output = Path(directory) / "real.json"
            link_output = Path(directory) / "link.json"
            real_output.write_text("existing", encoding="utf-8")
            link_output.symlink_to(real_output)

            exit_code, _, stderr = self._run(
                [
                    "scan",
                    "https://example.com",
                    "-o",
                    str(link_output),
                    "--overwrite",
                ]
            )

            self.assertEqual(exit_code, cli.EXIT_OUTPUT_FAILED)
            self.assertIn("output_symlink_not_allowed", stderr)
            self.assertEqual(real_output.read_text(encoding="utf-8"), "existing")

    def test_timeout_above_cli_cap_is_rejected(self) -> None:
        exit_code, _, stderr = self._run(
            ["scan", "https://example.com", "--timeout", "61"]
        )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("timeout_seconds_invalid", stderr)

    def test_retry_policy_validation_is_exposed_as_preflight_error(self) -> None:
        exit_code, _, stderr = self._run(
            ["scan", "https://example.com", "--max-attempts", "4"]
        )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("retry_policy_invalid", stderr)

    def test_target_validation_error_is_controlled(self) -> None:
        from webguard_scanner.scope_validator import TargetValidationError

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with patch.object(
                cli,
                "validate_target_url",
                side_effect=TargetValidationError(
                    "private_address_not_allowed",
                    "Private addresses are blocked.",
                ),
            ):
                exit_code, _, stderr = self._run(
                    ["scan", "https://example.com", "-o", str(output)]
                )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("private_address_not_allowed", stderr)

    def test_failed_scan_is_saved_and_returns_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"

            with patch.object(
                cli,
                "validate_target_url",
                return_value=_TARGET,
            ), patch.object(
                cli,
                "run_passive_header_scan",
                side_effect=lambda *args, **kwargs: _failed_result(
                    kwargs["scan_id"]
                ),
            ):
                exit_code, stdout, stderr = self._run(
                    ["scan", "https://example.com", "-o", str(output)]
                )

            self.assertEqual(exit_code, cli.EXIT_SCAN_FAILED)
            self.assertEqual(stderr, "")
            self.assertIn("Status: failed", stdout)
            self.assertEqual(
                load_scan_result_file(output).status,
                ScanStatus.FAILED,
            )

    def test_default_output_uses_generated_scan_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_directory = cli.DEFAULT_OUTPUT_DIRECTORY
            cli.DEFAULT_OUTPUT_DIRECTORY = Path(directory)
            try:
                with patch.object(
                    cli,
                    "validate_target_url",
                    return_value=_TARGET,
                ), patch.object(
                    cli,
                    "run_passive_header_scan",
                    side_effect=lambda *args, **kwargs: _completed_result(
                        kwargs["scan_id"]
                    ),
                ):
                    exit_code, stdout, _ = self._run(
                        ["scan", "https://example.com"]
                    )
            finally:
                cli.DEFAULT_OUTPUT_DIRECTORY = original_directory

            self.assertEqual(exit_code, cli.EXIT_SUCCESS)
            reports = list(Path(directory).glob("*.json"))
            self.assertEqual(len(reports), 1)
            loaded = load_scan_result_file(reports[0])
            self.assertEqual(reports[0].stem, loaded.scan_id)
            self.assertIn(str(reports[0]), stdout)

    def test_report_validate_accepts_valid_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(
                _completed_result("b8aa669a-1d31-4a56-bc0a-cab919e0a987").to_json(),
                encoding="utf-8",
            )

            exit_code, stdout, stderr = self._run(
                ["report", "validate", str(path)]
            )

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertIn("Valid report:", stdout)
        self.assertIn("Normalized schema: 1.1", stdout)

    def test_report_validate_rejects_invalid_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("{not json", encoding="utf-8")

            exit_code, stdout, stderr = self._run(
                ["report", "validate", str(path)]
            )

        self.assertEqual(exit_code, cli.EXIT_REPORT_INVALID)
        self.assertEqual(stdout, "")
        self.assertIn("scan_report_json_invalid", stderr)

    def test_report_inspect_prints_human_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(
                _completed_result("f260401f-a1e5-4657-915a-5e446fbb9231").to_json(),
                encoding="utf-8",
            )

            exit_code, stdout, _ = self._run(
                ["report", "inspect", str(path)]
            )

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertIn(f"Report: {path}", stdout)
        self.assertIn("Status: completed", stdout)

    def test_report_inspect_json_prints_canonical_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            result = _completed_result(
                "05707c91-ed4e-43ed-8866-4dc2bba8bde7"
            )
            path.write_text(result.to_json(), encoding="utf-8")

            exit_code, stdout, stderr = self._run(
                ["report", "inspect", str(path), "--json"]
            )

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout), result.to_dict())


if __name__ == "__main__":
    unittest.main()
