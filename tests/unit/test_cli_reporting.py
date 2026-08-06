from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from webguard_contracts import (
    Confidence,
    FindingIdentity,
    NormalizedFinding,
    ScanCoverage,
    ScanResult,
    ScanStatus,
    Severity,
    load_report_comparison_file,
)
from webguard_scanner import cli


BASE = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


def finding(rule: str, title: str) -> NormalizedFinding:
    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule,
            asset="https://example.com",
            path="/",
        ),
        source="webguard-native",
        title=title,
        description="Description",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        remediation="Remediate.",
        detected_at=BASE,
    )


def report(
    scan_id: str,
    completed_minute: int,
    findings: tuple[NormalizedFinding, ...] = (),
    target: str = "https://example.com/",
) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-response",
        status=ScanStatus.COMPLETED,
        target=target,
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=BASE + timedelta(minutes=completed_minute - 1),
        completed_at=BASE + timedelta(minutes=completed_minute),
        coverage=ScanCoverage(),
        findings=findings,
    )


class CliReportingTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def _write_reports(self, directory: str) -> tuple[Path, Path]:
        baseline = Path(directory) / "baseline.json"
        current = Path(directory) / "current.json"
        baseline.write_text(
            report(
                "11111111-1111-4111-8111-111111111111",
                1,
                (finding("web.fixed", "Fixed finding"),),
            ).to_json(),
            encoding="utf-8",
        )
        current.write_text(
            report(
                "22222222-2222-4222-8222-222222222222",
                2,
                (finding("web.new", "New finding"),),
            ).to_json(),
            encoding="utf-8",
        )
        return baseline, current

    def test_render_writes_html(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, current = self._write_reports(directory)
            output = Path(directory) / "report.html"
            with patch.object(
                cli,
                "_utc_now",
                return_value=BASE + timedelta(hours=1),
            ):
                code, stdout, stderr = self._run(
                    [
                        "report",
                        "render",
                        str(current),
                        "--organization",
                        "Example Ltd",
                        "--output",
                        str(output),
                    ]
                )
            content = output.read_text(encoding="utf-8")
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertIn("Professional HTML report", stdout)
        self.assertIn("Example Ltd", content)

    @unittest.skipUnless(os.name == "posix", "POSIX permission assertion")
    def test_render_uses_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, current = self._write_reports(directory)
            output = Path(directory) / "report.html"
            with patch.object(
                cli,
                "_utc_now",
                return_value=BASE + timedelta(hours=1),
            ):
                code, _, _ = self._run(
                    [
                        "report",
                        "render",
                        str(current),
                        "--organization",
                        "Example Ltd",
                        "--output",
                        str(output),
                    ]
                )
            mode = stat.S_IMODE(output.stat().st_mode)
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertEqual(mode, 0o600)

    def test_render_with_baseline_includes_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline, current = self._write_reports(directory)
            output = Path(directory) / "report.html"
            with patch.object(
                cli,
                "_utc_now",
                return_value=BASE + timedelta(hours=1),
            ):
                code, stdout, _ = self._run(
                    [
                        "report",
                        "render",
                        str(current),
                        "--baseline",
                        str(baseline),
                        "--organization",
                        "Example Ltd",
                        "--output",
                        str(output),
                    ]
                )
            content = output.read_text(encoding="utf-8")
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertIn("1 new, 0 remaining, 1 fixed", stdout)
        self.assertIn("Remediation verification", content)

    def test_render_rejects_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, current = self._write_reports(directory)
            output = Path(directory) / "report.html"
            output.write_text("existing", encoding="utf-8")
            code, _, stderr = self._run(
                [
                    "report",
                    "render",
                    str(current),
                    "--organization",
                    "Example Ltd",
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("output_exists", stderr)

    def test_render_overwrite_replaces_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, current = self._write_reports(directory)
            output = Path(directory) / "report.html"
            output.write_text("existing", encoding="utf-8")
            with patch.object(
                cli,
                "_utc_now",
                return_value=BASE + timedelta(hours=1),
            ):
                code, _, _ = self._run(
                    [
                        "report",
                        "render",
                        str(current),
                        "--organization",
                        "Example Ltd",
                        "--output",
                        str(output),
                        "--overwrite",
                    ]
                )
            content = output.read_text(encoding="utf-8")
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertTrue(content.startswith("<!doctype html>"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_render_rejects_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, current = self._write_reports(directory)
            target = Path(directory) / "target.html"
            target.write_text("safe", encoding="utf-8")
            link = Path(directory) / "link.html"
            link.symlink_to(target)
            code, _, stderr = self._run(
                [
                    "report",
                    "render",
                    str(current),
                    "--organization",
                    "Example Ltd",
                    "--output",
                    str(link),
                    "--overwrite",
                ]
            )
        self.assertEqual(code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("output_symlink_not_allowed", stderr)

    def test_render_rejects_target_mismatch_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline, current = self._write_reports(directory)
            baseline.write_text(
                report(
                    "11111111-1111-4111-8111-111111111111",
                    1,
                    target="https://other.example/",
                ).to_json(),
                encoding="utf-8",
            )
            output = Path(directory) / "report.html"
            code, _, stderr = self._run(
                [
                    "report",
                    "render",
                    str(current),
                    "--baseline",
                    str(baseline),
                    "--organization",
                    "Example Ltd",
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(code, cli.EXIT_REPORT_INVALID)
        self.assertIn("comparison_target_mismatch", stderr)

    def test_compare_writes_canonical_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline, current = self._write_reports(directory)
            output = Path(directory) / "comparison.json"
            with patch.object(
                cli,
                "_utc_now",
                return_value=BASE + timedelta(hours=1),
            ):
                code, stdout, stderr = self._run(
                    [
                        "report",
                        "compare",
                        str(baseline),
                        str(current),
                        "--output",
                        str(output),
                    ]
                )
            loaded = load_report_comparison_file(output)
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertIn("New findings: 1", stdout)
        self.assertEqual(loaded.new_count, 1)
        self.assertEqual(loaded.fixed_count, 1)

    @unittest.skipUnless(os.name == "posix", "POSIX permission assertion")
    def test_compare_uses_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline, current = self._write_reports(directory)
            output = Path(directory) / "comparison.json"
            with patch.object(
                cli,
                "_utc_now",
                return_value=BASE + timedelta(hours=1),
            ):
                code, _, _ = self._run(
                    [
                        "report",
                        "compare",
                        str(baseline),
                        str(current),
                        "--output",
                        str(output),
                    ]
                )
            mode = stat.S_IMODE(output.stat().st_mode)
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertEqual(mode, 0o600)

    def test_compare_rejects_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline, current = self._write_reports(directory)
            output = Path(directory) / "comparison.json"
            output.write_text("existing", encoding="utf-8")
            code, _, stderr = self._run(
                [
                    "report",
                    "compare",
                    str(baseline),
                    str(current),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("output_exists", stderr)

    def test_validate_comparison_accepts_generated_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline, current = self._write_reports(directory)
            output = Path(directory) / "comparison.json"
            with patch.object(
                cli,
                "_utc_now",
                return_value=BASE + timedelta(hours=1),
            ):
                first, _, _ = self._run(
                    [
                        "report",
                        "compare",
                        str(baseline),
                        str(current),
                        "--output",
                        str(output),
                    ]
                )
            second, stdout, stderr = self._run(
                ["report", "validate-comparison", str(output)]
            )
        self.assertEqual(first, cli.EXIT_SUCCESS)
        self.assertEqual(second, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertIn("Valid comparison", stdout)

    def test_validate_comparison_rejects_invalid_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "invalid.json"
            output.write_text("{}", encoding="utf-8")
            code, _, stderr = self._run(
                ["report", "validate-comparison", str(output)]
            )
        self.assertEqual(code, cli.EXIT_REPORT_INVALID)
        self.assertIn("comparison_fields_invalid", stderr)

    def test_render_requires_organization_argument(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, current = self._write_reports(directory)
            with self.assertRaises(SystemExit) as raised:
                cli.main(
                    [
                        "report",
                        "render",
                        str(current),
                        "--output",
                        str(Path(directory) / "report.html"),
                    ]
                )
        self.assertEqual(raised.exception.code, cli.EXIT_USAGE)

    def test_compare_output_is_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline, current = self._write_reports(directory)
            output = Path(directory) / "comparison.json"
            with patch.object(
                cli,
                "_utc_now",
                return_value=BASE + timedelta(hours=1),
            ):
                code, _, _ = self._run(
                    [
                        "report",
                        "compare",
                        str(baseline),
                        str(current),
                        "--output",
                        str(output),
                    ]
                )
            data = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertEqual(data["schema_version"], "1.0")


if __name__ == "__main__":
    unittest.main()
