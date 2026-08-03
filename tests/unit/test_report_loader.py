"""Tests for strict scan report loading and schema compatibility."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_contracts import (
    Confidence,
    Evidence,
    ExternalIdentifier,
    FindingIdentity,
    MalformedScanReportError,
    NormalizedFinding,
    RequestAttempt,
    RequestAttemptOutcome,
    ScanCoverage,
    ScanResult,
    ScanStatus,
    Severity,
    SkippedCheck,
    UnsupportedSchemaVersionError,
    load_scan_result,
    load_scan_result_file,
    load_scan_result_json,
)


STARTED_AT = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
ATTEMPT_COMPLETED_AT = STARTED_AT + timedelta(milliseconds=25)
COMPLETED_AT = STARTED_AT + timedelta(milliseconds=40)
SCAN_ID = "7bd54752-8df1-4f06-aac8-bdcb8441902e"


def finding() -> NormalizedFinding:
    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id="web.headers.csp.missing",
            asset="http://127.0.0.1:3000",
            path="/",
            method="GET",
        ),
        source="webguard-passive",
        source_rule_id="HTTP-HEADER-004",
        title="Content-Security-Policy header missing",
        description="The response does not define a CSP.",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        remediation="Deploy a tested CSP.",
        detected_at=ATTEMPT_COMPLETED_AT,
        identifiers=(
            ExternalIdentifier("CWE", "CWE-693"),
        ),
        evidence=(
            Evidence("No CSP response header was observed."),
        ),
        references=(
            "https://owasp.org/www-project-secure-headers/",
        ),
        tags=("http-headers", "passive"),
    )


def result() -> ScanResult:
    return ScanResult(
        scan_id=SCAN_ID,
        scan_type="passive-http-headers",
        status=ScanStatus.COMPLETED,
        target="http://127.0.0.1:3000/",
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=STARTED_AT,
        completed_at=COMPLETED_AT,
        coverage=ScanCoverage(
            planned_checks=(
                "web.headers.csp",
                "web.headers.hsts",
            ),
            executed_checks=("web.headers.csp",),
            skipped_checks=(
                SkippedCheck(
                    "web.headers.hsts",
                    "HSTS applies only to HTTPS.",
                ),
            ),
            requests_attempted=1,
            requests_succeeded=1,
        ),
        findings=(finding(),),
        connected_addresses=("127.0.0.1",),
        http_statuses=(200,),
        request_attempts=(
            RequestAttempt(
                attempt_number=1,
                started_at=STARTED_AT,
                completed_at=ATTEMPT_COMPLETED_AT,
                outcome=RequestAttemptOutcome.SUCCEEDED,
                connected_address="127.0.0.1",
                http_status=200,
            ),
        ),
    )


def current_report() -> dict[str, object]:
    return result().to_dict()


def legacy_report() -> dict[str, object]:
    report = current_report()
    report["schema_version"] = "1.0"
    report.pop("request_attempt_count")
    report.pop("request_attempts")
    return report


class ReportLoaderTests(unittest.TestCase):
    """Verify strict loading, migration, and corruption rejection."""

    def test_loads_current_report_dictionary(self) -> None:
        loaded = load_scan_result(current_report())

        self.assertEqual(loaded, result())
        self.assertEqual(loaded.schema_version, "1.1")

    def test_current_json_round_trip_is_deterministic(self) -> None:
        original = result().to_json()
        loaded = load_scan_result_json(original)

        self.assertEqual(loaded.to_json(), original)

    def test_loads_report_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text(result().to_json(), encoding="utf-8")

            loaded = load_scan_result_file(path)

        self.assertEqual(loaded, result())

    def test_migrates_legacy_1_0_report(self) -> None:
        loaded = load_scan_result(legacy_report())

        self.assertEqual(loaded.schema_version, "1.1")
        self.assertEqual(loaded.request_attempts, ())
        self.assertEqual(loaded.coverage.requests_attempted, 1)
        self.assertEqual(loaded.findings, result().findings)

    def test_legacy_json_reserialises_as_current_schema(self) -> None:
        loaded = load_scan_result_json(
            json.dumps(legacy_report())
        )
        migrated = json.loads(loaded.to_json())

        self.assertEqual(migrated["schema_version"], "1.1")
        self.assertEqual(migrated["request_attempt_count"], 0)
        self.assertEqual(migrated["request_attempts"], [])

    def test_rejects_invalid_json(self) -> None:
        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result_json("{not-json}")

        self.assertEqual(context.exception.code, "scan_report_json_invalid")

    def test_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result_json(
                '{"schema_version":"1.1","schema_version":"1.0"}'
            )

        self.assertEqual(context.exception.code, "scan_report_duplicate_key")

    def test_rejects_invalid_utf8(self) -> None:
        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result_json(b"\xff")

        self.assertEqual(context.exception.code, "scan_report_encoding_invalid")

    def test_rejects_unencodable_text(self) -> None:
        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result_json("\ud800")

        self.assertEqual(context.exception.code, "scan_report_encoding_invalid")

    def test_rejects_report_above_size_limit(self) -> None:
        with patch(
            "webguard_contracts.report_loader.MAXIMUM_SCAN_REPORT_BYTES",
            4,
        ):
            with self.assertRaises(MalformedScanReportError) as context:
                load_scan_result_json("{}   ")

        self.assertEqual(context.exception.code, "scan_report_too_large")

    def test_rejects_non_object_root(self) -> None:
        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result_json("[]")

        self.assertEqual(context.exception.code, "scan_report_object_required")

    def test_rejects_unsupported_future_schema(self) -> None:
        report = current_report()
        report["schema_version"] = "9.0"

        with self.assertRaises(UnsupportedSchemaVersionError) as context:
            load_scan_result(report)

        self.assertEqual(
            context.exception.code,
            "scan_schema_version_unsupported",
        )

    def test_rejects_missing_root_field(self) -> None:
        report = current_report()
        report.pop("engine")

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(context.exception.code, "scan_report_fields_invalid")

    def test_rejects_unexpected_root_field(self) -> None:
        report = current_report()
        report["secret"] = "unexpected"

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(context.exception.code, "scan_report_fields_invalid")

    def test_rejects_unexpected_nested_field(self) -> None:
        report = current_report()
        report["coverage"]["unexpected"] = True  # type: ignore[index]

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(context.exception.code, "scan_report_fields_invalid")

    def test_rejects_finding_count_mismatch(self) -> None:
        report = current_report()
        report["finding_count"] = 2

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(
            context.exception.code,
            "scan_report_finding_count_mismatch",
        )

    def test_rejects_error_count_mismatch(self) -> None:
        report = current_report()
        report["error_count"] = 1

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(
            context.exception.code,
            "scan_report_error_count_mismatch",
        )

    def test_rejects_attempt_count_mismatch(self) -> None:
        report = current_report()
        report["request_attempt_count"] = 2

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(
            context.exception.code,
            "scan_report_attempt_count_mismatch",
        )

    def test_rejects_corrupted_finding_fingerprint(self) -> None:
        report = current_report()
        report["findings"][0]["fingerprint"] = "0" * 64  # type: ignore[index]

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(
            context.exception.code,
            "scan_report_finding_inconsistent",
        )

    def test_rejects_incorrect_coverage_derived_value(self) -> None:
        report = current_report()
        report["coverage"]["completion_percent"] = 100.0  # type: ignore[index]

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(
            context.exception.code,
            "scan_report_coverage_inconsistent",
        )

    def test_rejects_incorrect_attempt_duration(self) -> None:
        report = current_report()
        report["request_attempts"][0]["duration_milliseconds"] = 999  # type: ignore[index]

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(
            context.exception.code,
            "scan_report_attempt_inconsistent",
        )

    def test_rejects_counter_and_attempt_history_mismatch(self) -> None:
        report = current_report()
        report["coverage"]["requests_attempted"] = 2  # type: ignore[index]

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(
            context.exception.code,
            "scan_report_contract_invalid",
        )

    def test_rejects_invalid_enum_value(self) -> None:
        report = current_report()
        report["status"] = "successful"

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(context.exception.code, "scan_report_enum_invalid")

    def test_rejects_non_canonical_timestamp(self) -> None:
        report = current_report()
        report["started_at"] = "2026-08-03T12:00:00+00:00"

        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result(report)

        self.assertEqual(context.exception.code, "scan_report_non_canonical")

    def test_rejects_missing_file(self) -> None:
        with self.assertRaises(MalformedScanReportError) as context:
            load_scan_result_file("/definitely/missing/webguard-report.json")

        self.assertEqual(
            context.exception.code,
            "scan_report_file_read_failed",
        )

    def test_input_dictionary_is_not_mutated(self) -> None:
        report = current_report()
        original = copy.deepcopy(report)

        load_scan_result(report)

        self.assertEqual(report, original)


if __name__ == "__main__":
    unittest.main()
