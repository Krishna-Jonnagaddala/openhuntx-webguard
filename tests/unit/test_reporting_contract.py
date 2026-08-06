from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_contracts import (
    ComparedFinding,
    Confidence,
    Evidence,
    FindingDisposition,
    FindingIdentity,
    NormalizedFinding,
    ReportComparison,
    ReportComparisonError,
    Severity,
    load_report_comparison,
    load_report_comparison_file,
    load_report_comparison_json,
)


BASE = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


def finding(rule: str = "web.headers.csp.missing") -> NormalizedFinding:
    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule,
            asset="https://example.com",
            path="/account",
        ),
        source="webguard-native",
        title="Content Security Policy missing",
        description="The response does not define a CSP.",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        remediation="Deploy a restrictive policy after report-only validation.",
        detected_at=BASE,
        evidence=(Evidence("No Content-Security-Policy header was present."),),
        references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",),
        tags=("headers", "hardening"),
    )


def comparison() -> ReportComparison:
    return ReportComparison(
        baseline_scan_id="11111111-1111-4111-8111-111111111111",
        current_scan_id="22222222-2222-4222-8222-222222222222",
        target="https://example.com/",
        baseline_completed_at=BASE,
        current_completed_at=BASE + timedelta(hours=1),
        generated_at=BASE + timedelta(hours=2),
        new_findings=(
            ComparedFinding(FindingDisposition.NEW, finding()),
        ),
        remaining_findings=(
            ComparedFinding(
                FindingDisposition.REMAINING,
                finding("web.headers.referrer_policy.missing"),
                presentation_changed=True,
            ),
        ),
        fixed_findings=(
            ComparedFinding(
                FindingDisposition.FIXED,
                finding("web.headers.frame_protection.missing"),
            ),
        ),
    )


class ComparedFindingTests(unittest.TestCase):
    def test_accepts_new_finding(self) -> None:
        item = ComparedFinding(FindingDisposition.NEW, finding())
        self.assertEqual(item.disposition, FindingDisposition.NEW)

    def test_rejects_non_enum_disposition(self) -> None:
        with self.assertRaisesRegex(ReportComparisonError, "FindingDisposition"):
            ComparedFinding("new", finding())  # type: ignore[arg-type]

    def test_rejects_non_finding(self) -> None:
        with self.assertRaisesRegex(ReportComparisonError, "NormalizedFinding"):
            ComparedFinding(FindingDisposition.NEW, object())  # type: ignore[arg-type]

    def test_rejects_non_boolean_changed_flag(self) -> None:
        with self.assertRaises(ReportComparisonError):
            ComparedFinding(
                FindingDisposition.REMAINING,
                finding(),
                presentation_changed=1,  # type: ignore[arg-type]
            )

    def test_rejects_changed_new_finding(self) -> None:
        with self.assertRaisesRegex(ReportComparisonError, "Only remaining"):
            ComparedFinding(
                FindingDisposition.NEW,
                finding(),
                presentation_changed=True,
            )

    def test_to_dict_contains_canonical_finding(self) -> None:
        data = ComparedFinding(FindingDisposition.NEW, finding()).to_dict()
        self.assertEqual(data["disposition"], "new")
        self.assertEqual(data["finding"]["fingerprint"], finding().fingerprint)


class ReportComparisonTests(unittest.TestCase):
    def test_counts_findings(self) -> None:
        item = comparison()
        self.assertEqual(item.new_count, 1)
        self.assertEqual(item.remaining_count, 1)
        self.assertEqual(item.fixed_count, 1)
        self.assertEqual(item.changed_count, 1)

    def test_normalizes_timestamps_to_utc(self) -> None:
        item = replace(
            comparison(),
            generated_at=(BASE + timedelta(hours=3)).astimezone(
                timezone(timedelta(hours=1))
            ),
        )
        self.assertEqual(item.generated_at.tzinfo, timezone.utc)

    def test_sorts_groups_by_fingerprint(self) -> None:
        first = ComparedFinding(
            FindingDisposition.NEW,
            finding("web.z.last"),
        )
        second = ComparedFinding(
            FindingDisposition.NEW,
            finding("web.a.first"),
        )
        item = replace(comparison(), new_findings=(first, second))
        self.assertEqual(
            tuple(entry.finding.fingerprint for entry in item.new_findings),
            tuple(sorted((first.finding.fingerprint, second.finding.fingerprint))),
        )

    def test_rejects_equal_scan_ids(self) -> None:
        item = comparison()
        with self.assertRaisesRegex(ReportComparisonError, "different"):
            replace(item, current_scan_id=item.baseline_scan_id)

    def test_rejects_current_before_baseline(self) -> None:
        with self.assertRaisesRegex(ReportComparisonError, "Current scan"):
            replace(
                comparison(),
                current_completed_at=BASE - timedelta(seconds=1),
            )

    def test_rejects_generated_before_current(self) -> None:
        with self.assertRaisesRegex(ReportComparisonError, "generated_at"):
            replace(comparison(), generated_at=BASE)

    def test_rejects_group_with_wrong_disposition(self) -> None:
        with self.assertRaisesRegex(ReportComparisonError, "disposition"):
            replace(
                comparison(),
                new_findings=(
                    ComparedFinding(FindingDisposition.FIXED, finding()),
                ),
            )

    def test_rejects_duplicate_fingerprint_across_groups(self) -> None:
        duplicate = finding()
        with self.assertRaisesRegex(ReportComparisonError, "only once"):
            replace(
                comparison(),
                new_findings=(ComparedFinding(FindingDisposition.NEW, duplicate),),
                fixed_findings=(ComparedFinding(FindingDisposition.FIXED, duplicate),),
            )

    def test_to_json_is_deterministic(self) -> None:
        item = comparison()
        self.assertEqual(item.to_json(), item.to_json())
        self.assertEqual(json.loads(item.to_json()), item.to_dict())

    def test_to_dict_has_version_and_summary(self) -> None:
        data = comparison().to_dict()
        self.assertEqual(data["comparison_type"], "finding_comparison")
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(
            data["summary"],
            {"new": 1, "remaining": 1, "fixed": 1, "changed": 1},
        )


class ComparisonLoadingTests(unittest.TestCase):
    def test_round_trip_json(self) -> None:
        loaded = load_report_comparison_json(comparison().to_json())
        self.assertEqual(loaded.to_dict(), comparison().to_dict())

    def test_round_trip_mapping(self) -> None:
        loaded = load_report_comparison(comparison().to_dict())
        self.assertEqual(loaded.to_json(), comparison().to_json())

    def test_round_trip_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comparison.json"
            path.write_text(comparison().to_json(), encoding="utf-8")
            loaded = load_report_comparison_file(path)
        self.assertEqual(loaded.current_scan_id, comparison().current_scan_id)

    def test_rejects_invalid_json(self) -> None:
        with self.assertRaisesRegex(ReportComparisonError, "valid JSON"):
            load_report_comparison_json("{broken")

    def test_rejects_non_text_json(self) -> None:
        with self.assertRaises(ReportComparisonError):
            load_report_comparison_json(b"{}")  # type: ignore[arg-type]

    def test_rejects_unknown_root_field(self) -> None:
        data = comparison().to_dict()
        data["unexpected"] = True
        with self.assertRaisesRegex(ReportComparisonError, "fields"):
            load_report_comparison(data)

    def test_rejects_unsupported_schema(self) -> None:
        data = comparison().to_dict()
        data["schema_version"] = "9.9"
        with self.assertRaisesRegex(ReportComparisonError, "schema_version"):
            load_report_comparison(data)

    def test_rejects_wrong_type(self) -> None:
        data = comparison().to_dict()
        data["comparison_type"] = "other"
        with self.assertRaisesRegex(ReportComparisonError, "comparison_type"):
            load_report_comparison(data)

    def test_rejects_summary_mismatch(self) -> None:
        data = comparison().to_dict()
        data["summary"]["new"] = 99
        with self.assertRaisesRegex(ReportComparisonError, "summary"):
            load_report_comparison(data)

    def test_rejects_wrong_group_disposition(self) -> None:
        data = comparison().to_dict()
        data["new_findings"][0]["disposition"] = "fixed"
        with self.assertRaisesRegex(ReportComparisonError, "disposition"):
            load_report_comparison(data)

    def test_rejects_changed_fixed_finding(self) -> None:
        data = comparison().to_dict()
        data["fixed_findings"][0]["presentation_changed"] = True
        with self.assertRaises(ReportComparisonError):
            load_report_comparison(data)

    def test_rejects_invalid_finding_fingerprint(self) -> None:
        data = comparison().to_dict()
        data["new_findings"][0]["finding"]["fingerprint"] = "0" * 64
        with self.assertRaisesRegex(ReportComparisonError, "invalid normalized"):
            load_report_comparison(data)

    def test_rejects_missing_file(self) -> None:
        with self.assertRaisesRegex(ReportComparisonError, "Unable to read"):
            load_report_comparison_file("/definitely/missing/comparison.json")


if __name__ == "__main__":
    unittest.main()
