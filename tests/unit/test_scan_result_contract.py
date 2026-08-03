"""Tests for the shared scan-result contract."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from uuid import UUID

from webguard_contracts import (
    Confidence,
    Evidence,
    FindingIdentity,
    NormalizedFinding,
    ScanContractValidationError,
    ScanCoverage,
    ScanError,
    ScanResult,
    ScanStatus,
    Severity,
    SkippedCheck,
)


STARTED_AT = datetime(
    2026,
    8,
    3,
    1,
    30,
    tzinfo=timezone.utc,
)
COMPLETED_AT = STARTED_AT + timedelta(seconds=2)


def make_finding(
    *,
    asset: str = "https://example.com",
    path: str = "/login",
) -> NormalizedFinding:
    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id="web.headers.csp.missing",
            asset=asset,
            path=path,
            method="GET",
        ),
        source="webguard-passive",
        source_rule_id="HTTP-HEADER-004",
        title="Content-Security-Policy header missing",
        description=(
            "The response does not define a Content Security Policy."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        remediation="Deploy and enforce a tested CSP.",
        detected_at=STARTED_AT,
        evidence=(
            Evidence(
                "No Content-Security-Policy response header was observed."
            ),
        ),
    )


def make_coverage(
    *,
    planned_checks: tuple[str, ...] = (
        "web.headers.csp",
        "web.headers.hsts",
    ),
    executed_checks: tuple[str, ...] = (
        "web.headers.csp",
        "web.headers.hsts",
    ),
    skipped_checks: tuple[SkippedCheck, ...] = (),
    requests_attempted: int = 1,
    requests_succeeded: int = 1,
) -> ScanCoverage:
    return ScanCoverage(
        planned_checks=planned_checks,
        executed_checks=executed_checks,
        skipped_checks=skipped_checks,
        requests_attempted=requests_attempted,
        requests_succeeded=requests_succeeded,
    )


def make_result(**changes) -> ScanResult:
    values = {
        "scan_id": "A8098C1A-FFAE-4BF2-947A-3B93B2398777",
        "scan_type": "passive-http-headers",
        "status": ScanStatus.COMPLETED,
        "target": "HTTPS://Example.COM.:443/login",
        "engine": "webguard-native",
        "engine_version": "0.1.0",
        "started_at": STARTED_AT,
        "completed_at": COMPLETED_AT,
        "coverage": make_coverage(),
        "findings": (make_finding(),),
        "connected_addresses": (
            "2001:4860:4860::8888",
            "93.184.216.34",
            "93.184.216.34",
        ),
        "http_statuses": (
            200,
            200,
        ),
    }

    values.update(changes)
    return ScanResult(**values)


class ScanResultContractTests(unittest.TestCase):
    """Verify scan lifecycle, coverage and serialization rules."""

    def test_completed_result_normalises_and_serialises(self) -> None:
        result = make_result()
        decoded = json.loads(result.to_json())

        self.assertEqual(
            result.scan_id,
            str(UUID(result.scan_id)),
        )
        self.assertEqual(
            result.target,
            "https://example.com/login",
        )
        self.assertEqual(
            result.connected_addresses,
            (
                "93.184.216.34",
                "2001:4860:4860::8888",
            ),
        )
        self.assertEqual(result.http_statuses, (200,))
        self.assertEqual(
            decoded["coverage"]["completion_percent"],
            100.0,
        )
        self.assertEqual(decoded["finding_count"], 1)
        self.assertEqual(decoded["error_count"], 0)
        self.assertEqual(
            decoded["completed_at"],
            "2026-08-03T01:30:02Z",
        )

    def test_json_is_deterministic(self) -> None:
        result = make_result()

        self.assertEqual(
            result.to_json(),
            result.to_json(),
        )

    def test_rejects_naive_started_at(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                started_at=datetime(
                    2026,
                    8,
                    3,
                    1,
                    30,
                ),
            )

        self.assertEqual(
            context.exception.code,
            "started_at_invalid",
        )

    def test_terminal_status_requires_completed_at(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(completed_at=None)

        self.assertEqual(
            context.exception.code,
            "completed_at_required",
        )

    def test_running_status_rejects_completed_at(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                status=ScanStatus.RUNNING,
            )

        self.assertEqual(
            context.exception.code,
            "completed_at_not_allowed",
        )

    def test_rejects_completed_at_before_started_at(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                completed_at=STARTED_AT - timedelta(seconds=1),
            )

        self.assertEqual(
            context.exception.code,
            "completed_at_before_started_at",
        )

    def test_completed_scan_rejects_errors(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                errors=(
                    ScanError(
                        code="response.failed",
                        message="The response could not be processed.",
                        stage="analysis",
                    ),
                ),
            )

        self.assertEqual(
            context.exception.code,
            "completed_scan_has_errors",
        )

    def test_failed_scan_requires_error(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                status=ScanStatus.FAILED,
            )

        self.assertEqual(
            context.exception.code,
            "scan_errors_required",
        )

    def test_completed_with_errors_accepts_error(self) -> None:
        result = make_result(
            status=ScanStatus.COMPLETED_WITH_ERRORS,
            errors=(
                ScanError(
                    code="check.skipped",
                    message="One optional check could not run.",
                    stage="analysis",
                    retryable=True,
                ),
            ),
        )

        self.assertEqual(
            result.status,
            ScanStatus.COMPLETED_WITH_ERRORS,
        )
        self.assertEqual(len(result.errors), 1)

    def test_coverage_rejects_unplanned_executed_check(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_coverage(
                planned_checks=("web.headers.csp",),
                executed_checks=("web.headers.hsts",),
            )

        self.assertEqual(
            context.exception.code,
            "executed_check_not_planned",
        )

    def test_coverage_rejects_executed_and_skipped_check(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_coverage(
                skipped_checks=(
                    SkippedCheck(
                        check_id="web.headers.hsts",
                        reason="Target did not use HTTPS.",
                    ),
                ),
            )

        self.assertEqual(
            context.exception.code,
            "check_executed_and_skipped",
        )

    def test_completed_scan_rejects_unaccounted_check(self) -> None:
        coverage = make_coverage(
            executed_checks=("web.headers.csp",),
        )

        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(coverage=coverage)

        self.assertEqual(
            context.exception.code,
            "terminal_coverage_incomplete",
        )

    def test_skipped_check_accounts_for_coverage(self) -> None:
        coverage = make_coverage(
            executed_checks=("web.headers.csp",),
            skipped_checks=(
                SkippedCheck(
                    check_id="web.headers.hsts",
                    reason="Target did not use HTTPS.",
                ),
            ),
        )

        result = make_result(coverage=coverage)

        self.assertEqual(
            result.coverage.unaccounted_checks,
            (),
        )
        self.assertEqual(
            result.coverage.completion_percent,
            50.0,
        )

    def test_rejects_duplicate_finding_fingerprint(self) -> None:
        finding = make_finding()

        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                findings=(finding, finding),
            )

        self.assertEqual(
            context.exception.code,
            "finding_duplicate",
        )

    def test_rejects_finding_from_different_asset(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                findings=(
                    make_finding(
                        asset="https://other.example",
                    ),
                ),
            )

        self.assertEqual(
            context.exception.code,
            "finding_asset_mismatch",
        )

    def test_rejects_invalid_connected_address(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                connected_addresses=("not-an-ip",),
            )

        self.assertEqual(
            context.exception.code,
            "connected_address_invalid",
        )

    def test_rejects_invalid_http_status(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                http_statuses=(700,),
            )

        self.assertEqual(
            context.exception.code,
            "http_status_invalid",
        )

    def test_rejects_target_credentials(self) -> None:
        with self.assertRaises(
            ScanContractValidationError
        ) as context:
            make_result(
                target="https://user:password@example.com/",
            )

        self.assertEqual(
            context.exception.code,
            "target_invalid",
        )


if __name__ == "__main__":
    unittest.main()
