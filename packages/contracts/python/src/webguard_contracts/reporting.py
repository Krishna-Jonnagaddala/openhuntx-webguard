"""Versioned contracts for professional reporting and remediation comparison."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Tuple

from .findings import Confidence, NormalizedFinding, Severity


CURRENT_REPORT_COMPARISON_SCHEMA_VERSION = "1.0"
REPORT_COMPARISON_TYPE = "finding_comparison"
MAXIMUM_REPORT_COMPARISON_BYTES = 16 * 1024 * 1024


class ReportComparisonError(ValueError):
    """Controlled failure raised for invalid comparison data."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class FindingDisposition(str, Enum):
    """Finding state between a baseline and current scan."""

    NEW = "new"
    REMAINING = "remaining"
    FIXED = "fixed"


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ReportComparisonError(
            f"{name}_invalid",
            f"{name} must be text.",
        )
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or "\x00" in cleaned:
        raise ReportComparisonError(
            f"{name}_invalid",
            f"{name} is empty, too long, or contains a null byte.",
        )
    return cleaned


def _timestamp(value: datetime, name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ReportComparisonError(
            f"{name}_invalid",
            f"{name} must be timezone-aware.",
        )
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ComparedFinding:
    """One normalized finding assigned a remediation disposition."""

    disposition: FindingDisposition
    finding: NormalizedFinding
    presentation_changed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, FindingDisposition):
            raise ReportComparisonError(
                "finding_disposition_invalid",
                "disposition must be a FindingDisposition value.",
            )
        if not isinstance(self.finding, NormalizedFinding):
            raise ReportComparisonError(
                "compared_finding_invalid",
                "finding must be a NormalizedFinding value.",
            )
        if not isinstance(self.presentation_changed, bool):
            raise ReportComparisonError(
                "presentation_changed_invalid",
                "presentation_changed must be boolean.",
            )
        if (
            self.disposition is not FindingDisposition.REMAINING
            and self.presentation_changed
        ):
            raise ReportComparisonError(
                "presentation_changed_disposition_invalid",
                "Only remaining findings can record presentation changes.",
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "presentation_changed": self.presentation_changed,
            "finding": self.finding.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ReportComparison:
    """Versioned comparison of two compatible WebGuard reports."""

    baseline_scan_id: str
    current_scan_id: str
    target: str
    baseline_completed_at: datetime
    current_completed_at: datetime
    generated_at: datetime
    new_findings: Tuple[ComparedFinding, ...] = ()
    remaining_findings: Tuple[ComparedFinding, ...] = ()
    fixed_findings: Tuple[ComparedFinding, ...] = ()

    comparison_type: str = field(
        default=REPORT_COMPARISON_TYPE,
        init=False,
    )
    schema_version: str = field(
        default=CURRENT_REPORT_COMPARISON_SCHEMA_VERSION,
        init=False,
    )

    def __post_init__(self) -> None:
        baseline_scan_id = _text(
            self.baseline_scan_id,
            "baseline_scan_id",
            64,
        )
        current_scan_id = _text(
            self.current_scan_id,
            "current_scan_id",
            64,
        )
        if baseline_scan_id == current_scan_id:
            raise ReportComparisonError(
                "comparison_scan_ids_equal",
                "Baseline and current scan IDs must be different.",
            )

        target = _text(self.target, "target", 4096)
        baseline_completed_at = _timestamp(
            self.baseline_completed_at,
            "baseline_completed_at",
        )
        current_completed_at = _timestamp(
            self.current_completed_at,
            "current_completed_at",
        )
        generated_at = _timestamp(self.generated_at, "generated_at")

        if current_completed_at < baseline_completed_at:
            raise ReportComparisonError(
                "comparison_scan_order_invalid",
                "Current scan must not complete before the baseline scan.",
            )
        if generated_at < current_completed_at:
            raise ReportComparisonError(
                "comparison_generated_at_invalid",
                "generated_at must not precede the current scan completion.",
            )

        groups = (
            ("new_findings", FindingDisposition.NEW, self.new_findings),
            (
                "remaining_findings",
                FindingDisposition.REMAINING,
                self.remaining_findings,
            ),
            ("fixed_findings", FindingDisposition.FIXED, self.fixed_findings),
        )
        all_fingerprints: set[str] = set()
        normalized: dict[str, tuple[ComparedFinding, ...]] = {}

        for name, expected, values in groups:
            if not isinstance(values, tuple) or any(
                not isinstance(item, ComparedFinding) for item in values
            ):
                raise ReportComparisonError(
                    f"{name}_invalid",
                    f"{name} must contain ComparedFinding values.",
                )
            if any(item.disposition is not expected for item in values):
                raise ReportComparisonError(
                    f"{name}_disposition_invalid",
                    f"Every item in {name} must have disposition {expected.value}.",
                )
            ordered = tuple(
                sorted(values, key=lambda item: item.finding.fingerprint)
            )
            for item in ordered:
                fingerprint = item.finding.fingerprint
                if fingerprint in all_fingerprints:
                    raise ReportComparisonError(
                        "comparison_fingerprint_duplicate",
                        "A finding fingerprint can appear only once.",
                    )
                all_fingerprints.add(fingerprint)
            normalized[name] = ordered

        object.__setattr__(self, "baseline_scan_id", baseline_scan_id)
        object.__setattr__(self, "current_scan_id", current_scan_id)
        object.__setattr__(self, "target", target)
        object.__setattr__(
            self,
            "baseline_completed_at",
            baseline_completed_at,
        )
        object.__setattr__(self, "current_completed_at", current_completed_at)
        object.__setattr__(self, "generated_at", generated_at)
        for name, values in normalized.items():
            object.__setattr__(self, name, values)

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def remaining_count(self) -> int:
        return len(self.remaining_findings)

    @property
    def fixed_count(self) -> int:
        return len(self.fixed_findings)

    @property
    def changed_count(self) -> int:
        return sum(
            1 for item in self.remaining_findings if item.presentation_changed
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "comparison_type": self.comparison_type,
            "schema_version": self.schema_version,
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "target": self.target,
            "baseline_completed_at": _timestamp_text(
                self.baseline_completed_at
            ),
            "current_completed_at": _timestamp_text(self.current_completed_at),
            "generated_at": _timestamp_text(self.generated_at),
            "summary": {
                "new": self.new_count,
                "remaining": self.remaining_count,
                "fixed": self.fixed_count,
                "changed": self.changed_count,
            },
            "new_findings": [item.to_dict() for item in self.new_findings],
            "remaining_findings": [
                item.to_dict() for item in self.remaining_findings
            ],
            "fixed_findings": [item.to_dict() for item in self.fixed_findings],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


def _parse_timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise ReportComparisonError(
            f"{name}_invalid",
            f"{name} must be an ISO 8601 timestamp.",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportComparisonError(
            f"{name}_invalid",
            f"{name} must be an ISO 8601 timestamp.",
        ) from exc
    return _timestamp(parsed, name)


def _strict_object(
    value: object,
    name: str,
    expected: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReportComparisonError(
            f"{name}_invalid",
            f"{name} must be a JSON object.",
        )
    result = dict(value)
    if set(result) != set(expected):
        raise ReportComparisonError(
            f"{name}_fields_invalid",
            f"{name} contains missing or unexpected fields.",
        )
    return result


def _load_normalized_finding(value: object) -> NormalizedFinding:
    # Reuse the strict scan-report loader's mature finding parser by embedding
    # one finding in a minimal canonical scan report.
    from .report_loader import load_scan_result

    finding_object = _strict_object(
        value,
        "finding",
        frozenset(
            {
                "schema_version",
                "fingerprint",
                "identity",
                "source",
                "source_rule_id",
                "title",
                "description",
                "severity",
                "confidence",
                "remediation",
                "detected_at",
                "identifiers",
                "evidence",
                "references",
                "tags",
            }
        ),
    )
    identity = _strict_object(
        finding_object["identity"],
        "finding.identity",
        frozenset({"rule_id", "asset", "path", "method", "parameter"}),
    )
    asset = identity["asset"]
    if not isinstance(asset, str):
        raise ReportComparisonError(
            "comparison_finding_invalid",
            "Comparison finding asset must be text.",
        )
    now = "2026-01-01T00:00:00Z"
    document = {
        "schema_version": "1.1",
        "scan_id": "00000000-0000-4000-8000-000000000001",
        "scan_type": "report-comparison-loader",
        "status": "completed",
        "target": asset.rstrip("/") + "/",
        "engine": "webguard-native",
        "engine_version": "0.1.0",
        "started_at": now,
        "completed_at": now,
        "coverage": {
            "planned_checks": [],
            "executed_checks": [],
            "skipped_checks": [],
            "unaccounted_checks": [],
            "completion_percent": None,
            "requests_attempted": 0,
            "requests_succeeded": 0,
        },
        "finding_count": 1,
        "findings": [value],
        "error_count": 0,
        "errors": [],
        "connected_addresses": [],
        "http_statuses": [],
        "request_attempt_count": 0,
        "request_attempts": [],
    }
    try:
        return load_scan_result(document).findings[0]
    except Exception as exc:
        raise ReportComparisonError(
            "comparison_finding_invalid",
            "Comparison contains an invalid normalized finding.",
        ) from exc


def _load_group(
    value: object,
    name: str,
    disposition: FindingDisposition,
) -> tuple[ComparedFinding, ...]:
    if not isinstance(value, list):
        raise ReportComparisonError(
            f"{name}_invalid",
            f"{name} must be a JSON array.",
        )
    result: list[ComparedFinding] = []
    for index, item in enumerate(value):
        data = _strict_object(
            item,
            f"{name}[{index}]",
            frozenset({"disposition", "presentation_changed", "finding"}),
        )
        if data["disposition"] != disposition.value:
            raise ReportComparisonError(
                f"{name}_disposition_invalid",
                f"{name}[{index}] has an invalid disposition.",
            )
        result.append(
            ComparedFinding(
                disposition=disposition,
                presentation_changed=data["presentation_changed"],
                finding=_load_normalized_finding(data["finding"]),
            )
        )
    return tuple(result)


def load_report_comparison(value: object) -> ReportComparison:
    """Strictly load a comparison document from a decoded JSON value."""

    data = _strict_object(
        value,
        "comparison",
        frozenset(
            {
                "comparison_type",
                "schema_version",
                "baseline_scan_id",
                "current_scan_id",
                "target",
                "baseline_completed_at",
                "current_completed_at",
                "generated_at",
                "summary",
                "new_findings",
                "remaining_findings",
                "fixed_findings",
            }
        ),
    )
    if data["comparison_type"] != REPORT_COMPARISON_TYPE:
        raise ReportComparisonError(
            "comparison_type_invalid",
            "Unsupported comparison_type.",
        )
    if data["schema_version"] != CURRENT_REPORT_COMPARISON_SCHEMA_VERSION:
        raise ReportComparisonError(
            "comparison_schema_version_unsupported",
            "Unsupported comparison schema_version.",
        )

    summary = _strict_object(
        data["summary"],
        "summary",
        frozenset({"new", "remaining", "fixed", "changed"}),
    )
    for name, value_item in summary.items():
        if isinstance(value_item, bool) or not isinstance(value_item, int):
            raise ReportComparisonError(
                "comparison_summary_invalid",
                f"summary.{name} must be an integer.",
            )

    comparison = ReportComparison(
        baseline_scan_id=data["baseline_scan_id"],
        current_scan_id=data["current_scan_id"],
        target=data["target"],
        baseline_completed_at=_parse_timestamp(
            data["baseline_completed_at"],
            "baseline_completed_at",
        ),
        current_completed_at=_parse_timestamp(
            data["current_completed_at"],
            "current_completed_at",
        ),
        generated_at=_parse_timestamp(data["generated_at"], "generated_at"),
        new_findings=_load_group(
            data["new_findings"],
            "new_findings",
            FindingDisposition.NEW,
        ),
        remaining_findings=_load_group(
            data["remaining_findings"],
            "remaining_findings",
            FindingDisposition.REMAINING,
        ),
        fixed_findings=_load_group(
            data["fixed_findings"],
            "fixed_findings",
            FindingDisposition.FIXED,
        ),
    )
    if summary != comparison.to_dict()["summary"]:
        raise ReportComparisonError(
            "comparison_summary_mismatch",
            "Comparison summary does not match finding groups.",
        )
    return comparison


def load_report_comparison_json(payload: str) -> ReportComparison:
    if not isinstance(payload, str):
        raise ReportComparisonError(
            "comparison_json_invalid",
            "Comparison JSON must be text.",
        )
    if len(payload.encode("utf-8")) > MAXIMUM_REPORT_COMPARISON_BYTES:
        raise ReportComparisonError(
            "comparison_too_large",
            "Comparison document exceeds the maximum size.",
        )
    try:
        decoded = json.loads(payload)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ReportComparisonError(
            "comparison_json_invalid",
            "Comparison document is not valid JSON.",
        ) from exc
    return load_report_comparison(decoded)


def load_report_comparison_file(path: str | Path) -> ReportComparison:
    candidate = Path(path)
    try:
        size = candidate.stat().st_size
        if size > MAXIMUM_REPORT_COMPARISON_BYTES:
            raise ReportComparisonError(
                "comparison_too_large",
                "Comparison document exceeds the maximum size.",
            )
        payload = candidate.read_text(encoding="utf-8")
    except ReportComparisonError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ReportComparisonError(
            "comparison_file_read_failed",
            f"Unable to read comparison file {candidate}.",
        ) from exc
    return load_report_comparison_json(payload)


__all__ = [
    "CURRENT_REPORT_COMPARISON_SCHEMA_VERSION",
    "MAXIMUM_REPORT_COMPARISON_BYTES",
    "REPORT_COMPARISON_TYPE",
    "ComparedFinding",
    "FindingDisposition",
    "ReportComparison",
    "ReportComparisonError",
    "load_report_comparison",
    "load_report_comparison_file",
    "load_report_comparison_json",
]
