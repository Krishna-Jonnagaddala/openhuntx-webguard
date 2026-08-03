"""Versioned scan-result contracts for OpenHuntX WebGuard."""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Tuple
from urllib.parse import urlsplit, urlunsplit

from .findings import NormalizedFinding


_IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class ScanStatus(str, Enum):
    """Lifecycle state of one scan execution."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanContractValidationError(ValueError):
    """Controlled failure raised for an invalid scan contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _required_text(
    value: str,
    name: str,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        raise ScanContractValidationError(
            f"{name}_invalid",
            f"{name} must be text.",
        )

    cleaned = value.strip()

    if (
        not cleaned
        or len(cleaned) > maximum
        or "\x00" in cleaned
    ):
        raise ScanContractValidationError(
            f"{name}_invalid",
            f"{name} is empty, too long, or contains a null byte.",
        )

    return cleaned


def _identifier(
    value: str,
    name: str,
    maximum: int = 128,
) -> str:
    cleaned = _required_text(
        value,
        name,
        maximum,
    ).lower()

    if not _IDENTIFIER.fullmatch(cleaned):
        raise ScanContractValidationError(
            f"{name}_invalid",
            f"{name} must use lowercase letters, digits, dots, "
            "underscores, or hyphens.",
        )

    return cleaned


def _aware_utc(
    value: datetime,
    name: str,
) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ScanContractValidationError(
            f"{name}_invalid",
            f"{name} must be timezone-aware.",
        )

    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return (
        value
        .isoformat()
        .replace("+00:00", "Z")
    )


def _canonical_target(target: str) -> str:
    candidate = _required_text(
        target,
        "target",
        4096,
    )

    if "\\" in candidate:
        raise ScanContractValidationError(
            "target_invalid",
            "target cannot contain backslashes.",
        )

    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise ScanContractValidationError(
            "target_invalid",
            "target is malformed.",
        ) from exc

    scheme = parsed.scheme.lower()

    if (
        scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ScanContractValidationError(
            "target_invalid",
            "target must be an HTTP(S) URL without credentials, "
            "query, or fragment.",
        )

    try:
        configured_port = parsed.port
    except ValueError as exc:
        raise ScanContractValidationError(
            "target_invalid",
            "target contains an invalid port.",
        ) from exc

    hostname = parsed.hostname.lower().rstrip(".")

    if not hostname:
        raise ScanContractValidationError(
            "target_invalid",
            "target does not contain a usable hostname.",
        )

    port = configured_port or (
        443 if scheme == "https" else 80
    )
    default_port = (
        443 if scheme == "https" else 80
    )

    formatted_hostname = (
        f"[{hostname}]"
        if ":" in hostname
        else hostname
    )

    authority = (
        formatted_hostname
        if port == default_port
        else f"{formatted_hostname}:{port}"
    )

    return urlunsplit(
        (
            scheme,
            authority,
            parsed.path or "/",
            "",
            "",
        )
    )


def _target_origin(canonical_target: str) -> str:
    parsed = urlsplit(canonical_target)
    scheme = parsed.scheme
    hostname = parsed.hostname or ""
    port = parsed.port or (
        443 if scheme == "https" else 80
    )
    default_port = (
        443 if scheme == "https" else 80
    )
    formatted_hostname = (
        f"[{hostname}]"
        if ":" in hostname
        else hostname
    )
    return (
        f"{scheme}://{formatted_hostname}"
        if port == default_port
        else f"{scheme}://{formatted_hostname}:{port}"
    )


@dataclass(frozen=True, slots=True, order=True)
class SkippedCheck:
    """A planned check that was not executed."""

    check_id: str
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "check_id",
            _identifier(
                self.check_id,
                "check_id",
            ),
        )
        object.__setattr__(
            self,
            "reason",
            _required_text(
                self.reason,
                "skip_reason",
                2048,
            ),
        )


@dataclass(frozen=True, slots=True)
class ScanCoverage:
    """Explicit coverage recorded for one scan execution."""

    planned_checks: Tuple[str, ...] = ()
    executed_checks: Tuple[str, ...] = ()
    skipped_checks: Tuple[SkippedCheck, ...] = ()
    requests_attempted: int = 0
    requests_succeeded: int = 0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.requests_attempted, int)
            or isinstance(self.requests_attempted, bool)
            or self.requests_attempted < 0
        ):
            raise ScanContractValidationError(
                "requests_attempted_invalid",
                "requests_attempted must be a non-negative integer.",
            )

        if (
            not isinstance(self.requests_succeeded, int)
            or isinstance(self.requests_succeeded, bool)
            or self.requests_succeeded < 0
            or self.requests_succeeded > self.requests_attempted
        ):
            raise ScanContractValidationError(
                "requests_succeeded_invalid",
                "requests_succeeded must be between zero and "
                "requests_attempted.",
            )

        planned = tuple(
            sorted(
                {
                    _identifier(
                        check_id,
                        "planned_check_id",
                    )
                    for check_id in self.planned_checks
                }
            )
        )

        executed = tuple(
            sorted(
                {
                    _identifier(
                        check_id,
                        "executed_check_id",
                    )
                    for check_id in self.executed_checks
                }
            )
        )

        if not set(executed).issubset(planned):
            raise ScanContractValidationError(
                "executed_check_not_planned",
                "Every executed check must appear in planned_checks.",
            )

        if any(
            not isinstance(item, SkippedCheck)
            for item in self.skipped_checks
        ):
            raise ScanContractValidationError(
                "skipped_checks_invalid",
                "skipped_checks contains an invalid value.",
            )

        skipped_by_id: dict[str, SkippedCheck] = {}

        for item in self.skipped_checks:
            if item.check_id in skipped_by_id:
                raise ScanContractValidationError(
                    "skipped_check_duplicate",
                    "A check cannot be skipped more than once.",
                )

            skipped_by_id[item.check_id] = item

        skipped_ids = set(skipped_by_id)

        if not skipped_ids.issubset(planned):
            raise ScanContractValidationError(
                "skipped_check_not_planned",
                "Every skipped check must appear in planned_checks.",
            )

        if skipped_ids.intersection(executed):
            raise ScanContractValidationError(
                "check_executed_and_skipped",
                "A check cannot be both executed and skipped.",
            )

        object.__setattr__(
            self,
            "planned_checks",
            planned,
        )
        object.__setattr__(
            self,
            "executed_checks",
            executed,
        )
        object.__setattr__(
            self,
            "skipped_checks",
            tuple(
                sorted(
                    skipped_by_id.values(),
                    key=lambda item: item.check_id,
                )
            ),
        )

    @property
    def unaccounted_checks(self) -> Tuple[str, ...]:
        """Return planned checks that were neither executed nor skipped."""

        accounted = set(self.executed_checks).union(
            item.check_id
            for item in self.skipped_checks
        )

        return tuple(
            check_id
            for check_id in self.planned_checks
            if check_id not in accounted
        )

    @property
    def completion_percent(self) -> float | None:
        """Return executed-check coverage, or None when nothing was planned."""

        if not self.planned_checks:
            return None

        return round(
            len(self.executed_checks)
            / len(self.planned_checks)
            * 100,
            2,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "planned_checks": list(self.planned_checks),
            "executed_checks": list(self.executed_checks),
            "skipped_checks": [
                {
                    "check_id": item.check_id,
                    "reason": item.reason,
                }
                for item in self.skipped_checks
            ],
            "unaccounted_checks": list(self.unaccounted_checks),
            "completion_percent": self.completion_percent,
            "requests_attempted": self.requests_attempted,
            "requests_succeeded": self.requests_succeeded,
        }


@dataclass(frozen=True, slots=True, order=True)
class ScanError:
    """A bounded, non-secret error recorded during a scan."""

    code: str
    message: str
    stage: str
    retryable: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "code",
            _identifier(
                self.code,
                "error_code",
            ),
        )
        object.__setattr__(
            self,
            "stage",
            _identifier(
                self.stage,
                "error_stage",
            ),
        )
        object.__setattr__(
            self,
            "message",
            _required_text(
                self.message,
                "error_message",
                4096,
            ),
        )

        if not isinstance(self.retryable, bool):
            raise ScanContractValidationError(
                "error_retryable_invalid",
                "retryable must be boolean.",
            )


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Versioned, scanner-independent result for one scan execution."""

    scan_id: str
    scan_type: str
    status: ScanStatus
    target: str
    engine: str
    engine_version: str
    started_at: datetime
    coverage: ScanCoverage

    completed_at: datetime | None = None
    findings: Tuple[NormalizedFinding, ...] = ()
    errors: Tuple[ScanError, ...] = ()
    connected_addresses: Tuple[str, ...] = ()
    http_statuses: Tuple[int, ...] = ()

    schema_version: str = field(
        default="1.0",
        init=False,
    )

    def __post_init__(self) -> None:
        try:
            canonical_scan_id = str(
                uuid.UUID(
                    _required_text(
                        self.scan_id,
                        "scan_id",
                        64,
                    )
                )
            )
        except (ValueError, AttributeError) as exc:
            raise ScanContractValidationError(
                "scan_id_invalid",
                "scan_id must be a valid UUID.",
            ) from exc

        if not isinstance(self.status, ScanStatus):
            raise ScanContractValidationError(
                "status_invalid",
                "status must be a ScanStatus value.",
            )

        if not isinstance(self.coverage, ScanCoverage):
            raise ScanContractValidationError(
                "coverage_invalid",
                "coverage must be a ScanCoverage value.",
            )

        canonical_target = _canonical_target(
            self.target
        )
        target_origin = _target_origin(
            canonical_target
        )

        started_at = _aware_utc(
            self.started_at,
            "started_at",
        )

        completed_at = (
            None
            if self.completed_at is None
            else _aware_utc(
                self.completed_at,
                "completed_at",
            )
        )

        terminal_statuses = {
            ScanStatus.COMPLETED,
            ScanStatus.COMPLETED_WITH_ERRORS,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        }

        if self.status in terminal_statuses:
            if completed_at is None:
                raise ScanContractValidationError(
                    "completed_at_required",
                    "Terminal scan statuses require completed_at.",
                )
        elif completed_at is not None:
            raise ScanContractValidationError(
                "completed_at_not_allowed",
                "Non-terminal scan statuses cannot have completed_at.",
            )

        if (
            completed_at is not None
            and completed_at < started_at
        ):
            raise ScanContractValidationError(
                "completed_at_before_started_at",
                "completed_at cannot be earlier than started_at.",
            )

        if any(
            not isinstance(item, NormalizedFinding)
            for item in self.findings
        ):
            raise ScanContractValidationError(
                "findings_invalid",
                "findings contains an invalid value.",
            )

        findings_by_fingerprint: dict[str, NormalizedFinding] = {}

        for finding in self.findings:
            if finding.identity.asset != target_origin:
                raise ScanContractValidationError(
                    "finding_asset_mismatch",
                    "Every finding must belong to the scan target origin.",
                )

            if finding.fingerprint in findings_by_fingerprint:
                raise ScanContractValidationError(
                    "finding_duplicate",
                    "A scan result cannot contain duplicate finding "
                    "fingerprints.",
                )

            findings_by_fingerprint[finding.fingerprint] = finding

        if any(
            not isinstance(item, ScanError)
            for item in self.errors
        ):
            raise ScanContractValidationError(
                "errors_invalid",
                "errors contains an invalid value.",
            )

        errors = tuple(sorted(set(self.errors)))

        if (
            self.status
            in {
                ScanStatus.COMPLETED,
                ScanStatus.COMPLETED_WITH_ERRORS,
            }
            and self.coverage.unaccounted_checks
        ):
            raise ScanContractValidationError(
                "terminal_coverage_incomplete",
                "Completed scans must account for every planned check.",
            )

        if (
            self.status is ScanStatus.COMPLETED
            and errors
        ):
            raise ScanContractValidationError(
                "completed_scan_has_errors",
                "A completed scan cannot contain errors.",
            )

        if (
            self.status
            in {
                ScanStatus.COMPLETED_WITH_ERRORS,
                ScanStatus.FAILED,
            }
            and not errors
        ):
            raise ScanContractValidationError(
                "scan_errors_required",
                "This scan status requires at least one error.",
            )

        canonical_addresses: set[str] = set()

        for address_text in self.connected_addresses:
            try:
                canonical_addresses.add(
                    ipaddress.ip_address(
                        address_text
                    ).compressed
                )
            except ValueError as exc:
                raise ScanContractValidationError(
                    "connected_address_invalid",
                    f"Invalid connected address {address_text!r}.",
                ) from exc

        canonical_statuses: set[int] = set()

        for status_code in self.http_statuses:
            if (
                not isinstance(status_code, int)
                or isinstance(status_code, bool)
                or not 100 <= status_code <= 599
            ):
                raise ScanContractValidationError(
                    "http_status_invalid",
                    "HTTP status codes must be integers from 100 to 599.",
                )

            canonical_statuses.add(status_code)

        object.__setattr__(
            self,
            "scan_id",
            canonical_scan_id,
        )
        object.__setattr__(
            self,
            "scan_type",
            _identifier(
                self.scan_type,
                "scan_type",
            ),
        )
        object.__setattr__(
            self,
            "target",
            canonical_target,
        )
        object.__setattr__(
            self,
            "engine",
            _identifier(
                self.engine,
                "engine",
            ),
        )
        object.__setattr__(
            self,
            "engine_version",
            _required_text(
                self.engine_version,
                "engine_version",
                64,
            ),
        )
        object.__setattr__(
            self,
            "started_at",
            started_at,
        )
        object.__setattr__(
            self,
            "completed_at",
            completed_at,
        )
        object.__setattr__(
            self,
            "findings",
            tuple(
                sorted(
                    findings_by_fingerprint.values(),
                    key=lambda item: item.fingerprint,
                )
            ),
        )
        object.__setattr__(
            self,
            "errors",
            errors,
        )
        object.__setattr__(
            self,
            "connected_addresses",
            tuple(
                sorted(
                    canonical_addresses,
                    key=lambda value: (
                        ipaddress.ip_address(value).version,
                        int(ipaddress.ip_address(value)),
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "http_statuses",
            tuple(
                sorted(canonical_statuses)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "status": self.status.value,
            "target": self.target,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "started_at": _timestamp(self.started_at),
            "completed_at": (
                None
                if self.completed_at is None
                else _timestamp(self.completed_at)
            ),
            "coverage": self.coverage.to_dict(),
            "finding_count": len(self.findings),
            "findings": [
                item.to_dict()
                for item in self.findings
            ],
            "error_count": len(self.errors),
            "errors": [
                {
                    "code": item.code,
                    "message": item.message,
                    "stage": item.stage,
                    "retryable": item.retryable,
                }
                for item in self.errors
            ],
            "connected_addresses": list(
                self.connected_addresses
            ),
            "http_statuses": list(
                self.http_statuses
            ),
        }

    def to_json(self) -> str:
        """Serialise deterministically for storage and queues."""

        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
