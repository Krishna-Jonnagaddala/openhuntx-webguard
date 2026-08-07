"""Versioned recurring scan-schedule contracts for WebGuard."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from .owned_targets import OwnedTargetContractError, canonicalize_owned_target_url
from .scan_jobs import ScanJobMode

CURRENT_SCAN_SCHEDULE_SCHEMA_VERSION = "1.0"
SUPPORTED_SCAN_SCHEDULE_SCHEMA_VERSIONS = ("1.0",)
SCAN_SCHEDULE_RECORD_TYPE = "scan_schedule_record"
MAXIMUM_SCAN_SCHEDULE_DOCUMENT_BYTES = 128 * 1024
MAXIMUM_SCAN_SCHEDULE_NAME_LENGTH = 120
MINIMUM_SCAN_SCHEDULE_INTERVAL_SECONDS = 3600
MAXIMUM_SCAN_SCHEDULE_INTERVAL_SECONDS = 365 * 24 * 60 * 60

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_ERROR_CODE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class ScanScheduleState(str, Enum):
    """Persistent lifecycle state for a recurring scan schedule."""

    ACTIVE = "active"
    PAUSED = "paused"


class ScanScheduleContractError(ValueError):
    """Base class for controlled scan-schedule contract failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ScanScheduleValidationError(ScanScheduleContractError):
    """Raised when an in-memory scan-schedule value is invalid."""


class ScanScheduleLoadError(ScanScheduleContractError):
    """Raised when serialized schedule JSON is invalid."""


class _DuplicateJsonKeyError(ValueError):
    pass


def _required_text(value: object, field_name: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ScanScheduleValidationError(
            "scan_schedule_text_invalid",
            f"{field_name} must be text.",
        )
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise ScanScheduleValidationError(
            "scan_schedule_text_invalid",
            f"{field_name} must contain 1 to {maximum} characters.",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise ScanScheduleValidationError(
            "scan_schedule_text_control_character",
            f"{field_name} cannot contain control characters.",
        )
    return cleaned


def _canonical_uuid(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ScanScheduleValidationError(
            "scan_schedule_uuid_invalid",
            f"{field_name} must be a canonical UUID string.",
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ScanScheduleValidationError(
            "scan_schedule_uuid_invalid",
            f"{field_name} must be a canonical UUID string.",
        ) from exc
    canonical = str(parsed)
    if canonical != value:
        raise ScanScheduleValidationError(
            "scan_schedule_uuid_non_canonical",
            f"{field_name} must use canonical lower-case UUID notation.",
        )
    return canonical


def _utc_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ScanScheduleValidationError(
            "scan_schedule_timestamp_invalid",
            f"{field_name} must be a timezone-aware datetime.",
        )
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ScanScheduleLoadError(
            "scan_schedule_timestamp_invalid",
            f"{field_name} must use canonical UTC Z notation.",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ScanScheduleLoadError(
            "scan_schedule_timestamp_invalid",
            f"{field_name} is not a valid timestamp.",
        ) from exc
    if _timestamp_text(parsed) != value:
        raise ScanScheduleLoadError(
            "scan_schedule_timestamp_non_canonical",
            f"{field_name} must use canonical microsecond UTC notation.",
        )
    return parsed.astimezone(timezone.utc)


def _optional_timestamp(value: object, field_name: str) -> datetime | None:
    if value is None:
        return None
    return _parse_timestamp(value, field_name)


def _interval(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScanScheduleValidationError(
            "scan_schedule_interval_invalid",
            "interval_seconds must be an integer.",
        )
    if not MINIMUM_SCAN_SCHEDULE_INTERVAL_SECONDS <= value <= MAXIMUM_SCAN_SCHEDULE_INTERVAL_SECONDS:
        raise ScanScheduleValidationError(
            "scan_schedule_interval_invalid",
            "interval_seconds must be from 3600 to 31536000.",
        )
    return value


def _revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ScanScheduleValidationError(
            "scan_schedule_revision_invalid",
            "revision must be a non-negative integer.",
        )
    return value


def _sha256(value: object) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ScanScheduleValidationError(
            "scan_schedule_sha256_invalid",
            "authorization_sha256 must be a lower-case SHA-256 digest.",
        )
    return value


def _error_code(value: object) -> str | None:
    if value is None:
        return None
    cleaned = _required_text(value, "last_error_code", maximum=128).lower()
    if not _ERROR_CODE.fullmatch(cleaned):
        raise ScanScheduleValidationError(
            "scan_schedule_error_code_invalid",
            "last_error_code must use a canonical lower-case identifier.",
        )
    return cleaned


def _strict_mapping(
    value: object,
    *,
    required: set[str],
    optional: set[str] = frozenset(),
    context: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ScanScheduleLoadError(
            "scan_schedule_document_invalid",
            f"{context} must be a JSON object.",
        )
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ScanScheduleLoadError(
            "scan_schedule_field_missing",
            f"{context} is missing required field {sorted(missing)[0]!r}.",
        )
    if unknown:
        raise ScanScheduleLoadError(
            "scan_schedule_field_unknown",
            f"{context} contains unknown field {sorted(unknown)[0]!r}.",
        )
    return value


@dataclass(frozen=True, slots=True)
class ScanScheduleSubmission:
    """Validated API request for a recurring authorised scan."""

    name: str
    target: str
    authorization_id: str
    confirmation: str
    mode: ScanJobMode
    interval_seconds: int
    starts_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "name",
            _required_text(self.name, "name", maximum=MAXIMUM_SCAN_SCHEDULE_NAME_LENGTH),
        )
        try:
            target = canonicalize_owned_target_url(self.target)
        except OwnedTargetContractError as exc:
            raise ScanScheduleValidationError(exc.code, exc.message) from exc
        object.__setattr__(self, "target", target)
        object.__setattr__(
            self,
            "authorization_id",
            _canonical_uuid(self.authorization_id, "authorization_id"),
        )
        object.__setattr__(
            self,
            "confirmation",
            _canonical_uuid(self.confirmation, "confirmation"),
        )
        if self.confirmation != self.authorization_id:
            raise ScanScheduleValidationError(
                "scan_schedule_authorization_confirmation_mismatch",
                "confirmation must exactly match authorization_id.",
            )
        if not isinstance(self.mode, ScanJobMode):
            raise ScanScheduleValidationError(
                "scan_schedule_mode_invalid",
                "mode must be a supported scan-job mode.",
            )
        object.__setattr__(self, "interval_seconds", _interval(self.interval_seconds))
        object.__setattr__(self, "starts_at", _utc_datetime(self.starts_at, "starts_at"))


@dataclass(frozen=True, slots=True)
class ScanScheduleRecord:
    """Persistent organisation-scoped recurring schedule metadata."""

    schedule_id: str
    organization_id: str
    created_by: str
    name: str
    target: str
    authorization_id: str
    authorization_sha256: str
    mode: ScanJobMode
    interval_seconds: int
    state: ScanScheduleState
    created_at: datetime
    updated_at: datetime
    next_run_at: datetime
    revision: int = 0
    last_enqueued_at: datetime | None = None
    last_job_id: str | None = None
    last_error_code: str | None = None
    last_error_at: datetime | None = None
    record_type: str = SCAN_SCHEDULE_RECORD_TYPE
    schema_version: str = CURRENT_SCAN_SCHEDULE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.record_type != SCAN_SCHEDULE_RECORD_TYPE:
            raise ScanScheduleValidationError(
                "scan_schedule_type_invalid", "record_type is unsupported."
            )
        if self.schema_version not in SUPPORTED_SCAN_SCHEDULE_SCHEMA_VERSIONS:
            raise ScanScheduleValidationError(
                "scan_schedule_schema_unsupported", "schema_version is unsupported."
            )
        object.__setattr__(self, "schedule_id", _canonical_uuid(self.schedule_id, "schedule_id"))
        object.__setattr__(
            self, "organization_id", _canonical_uuid(self.organization_id, "organization_id")
        )
        object.__setattr__(self, "created_by", _canonical_uuid(self.created_by, "created_by"))
        object.__setattr__(
            self,
            "name",
            _required_text(self.name, "name", maximum=MAXIMUM_SCAN_SCHEDULE_NAME_LENGTH),
        )
        try:
            target = canonicalize_owned_target_url(self.target)
        except OwnedTargetContractError as exc:
            raise ScanScheduleValidationError(exc.code, exc.message) from exc
        object.__setattr__(self, "target", target)
        object.__setattr__(
            self,
            "authorization_id",
            _canonical_uuid(self.authorization_id, "authorization_id"),
        )
        object.__setattr__(self, "authorization_sha256", _sha256(self.authorization_sha256))
        if not isinstance(self.mode, ScanJobMode):
            raise ScanScheduleValidationError(
                "scan_schedule_mode_invalid", "mode must be a supported scan-job mode."
            )
        object.__setattr__(self, "interval_seconds", _interval(self.interval_seconds))
        if not isinstance(self.state, ScanScheduleState):
            raise ScanScheduleValidationError(
                "scan_schedule_state_invalid", "state must be active or paused."
            )
        created_at = _utc_datetime(self.created_at, "created_at")
        updated_at = _utc_datetime(self.updated_at, "updated_at")
        next_run_at = _utc_datetime(self.next_run_at, "next_run_at")
        if updated_at < created_at:
            raise ScanScheduleValidationError(
                "scan_schedule_timestamp_order_invalid",
                "updated_at cannot be earlier than created_at.",
            )
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "updated_at", updated_at)
        object.__setattr__(self, "next_run_at", next_run_at)
        object.__setattr__(self, "revision", _revision(self.revision))
        if self.last_enqueued_at is not None:
            object.__setattr__(
                self,
                "last_enqueued_at",
                _utc_datetime(self.last_enqueued_at, "last_enqueued_at"),
            )
        if self.last_job_id is not None:
            object.__setattr__(self, "last_job_id", _canonical_uuid(self.last_job_id, "last_job_id"))
        object.__setattr__(self, "last_error_code", _error_code(self.last_error_code))
        if self.last_error_at is not None:
            object.__setattr__(
                self,
                "last_error_at",
                _utc_datetime(self.last_error_at, "last_error_at"),
            )
        if (self.last_error_code is None) != (self.last_error_at is None):
            raise ScanScheduleValidationError(
                "scan_schedule_error_projection_invalid",
                "last_error_code and last_error_at must be set together.",
            )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "schedule_id": self.schedule_id,
            "organization_id": self.organization_id,
            "created_by": self.created_by,
            "name": self.name,
            "target": self.target,
            "authorization_id": self.authorization_id,
            "mode": self.mode.value,
            "interval_seconds": self.interval_seconds,
            "state": self.state.value,
            "created_at": _timestamp_text(self.created_at),
            "updated_at": _timestamp_text(self.updated_at),
            "next_run_at": _timestamp_text(self.next_run_at),
            "revision": self.revision,
            "last_enqueued_at": None
            if self.last_enqueued_at is None
            else _timestamp_text(self.last_enqueued_at),
            "last_job_id": self.last_job_id,
            "last_error_code": self.last_error_code,
            "last_error_at": None
            if self.last_error_at is None
            else _timestamp_text(self.last_error_at),
        }


def _decode_json(data: bytes) -> object:
    if not isinstance(data, bytes):
        raise ScanScheduleLoadError(
            "scan_schedule_document_invalid", "Scan-schedule JSON must be bytes."
        )
    if len(data) > MAXIMUM_SCAN_SCHEDULE_DOCUMENT_BYTES:
        raise ScanScheduleLoadError(
            "scan_schedule_document_too_large", "Scan-schedule JSON is too large."
        )

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise _DuplicateJsonKeyError(key)
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except UnicodeDecodeError as exc:
        raise ScanScheduleLoadError(
            "scan_schedule_encoding_invalid", "Scan-schedule JSON must be UTF-8."
        ) from exc
    except _DuplicateJsonKeyError as exc:
        raise ScanScheduleLoadError(
            "scan_schedule_duplicate_key", f"Duplicate JSON key {str(exc)!r}."
        ) from exc
    except json.JSONDecodeError as exc:
        raise ScanScheduleLoadError(
            "scan_schedule_json_invalid", "Scan-schedule JSON is malformed."
        ) from exc


def load_scan_schedule_submission(value: object) -> ScanScheduleSubmission:
    root = _strict_mapping(
        value,
        required={
            "name",
            "target",
            "authorization_id",
            "confirm_authorization",
            "mode",
            "interval_seconds",
            "starts_at",
        },
        context="schedule submission",
    )
    try:
        mode = ScanJobMode(root["mode"])
    except (TypeError, ValueError) as exc:
        raise ScanScheduleLoadError(
            "scan_schedule_mode_invalid", "mode must be single_page or crawl."
        ) from exc
    starts_at = _parse_timestamp(root["starts_at"], "starts_at")
    try:
        return ScanScheduleSubmission(
            name=root["name"],
            target=root["target"],
            authorization_id=root["authorization_id"],
            confirmation=root["confirm_authorization"],
            mode=mode,
            interval_seconds=root["interval_seconds"],
            starts_at=starts_at,
        )
    except ScanScheduleValidationError as exc:
        raise ScanScheduleLoadError(exc.code, exc.message) from exc


def load_scan_schedule_submission_json(data: bytes) -> ScanScheduleSubmission:
    return load_scan_schedule_submission(_decode_json(data))



__all__ = [
    "CURRENT_SCAN_SCHEDULE_SCHEMA_VERSION",
    "MAXIMUM_SCAN_SCHEDULE_DOCUMENT_BYTES",
    "MAXIMUM_SCAN_SCHEDULE_INTERVAL_SECONDS",
    "MAXIMUM_SCAN_SCHEDULE_NAME_LENGTH",
    "MINIMUM_SCAN_SCHEDULE_INTERVAL_SECONDS",
    "SCAN_SCHEDULE_RECORD_TYPE",
    "SUPPORTED_SCAN_SCHEDULE_SCHEMA_VERSIONS",
    "ScanScheduleContractError",
    "ScanScheduleLoadError",
    "ScanScheduleRecord",
    "ScanScheduleState",
    "ScanScheduleSubmission",
    "ScanScheduleValidationError",
    "load_scan_schedule_submission",
    "load_scan_schedule_submission_json",
]
