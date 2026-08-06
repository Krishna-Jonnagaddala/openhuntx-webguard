"""Versioned scan-job contracts for the OpenHuntX WebGuard service."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Mapping

from .owned_targets import OwnedTargetContractError, canonicalize_owned_target_url
from .scans import ScanStatus


CURRENT_SCAN_JOB_SCHEMA_VERSION = "1.0"
SUPPORTED_SCAN_JOB_SCHEMA_VERSIONS = ("1.0",)
SCAN_JOB_REQUEST_TYPE = "scan_job_request"
SCAN_JOB_RECORD_TYPE = "scan_job_record"
MAXIMUM_SCAN_JOB_DOCUMENT_BYTES = 128 * 1024
MAXIMUM_SCAN_JOB_ERROR_MESSAGE_LENGTH = 2048
MAXIMUM_SCAN_JOB_ARTIFACT_REFERENCE_LENGTH = 512
MAXIMUM_IDEMPOTENCY_KEY_LENGTH = 128
MINIMUM_IDEMPOTENCY_KEY_LENGTH = 8

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_ERROR_CODE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class ScanJobMode(str, Enum):
    """Supported scanner execution modes exposed by the service."""

    SINGLE_PAGE = "single_page"
    CRAWL = "crawl"


class ScanJobState(str, Enum):
    """Persistent lifecycle state for a queued scanner job."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in {
            ScanJobState.COMPLETED,
            ScanJobState.COMPLETED_WITH_ERRORS,
            ScanJobState.FAILED,
            ScanJobState.CANCELLED,
        }


class ScanJobContractError(ValueError):
    """Base class for controlled scan-job contract failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ScanJobValidationError(ScanJobContractError):
    """Raised when an in-memory scan-job value is invalid."""


class ScanJobLoadError(ScanJobContractError):
    """Raised when a serialized scan-job document is invalid."""


class _DuplicateJsonKeyError(ValueError):
    pass


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ScanJobValidationError(
            "scan_job_json_invalid",
            "The scan-job value cannot be encoded as canonical JSON.",
        ) from exc


def _required_text(
    value: object,
    field_name: str,
    *,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        raise ScanJobValidationError(
            "scan_job_text_invalid",
            f"{field_name} must be text.",
        )
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise ScanJobValidationError(
            "scan_job_text_invalid",
            f"{field_name} must contain 1 to {maximum} characters.",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise ScanJobValidationError(
            "scan_job_text_control_character",
            f"{field_name} cannot contain control characters.",
        )
    return cleaned


def _canonical_uuid(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ScanJobValidationError(
            "scan_job_uuid_invalid",
            f"{field_name} must be a canonical UUID string.",
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ScanJobValidationError(
            "scan_job_uuid_invalid",
            f"{field_name} must be a canonical UUID string.",
        ) from exc
    canonical = str(parsed)
    if canonical != value:
        raise ScanJobValidationError(
            "scan_job_uuid_non_canonical",
            f"{field_name} must use canonical lower-case UUID notation.",
        )
    return canonical


def _utc_datetime(value: object, field_name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ScanJobValidationError(
            "scan_job_timestamp_invalid",
            f"{field_name} must be a timezone-aware datetime.",
        )
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ScanJobLoadError(
            "scan_job_timestamp_invalid",
            f"{field_name} must use canonical UTC Z notation.",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ScanJobLoadError(
            "scan_job_timestamp_invalid",
            f"{field_name} is not a valid timestamp.",
        ) from exc
    if _timestamp_text(parsed) != value:
        raise ScanJobLoadError(
            "scan_job_timestamp_non_canonical",
            f"{field_name} must use canonical microsecond UTC notation.",
        )
    return parsed.astimezone(timezone.utc)


def _optional_timestamp(value: object, field_name: str) -> datetime | None:
    if value is None:
        return None
    return _parse_timestamp(value, field_name)


def _idempotency_key(value: object) -> str:
    cleaned = _required_text(
        value,
        "idempotency_key",
        maximum=MAXIMUM_IDEMPOTENCY_KEY_LENGTH,
    )
    if (
        len(cleaned) < MINIMUM_IDEMPOTENCY_KEY_LENGTH
        or not _IDEMPOTENCY_KEY.fullmatch(cleaned)
    ):
        raise ScanJobValidationError(
            "scan_job_idempotency_key_invalid",
            "idempotency_key must contain 8 to 128 letters, digits, dots, "
            "underscores, colons, or hyphens.",
        )
    return cleaned


def _sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ScanJobValidationError(
            "scan_job_sha256_invalid",
            f"{field_name} must be a lower-case SHA-256 hexadecimal digest.",
        )
    return value


def _artifact_reference(value: object, field_name: str) -> str:
    cleaned = _required_text(
        value,
        field_name,
        maximum=MAXIMUM_SCAN_JOB_ARTIFACT_REFERENCE_LENGTH,
    )
    if "\\" in cleaned:
        raise ScanJobValidationError(
            "scan_job_artifact_reference_invalid",
            f"{field_name} must use POSIX separators.",
        )
    path = PurePosixPath(cleaned)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ScanJobValidationError(
            "scan_job_artifact_reference_invalid",
            f"{field_name} must be a safe relative artifact reference.",
        )
    return path.as_posix()


def _optional_text(
    value: object,
    field_name: str,
    *,
    maximum: int,
) -> str | None:
    if value is None:
        return None
    return _required_text(value, field_name, maximum=maximum)


def _error_code(value: object) -> str | None:
    if value is None:
        return None
    cleaned = _required_text(value, "error_code", maximum=128).lower()
    if not _ERROR_CODE.fullmatch(cleaned):
        raise ScanJobValidationError(
            "scan_job_error_code_invalid",
            "error_code must use a canonical lower-case identifier.",
        )
    return cleaned


def _revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ScanJobValidationError(
            "scan_job_revision_invalid",
            "revision must be a non-negative integer.",
        )
    return value


def _strict_mapping(
    value: object,
    *,
    required: set[str],
    optional: set[str] = frozenset(),
    context: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ScanJobLoadError(
            "scan_job_document_invalid",
            f"{context} must be a JSON object.",
        )
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ScanJobLoadError(
            "scan_job_field_missing",
            f"{context} is missing required field {sorted(missing)[0]!r}.",
        )
    if unknown:
        raise ScanJobLoadError(
            "scan_job_field_unknown",
            f"{context} contains unknown field {sorted(unknown)[0]!r}.",
        )
    return value


@dataclass(frozen=True, slots=True)
class ScanJobSubmission:
    """Validated API submission before service-owned metadata is added."""

    target: str
    authorization_id: str
    confirmation: str
    mode: ScanJobMode

    def __post_init__(self) -> None:
        try:
            target = canonicalize_owned_target_url(self.target)
        except OwnedTargetContractError as exc:
            raise ScanJobValidationError(exc.code, exc.message) from exc
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
            raise ScanJobValidationError(
                "scan_job_authorization_confirmation_mismatch",
                "confirmation must exactly match authorization_id.",
            )
        if not isinstance(self.mode, ScanJobMode):
            raise ScanJobValidationError(
                "scan_job_mode_invalid",
                "mode must be a ScanJobMode value.",
            )


@dataclass(frozen=True, slots=True)
class ScanJobRequest:
    """Canonical persisted request after authorization lookup succeeds."""

    idempotency_key: str
    target: str
    authorization_id: str
    authorization_sha256: str
    mode: ScanJobMode
    submitted_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "idempotency_key", _idempotency_key(self.idempotency_key))
        try:
            target = canonicalize_owned_target_url(self.target)
        except OwnedTargetContractError as exc:
            raise ScanJobValidationError(exc.code, exc.message) from exc
        object.__setattr__(self, "target", target)
        object.__setattr__(
            self,
            "authorization_id",
            _canonical_uuid(self.authorization_id, "authorization_id"),
        )
        object.__setattr__(
            self,
            "authorization_sha256",
            _sha256(self.authorization_sha256, "authorization_sha256"),
        )
        if not isinstance(self.mode, ScanJobMode):
            raise ScanJobValidationError(
                "scan_job_mode_invalid",
                "mode must be a ScanJobMode value.",
            )
        object.__setattr__(
            self,
            "submitted_at",
            _utc_datetime(self.submitted_at, "submitted_at"),
        )

    @property
    def fingerprint(self) -> str:
        payload = {
            "target": self.target,
            "authorization_id": self.authorization_id,
            "authorization_sha256": self.authorization_sha256,
            "mode": self.mode.value,
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": SCAN_JOB_REQUEST_TYPE,
            "schema_version": CURRENT_SCAN_JOB_SCHEMA_VERSION,
            "idempotency_key": self.idempotency_key,
            "target": self.target,
            "authorization_id": self.authorization_id,
            "authorization_sha256": self.authorization_sha256,
            "mode": self.mode.value,
            "submitted_at": _timestamp_text(self.submitted_at),
            "fingerprint": self.fingerprint,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict()).decode("utf-8")


@dataclass(frozen=True, slots=True)
class ScanJobRecord:
    """Canonical persisted metadata for one scanner job."""

    job_id: str
    request: ScanJobRequest
    state: ScanJobState
    updated_at: datetime
    revision: int = 0
    cancellation_requested: bool = False
    started_at: datetime | None = None
    completed_at: datetime | None = None
    scan_id: str | None = None
    result_status: ScanStatus | None = None
    report_ref: str | None = None
    audit_ref: str | None = None
    error_code: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _canonical_uuid(self.job_id, "job_id"))
        if not isinstance(self.request, ScanJobRequest):
            raise ScanJobValidationError(
                "scan_job_request_invalid",
                "request must be a ScanJobRequest value.",
            )
        if not isinstance(self.state, ScanJobState):
            raise ScanJobValidationError(
                "scan_job_state_invalid",
                "state must be a ScanJobState value.",
            )
        object.__setattr__(self, "updated_at", _utc_datetime(self.updated_at, "updated_at"))
        object.__setattr__(self, "revision", _revision(self.revision))
        if not isinstance(self.cancellation_requested, bool):
            raise ScanJobValidationError(
                "scan_job_cancellation_flag_invalid",
                "cancellation_requested must be boolean.",
            )
        if self.started_at is not None:
            object.__setattr__(
                self,
                "started_at",
                _utc_datetime(self.started_at, "started_at"),
            )
        if self.completed_at is not None:
            object.__setattr__(
                self,
                "completed_at",
                _utc_datetime(self.completed_at, "completed_at"),
            )
        if self.updated_at < self.request.submitted_at:
            raise ScanJobValidationError(
                "scan_job_timestamp_order_invalid",
                "updated_at cannot precede submitted_at.",
            )
        if self.started_at is not None and self.started_at < self.request.submitted_at:
            raise ScanJobValidationError(
                "scan_job_timestamp_order_invalid",
                "started_at cannot precede submitted_at.",
            )
        if self.completed_at is not None:
            boundary = self.started_at or self.request.submitted_at
            if self.completed_at < boundary:
                raise ScanJobValidationError(
                    "scan_job_timestamp_order_invalid",
                    "completed_at cannot precede the job start boundary.",
                )
        if self.scan_id is not None:
            object.__setattr__(self, "scan_id", _canonical_uuid(self.scan_id, "scan_id"))
        if self.result_status is not None and not isinstance(self.result_status, ScanStatus):
            raise ScanJobValidationError(
                "scan_job_result_status_invalid",
                "result_status must be a ScanStatus value.",
            )
        if self.report_ref is not None:
            object.__setattr__(
                self,
                "report_ref",
                _artifact_reference(self.report_ref, "report_ref"),
            )
        if self.audit_ref is not None:
            object.__setattr__(
                self,
                "audit_ref",
                _artifact_reference(self.audit_ref, "audit_ref"),
            )
        object.__setattr__(self, "error_code", _error_code(self.error_code))
        object.__setattr__(
            self,
            "error_message",
            _optional_text(
                self.error_message,
                "error_message",
                maximum=MAXIMUM_SCAN_JOB_ERROR_MESSAGE_LENGTH,
            ),
        )
        self._validate_state_projection()

    def _validate_state_projection(self) -> None:
        if self.state is ScanJobState.QUEUED:
            if any(
                value is not None
                for value in (
                    self.started_at,
                    self.completed_at,
                    self.scan_id,
                    self.result_status,
                    self.report_ref,
                    self.audit_ref,
                    self.error_code,
                    self.error_message,
                )
            ):
                raise ScanJobValidationError(
                    "scan_job_queued_projection_invalid",
                    "Queued jobs cannot contain execution or result metadata.",
                )
            return

        if self.state is ScanJobState.RUNNING:
            if self.started_at is None or self.completed_at is not None:
                raise ScanJobValidationError(
                    "scan_job_running_projection_invalid",
                    "Running jobs require started_at and cannot have completed_at.",
                )
            if any(
                value is not None
                for value in (
                    self.scan_id,
                    self.result_status,
                    self.report_ref,
                    self.audit_ref,
                    self.error_code,
                    self.error_message,
                )
            ):
                raise ScanJobValidationError(
                    "scan_job_running_projection_invalid",
                    "Running jobs cannot contain terminal result metadata.",
                )
            return

        if self.completed_at is None:
            raise ScanJobValidationError(
                "scan_job_terminal_timestamp_missing",
                "Terminal jobs require completed_at.",
            )

        result_fields = (
            self.scan_id,
            self.result_status,
            self.report_ref,
            self.audit_ref,
        )
        has_any_result = any(value is not None for value in result_fields)
        has_all_result = all(value is not None for value in result_fields)
        has_any_error = self.error_code is not None or self.error_message is not None
        has_all_error = self.error_code is not None and self.error_message is not None

        if has_any_result and not has_all_result:
            raise ScanJobValidationError(
                "scan_job_result_projection_invalid",
                "Result-backed jobs require complete scan and artifact metadata.",
            )
        if has_any_error and not has_all_error:
            raise ScanJobValidationError(
                "scan_job_error_projection_invalid",
                "Service failures require both error_code and error_message.",
            )
        if has_all_result and has_all_error:
            raise ScanJobValidationError(
                "scan_job_terminal_projection_conflict",
                "A terminal job cannot contain both a scan result and a service error.",
            )

        expected_result_state = {
            ScanStatus.COMPLETED: ScanJobState.COMPLETED,
            ScanStatus.COMPLETED_WITH_ERRORS: ScanJobState.COMPLETED_WITH_ERRORS,
            ScanStatus.FAILED: ScanJobState.FAILED,
            ScanStatus.CANCELLED: ScanJobState.CANCELLED,
        }
        if has_all_result:
            if self.started_at is None:
                raise ScanJobValidationError(
                    "scan_job_result_start_missing",
                    "Result-backed jobs require started_at.",
                )
            assert self.result_status is not None
            expected = expected_result_state.get(self.result_status)
            if expected is None or self.state is not expected:
                raise ScanJobValidationError(
                    "scan_job_result_status_mismatch",
                    "Job state and scan result status do not match.",
                )
            return

        if self.state is ScanJobState.FAILED:
            if self.started_at is None or not has_all_error:
                raise ScanJobValidationError(
                    "scan_job_failed_projection_invalid",
                    "Service-failed jobs require started_at and controlled error metadata.",
                )
            return

        if self.state is ScanJobState.CANCELLED:
            if has_any_error:
                raise ScanJobValidationError(
                    "scan_job_cancelled_error_invalid",
                    "Cancelled jobs cannot contain service error metadata.",
                )
            return

        raise ScanJobValidationError(
            "scan_job_terminal_projection_invalid",
            "Completed job states require result-backed metadata.",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": SCAN_JOB_RECORD_TYPE,
            "schema_version": CURRENT_SCAN_JOB_SCHEMA_VERSION,
            "job_id": self.job_id,
            "request": self.request.to_dict(),
            "state": self.state.value,
            "updated_at": _timestamp_text(self.updated_at),
            "revision": self.revision,
            "cancellation_requested": self.cancellation_requested,
            "started_at": None if self.started_at is None else _timestamp_text(self.started_at),
            "completed_at": None if self.completed_at is None else _timestamp_text(self.completed_at),
            "scan_id": self.scan_id,
            "result_status": None if self.result_status is None else self.result_status.value,
            "report_ref": self.report_ref,
            "audit_ref": self.audit_ref,
            "error": None
            if self.error_code is None
            else {"code": self.error_code, "message": self.error_message},
        }

    def to_public_dict(self) -> dict[str, Any]:
        """Return API-safe metadata without keys, authorization digests, or bodies."""

        return {
            "type": SCAN_JOB_RECORD_TYPE,
            "schema_version": CURRENT_SCAN_JOB_SCHEMA_VERSION,
            "job_id": self.job_id,
            "request": {
                "target": self.request.target,
                "authorization_id": self.request.authorization_id,
                "mode": self.request.mode.value,
                "submitted_at": _timestamp_text(self.request.submitted_at),
            },
            "state": self.state.value,
            "updated_at": _timestamp_text(self.updated_at),
            "revision": self.revision,
            "cancellation_requested": self.cancellation_requested,
            "started_at": None if self.started_at is None else _timestamp_text(self.started_at),
            "completed_at": None if self.completed_at is None else _timestamp_text(self.completed_at),
            "scan_id": self.scan_id,
            "result_status": None if self.result_status is None else self.result_status.value,
            "report_ref": self.report_ref,
            "audit_ref": self.audit_ref,
            "error": None
            if self.error_code is None
            else {"code": self.error_code, "message": self.error_message},
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict()).decode("utf-8")


def load_scan_job_submission(value: object) -> ScanJobSubmission:
    mapping = _strict_mapping(
        value,
        required={"target", "authorization_id", "confirm_authorization", "mode"},
        context="scan-job submission",
    )
    try:
        mode = ScanJobMode(mapping["mode"])
    except (TypeError, ValueError) as exc:
        raise ScanJobLoadError(
            "scan_job_mode_invalid",
            "mode must be 'single_page' or 'crawl'.",
        ) from exc
    try:
        return ScanJobSubmission(
            target=mapping["target"],
            authorization_id=mapping["authorization_id"],
            confirmation=mapping["confirm_authorization"],
            mode=mode,
        )
    except (ScanJobValidationError, OwnedTargetContractError) as exc:
        raise ScanJobLoadError(exc.code, exc.message) from exc


def load_scan_job_submission_json(document: str | bytes) -> ScanJobSubmission:
    raw = _decode_json_document(document)
    return load_scan_job_submission(raw)


def _decode_json_document(document: str | bytes) -> object:
    if isinstance(document, str):
        try:
            encoded = document.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ScanJobLoadError(
                "scan_job_document_encoding_invalid",
                "The scan-job document is not valid UTF-8 text.",
            ) from exc
    elif isinstance(document, bytes):
        encoded = document
    else:
        raise ScanJobLoadError(
            "scan_job_document_type_invalid",
            "The scan-job document must be text or bytes.",
        )
    if len(encoded) > MAXIMUM_SCAN_JOB_DOCUMENT_BYTES:
        raise ScanJobLoadError(
            "scan_job_document_too_large",
            "The scan-job document exceeds 128 KiB.",
        )
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanJobLoadError(
            "scan_job_document_encoding_invalid",
            "The scan-job document is not valid UTF-8.",
        ) from exc

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateJsonKeyError(key)
            result[key] = value
        return result

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except _DuplicateJsonKeyError as exc:
        raise ScanJobLoadError(
            "scan_job_duplicate_json_key",
            f"The scan-job document contains duplicate key {str(exc)!r}.",
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ScanJobLoadError(
            "scan_job_json_invalid",
            "The scan-job document is not valid strict JSON.",
        ) from exc


def load_scan_job_request(value: object) -> ScanJobRequest:
    mapping = _strict_mapping(
        value,
        required={
            "type",
            "schema_version",
            "idempotency_key",
            "target",
            "authorization_id",
            "authorization_sha256",
            "mode",
            "submitted_at",
            "fingerprint",
        },
        context="scan-job request",
    )
    if mapping["type"] != SCAN_JOB_REQUEST_TYPE:
        raise ScanJobLoadError("scan_job_type_invalid", "Unexpected scan-job request type.")
    if mapping["schema_version"] not in SUPPORTED_SCAN_JOB_SCHEMA_VERSIONS:
        raise ScanJobLoadError(
            "scan_job_schema_unsupported",
            "Unsupported scan-job schema version.",
        )
    try:
        mode = ScanJobMode(mapping["mode"])
        request = ScanJobRequest(
            idempotency_key=mapping["idempotency_key"],
            target=mapping["target"],
            authorization_id=mapping["authorization_id"],
            authorization_sha256=mapping["authorization_sha256"],
            mode=mode,
            submitted_at=_parse_timestamp(mapping["submitted_at"], "submitted_at"),
        )
    except (ScanJobValidationError, OwnedTargetContractError, ValueError, TypeError) as exc:
        if isinstance(exc, (ScanJobContractError, OwnedTargetContractError)):
            raise ScanJobLoadError(exc.code, exc.message) from exc
        raise ScanJobLoadError("scan_job_request_invalid", "Invalid scan-job request.") from exc
    if mapping["fingerprint"] != request.fingerprint:
        raise ScanJobLoadError(
            "scan_job_fingerprint_mismatch",
            "The scan-job request fingerprint is invalid.",
        )
    return request


def load_scan_job_record(value: object) -> ScanJobRecord:
    mapping = _strict_mapping(
        value,
        required={
            "type",
            "schema_version",
            "job_id",
            "request",
            "state",
            "updated_at",
            "revision",
            "cancellation_requested",
            "started_at",
            "completed_at",
            "scan_id",
            "result_status",
            "report_ref",
            "audit_ref",
            "error",
        },
        context="scan-job record",
    )
    if mapping["type"] != SCAN_JOB_RECORD_TYPE:
        raise ScanJobLoadError("scan_job_type_invalid", "Unexpected scan-job record type.")
    if mapping["schema_version"] not in SUPPORTED_SCAN_JOB_SCHEMA_VERSIONS:
        raise ScanJobLoadError(
            "scan_job_schema_unsupported",
            "Unsupported scan-job schema version.",
        )
    error_code: object = None
    error_message: object = None
    if mapping["error"] is not None:
        error = _strict_mapping(
            mapping["error"],
            required={"code", "message"},
            context="scan-job error",
        )
        error_code = error["code"]
        error_message = error["message"]
    try:
        state = ScanJobState(mapping["state"])
        result_status = (
            None
            if mapping["result_status"] is None
            else ScanStatus(mapping["result_status"])
        )
        return ScanJobRecord(
            job_id=mapping["job_id"],
            request=load_scan_job_request(mapping["request"]),
            state=state,
            updated_at=_parse_timestamp(mapping["updated_at"], "updated_at"),
            revision=mapping["revision"],
            cancellation_requested=mapping["cancellation_requested"],
            started_at=_optional_timestamp(mapping["started_at"], "started_at"),
            completed_at=_optional_timestamp(mapping["completed_at"], "completed_at"),
            scan_id=mapping["scan_id"],
            result_status=result_status,
            report_ref=mapping["report_ref"],
            audit_ref=mapping["audit_ref"],
            error_code=error_code,
            error_message=error_message,
        )
    except (ScanJobValidationError, ValueError, TypeError) as exc:
        if isinstance(exc, ScanJobContractError):
            raise ScanJobLoadError(exc.code, exc.message) from exc
        raise ScanJobLoadError("scan_job_record_invalid", "Invalid scan-job record.") from exc


def load_scan_job_request_json(document: str | bytes) -> ScanJobRequest:
    return load_scan_job_request(_decode_json_document(document))


def load_scan_job_record_json(document: str | bytes) -> ScanJobRecord:
    return load_scan_job_record(_decode_json_document(document))


__all__ = [
    "CURRENT_SCAN_JOB_SCHEMA_VERSION",
    "MAXIMUM_IDEMPOTENCY_KEY_LENGTH",
    "MAXIMUM_SCAN_JOB_ARTIFACT_REFERENCE_LENGTH",
    "MAXIMUM_SCAN_JOB_DOCUMENT_BYTES",
    "MAXIMUM_SCAN_JOB_ERROR_MESSAGE_LENGTH",
    "MINIMUM_IDEMPOTENCY_KEY_LENGTH",
    "SCAN_JOB_RECORD_TYPE",
    "SCAN_JOB_REQUEST_TYPE",
    "SUPPORTED_SCAN_JOB_SCHEMA_VERSIONS",
    "ScanJobContractError",
    "ScanJobLoadError",
    "ScanJobMode",
    "ScanJobRecord",
    "ScanJobRequest",
    "ScanJobState",
    "ScanJobSubmission",
    "ScanJobValidationError",
    "load_scan_job_record",
    "load_scan_job_record_json",
    "load_scan_job_request",
    "load_scan_job_request_json",
    "load_scan_job_submission",
    "load_scan_job_submission_json",
]
