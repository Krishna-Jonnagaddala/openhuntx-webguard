"""TrustScan cryptographic scan-permit contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .owned_targets import OwnedTargetContractError, canonicalize_owned_target_url
from .scan_jobs import ScanJobMode


CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION = "1.0"
SUPPORTED_TRUSTSCAN_PERMIT_SCHEMA_VERSIONS = ("1.0",)
TRUSTSCAN_PERMIT_TYPE = "trustscan_scan_permit"
TRUSTSCAN_SIGNATURE_ALGORITHM = "Ed25519"
MAXIMUM_TRUSTSCAN_PERMIT_DOCUMENT_BYTES = 128 * 1024
MAXIMUM_TRUSTSCAN_PERMIT_VALIDITY_DAYS = 90
MINIMUM_TRUSTSCAN_REQUESTS_PER_SECOND = 0.2
MAXIMUM_TRUSTSCAN_REQUESTS_PER_SECOND = 2.0
MAXIMUM_TRUSTSCAN_REQUEST_ATTEMPTS = 150
TRUSTSCAN_V1_MAXIMUM_CONCURRENCY = 1
TRUSTSCAN_ALLOWED_HTTP_METHODS = ("GET", "HEAD")
TRUSTSCAN_PROHIBITED_OPERATIONS = (
    "autonomous_exploitation",
    "credential_attacks",
    "data_destruction",
    "denial_of_service",
    "malware",
    "persistence",
    "social_engineering",
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class TrustScanPermitContractError(ValueError):
    """Base class for controlled TrustScan permit contract failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class TrustScanPermitValidationError(TrustScanPermitContractError):
    """Raised when an in-memory permit value is invalid."""


class TrustScanPermitLoadError(TrustScanPermitContractError):
    """Raised when a serialized permit document cannot be loaded safely."""


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
        raise TrustScanPermitValidationError(
            "trustscan_permit_json_invalid",
            "The TrustScan permit cannot be encoded as canonical JSON.",
        ) from exc


def _uuid(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise TrustScanPermitValidationError(
            "trustscan_permit_uuid_invalid",
            f"{field_name} must be a canonical UUID string.",
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise TrustScanPermitValidationError(
            "trustscan_permit_uuid_invalid",
            f"{field_name} must be a canonical UUID string.",
        ) from exc
    canonical = str(parsed)
    if canonical != value:
        raise TrustScanPermitValidationError(
            "trustscan_permit_uuid_non_canonical",
            f"{field_name} must use canonical lower-case UUID notation.",
        )
    return canonical


def _sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise TrustScanPermitValidationError(
            "trustscan_permit_sha256_invalid",
            f"{field_name} must be a lower-case SHA-256 digest.",
        )
    return value


def _utc_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TrustScanPermitValidationError(
            "trustscan_permit_timestamp_invalid",
            f"{field_name} must be a timezone-aware datetime.",
        )
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TrustScanPermitLoadError(
            "trustscan_permit_timestamp_invalid",
            f"{field_name} must use canonical UTC Z notation.",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TrustScanPermitLoadError(
            "trustscan_permit_timestamp_invalid",
            f"{field_name} is not a valid timestamp.",
        ) from exc
    if _timestamp_text(parsed) != value:
        raise TrustScanPermitLoadError(
            "trustscan_permit_timestamp_non_canonical",
            f"{field_name} must use canonical microsecond UTC notation.",
        )
    return parsed.astimezone(timezone.utc)


def _positive_integer(value: object, field_name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise TrustScanPermitValidationError(
            "trustscan_permit_integer_invalid",
            f"{field_name} must be an integer from 1 to {maximum}.",
        )
    return value


def _requests_per_second(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TrustScanPermitValidationError(
            "trustscan_permit_rate_invalid",
            "maximum_requests_per_second must be a finite number.",
        )
    converted = float(value)
    if (
        not math.isfinite(converted)
        or not MINIMUM_TRUSTSCAN_REQUESTS_PER_SECOND
        <= converted
        <= MAXIMUM_TRUSTSCAN_REQUESTS_PER_SECOND
    ):
        raise TrustScanPermitValidationError(
            "trustscan_permit_rate_invalid",
            "maximum_requests_per_second must be from 0.2 to 2.0.",
        )
    return converted


def _modes(value: object) -> tuple[ScanJobMode, ...]:
    if not isinstance(value, tuple) or not value:
        raise TrustScanPermitValidationError(
            "trustscan_permit_modes_invalid",
            "permitted_modes must be a non-empty tuple.",
        )
    if any(not isinstance(item, ScanJobMode) for item in value):
        raise TrustScanPermitValidationError(
            "trustscan_permit_modes_invalid",
            "permitted_modes contains an unsupported scan mode.",
        )
    canonical = tuple(sorted(set(value), key=lambda item: item.value))
    if canonical != value:
        raise TrustScanPermitValidationError(
            "trustscan_permit_modes_non_canonical",
            "permitted_modes must be sorted and unique.",
        )
    return value


def _http_methods(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise TrustScanPermitValidationError(
            "trustscan_permit_methods_invalid",
            "allowed_http_methods must be a non-empty tuple.",
        )
    if any(not isinstance(item, str) for item in value):
        raise TrustScanPermitValidationError(
            "trustscan_permit_methods_invalid",
            "allowed_http_methods must contain method names.",
        )
    canonical = tuple(sorted(set(item.upper() for item in value)))
    if canonical != value:
        raise TrustScanPermitValidationError(
            "trustscan_permit_methods_non_canonical",
            "allowed_http_methods must be sorted, unique, and uppercase.",
        )
    if any(item not in TRUSTSCAN_ALLOWED_HTTP_METHODS for item in canonical):
        raise TrustScanPermitValidationError(
            "trustscan_permit_methods_invalid",
            "TrustScan permit v1 only permits GET and HEAD.",
        )
    if "GET" not in canonical:
        raise TrustScanPermitValidationError(
            "trustscan_permit_get_required",
            "TrustScan permit v1 requires GET for passive assessment execution.",
        )
    return canonical


def _prohibited_operations(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or value != TRUSTSCAN_PROHIBITED_OPERATIONS:
        raise TrustScanPermitValidationError(
            "trustscan_permit_prohibited_operations_invalid",
            "prohibited_operations must equal the TrustScan v1 mandatory safety set.",
        )
    return value


def _strict_mapping(
    value: object,
    *,
    required: set[str],
    context: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TrustScanPermitLoadError(
            "trustscan_permit_document_invalid",
            f"{context} must be a JSON object.",
        )
    keys = set(value)
    missing = required - keys
    unknown = keys - required
    if missing:
        raise TrustScanPermitLoadError(
            "trustscan_permit_field_missing",
            f"{context} is missing required field {sorted(missing)[0]!r}.",
        )
    if unknown:
        raise TrustScanPermitLoadError(
            "trustscan_permit_field_unknown",
            f"{context} contains unknown field {sorted(unknown)[0]!r}.",
        )
    return value


def _parse_json(document: str | bytes) -> object:
    raw = document.encode("utf-8") if isinstance(document, str) else bytes(document)
    if len(raw) > MAXIMUM_TRUSTSCAN_PERMIT_DOCUMENT_BYTES:
        raise TrustScanPermitLoadError(
            "trustscan_permit_document_too_large",
            "TrustScan permit document exceeds 128 KiB.",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TrustScanPermitLoadError(
            "trustscan_permit_encoding_invalid",
            "TrustScan permit document must be valid UTF-8.",
        ) from exc

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateJsonKeyError(key)
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=hook)
    except (_DuplicateJsonKeyError, json.JSONDecodeError) as exc:
        raise TrustScanPermitLoadError(
            "trustscan_permit_json_invalid",
            "TrustScan permit document is not valid strict JSON.",
        ) from exc


@dataclass(frozen=True, slots=True)
class TrustScanPermitSubmission:
    """Validated request to issue a TrustScan permit."""

    target: str
    authorization_id: str
    confirmation: str
    permitted_modes: tuple[ScanJobMode, ...]
    allowed_http_methods: tuple[str, ...]
    not_before: datetime
    expires_at: datetime
    maximum_request_attempts: int
    maximum_requests_per_second: float
    maximum_concurrency: int = TRUSTSCAN_V1_MAXIMUM_CONCURRENCY

    def __post_init__(self) -> None:
        try:
            target = canonicalize_owned_target_url(self.target)
        except OwnedTargetContractError as exc:
            raise TrustScanPermitValidationError(exc.code, exc.message) from exc
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "authorization_id", _uuid(self.authorization_id, "authorization_id"))
        object.__setattr__(self, "confirmation", _uuid(self.confirmation, "confirmation"))
        if self.confirmation != self.authorization_id:
            raise TrustScanPermitValidationError(
                "trustscan_permit_authorization_confirmation_mismatch",
                "confirmation must exactly match authorization_id.",
            )
        object.__setattr__(self, "permitted_modes", _modes(self.permitted_modes))
        object.__setattr__(self, "allowed_http_methods", _http_methods(self.allowed_http_methods))
        not_before = _utc_datetime(self.not_before, "not_before")
        expires_at = _utc_datetime(self.expires_at, "expires_at")
        if expires_at <= not_before:
            raise TrustScanPermitValidationError(
                "trustscan_permit_window_invalid",
                "expires_at must be later than not_before.",
            )
        if expires_at - not_before > timedelta(days=MAXIMUM_TRUSTSCAN_PERMIT_VALIDITY_DAYS):
            raise TrustScanPermitValidationError(
                "trustscan_permit_window_too_long",
                "TrustScan permit validity cannot exceed 90 days.",
            )
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(
            self,
            "maximum_request_attempts",
            _positive_integer(
                self.maximum_request_attempts,
                "maximum_request_attempts",
                maximum=MAXIMUM_TRUSTSCAN_REQUEST_ATTEMPTS,
            ),
        )
        object.__setattr__(
            self,
            "maximum_requests_per_second",
            _requests_per_second(self.maximum_requests_per_second),
        )
        concurrency = _positive_integer(
            self.maximum_concurrency,
            "maximum_concurrency",
            maximum=TRUSTSCAN_V1_MAXIMUM_CONCURRENCY,
        )
        if concurrency != TRUSTSCAN_V1_MAXIMUM_CONCURRENCY:
            raise TrustScanPermitValidationError(
                "trustscan_permit_concurrency_invalid",
                "TrustScan permit v1 requires maximum_concurrency to be 1.",
            )
        object.__setattr__(self, "maximum_concurrency", concurrency)


@dataclass(frozen=True, slots=True)
class TrustScanPermitClaims:
    """Immutable claims that are cryptographically signed for one scan permit."""

    permit_id: str
    organization_id: str
    authorization_id: str
    authorization_sha256: str
    target: str
    issued_by: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    permitted_modes: tuple[ScanJobMode, ...]
    allowed_http_methods: tuple[str, ...]
    maximum_request_attempts: int
    maximum_requests_per_second: float
    maximum_concurrency: int = TRUSTSCAN_V1_MAXIMUM_CONCURRENCY
    prohibited_operations: tuple[str, ...] = TRUSTSCAN_PROHIBITED_OPERATIONS

    def __post_init__(self) -> None:
        object.__setattr__(self, "permit_id", _uuid(self.permit_id, "permit_id"))
        object.__setattr__(self, "organization_id", _uuid(self.organization_id, "organization_id"))
        object.__setattr__(self, "authorization_id", _uuid(self.authorization_id, "authorization_id"))
        object.__setattr__(
            self,
            "authorization_sha256",
            _sha256(self.authorization_sha256, "authorization_sha256"),
        )
        try:
            target = canonicalize_owned_target_url(self.target)
        except OwnedTargetContractError as exc:
            raise TrustScanPermitValidationError(exc.code, exc.message) from exc
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "issued_by", _uuid(self.issued_by, "issued_by"))
        issued_at = _utc_datetime(self.issued_at, "issued_at")
        not_before = _utc_datetime(self.not_before, "not_before")
        expires_at = _utc_datetime(self.expires_at, "expires_at")
        if not_before < issued_at:
            raise TrustScanPermitValidationError(
                "trustscan_permit_window_invalid",
                "not_before cannot precede issued_at.",
            )
        if expires_at <= not_before:
            raise TrustScanPermitValidationError(
                "trustscan_permit_window_invalid",
                "expires_at must be later than not_before.",
            )
        if expires_at - not_before > timedelta(days=MAXIMUM_TRUSTSCAN_PERMIT_VALIDITY_DAYS):
            raise TrustScanPermitValidationError(
                "trustscan_permit_window_too_long",
                "TrustScan permit validity cannot exceed 90 days.",
            )
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "permitted_modes", _modes(self.permitted_modes))
        object.__setattr__(self, "allowed_http_methods", _http_methods(self.allowed_http_methods))
        object.__setattr__(
            self,
            "maximum_request_attempts",
            _positive_integer(
                self.maximum_request_attempts,
                "maximum_request_attempts",
                maximum=MAXIMUM_TRUSTSCAN_REQUEST_ATTEMPTS,
            ),
        )
        object.__setattr__(
            self,
            "maximum_requests_per_second",
            _requests_per_second(self.maximum_requests_per_second),
        )
        concurrency = _positive_integer(
            self.maximum_concurrency,
            "maximum_concurrency",
            maximum=TRUSTSCAN_V1_MAXIMUM_CONCURRENCY,
        )
        object.__setattr__(self, "maximum_concurrency", concurrency)
        object.__setattr__(
            self,
            "prohibited_operations",
            _prohibited_operations(self.prohibited_operations),
        )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.signing_bytes).hexdigest()

    @property
    def signing_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "permit_id": self.permit_id,
            "organization_id": self.organization_id,
            "authorization_id": self.authorization_id,
            "authorization_sha256": self.authorization_sha256,
            "target": self.target,
            "issued_by": self.issued_by,
            "issued_at": _timestamp_text(self.issued_at),
            "not_before": _timestamp_text(self.not_before),
            "expires_at": _timestamp_text(self.expires_at),
            "permitted_modes": [mode.value for mode in self.permitted_modes],
            "allowed_http_methods": list(self.allowed_http_methods),
            "maximum_request_attempts": self.maximum_request_attempts,
            "maximum_requests_per_second": self.maximum_requests_per_second,
            "maximum_concurrency": self.maximum_concurrency,
            "prohibited_operations": list(self.prohibited_operations),
        }


@dataclass(frozen=True, slots=True)
class SignedTrustScanPermit:
    """One Ed25519-signed TrustScan permit document."""

    claims: TrustScanPermitClaims
    signing_key_id: str
    signature: str
    signature_algorithm: str = TRUSTSCAN_SIGNATURE_ALGORITHM
    permit_type: str = TRUSTSCAN_PERMIT_TYPE
    schema_version: str = CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.claims, TrustScanPermitClaims):
            raise TrustScanPermitValidationError(
                "trustscan_permit_claims_invalid",
                "claims must be TrustScanPermitClaims.",
            )
        if self.permit_type != TRUSTSCAN_PERMIT_TYPE:
            raise TrustScanPermitValidationError(
                "trustscan_permit_type_invalid",
                "permit_type is invalid.",
            )
        if self.schema_version not in SUPPORTED_TRUSTSCAN_PERMIT_SCHEMA_VERSIONS:
            raise TrustScanPermitValidationError(
                "trustscan_permit_schema_unsupported",
                "TrustScan permit schema_version is unsupported.",
            )
        if self.signature_algorithm != TRUSTSCAN_SIGNATURE_ALGORITHM:
            raise TrustScanPermitValidationError(
                "trustscan_permit_signature_algorithm_invalid",
                "TrustScan permit signature algorithm must be Ed25519.",
            )
        if not isinstance(self.signing_key_id, str) or not _KEY_ID.fullmatch(self.signing_key_id):
            raise TrustScanPermitValidationError(
                "trustscan_permit_key_id_invalid",
                "signing_key_id must be a SHA-256 key identifier.",
            )
        if (
            not isinstance(self.signature, str)
            or not 80 <= len(self.signature) <= 128
            or not _BASE64URL.fullmatch(self.signature)
        ):
            raise TrustScanPermitValidationError(
                "trustscan_permit_signature_invalid",
                "signature must be canonical unpadded Base64URL text.",
            )

    @property
    def fingerprint(self) -> str:
        return self.claims.fingerprint

    def to_dict(self) -> dict[str, object]:
        return {
            "permit_type": self.permit_type,
            "schema_version": self.schema_version,
            "claims": self.claims.to_dict(),
            "signature": {
                "algorithm": self.signature_algorithm,
                "key_id": self.signing_key_id,
                "value": self.signature,
            },
            "permit_sha256": self.fingerprint,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict()).decode("utf-8")


def load_trustscan_permit_submission_json(document: str | bytes) -> TrustScanPermitSubmission:
    root = _strict_mapping(
        _parse_json(document),
        required={
            "target",
            "authorization_id",
            "confirm_authorization",
            "permitted_modes",
            "allowed_http_methods",
            "not_before",
            "expires_at",
            "maximum_request_attempts",
            "maximum_requests_per_second",
            "maximum_concurrency",
        },
        context="TrustScan permit submission",
    )
    mode_values = root["permitted_modes"]
    method_values = root["allowed_http_methods"]
    if not isinstance(mode_values, list) or not isinstance(method_values, list):
        raise TrustScanPermitLoadError(
            "trustscan_permit_list_required",
            "permitted_modes and allowed_http_methods must be JSON arrays.",
        )
    try:
        submission = TrustScanPermitSubmission(
            target=root["target"],
            authorization_id=root["authorization_id"],
            confirmation=root["confirm_authorization"],
            permitted_modes=tuple(ScanJobMode(value) for value in mode_values),
            allowed_http_methods=tuple(method_values),
            not_before=_parse_timestamp(root["not_before"], "not_before"),
            expires_at=_parse_timestamp(root["expires_at"], "expires_at"),
            maximum_request_attempts=root["maximum_request_attempts"],
            maximum_requests_per_second=root["maximum_requests_per_second"],
            maximum_concurrency=root["maximum_concurrency"],
        )
    except ValueError as exc:
        if isinstance(exc, TrustScanPermitContractError):
            raise TrustScanPermitLoadError(exc.code, exc.message) from exc
        raise TrustScanPermitLoadError(
            "trustscan_permit_modes_invalid",
            "permitted_modes contains an unsupported scan mode.",
        ) from exc
    return submission


def load_signed_trustscan_permit_json(document: str | bytes) -> SignedTrustScanPermit:
    root = _strict_mapping(
        _parse_json(document),
        required={"permit_type", "schema_version", "claims", "signature", "permit_sha256"},
        context="TrustScan permit",
    )
    claims = _strict_mapping(
        root["claims"],
        required={
            "permit_id",
            "organization_id",
            "authorization_id",
            "authorization_sha256",
            "target",
            "issued_by",
            "issued_at",
            "not_before",
            "expires_at",
            "permitted_modes",
            "allowed_http_methods",
            "maximum_request_attempts",
            "maximum_requests_per_second",
            "maximum_concurrency",
            "prohibited_operations",
        },
        context="TrustScan permit claims",
    )
    signature = _strict_mapping(
        root["signature"],
        required={"algorithm", "key_id", "value"},
        context="TrustScan permit signature",
    )
    mode_values = claims["permitted_modes"]
    method_values = claims["allowed_http_methods"]
    prohibited_values = claims["prohibited_operations"]
    if not all(isinstance(value, list) for value in (mode_values, method_values, prohibited_values)):
        raise TrustScanPermitLoadError(
            "trustscan_permit_list_required",
            "Permit list fields must be JSON arrays.",
        )
    try:
        value = SignedTrustScanPermit(
            permit_type=root["permit_type"],
            schema_version=root["schema_version"],
            claims=TrustScanPermitClaims(
                permit_id=claims["permit_id"],
                organization_id=claims["organization_id"],
                authorization_id=claims["authorization_id"],
                authorization_sha256=claims["authorization_sha256"],
                target=claims["target"],
                issued_by=claims["issued_by"],
                issued_at=_parse_timestamp(claims["issued_at"], "issued_at"),
                not_before=_parse_timestamp(claims["not_before"], "not_before"),
                expires_at=_parse_timestamp(claims["expires_at"], "expires_at"),
                permitted_modes=tuple(ScanJobMode(item) for item in mode_values),
                allowed_http_methods=tuple(method_values),
                maximum_request_attempts=claims["maximum_request_attempts"],
                maximum_requests_per_second=claims["maximum_requests_per_second"],
                maximum_concurrency=claims["maximum_concurrency"],
                prohibited_operations=tuple(prohibited_values),
            ),
            signature_algorithm=signature["algorithm"],
            signing_key_id=signature["key_id"],
            signature=signature["value"],
        )
    except ValueError as exc:
        if isinstance(exc, TrustScanPermitContractError):
            raise TrustScanPermitLoadError(exc.code, exc.message) from exc
        raise TrustScanPermitLoadError(
            "trustscan_permit_modes_invalid",
            "permitted_modes contains an unsupported scan mode.",
        ) from exc
    try:
        supplied_fingerprint = _sha256(root["permit_sha256"], "permit_sha256")
    except TrustScanPermitValidationError as exc:
        raise TrustScanPermitLoadError(exc.code, exc.message) from exc
    if supplied_fingerprint != value.fingerprint:
        raise TrustScanPermitLoadError(
            "trustscan_permit_fingerprint_mismatch",
            "permit_sha256 does not match the canonical signed claims.",
        )
    if _canonical_json(value.to_dict()) != _canonical_json(root):
        raise TrustScanPermitLoadError(
            "trustscan_permit_non_canonical",
            "TrustScan permit document contains non-canonical values.",
        )
    return value


__all__ = [
    "CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION",
    "MAXIMUM_TRUSTSCAN_PERMIT_DOCUMENT_BYTES",
    "MAXIMUM_TRUSTSCAN_PERMIT_VALIDITY_DAYS",
    "MAXIMUM_TRUSTSCAN_REQUEST_ATTEMPTS",
    "MAXIMUM_TRUSTSCAN_REQUESTS_PER_SECOND",
    "MINIMUM_TRUSTSCAN_REQUESTS_PER_SECOND",
    "SUPPORTED_TRUSTSCAN_PERMIT_SCHEMA_VERSIONS",
    "TRUSTSCAN_ALLOWED_HTTP_METHODS",
    "TRUSTSCAN_PERMIT_TYPE",
    "TRUSTSCAN_PROHIBITED_OPERATIONS",
    "TRUSTSCAN_SIGNATURE_ALGORITHM",
    "TRUSTSCAN_V1_MAXIMUM_CONCURRENCY",
    "SignedTrustScanPermit",
    "TrustScanPermitClaims",
    "TrustScanPermitContractError",
    "TrustScanPermitLoadError",
    "TrustScanPermitSubmission",
    "TrustScanPermitValidationError",
    "load_signed_trustscan_permit_json",
    "load_trustscan_permit_submission_json",
]
