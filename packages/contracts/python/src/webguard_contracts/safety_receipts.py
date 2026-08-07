"""TrustScan runtime safety receipt contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

CURRENT_TRUSTSCAN_SAFETY_RECEIPT_SCHEMA_VERSION = "1.0"
TRUSTSCAN_SAFETY_RECEIPT_TYPE = "trustscan_safety_receipt"
TRUSTSCAN_SAFETY_RECEIPT_SIGNATURE_ALGORITHM = "Ed25519"
TRUSTSCAN_SAFETY_RECEIPT_MAXIMUM_BYTES = 128 * 1024

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")


class TrustScanSafetyReceiptError(ValueError):
    """Controlled safety-receipt contract failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


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
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_json_invalid",
            "The safety receipt cannot be encoded as canonical JSON.",
        ) from exc



def _parse_json(document: str | bytes) -> object:
    if isinstance(document, str):
        encoded = document.encode("utf-8")
    elif isinstance(document, bytes):
        encoded = document
    else:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_document_invalid",
            "Safety receipt document must be JSON text or bytes.",
        )
    if len(encoded) > TRUSTSCAN_SAFETY_RECEIPT_MAXIMUM_BYTES:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_document_too_large",
            "Safety receipt document exceeds the maximum supported size.",
        )
    try:
        return json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_json_invalid",
            "Safety receipt document is not valid UTF-8 JSON.",
        ) from exc


def _strict_mapping(value: object, *, required: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_object_invalid",
            f"{context} must be a JSON object.",
        )
    supplied = set(value)
    if supplied != required:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_fields_invalid",
            f"{context} contains missing or unexpected fields.",
        )
    return value


def _parse_timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_timestamp_invalid",
            f"{name} must be a canonical UTC timestamp.",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_timestamp_invalid",
            f"{name} must be a canonical UTC timestamp.",
        ) from exc
    parsed = _utc(parsed, name)
    if _timestamp(parsed) != value:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_timestamp_non_canonical",
            f"{name} must use canonical microsecond UTC notation.",
        )
    return parsed

def _uuid(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_uuid_invalid",
            f"{name} must be a canonical UUID string.",
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_uuid_invalid",
            f"{name} must be a canonical UUID string.",
        ) from exc
    canonical = str(parsed)
    if canonical != value:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_uuid_non_canonical",
            f"{name} must use canonical lower-case UUID notation.",
        )
    return canonical


def _sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_sha256_invalid",
            f"{name} must be a lower-case SHA-256 digest.",
        )
    return value


def _utc(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_timestamp_invalid",
            f"{name} must be timezone-aware.",
        )
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_count_invalid",
            f"{name} must be a non-negative integer.",
        )
    return value


@dataclass(frozen=True, slots=True)
class TrustScanSafetyReceiptClaims:
    """Immutable observed runtime safety facts for one scan execution."""

    receipt_id: str
    permit_id: str
    permit_sha256: str
    organization_id: str
    job_id: str
    scan_id: str
    target: str
    started_at: datetime
    completed_at: datetime
    maximum_request_attempts: int
    maximum_requests_per_second: float
    maximum_concurrency: int
    requests_attempted: int
    requests_permitted: int
    requests_blocked: int
    responses_429: int
    responses_5xx: int
    request_errors: int
    throttles: int
    throttle_seconds: float
    circuit_breaker_activations: int
    scope_violations: int
    permit_revalidations: int
    peak_concurrency: int
    termination_reason: str
    safety_policy_respected: bool

    def __post_init__(self) -> None:
        for name in ("receipt_id", "permit_id", "organization_id", "job_id", "scan_id"):
            object.__setattr__(self, name, _uuid(getattr(self, name), name))
        object.__setattr__(self, "permit_sha256", _sha256(self.permit_sha256, "permit_sha256"))
        if not isinstance(self.target, str) or not self.target.startswith(("http://", "https://")):
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_target_invalid",
                "target must be a canonical HTTP or HTTPS URL.",
            )
        started = _utc(self.started_at, "started_at")
        completed = _utc(self.completed_at, "completed_at")
        if completed < started:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_timestamp_order_invalid",
                "completed_at cannot precede started_at.",
            )
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)
        for name in (
            "maximum_request_attempts", "maximum_concurrency", "requests_attempted",
            "requests_permitted", "requests_blocked", "responses_429", "responses_5xx",
            "request_errors", "throttles", "circuit_breaker_activations", "scope_violations",
            "permit_revalidations", "peak_concurrency",
        ):
            object.__setattr__(self, name, _count(getattr(self, name), name))
        if self.maximum_request_attempts < 1 or self.maximum_concurrency < 1:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_limit_invalid",
                "Runtime safety limits must be positive.",
            )
        rate = float(self.maximum_requests_per_second)
        throttle = float(self.throttle_seconds)
        if not math.isfinite(rate) or rate <= 0 or not math.isfinite(throttle) or throttle < 0:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_rate_invalid",
                "Runtime rate and throttle values must be finite and valid.",
            )
        object.__setattr__(self, "maximum_requests_per_second", rate)
        object.__setattr__(self, "throttle_seconds", throttle)
        if self.requests_permitted > self.requests_attempted:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_request_counts_invalid",
                "Permitted requests cannot exceed attempted requests.",
            )
        if self.peak_concurrency > self.maximum_concurrency:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_concurrency_invalid",
                "Observed peak concurrency exceeds the authorised limit.",
            )
        if not isinstance(self.termination_reason, str) or _IDENTIFIER.fullmatch(self.termination_reason) is None:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_termination_invalid",
                "termination_reason must be a stable identifier.",
            )
        if not isinstance(self.safety_policy_respected, bool):
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_policy_flag_invalid",
                "safety_policy_respected must be boolean.",
            )

    @property
    def signing_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.signing_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "permit_id": self.permit_id,
            "permit_sha256": self.permit_sha256,
            "organization_id": self.organization_id,
            "job_id": self.job_id,
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": _timestamp(self.started_at),
            "completed_at": _timestamp(self.completed_at),
            "maximum_request_attempts": self.maximum_request_attempts,
            "maximum_requests_per_second": self.maximum_requests_per_second,
            "maximum_concurrency": self.maximum_concurrency,
            "requests_attempted": self.requests_attempted,
            "requests_permitted": self.requests_permitted,
            "requests_blocked": self.requests_blocked,
            "responses_429": self.responses_429,
            "responses_5xx": self.responses_5xx,
            "request_errors": self.request_errors,
            "throttles": self.throttles,
            "throttle_seconds": round(self.throttle_seconds, 6),
            "circuit_breaker_activations": self.circuit_breaker_activations,
            "scope_violations": self.scope_violations,
            "permit_revalidations": self.permit_revalidations,
            "peak_concurrency": self.peak_concurrency,
            "termination_reason": self.termination_reason,
            "safety_policy_respected": self.safety_policy_respected,
        }


@dataclass(frozen=True, slots=True)
class SignedTrustScanSafetyReceipt:
    """Ed25519-signed runtime safety receipt."""

    claims: TrustScanSafetyReceiptClaims
    signing_key_id: str
    signature: str
    signature_algorithm: str = TRUSTSCAN_SAFETY_RECEIPT_SIGNATURE_ALGORITHM
    receipt_type: str = TRUSTSCAN_SAFETY_RECEIPT_TYPE
    schema_version: str = CURRENT_TRUSTSCAN_SAFETY_RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.claims, TrustScanSafetyReceiptClaims):
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_claims_invalid", "claims are invalid."
            )
        if self.receipt_type != TRUSTSCAN_SAFETY_RECEIPT_TYPE or self.schema_version != CURRENT_TRUSTSCAN_SAFETY_RECEIPT_SCHEMA_VERSION:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_type_invalid", "Safety receipt type or schema is invalid."
            )
        if self.signature_algorithm != TRUSTSCAN_SAFETY_RECEIPT_SIGNATURE_ALGORITHM:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_signature_algorithm_invalid", "Signature algorithm must be Ed25519."
            )
        if not isinstance(self.signing_key_id, str) or _KEY_ID.fullmatch(self.signing_key_id) is None:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_key_id_invalid", "signing_key_id is invalid."
            )
        if not isinstance(self.signature, str) or _BASE64URL.fullmatch(self.signature) is None:
            raise TrustScanSafetyReceiptError(
                "trustscan_safety_receipt_signature_invalid", "signature must be canonical Base64URL text."
            )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_type": self.receipt_type,
            "schema_version": self.schema_version,
            "claims": self.claims.to_dict(),
            "signing_key_id": self.signing_key_id,
            "signature_algorithm": self.signature_algorithm,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict()).decode("utf-8")


def load_signed_trustscan_safety_receipt_json(
    document: str | bytes,
) -> SignedTrustScanSafetyReceipt:
    """Load one strict canonical TrustScan Safety Receipt v1 document."""

    root = _strict_mapping(
        _parse_json(document),
        required={
            "receipt_type",
            "schema_version",
            "claims",
            "signing_key_id",
            "signature_algorithm",
            "signature",
        },
        context="TrustScan safety receipt",
    )
    claims = _strict_mapping(
        root["claims"],
        required={
            "receipt_id",
            "permit_id",
            "permit_sha256",
            "organization_id",
            "job_id",
            "scan_id",
            "target",
            "started_at",
            "completed_at",
            "maximum_request_attempts",
            "maximum_requests_per_second",
            "maximum_concurrency",
            "requests_attempted",
            "requests_permitted",
            "requests_blocked",
            "responses_429",
            "responses_5xx",
            "request_errors",
            "throttles",
            "throttle_seconds",
            "circuit_breaker_activations",
            "scope_violations",
            "permit_revalidations",
            "peak_concurrency",
            "termination_reason",
            "safety_policy_respected",
        },
        context="TrustScan safety receipt claims",
    )
    try:
        receipt = SignedTrustScanSafetyReceipt(
            receipt_type=root["receipt_type"],
            schema_version=root["schema_version"],
            claims=TrustScanSafetyReceiptClaims(
                receipt_id=claims["receipt_id"],
                permit_id=claims["permit_id"],
                permit_sha256=claims["permit_sha256"],
                organization_id=claims["organization_id"],
                job_id=claims["job_id"],
                scan_id=claims["scan_id"],
                target=claims["target"],
                started_at=_parse_timestamp(claims["started_at"], "started_at"),
                completed_at=_parse_timestamp(claims["completed_at"], "completed_at"),
                maximum_request_attempts=claims["maximum_request_attempts"],
                maximum_requests_per_second=claims["maximum_requests_per_second"],
                maximum_concurrency=claims["maximum_concurrency"],
                requests_attempted=claims["requests_attempted"],
                requests_permitted=claims["requests_permitted"],
                requests_blocked=claims["requests_blocked"],
                responses_429=claims["responses_429"],
                responses_5xx=claims["responses_5xx"],
                request_errors=claims["request_errors"],
                throttles=claims["throttles"],
                throttle_seconds=claims["throttle_seconds"],
                circuit_breaker_activations=claims["circuit_breaker_activations"],
                scope_violations=claims["scope_violations"],
                permit_revalidations=claims["permit_revalidations"],
                peak_concurrency=claims["peak_concurrency"],
                termination_reason=claims["termination_reason"],
                safety_policy_respected=claims["safety_policy_respected"],
            ),
            signing_key_id=root["signing_key_id"],
            signature_algorithm=root["signature_algorithm"],
            signature=root["signature"],
        )
    except TrustScanSafetyReceiptError:
        raise
    if _canonical_json(receipt.to_dict()) != _canonical_json(root):
        raise TrustScanSafetyReceiptError(
            "trustscan_safety_receipt_document_non_canonical",
            "Safety receipt document contains non-canonical values.",
        )
    return receipt


__all__ = [
    "CURRENT_TRUSTSCAN_SAFETY_RECEIPT_SCHEMA_VERSION",
    "SignedTrustScanSafetyReceipt",
    "TRUSTSCAN_SAFETY_RECEIPT_MAXIMUM_BYTES",
    "TRUSTSCAN_SAFETY_RECEIPT_SIGNATURE_ALGORITHM",
    "TRUSTSCAN_SAFETY_RECEIPT_TYPE",
    "TrustScanSafetyReceiptClaims",
    "TrustScanSafetyReceiptError",
    "load_signed_trustscan_safety_receipt_json",
]
