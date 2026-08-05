"""Versioned authorization and audit contracts for owned-target scans."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit


CURRENT_OWNED_TARGET_AUTHORIZATION_SCHEMA_VERSION = "1.0"
SUPPORTED_OWNED_TARGET_AUTHORIZATION_SCHEMA_VERSIONS = ("1.0",)
OWNED_TARGET_AUTHORIZATION_TYPE = "owned_target_authorization"
CURRENT_OWNED_TARGET_AUDIT_SCHEMA_VERSION = "1.0"
SUPPORTED_OWNED_TARGET_AUDIT_SCHEMA_VERSIONS = ("1.0",)
OWNED_TARGET_AUDIT_TYPE = "owned_target_preflight_audit"
MAXIMUM_OWNED_TARGET_DOCUMENT_BYTES = 256 * 1024
MAXIMUM_OWNED_TARGET_AUTHORIZATION_VALIDITY_DAYS = 366

OWNED_TARGET_STOP_CONDITIONS = (
    "scope_or_dns_validation_failure",
    "redirect_response",
    "tls_certificate_verification_failure",
    "request_attempt_budget",
    "execution_time_budget",
    "root_request_failure",
    "operator_interrupt",
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class OwnedTargetContractError(ValueError):
    """Base class for controlled owned-target contract failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class OwnedTargetValidationError(OwnedTargetContractError):
    """Raised when an in-memory owned-target value is invalid."""


class OwnedTargetLoadError(OwnedTargetContractError):
    """Raised when an owned-target document cannot be loaded safely."""


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
        raise OwnedTargetValidationError(
            "owned_target_json_invalid",
            "The owned-target document cannot be encoded as canonical JSON.",
        ) from exc


def _uuid(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise OwnedTargetValidationError(
            "owned_target_uuid_invalid",
            f"{field_name} must be a canonical UUID string.",
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise OwnedTargetValidationError(
            "owned_target_uuid_invalid",
            f"{field_name} must be a canonical UUID string.",
        ) from exc
    canonical = str(parsed)
    if canonical != value:
        raise OwnedTargetValidationError(
            "owned_target_uuid_non_canonical",
            f"{field_name} must use canonical lower-case UUID notation.",
        )
    return canonical


def _bounded_text(
    value: object,
    field_name: str,
    *,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        raise OwnedTargetValidationError(
            "owned_target_text_invalid",
            f"{field_name} must be text.",
        )
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise OwnedTargetValidationError(
            "owned_target_text_invalid",
            f"{field_name} must contain 1 to {maximum} characters.",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise OwnedTargetValidationError(
            "owned_target_text_control_character",
            f"{field_name} cannot contain control characters.",
        )
    return cleaned


def _bounded_integer(
    value: object,
    field_name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise OwnedTargetValidationError(
            "owned_target_integer_invalid",
            f"{field_name} must be an integer from {minimum} to {maximum}.",
        )
    return value


def _bounded_number(
    value: object,
    field_name: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OwnedTargetValidationError(
            "owned_target_number_invalid",
            f"{field_name} must be a number.",
        )
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise OwnedTargetValidationError(
            "owned_target_number_invalid",
            f"{field_name} must be from {minimum:g} to {maximum:g}.",
        )
    return number


def _utc_datetime(value: object, field_name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise OwnedTargetValidationError(
            "owned_target_timestamp_invalid",
            f"{field_name} must be a timezone-aware datetime.",
        )
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise OwnedTargetLoadError(
            "owned_target_timestamp_invalid",
            f"{field_name} must use canonical UTC Z notation.",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise OwnedTargetLoadError(
            "owned_target_timestamp_invalid",
            f"{field_name} is not a valid timestamp.",
        ) from exc
    canonical = _timestamp_text(parsed)
    if canonical != value:
        raise OwnedTargetLoadError(
            "owned_target_timestamp_non_canonical",
            f"{field_name} must use canonical microsecond UTC notation.",
        )
    return parsed.astimezone(timezone.utc)


def canonicalize_owned_target_hostname(value: object) -> str:
    """Return a canonical IDNA DNS hostname for an owned public target."""

    if not isinstance(value, str):
        raise OwnedTargetValidationError(
            "owned_target_hostname_invalid",
            "Owned-target hostnames must be text.",
        )
    candidate = value.strip().rstrip(".")
    if not candidate or "%" in candidate:
        raise OwnedTargetValidationError(
            "owned_target_hostname_invalid",
            "Owned-target hostname is invalid.",
        )
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise OwnedTargetValidationError(
            "owned_target_hostname_ip_not_allowed",
            "Owned production authorizations require a DNS hostname, not an IP literal.",
        )
    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise OwnedTargetValidationError(
            "owned_target_hostname_invalid",
            "Owned-target hostname is not valid IDNA text.",
        ) from exc
    if len(hostname) > 253:
        raise OwnedTargetValidationError(
            "owned_target_hostname_invalid",
            "Owned-target hostname exceeds 253 characters.",
        )
    labels = hostname.split(".")
    if len(labels) < 2:
        raise OwnedTargetValidationError(
            "owned_target_hostname_public_name_required",
            "Owned production authorizations require a fully qualified public DNS name.",
        )
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
        ):
            raise OwnedTargetValidationError(
                "owned_target_hostname_invalid",
                "Owned-target hostname contains an invalid DNS label.",
            )
    return hostname


def canonicalize_owned_target_url(value: object) -> str:
    """Return the canonical HTTPS URL accepted by owned-target authorization."""

    if not isinstance(value, str):
        raise OwnedTargetValidationError(
            "owned_target_url_invalid",
            "Owned-target URL must be text.",
        )
    candidate = value.strip()
    if not candidate or len(candidate) > 2048 or "\\" in candidate:
        raise OwnedTargetValidationError(
            "owned_target_url_invalid",
            "Owned-target URL is invalid or exceeds 2048 characters.",
        )
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise OwnedTargetValidationError(
            "owned_target_url_invalid",
            "Owned-target URL is invalid.",
        ) from exc
    if parsed.scheme.lower() != "https":
        raise OwnedTargetValidationError(
            "owned_target_https_required",
            "Owned production targets must use HTTPS.",
        )
    if parsed.username is not None or parsed.password is not None:
        raise OwnedTargetValidationError(
            "owned_target_credentials_not_allowed",
            "Owned-target URL cannot contain credentials.",
        )
    if parsed.query or parsed.fragment:
        raise OwnedTargetValidationError(
            "owned_target_query_fragment_not_allowed",
            "Owned-target URL cannot contain a query string or fragment.",
        )
    if parsed.hostname is None:
        raise OwnedTargetValidationError(
            "owned_target_hostname_missing",
            "Owned-target URL must contain a hostname.",
        )
    hostname = canonicalize_owned_target_hostname(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise OwnedTargetValidationError(
            "owned_target_port_invalid",
            "Owned-target URL contains an invalid port.",
        ) from exc
    authority = hostname if port in {None, 443} else f"{hostname}:{port}"
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    path_segments = path.split("/")
    if any(segment in {".", ".."} for segment in path_segments):
        raise OwnedTargetValidationError(
            "owned_target_path_ambiguous",
            "Owned-target URL cannot contain dot path segments.",
        )
    canonical = urlunsplit(("https", authority, path, "", ""))
    return canonical


def _canonical_ip_tuple(values: object) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values:
        raise OwnedTargetValidationError(
            "owned_target_addresses_invalid",
            "resolved_addresses must be a non-empty tuple.",
        )
    addresses: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            raise OwnedTargetValidationError(
                "owned_target_address_invalid",
                "resolved_addresses contains a non-text value.",
            )
        try:
            address = ipaddress.ip_address(item)
        except ValueError as exc:
            raise OwnedTargetValidationError(
                "owned_target_address_invalid",
                "resolved_addresses contains an invalid IP address.",
            ) from exc
        addresses.add(address.compressed)
    return tuple(
        sorted(
            addresses,
            key=lambda item: (
                ipaddress.ip_address(item).version,
                int(ipaddress.ip_address(item)),
            ),
        )
    )


@dataclass(frozen=True, slots=True)
class OwnedTargetLimits:
    """Maximum allowed settings for one owned-target authorization."""

    maximum_pages: int = 10
    maximum_depth: int = 1
    maximum_links_per_page: int = 50
    minimum_delay_seconds: float = 1.0
    maximum_execution_seconds: float = 60.0
    maximum_request_attempts: int = 15
    maximum_attempts_per_request: int = 1
    timeout_seconds: float = 10.0
    maximum_body_bytes: int = 1_048_576
    maximum_header_bytes: int = 65_536
    maximum_header_count: int = 100

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "maximum_pages",
            _bounded_integer(
                self.maximum_pages,
                "limits.maximum_pages",
                minimum=1,
                maximum=50,
            ),
        )
        object.__setattr__(
            self,
            "maximum_depth",
            _bounded_integer(
                self.maximum_depth,
                "limits.maximum_depth",
                minimum=0,
                maximum=3,
            ),
        )
        object.__setattr__(
            self,
            "maximum_links_per_page",
            _bounded_integer(
                self.maximum_links_per_page,
                "limits.maximum_links_per_page",
                minimum=1,
                maximum=500,
            ),
        )
        object.__setattr__(
            self,
            "minimum_delay_seconds",
            _bounded_number(
                self.minimum_delay_seconds,
                "limits.minimum_delay_seconds",
                minimum=0.5,
                maximum=5.0,
            ),
        )
        object.__setattr__(
            self,
            "maximum_execution_seconds",
            _bounded_number(
                self.maximum_execution_seconds,
                "limits.maximum_execution_seconds",
                minimum=1.0,
                maximum=300.0,
            ),
        )
        object.__setattr__(
            self,
            "maximum_request_attempts",
            _bounded_integer(
                self.maximum_request_attempts,
                "limits.maximum_request_attempts",
                minimum=1,
                maximum=150,
            ),
        )
        object.__setattr__(
            self,
            "maximum_attempts_per_request",
            _bounded_integer(
                self.maximum_attempts_per_request,
                "limits.maximum_attempts_per_request",
                minimum=1,
                maximum=3,
            ),
        )
        object.__setattr__(
            self,
            "timeout_seconds",
            _bounded_number(
                self.timeout_seconds,
                "limits.timeout_seconds",
                minimum=1.0,
                maximum=60.0,
            ),
        )
        object.__setattr__(
            self,
            "maximum_body_bytes",
            _bounded_integer(
                self.maximum_body_bytes,
                "limits.maximum_body_bytes",
                minimum=1,
                maximum=16 * 1024 * 1024,
            ),
        )
        object.__setattr__(
            self,
            "maximum_header_bytes",
            _bounded_integer(
                self.maximum_header_bytes,
                "limits.maximum_header_bytes",
                minimum=1,
                maximum=1024 * 1024,
            ),
        )
        object.__setattr__(
            self,
            "maximum_header_count",
            _bounded_integer(
                self.maximum_header_count,
                "limits.maximum_header_count",
                minimum=1,
                maximum=1000,
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "maximum_pages": self.maximum_pages,
            "maximum_depth": self.maximum_depth,
            "maximum_links_per_page": self.maximum_links_per_page,
            "minimum_delay_seconds": self.minimum_delay_seconds,
            "maximum_execution_seconds": self.maximum_execution_seconds,
            "maximum_request_attempts": self.maximum_request_attempts,
            "maximum_attempts_per_request": self.maximum_attempts_per_request,
            "timeout_seconds": self.timeout_seconds,
            "maximum_body_bytes": self.maximum_body_bytes,
            "maximum_header_bytes": self.maximum_header_bytes,
            "maximum_header_count": self.maximum_header_count,
        }


@dataclass(frozen=True, slots=True)
class OwnedTargetAuthorization:
    """Explicit bounded authorization for a passive owned-target assessment."""

    authorization_id: str
    organization: str
    authorized_by: str
    target: str
    allowed_hosts: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    purpose: str
    limits: OwnedTargetLimits = OwnedTargetLimits()
    passive_only: bool = True
    authorization_type: str = OWNED_TARGET_AUTHORIZATION_TYPE
    schema_version: str = CURRENT_OWNED_TARGET_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.authorization_type != OWNED_TARGET_AUTHORIZATION_TYPE:
            raise OwnedTargetValidationError(
                "owned_target_authorization_type_invalid",
                "authorization_type is invalid.",
            )
        if self.schema_version not in SUPPORTED_OWNED_TARGET_AUTHORIZATION_SCHEMA_VERSIONS:
            raise OwnedTargetValidationError(
                "owned_target_authorization_schema_unsupported",
                "Authorization schema_version is unsupported.",
            )
        authorization_id = _uuid(self.authorization_id, "authorization_id")
        organization = _bounded_text(
            self.organization,
            "organization",
            maximum=200,
        )
        authorized_by = _bounded_text(
            self.authorized_by,
            "authorized_by",
            maximum=200,
        )
        target = canonicalize_owned_target_url(self.target)
        if target != self.target:
            raise OwnedTargetValidationError(
                "owned_target_url_non_canonical",
                f"target must use canonical form {target!r}.",
            )
        if not isinstance(self.allowed_hosts, tuple) or not self.allowed_hosts:
            raise OwnedTargetValidationError(
                "owned_target_allowed_hosts_invalid",
                "allowed_hosts must be a non-empty tuple.",
            )
        hosts = tuple(
            sorted(
                {
                    canonicalize_owned_target_hostname(host)
                    for host in self.allowed_hosts
                }
            )
        )
        if hosts != self.allowed_hosts:
            raise OwnedTargetValidationError(
                "owned_target_allowed_hosts_non_canonical",
                "allowed_hosts must be sorted, unique, and canonical.",
            )
        target_hostname = urlsplit(target).hostname
        assert target_hostname is not None
        if target_hostname not in hosts:
            raise OwnedTargetValidationError(
                "owned_target_canonical_host_not_allowed",
                "The canonical target hostname must appear in allowed_hosts.",
            )
        issued_at = _utc_datetime(self.issued_at, "issued_at")
        expires_at = _utc_datetime(self.expires_at, "expires_at")
        if expires_at <= issued_at:
            raise OwnedTargetValidationError(
                "owned_target_authorization_window_invalid",
                "expires_at must be later than issued_at.",
            )
        if expires_at - issued_at > timedelta(
            days=MAXIMUM_OWNED_TARGET_AUTHORIZATION_VALIDITY_DAYS
        ):
            raise OwnedTargetValidationError(
                "owned_target_authorization_window_too_long",
                "Owned-target authorization cannot exceed 366 days.",
            )
        purpose = _bounded_text(self.purpose, "purpose", maximum=500)
        if self.passive_only is not True:
            raise OwnedTargetValidationError(
                "owned_target_passive_only_required",
                "Owned-target authorization must explicitly set passive_only to true.",
            )
        if not isinstance(self.limits, OwnedTargetLimits):
            raise OwnedTargetValidationError(
                "owned_target_limits_invalid",
                "limits must be an OwnedTargetLimits value.",
            )
        object.__setattr__(self, "authorization_id", authorization_id)
        object.__setattr__(self, "organization", organization)
        object.__setattr__(self, "authorized_by", authorized_by)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "allowed_hosts", hosts)
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "purpose", purpose)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "authorization_type": self.authorization_type,
            "schema_version": self.schema_version,
            "authorization_id": self.authorization_id,
            "organization": self.organization,
            "authorized_by": self.authorized_by,
            "target": self.target,
            "allowed_hosts": list(self.allowed_hosts),
            "issued_at": _timestamp_text(self.issued_at),
            "expires_at": _timestamp_text(self.expires_at),
            "purpose": self.purpose,
            "passive_only": self.passive_only,
            "limits": self.limits.to_dict(),
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict()).decode("utf-8")


@dataclass(frozen=True, slots=True)
class OwnedTargetExecutionPolicy:
    """Exact effective policy captured before external scan traffic."""

    timeout_seconds: float
    maximum_body_bytes: int
    maximum_header_bytes: int
    maximum_header_count: int
    maximum_attempts_per_request: int
    crawl_enabled: bool
    maximum_pages: int | None = None
    maximum_depth: int | None = None
    maximum_links_per_page: int | None = None
    minimum_delay_seconds: float | None = None
    maximum_execution_seconds: float | None = None
    maximum_request_attempts: int | None = None
    query_mode: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "timeout_seconds",
            _bounded_number(
                self.timeout_seconds,
                "execution_policy.timeout_seconds",
                minimum=0.001,
                maximum=60.0,
            ),
        )
        for name, maximum in (
            ("maximum_body_bytes", 16 * 1024 * 1024),
            ("maximum_header_bytes", 1024 * 1024),
            ("maximum_header_count", 1000),
            ("maximum_attempts_per_request", 3),
        ):
            object.__setattr__(
                self,
                name,
                _bounded_integer(
                    getattr(self, name),
                    f"execution_policy.{name}",
                    minimum=1,
                    maximum=maximum,
                ),
            )
        if not isinstance(self.crawl_enabled, bool):
            raise OwnedTargetValidationError(
                "owned_target_execution_policy_invalid",
                "crawl_enabled must be boolean.",
            )
        crawl_fields = (
            self.maximum_pages,
            self.maximum_depth,
            self.maximum_links_per_page,
            self.minimum_delay_seconds,
            self.maximum_execution_seconds,
            self.maximum_request_attempts,
            self.query_mode,
        )
        if not self.crawl_enabled:
            if any(value is not None for value in crawl_fields):
                raise OwnedTargetValidationError(
                    "owned_target_execution_policy_invalid",
                    "Single-page execution policy cannot contain crawl settings.",
                )
            return
        if any(value is None for value in crawl_fields):
            raise OwnedTargetValidationError(
                "owned_target_execution_policy_invalid",
                "Crawl execution policy requires every crawl setting.",
            )
        object.__setattr__(
            self,
            "maximum_pages",
            _bounded_integer(
                self.maximum_pages,
                "execution_policy.maximum_pages",
                minimum=1,
                maximum=50,
            ),
        )
        object.__setattr__(
            self,
            "maximum_depth",
            _bounded_integer(
                self.maximum_depth,
                "execution_policy.maximum_depth",
                minimum=0,
                maximum=3,
            ),
        )
        object.__setattr__(
            self,
            "maximum_links_per_page",
            _bounded_integer(
                self.maximum_links_per_page,
                "execution_policy.maximum_links_per_page",
                minimum=1,
                maximum=500,
            ),
        )
        object.__setattr__(
            self,
            "minimum_delay_seconds",
            _bounded_number(
                self.minimum_delay_seconds,
                "execution_policy.minimum_delay_seconds",
                minimum=0.0,
                maximum=5.0,
            ),
        )
        object.__setattr__(
            self,
            "maximum_execution_seconds",
            _bounded_number(
                self.maximum_execution_seconds,
                "execution_policy.maximum_execution_seconds",
                minimum=0.001,
                maximum=3600.0,
            ),
        )
        object.__setattr__(
            self,
            "maximum_request_attempts",
            _bounded_integer(
                self.maximum_request_attempts,
                "execution_policy.maximum_request_attempts",
                minimum=1,
                maximum=150,
            ),
        )
        if self.query_mode not in {"drop", "reject"}:
            raise OwnedTargetValidationError(
                "owned_target_execution_policy_invalid",
                "query_mode must be 'drop' or 'reject'.",
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "maximum_body_bytes": self.maximum_body_bytes,
            "maximum_header_bytes": self.maximum_header_bytes,
            "maximum_header_count": self.maximum_header_count,
            "maximum_attempts_per_request": self.maximum_attempts_per_request,
            "crawl_enabled": self.crawl_enabled,
            "maximum_pages": self.maximum_pages,
            "maximum_depth": self.maximum_depth,
            "maximum_links_per_page": self.maximum_links_per_page,
            "minimum_delay_seconds": self.minimum_delay_seconds,
            "maximum_execution_seconds": self.maximum_execution_seconds,
            "maximum_request_attempts": self.maximum_request_attempts,
            "query_mode": self.query_mode,
        }


@dataclass(frozen=True, slots=True)
class OwnedTargetAuditRecord:
    """Immutable preflight evidence written before owned-target scan traffic."""

    scan_id: str
    authorization_id: str
    authorization_sha256: str
    organization: str
    authorized_by: str
    target: str
    resolved_addresses: tuple[str, ...]
    created_at: datetime
    execution_policy: OwnedTargetExecutionPolicy
    stop_conditions: tuple[str, ...] = OWNED_TARGET_STOP_CONDITIONS
    audit_type: str = OWNED_TARGET_AUDIT_TYPE
    schema_version: str = CURRENT_OWNED_TARGET_AUDIT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.audit_type != OWNED_TARGET_AUDIT_TYPE:
            raise OwnedTargetValidationError(
                "owned_target_audit_type_invalid",
                "audit_type is invalid.",
            )
        if self.schema_version not in SUPPORTED_OWNED_TARGET_AUDIT_SCHEMA_VERSIONS:
            raise OwnedTargetValidationError(
                "owned_target_audit_schema_unsupported",
                "Audit schema_version is unsupported.",
            )
        scan_id = _uuid(self.scan_id, "scan_id")
        authorization_id = _uuid(self.authorization_id, "authorization_id")
        if (
            not isinstance(self.authorization_sha256, str)
            or _HEX_64.fullmatch(self.authorization_sha256) is None
        ):
            raise OwnedTargetValidationError(
                "owned_target_authorization_fingerprint_invalid",
                "authorization_sha256 must be a lower-case SHA-256 digest.",
            )
        organization = _bounded_text(
            self.organization,
            "organization",
            maximum=200,
        )
        authorized_by = _bounded_text(
            self.authorized_by,
            "authorized_by",
            maximum=200,
        )
        target = canonicalize_owned_target_url(self.target)
        if target != self.target:
            raise OwnedTargetValidationError(
                "owned_target_url_non_canonical",
                "Audit target must be canonical.",
            )
        addresses = _canonical_ip_tuple(self.resolved_addresses)
        if addresses != self.resolved_addresses:
            raise OwnedTargetValidationError(
                "owned_target_addresses_non_canonical",
                "resolved_addresses must be sorted, unique, and canonical.",
            )
        created_at = _utc_datetime(self.created_at, "created_at")
        if not isinstance(self.execution_policy, OwnedTargetExecutionPolicy):
            raise OwnedTargetValidationError(
                "owned_target_execution_policy_invalid",
                "execution_policy must be an OwnedTargetExecutionPolicy value.",
            )
        if self.stop_conditions != OWNED_TARGET_STOP_CONDITIONS:
            raise OwnedTargetValidationError(
                "owned_target_stop_conditions_invalid",
                "stop_conditions must match the controlled owned-target gate.",
            )
        object.__setattr__(self, "scan_id", scan_id)
        object.__setattr__(self, "authorization_id", authorization_id)
        object.__setattr__(self, "organization", organization)
        object.__setattr__(self, "authorized_by", authorized_by)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "resolved_addresses", addresses)
        object.__setattr__(self, "created_at", created_at)

    def to_dict(self) -> dict[str, object]:
        return {
            "audit_type": self.audit_type,
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "authorization_id": self.authorization_id,
            "authorization_sha256": self.authorization_sha256,
            "organization": self.organization,
            "authorized_by": self.authorized_by,
            "target": self.target,
            "resolved_addresses": list(self.resolved_addresses),
            "created_at": _timestamp_text(self.created_at),
            "execution_policy": self.execution_policy.to_dict(),
            "stop_conditions": list(self.stop_conditions),
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict()).decode("utf-8")


def _strict_object(
    value: object,
    field_name: str,
    expected_fields: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnedTargetLoadError(
            "owned_target_object_required",
            f"{field_name} must be a JSON object.",
        )
    result = dict(value)
    if any(not isinstance(key, str) for key in result):
        raise OwnedTargetLoadError(
            "owned_target_key_invalid",
            f"{field_name} contains a non-text key.",
        )
    actual = set(result)
    missing = sorted(expected_fields - actual)
    unexpected = sorted(actual - expected_fields)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise OwnedTargetLoadError(
            "owned_target_fields_invalid",
            f"{field_name} has invalid fields ({'; '.join(details)}).",
        )
    return result


def _text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise OwnedTargetLoadError(
            "owned_target_text_required",
            f"{field_name} must be text.",
        )
    return value


def _integer(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OwnedTargetLoadError(
            "owned_target_integer_required",
            f"{field_name} must be an integer.",
        )
    return value


def _number(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OwnedTargetLoadError(
            "owned_target_number_required",
            f"{field_name} must be a number.",
        )
    return float(value)


def _boolean(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise OwnedTargetLoadError(
            "owned_target_boolean_required",
            f"{field_name} must be boolean.",
        )
    return value


def _optional_integer(value: object, field_name: str) -> int | None:
    return None if value is None else _integer(value, field_name)


def _optional_number(value: object, field_name: str) -> float | None:
    return None if value is None else _number(value, field_name)


def _optional_text(value: object, field_name: str) -> str | None:
    return None if value is None else _text(value, field_name)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Unsupported JSON constant: {value}")


def _parse_json_document(document: str | bytes | bytearray) -> dict[str, Any]:
    if isinstance(document, str):
        try:
            raw = document.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise OwnedTargetLoadError(
                "owned_target_encoding_invalid",
                "Owned-target document must be valid UTF-8.",
            ) from exc
    elif isinstance(document, (bytes, bytearray)):
        raw = bytes(document)
    else:
        raise OwnedTargetLoadError(
            "owned_target_document_invalid",
            "Owned-target document must be text or UTF-8 bytes.",
        )
    if len(raw) > MAXIMUM_OWNED_TARGET_DOCUMENT_BYTES:
        raise OwnedTargetLoadError(
            "owned_target_document_too_large",
            "Owned-target document exceeds 256 KiB.",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OwnedTargetLoadError(
            "owned_target_encoding_invalid",
            "Owned-target document must be valid UTF-8.",
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKeyError as exc:
        raise OwnedTargetLoadError(
            "owned_target_duplicate_key",
            f"Owned-target document contains duplicate key {exc.args[0]!r}.",
        ) from exc
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise OwnedTargetLoadError(
            "owned_target_json_invalid",
            "Owned-target document is not valid strict JSON.",
        ) from exc
    if not isinstance(value, Mapping):
        raise OwnedTargetLoadError(
            "owned_target_object_required",
            "Owned-target document root must be a JSON object.",
        )
    return dict(value)


_AUTHORIZATION_FIELDS = frozenset(
    {
        "authorization_type",
        "schema_version",
        "authorization_id",
        "organization",
        "authorized_by",
        "target",
        "allowed_hosts",
        "issued_at",
        "expires_at",
        "purpose",
        "passive_only",
        "limits",
    }
)
_LIMIT_FIELDS = frozenset(OwnedTargetLimits().to_dict())
_AUDIT_FIELDS = frozenset(
    {
        "audit_type",
        "schema_version",
        "scan_id",
        "authorization_id",
        "authorization_sha256",
        "organization",
        "authorized_by",
        "target",
        "resolved_addresses",
        "created_at",
        "execution_policy",
        "stop_conditions",
    }
)
_EXECUTION_POLICY_FIELDS = frozenset(
    {
        "timeout_seconds",
        "maximum_body_bytes",
        "maximum_header_bytes",
        "maximum_header_count",
        "maximum_attempts_per_request",
        "crawl_enabled",
        "maximum_pages",
        "maximum_depth",
        "maximum_links_per_page",
        "minimum_delay_seconds",
        "maximum_execution_seconds",
        "maximum_request_attempts",
        "query_mode",
    }
)


def _load_limits(value: object) -> OwnedTargetLimits:
    data = _strict_object(value, "limits", _LIMIT_FIELDS)
    try:
        limits = OwnedTargetLimits(
            maximum_pages=_integer(data["maximum_pages"], "limits.maximum_pages"),
            maximum_depth=_integer(data["maximum_depth"], "limits.maximum_depth"),
            maximum_links_per_page=_integer(
                data["maximum_links_per_page"],
                "limits.maximum_links_per_page",
            ),
            minimum_delay_seconds=_number(
                data["minimum_delay_seconds"],
                "limits.minimum_delay_seconds",
            ),
            maximum_execution_seconds=_number(
                data["maximum_execution_seconds"],
                "limits.maximum_execution_seconds",
            ),
            maximum_request_attempts=_integer(
                data["maximum_request_attempts"],
                "limits.maximum_request_attempts",
            ),
            maximum_attempts_per_request=_integer(
                data["maximum_attempts_per_request"],
                "limits.maximum_attempts_per_request",
            ),
            timeout_seconds=_number(data["timeout_seconds"], "limits.timeout_seconds"),
            maximum_body_bytes=_integer(
                data["maximum_body_bytes"],
                "limits.maximum_body_bytes",
            ),
            maximum_header_bytes=_integer(
                data["maximum_header_bytes"],
                "limits.maximum_header_bytes",
            ),
            maximum_header_count=_integer(
                data["maximum_header_count"],
                "limits.maximum_header_count",
            ),
        )
    except OwnedTargetValidationError as exc:
        raise OwnedTargetLoadError(exc.code, exc.message) from exc
    if _canonical_json(limits.to_dict()) != _canonical_json(data):
        raise OwnedTargetLoadError(
            "owned_target_limits_non_canonical",
            "limits contains non-canonical numeric values.",
        )
    return limits


def load_owned_target_authorization_json(
    document: str | bytes | bytearray,
) -> OwnedTargetAuthorization:
    """Strictly load one bounded owned-target authorization document."""

    root = _strict_object(
        _parse_json_document(document),
        "authorization",
        _AUTHORIZATION_FIELDS,
    )
    schema_version = _text(root["schema_version"], "schema_version")
    if schema_version not in SUPPORTED_OWNED_TARGET_AUTHORIZATION_SCHEMA_VERSIONS:
        raise OwnedTargetLoadError(
            "owned_target_authorization_schema_unsupported",
            f"Unsupported authorization schema_version {schema_version!r}.",
        )
    hosts_value = root["allowed_hosts"]
    if not isinstance(hosts_value, list):
        raise OwnedTargetLoadError(
            "owned_target_allowed_hosts_invalid",
            "allowed_hosts must be a JSON array.",
        )
    hosts = tuple(
        _text(value, f"allowed_hosts[{index}]")
        for index, value in enumerate(hosts_value)
    )
    try:
        authorization = OwnedTargetAuthorization(
            authorization_type=_text(
                root["authorization_type"],
                "authorization_type",
            ),
            schema_version=schema_version,
            authorization_id=_text(root["authorization_id"], "authorization_id"),
            organization=_text(root["organization"], "organization"),
            authorized_by=_text(root["authorized_by"], "authorized_by"),
            target=_text(root["target"], "target"),
            allowed_hosts=hosts,
            issued_at=_parse_timestamp(root["issued_at"], "issued_at"),
            expires_at=_parse_timestamp(root["expires_at"], "expires_at"),
            purpose=_text(root["purpose"], "purpose"),
            passive_only=_boolean(root["passive_only"], "passive_only"),
            limits=_load_limits(root["limits"]),
        )
    except OwnedTargetLoadError:
        raise
    except OwnedTargetValidationError as exc:
        raise OwnedTargetLoadError(exc.code, exc.message) from exc
    if _canonical_json(authorization.to_dict()) != _canonical_json(root):
        raise OwnedTargetLoadError(
            "owned_target_authorization_non_canonical",
            "Authorization document contains non-canonical values.",
        )
    return authorization


def _load_execution_policy(value: object) -> OwnedTargetExecutionPolicy:
    data = _strict_object(
        value,
        "execution_policy",
        _EXECUTION_POLICY_FIELDS,
    )
    try:
        policy = OwnedTargetExecutionPolicy(
            timeout_seconds=_number(
                data["timeout_seconds"],
                "execution_policy.timeout_seconds",
            ),
            maximum_body_bytes=_integer(
                data["maximum_body_bytes"],
                "execution_policy.maximum_body_bytes",
            ),
            maximum_header_bytes=_integer(
                data["maximum_header_bytes"],
                "execution_policy.maximum_header_bytes",
            ),
            maximum_header_count=_integer(
                data["maximum_header_count"],
                "execution_policy.maximum_header_count",
            ),
            maximum_attempts_per_request=_integer(
                data["maximum_attempts_per_request"],
                "execution_policy.maximum_attempts_per_request",
            ),
            crawl_enabled=_boolean(
                data["crawl_enabled"],
                "execution_policy.crawl_enabled",
            ),
            maximum_pages=_optional_integer(
                data["maximum_pages"],
                "execution_policy.maximum_pages",
            ),
            maximum_depth=_optional_integer(
                data["maximum_depth"],
                "execution_policy.maximum_depth",
            ),
            maximum_links_per_page=_optional_integer(
                data["maximum_links_per_page"],
                "execution_policy.maximum_links_per_page",
            ),
            minimum_delay_seconds=_optional_number(
                data["minimum_delay_seconds"],
                "execution_policy.minimum_delay_seconds",
            ),
            maximum_execution_seconds=_optional_number(
                data["maximum_execution_seconds"],
                "execution_policy.maximum_execution_seconds",
            ),
            maximum_request_attempts=_optional_integer(
                data["maximum_request_attempts"],
                "execution_policy.maximum_request_attempts",
            ),
            query_mode=_optional_text(
                data["query_mode"],
                "execution_policy.query_mode",
            ),
        )
    except OwnedTargetValidationError as exc:
        raise OwnedTargetLoadError(exc.code, exc.message) from exc
    if _canonical_json(policy.to_dict()) != _canonical_json(data):
        raise OwnedTargetLoadError(
            "owned_target_execution_policy_non_canonical",
            "execution_policy contains non-canonical values.",
        )
    return policy


def load_owned_target_audit_json(
    document: str | bytes | bytearray,
) -> OwnedTargetAuditRecord:
    """Strictly load one owned-target preflight audit record."""

    root = _strict_object(
        _parse_json_document(document),
        "audit",
        _AUDIT_FIELDS,
    )
    schema_version = _text(root["schema_version"], "schema_version")
    if schema_version not in SUPPORTED_OWNED_TARGET_AUDIT_SCHEMA_VERSIONS:
        raise OwnedTargetLoadError(
            "owned_target_audit_schema_unsupported",
            f"Unsupported audit schema_version {schema_version!r}.",
        )
    address_values = root["resolved_addresses"]
    stop_values = root["stop_conditions"]
    if not isinstance(address_values, list) or not isinstance(stop_values, list):
        raise OwnedTargetLoadError(
            "owned_target_list_required",
            "resolved_addresses and stop_conditions must be JSON arrays.",
        )
    try:
        audit = OwnedTargetAuditRecord(
            audit_type=_text(root["audit_type"], "audit_type"),
            schema_version=schema_version,
            scan_id=_text(root["scan_id"], "scan_id"),
            authorization_id=_text(root["authorization_id"], "authorization_id"),
            authorization_sha256=_text(
                root["authorization_sha256"],
                "authorization_sha256",
            ),
            organization=_text(root["organization"], "organization"),
            authorized_by=_text(root["authorized_by"], "authorized_by"),
            target=_text(root["target"], "target"),
            resolved_addresses=tuple(
                _text(value, f"resolved_addresses[{index}]")
                for index, value in enumerate(address_values)
            ),
            created_at=_parse_timestamp(root["created_at"], "created_at"),
            execution_policy=_load_execution_policy(root["execution_policy"]),
            stop_conditions=tuple(
                _text(value, f"stop_conditions[{index}]")
                for index, value in enumerate(stop_values)
            ),
        )
    except OwnedTargetLoadError:
        raise
    except OwnedTargetValidationError as exc:
        raise OwnedTargetLoadError(exc.code, exc.message) from exc
    if _canonical_json(audit.to_dict()) != _canonical_json(root):
        raise OwnedTargetLoadError(
            "owned_target_audit_non_canonical",
            "Audit document contains non-canonical values.",
        )
    return audit


def _read_owned_target_file(path: str | Path) -> bytes:
    try:
        document_path = Path(path).expanduser()
    except (TypeError, ValueError, RuntimeError) as exc:
        raise OwnedTargetLoadError(
            "owned_target_path_invalid",
            "Owned-target document path is invalid.",
        ) from exc
    try:
        metadata = document_path.lstat()
    except OSError as exc:
        raise OwnedTargetLoadError(
            "owned_target_file_read_failed",
            f"Unable to inspect owned-target document {document_path}.",
        ) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise OwnedTargetLoadError(
            "owned_target_symlink_not_allowed",
            "Owned-target document cannot be a symbolic link.",
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise OwnedTargetLoadError(
            "owned_target_not_regular_file",
            "Owned-target document must be a regular file.",
        )
    if metadata.st_size > MAXIMUM_OWNED_TARGET_DOCUMENT_BYTES:
        raise OwnedTargetLoadError(
            "owned_target_document_too_large",
            "Owned-target document exceeds 256 KiB.",
        )
    try:
        return document_path.read_bytes()
    except OSError as exc:
        raise OwnedTargetLoadError(
            "owned_target_file_read_failed",
            f"Unable to read owned-target document {document_path}.",
        ) from exc


def load_owned_target_authorization_file(
    path: str | Path,
) -> OwnedTargetAuthorization:
    return load_owned_target_authorization_json(_read_owned_target_file(path))


def load_owned_target_audit_file(path: str | Path) -> OwnedTargetAuditRecord:
    return load_owned_target_audit_json(_read_owned_target_file(path))


def _write_owned_target_document(
    document: str,
    path: str | Path,
    *,
    overwrite: bool,
) -> Path:
    try:
        document_path = Path(path).expanduser()
    except (TypeError, ValueError, RuntimeError) as exc:
        raise OwnedTargetLoadError(
            "owned_target_path_invalid",
            "Owned-target destination path is invalid.",
        ) from exc
    try:
        exists = os.path.lexists(document_path)
    except OSError as exc:
        raise OwnedTargetLoadError(
            "owned_target_path_inspection_failed",
            "Unable to inspect owned-target destination.",
        ) from exc
    if exists:
        try:
            metadata = document_path.lstat()
        except OSError as exc:
            raise OwnedTargetLoadError(
                "owned_target_path_inspection_failed",
                "Unable to inspect owned-target destination.",
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise OwnedTargetLoadError(
                "owned_target_symlink_not_allowed",
                "Owned-target destination cannot be a symbolic link.",
            )
        if not stat.S_ISREG(metadata.st_mode):
            raise OwnedTargetLoadError(
                "owned_target_not_regular_file",
                "Owned-target destination must be a regular file.",
            )
        if not overwrite:
            raise OwnedTargetLoadError(
                "owned_target_file_exists",
                "Owned-target destination already exists.",
            )
    try:
        document_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OwnedTargetLoadError(
            "owned_target_directory_create_failed",
            "Unable to create owned-target destination directory.",
        ) from exc
    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{document_path.name}.",
            suffix=".tmp",
            dir=document_path.parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output:
            descriptor = None
            output.write(document)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        if overwrite:
            os.replace(temporary_path, document_path)
            temporary_path = None
        else:
            try:
                os.link(temporary_path, document_path)
            except FileExistsError as exc:
                raise OwnedTargetLoadError(
                    "owned_target_file_exists",
                    "Owned-target destination already exists.",
                ) from exc
            temporary_path.unlink()
            temporary_path = None
        try:
            directory_descriptor = os.open(document_path.parent, os.O_RDONLY)
        except OSError:
            directory_descriptor = None
        if directory_descriptor is not None:
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except OwnedTargetContractError:
        raise
    except OSError as exc:
        raise OwnedTargetLoadError(
            "owned_target_write_failed",
            "Unable to atomically write owned-target document.",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
    return document_path


def write_owned_target_authorization_file(
    authorization: OwnedTargetAuthorization,
    path: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    if not isinstance(authorization, OwnedTargetAuthorization):
        raise OwnedTargetValidationError(
            "owned_target_authorization_value_invalid",
            "authorization must be an OwnedTargetAuthorization value.",
        )
    return _write_owned_target_document(
        authorization.to_json(),
        path,
        overwrite=overwrite,
    )


def write_owned_target_audit_file(
    audit: OwnedTargetAuditRecord,
    path: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    if not isinstance(audit, OwnedTargetAuditRecord):
        raise OwnedTargetValidationError(
            "owned_target_audit_value_invalid",
            "audit must be an OwnedTargetAuditRecord value.",
        )
    return _write_owned_target_document(
        audit.to_json(),
        path,
        overwrite=overwrite,
    )


__all__ = [
    "CURRENT_OWNED_TARGET_AUDIT_SCHEMA_VERSION",
    "CURRENT_OWNED_TARGET_AUTHORIZATION_SCHEMA_VERSION",
    "MAXIMUM_OWNED_TARGET_AUTHORIZATION_VALIDITY_DAYS",
    "MAXIMUM_OWNED_TARGET_DOCUMENT_BYTES",
    "OWNED_TARGET_AUDIT_TYPE",
    "OWNED_TARGET_AUTHORIZATION_TYPE",
    "OWNED_TARGET_STOP_CONDITIONS",
    "OwnedTargetAuditRecord",
    "OwnedTargetAuthorization",
    "OwnedTargetContractError",
    "OwnedTargetExecutionPolicy",
    "OwnedTargetLimits",
    "OwnedTargetLoadError",
    "OwnedTargetValidationError",
    "canonicalize_owned_target_hostname",
    "canonicalize_owned_target_url",
    "load_owned_target_audit_file",
    "load_owned_target_audit_json",
    "load_owned_target_authorization_file",
    "load_owned_target_authorization_json",
    "write_owned_target_audit_file",
    "write_owned_target_authorization_file",
]
