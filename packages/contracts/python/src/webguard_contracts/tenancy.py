"""Versioned organization, principal, token, and audit contracts."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


CURRENT_TENANCY_SCHEMA_VERSION = "1.0"
ORGANIZATION_TYPE = "organization"
PRINCIPAL_TYPE = "principal"
API_TOKEN_METADATA_TYPE = "api_token_metadata"
SECURITY_AUDIT_EVENT_TYPE = "security_audit_event"
MAXIMUM_ORGANIZATION_NAME_LENGTH = 120
MAXIMUM_PRINCIPAL_NAME_LENGTH = 120
MAXIMUM_TOKEN_LABEL_LENGTH = 120
MAXIMUM_AUDIT_ACTION_LENGTH = 128
MAXIMUM_AUDIT_RESOURCE_LENGTH = 128

_IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class OrganizationStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class PrincipalType(str, Enum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"


class OrganizationRole(str, Enum):
    OWNER = "owner"
    ADMINISTRATOR = "administrator"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AuditOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    FAILED = "failed"


class TenancyContractError(ValueError):
    """Controlled invalid tenancy value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _uuid(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TenancyContractError(
            "tenancy_uuid_invalid",
            f"{field} must be a canonical UUID string.",
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise TenancyContractError(
            "tenancy_uuid_invalid",
            f"{field} must be a canonical UUID string.",
        ) from exc
    canonical = str(parsed)
    if canonical != value:
        raise TenancyContractError(
            "tenancy_uuid_non_canonical",
            f"{field} must use canonical lower-case UUID notation.",
        )
    return canonical


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise TenancyContractError("tenancy_text_invalid", f"{field} must be text.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise TenancyContractError(
            "tenancy_text_invalid",
            f"{field} must contain 1 to {maximum} characters.",
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in cleaned):
        raise TenancyContractError(
            "tenancy_text_control_character",
            f"{field} cannot contain control characters.",
        )
    return cleaned


def _identifier(value: object, field: str, maximum: int = 128) -> str:
    cleaned = _text(value, field, maximum).lower()
    if not _IDENTIFIER.fullmatch(cleaned):
        raise TenancyContractError(
            "tenancy_identifier_invalid",
            f"{field} must be a canonical lower-case identifier.",
        )
    return cleaned


def _datetime(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TenancyContractError(
            "tenancy_timestamp_invalid",
            f"{field} must be a timezone-aware datetime.",
        )
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


@dataclass(frozen=True, slots=True)
class Organization:
    organization_id: str
    name: str
    status: OrganizationStatus
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "organization_id", _uuid(self.organization_id, "organization_id"))
        object.__setattr__(self, "name", _text(self.name, "name", MAXIMUM_ORGANIZATION_NAME_LENGTH))
        if not isinstance(self.status, OrganizationStatus):
            raise TenancyContractError(
                "organization_status_invalid", "status must be an OrganizationStatus value."
            )
        object.__setattr__(self, "created_at", _datetime(self.created_at, "created_at"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": ORGANIZATION_TYPE,
            "schema_version": CURRENT_TENANCY_SCHEMA_VERSION,
            "organization_id": self.organization_id,
            "name": self.name,
            "status": self.status.value,
            "created_at": _timestamp(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    organization_id: str
    display_name: str
    principal_type: PrincipalType
    role: OrganizationRole
    active: bool
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "principal_id", _uuid(self.principal_id, "principal_id"))
        object.__setattr__(self, "organization_id", _uuid(self.organization_id, "organization_id"))
        object.__setattr__(
            self,
            "display_name",
            _text(self.display_name, "display_name", MAXIMUM_PRINCIPAL_NAME_LENGTH),
        )
        if not isinstance(self.principal_type, PrincipalType):
            raise TenancyContractError(
                "principal_type_invalid", "principal_type must be a PrincipalType value."
            )
        if not isinstance(self.role, OrganizationRole):
            raise TenancyContractError(
                "organization_role_invalid", "role must be an OrganizationRole value."
            )
        if not isinstance(self.active, bool):
            raise TenancyContractError("principal_active_invalid", "active must be boolean.")
        object.__setattr__(self, "created_at", _datetime(self.created_at, "created_at"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": PRINCIPAL_TYPE,
            "schema_version": CURRENT_TENANCY_SCHEMA_VERSION,
            "principal_id": self.principal_id,
            "organization_id": self.organization_id,
            "display_name": self.display_name,
            "principal_type": self.principal_type.value,
            "role": self.role.value,
            "active": self.active,
            "created_at": _timestamp(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class ApiTokenMetadata:
    token_id: str
    organization_id: str
    principal_id: str
    label: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "token_id", _uuid(self.token_id, "token_id"))
        object.__setattr__(self, "organization_id", _uuid(self.organization_id, "organization_id"))
        object.__setattr__(self, "principal_id", _uuid(self.principal_id, "principal_id"))
        object.__setattr__(self, "label", _text(self.label, "label", MAXIMUM_TOKEN_LABEL_LENGTH))
        object.__setattr__(self, "created_at", _datetime(self.created_at, "created_at"))
        object.__setattr__(self, "expires_at", _datetime(self.expires_at, "expires_at"))
        if self.expires_at <= self.created_at:
            raise TenancyContractError(
                "token_expiry_invalid", "expires_at must be later than created_at."
            )
        if self.revoked_at is not None:
            object.__setattr__(self, "revoked_at", _datetime(self.revoked_at, "revoked_at"))
        if self.last_used_at is not None:
            object.__setattr__(self, "last_used_at", _datetime(self.last_used_at, "last_used_at"))

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": API_TOKEN_METADATA_TYPE,
            "schema_version": CURRENT_TENANCY_SCHEMA_VERSION,
            "token_id": self.token_id,
            "organization_id": self.organization_id,
            "principal_id": self.principal_id,
            "label": self.label,
            "created_at": _timestamp(self.created_at),
            "expires_at": _timestamp(self.expires_at),
            "revoked_at": None if self.revoked_at is None else _timestamp(self.revoked_at),
            "last_used_at": None if self.last_used_at is None else _timestamp(self.last_used_at),
        }


@dataclass(frozen=True, slots=True)
class SecurityAuditEvent:
    event_id: str
    request_id: str
    organization_id: str
    principal_id: str
    token_id: str
    action: str
    resource_type: str
    resource_id: str
    outcome: AuditOutcome
    occurred_at: datetime
    detail_code: str | None = None

    def __post_init__(self) -> None:
        for field in ("event_id", "request_id", "organization_id", "principal_id", "token_id"):
            object.__setattr__(self, field, _uuid(getattr(self, field), field))
        object.__setattr__(
            self, "action", _identifier(self.action, "action", MAXIMUM_AUDIT_ACTION_LENGTH)
        )
        object.__setattr__(
            self,
            "resource_type",
            _identifier(self.resource_type, "resource_type", MAXIMUM_AUDIT_RESOURCE_LENGTH),
        )
        object.__setattr__(
            self,
            "resource_id",
            _text(self.resource_id, "resource_id", MAXIMUM_AUDIT_RESOURCE_LENGTH),
        )
        if not isinstance(self.outcome, AuditOutcome):
            raise TenancyContractError(
                "audit_outcome_invalid", "outcome must be an AuditOutcome value."
            )
        object.__setattr__(self, "occurred_at", _datetime(self.occurred_at, "occurred_at"))
        if self.detail_code is not None:
            object.__setattr__(self, "detail_code", _identifier(self.detail_code, "detail_code"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": SECURITY_AUDIT_EVENT_TYPE,
            "schema_version": CURRENT_TENANCY_SCHEMA_VERSION,
            "event_id": self.event_id,
            "request_id": self.request_id,
            "organization_id": self.organization_id,
            "principal_id": self.principal_id,
            "token_id": self.token_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "outcome": self.outcome.value,
            "occurred_at": _timestamp(self.occurred_at),
            "detail_code": self.detail_code,
        }


__all__ = [
    "API_TOKEN_METADATA_TYPE",
    "AuditOutcome",
    "ApiTokenMetadata",
    "CURRENT_TENANCY_SCHEMA_VERSION",
    "MAXIMUM_AUDIT_ACTION_LENGTH",
    "MAXIMUM_AUDIT_RESOURCE_LENGTH",
    "MAXIMUM_ORGANIZATION_NAME_LENGTH",
    "MAXIMUM_PRINCIPAL_NAME_LENGTH",
    "MAXIMUM_TOKEN_LABEL_LENGTH",
    "ORGANIZATION_TYPE",
    "Organization",
    "OrganizationRole",
    "OrganizationStatus",
    "PRINCIPAL_TYPE",
    "Principal",
    "PrincipalType",
    "SECURITY_AUDIT_EVENT_TYPE",
    "SecurityAuditEvent",
    "TenancyContractError",
]
