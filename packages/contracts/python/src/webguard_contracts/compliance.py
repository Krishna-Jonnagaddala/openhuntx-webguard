"""Compliance framework and master control catalog contracts (platform
expansion, docs/PLATFORM_SCOPE.md, handoff section 10.1).

Framework and MasterControl describe the catalog: a versioned
reference to what a framework requires, shared identically across
every organization, the same relationship ``webguard_contracts.findings``
has to a specific scan's own findings versus the CWE registry a
finding cites. They carry no organization_id at all, unlike every
other contract in this package: this is the first genuinely global,
non-tenant reference data this platform has, see
docs/adr/0034-compliance-catalog-is-global-reference-data.md for why
that is a deliberate, reviewed decision, not an oversight.

A scoped, per-organization "how is this specific tenant doing against
this control" record (implementation, assertion, evidence) is a
distinct, tenant-scoped concept (handoff section 10.1's own "scoped
implementations" versus this module's plain "master controls").
Applicability, the first of section 10.2's status dimensions, is now
built: see ``compliance_scope.ScopedControlImplementation``. The
remaining dimensions (collection, test execution, assertion, control
assessment, treatment, assurance review) are still not built.

FrameworkStatus.PLACEHOLDER exists because this platform ships no
framework's real legally-reviewed content yet (docs/PLATFORM_SCOPE.md's
own blocker list): a Framework row can exist, named and cited to its
authoritative source, with zero MasterControl rows under it, honestly
representing "we intend to support this, we have not loaded its real
content yet" rather than silently having no row at all or fabricating
placeholder control text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

_IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
MAXIMUM_FRAMEWORK_NAME_LENGTH = 200
MAXIMUM_VERSION_LENGTH = 64
MAXIMUM_SOURCE_REFERENCE_LENGTH = 512
MAXIMUM_CONTROL_NUMBER_LENGTH = 32
MAXIMUM_CONTROL_TITLE_LENGTH = 300
MAXIMUM_CONTROL_DESCRIPTION_LENGTH = 4000
MAXIMUM_CONTROL_CATEGORY_LENGTH = 120


class FrameworkStatus(str, Enum):
    PLACEHOLDER = "placeholder"
    CURRENT = "current"
    PROPOSED = "proposed"
    FUTURE_READINESS = "future_readiness"
    SUPERSEDED = "superseded"


class ComplianceContractError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ComplianceContractError(f"compliance_{field}_invalid", f"{field} must be text.")
    cleaned = value.strip().lower()
    if not cleaned or not _IDENTIFIER.fullmatch(cleaned):
        raise ComplianceContractError(
            f"compliance_{field}_invalid",
            f"{field} must use lowercase letters, digits, dots, underscores, or hyphens.",
        )
    return cleaned


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ComplianceContractError(f"compliance_{field}_invalid", f"{field} must be text.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise ComplianceContractError(
            f"compliance_{field}_invalid", f"{field} must contain 1 to {maximum} characters."
        )
    return cleaned


def _optional_text(value: object, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _text(value, field, maximum)


def _datetime(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ComplianceContractError(
            f"compliance_{field}_invalid", f"{field} must be a timezone-aware datetime."
        )
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class Framework:
    framework_id: str
    name: str
    version: str
    status: FrameworkStatus
    source_reference: str
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "framework_id", _identifier(self.framework_id, "framework_id"))
        object.__setattr__(self, "name", _text(self.name, "name", MAXIMUM_FRAMEWORK_NAME_LENGTH))
        object.__setattr__(self, "version", _text(self.version, "version", MAXIMUM_VERSION_LENGTH))
        if not isinstance(self.status, FrameworkStatus):
            raise ComplianceContractError(
                "compliance_framework_status_invalid", "status must be a FrameworkStatus value."
            )
        object.__setattr__(
            self,
            "source_reference",
            _text(self.source_reference, "source_reference", MAXIMUM_SOURCE_REFERENCE_LENGTH),
        )
        object.__setattr__(self, "created_at", _datetime(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", _datetime(self.updated_at, "updated_at"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "source_reference": self.source_reference,
            "created_at": _timestamp(self.created_at),
            "updated_at": _timestamp(self.updated_at),
        }


@dataclass(frozen=True, slots=True)
class MasterControl:
    control_id: str
    framework_id: str
    control_number: str
    title: str
    created_at: datetime
    updated_at: datetime
    description: str | None = None
    category: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "control_id", _identifier(self.control_id, "control_id"))
        object.__setattr__(self, "framework_id", _identifier(self.framework_id, "framework_id"))
        object.__setattr__(
            self,
            "control_number",
            _text(self.control_number, "control_number", MAXIMUM_CONTROL_NUMBER_LENGTH),
        )
        object.__setattr__(self, "title", _text(self.title, "title", MAXIMUM_CONTROL_TITLE_LENGTH))
        object.__setattr__(self, "created_at", _datetime(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", _datetime(self.updated_at, "updated_at"))
        object.__setattr__(
            self,
            "description",
            _optional_text(self.description, "description", MAXIMUM_CONTROL_DESCRIPTION_LENGTH),
        )
        object.__setattr__(
            self, "category", _optional_text(self.category, "category", MAXIMUM_CONTROL_CATEGORY_LENGTH)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "framework_id": self.framework_id,
            "control_number": self.control_number,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "created_at": _timestamp(self.created_at),
            "updated_at": _timestamp(self.updated_at),
        }


__all__ = [
    "ComplianceContractError",
    "Framework",
    "FrameworkStatus",
    "MasterControl",
]
