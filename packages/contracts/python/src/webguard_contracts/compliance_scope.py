"""Tenant-scoped compliance applicability contracts (platform
expansion, docs/PLATFORM_SCOPE.md, handoff section 10.1-10.2).

Framework and MasterControl (compliance.py) describe the catalog: the
same for every organization. ScopedControlImplementation is the first
tenant-scoped Compliance record, the entry point handoff section
10.1 calls a "scoped implementation": one organization's own
applicability decision against one master control from that catalog.
It answers exactly one question, does this control apply to this
organization and who decided that, not whether the organization
satisfies it. Assertions, tests, and evidence (the rest of section
10.1's model, and the other six status dimensions section 10.2 lists
alongside applicability: collection, test execution, assertion,
control assessment, treatment, assurance review) are later, distinct
concepts and are explicitly not built in this slice. They attach to a
control only once applicability has actually been resolved as
applicable here, never before.

ApplicabilityStatus's three values are not interchangeable
placeholders. UNRESOLVED means nobody has made this call yet: it
carries no rationale and no deciding principal, because there is no
decision to attribute one to. APPLICABLE and NOT_APPLICABLE_WITH_RATIONALE
both represent a real human decision (section 10.1's "reviewer-approved
inclusion/exclusion", section 10.4's "risk acceptance is an authorised
human decision") and therefore both require a deciding principal and a
decision timestamp; NOT_APPLICABLE_WITH_RATIONALE additionally requires
the rationale text itself, since an unattributed or unexplained "not
applicable" is exactly the kind of manufactured compliance signal
docs/PLATFORM_SCOPE.md's claim-boundaries section forbids.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

_IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
MAXIMUM_ORGANIZATION_ID_LENGTH = 64
MAXIMUM_PRINCIPAL_ID_LENGTH = 64
MAXIMUM_RATIONALE_LENGTH = 4000


class ApplicabilityStatus(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE_WITH_RATIONALE = "not_applicable_with_rationale"
    UNRESOLVED = "unresolved"


class ComplianceScopeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ComplianceScopeError(f"compliance_scope_{field}_invalid", f"{field} must be text.")
    cleaned = value.strip().lower()
    if not cleaned or not _IDENTIFIER.fullmatch(cleaned):
        raise ComplianceScopeError(
            f"compliance_scope_{field}_invalid",
            f"{field} must use lowercase letters, digits, dots, underscores, or hyphens.",
        )
    return cleaned


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ComplianceScopeError(f"compliance_scope_{field}_invalid", f"{field} must be text.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise ComplianceScopeError(
            f"compliance_scope_{field}_invalid", f"{field} must contain 1 to {maximum} characters."
        )
    return cleaned


def _datetime(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ComplianceScopeError(
            f"compliance_scope_{field}_invalid", f"{field} must be a timezone-aware datetime."
        )
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ScopedControlImplementation:
    organization_id: str
    framework_id: str
    control_id: str
    applicability_status: ApplicabilityStatus
    created_at: datetime
    updated_at: datetime
    rationale: str | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "organization_id",
            _text(self.organization_id, "organization_id", MAXIMUM_ORGANIZATION_ID_LENGTH),
        )
        object.__setattr__(self, "framework_id", _identifier(self.framework_id, "framework_id"))
        object.__setattr__(self, "control_id", _identifier(self.control_id, "control_id"))
        if not isinstance(self.applicability_status, ApplicabilityStatus):
            raise ComplianceScopeError(
                "compliance_scope_applicability_status_invalid",
                "applicability_status must be an ApplicabilityStatus value.",
            )
        object.__setattr__(self, "created_at", _datetime(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", _datetime(self.updated_at, "updated_at"))

        if self.applicability_status is ApplicabilityStatus.UNRESOLVED:
            if self.rationale is not None or self.decided_by is not None or self.decided_at is not None:
                raise ComplianceScopeError(
                    "compliance_scope_unresolved_must_be_undecided",
                    "an unresolved applicability status must not carry a rationale, deciding "
                    "principal, or decision time: nobody has made this call yet.",
                )
            return

        if self.decided_by is None or self.decided_at is None:
            raise ComplianceScopeError(
                "compliance_scope_decision_requires_principal_and_time",
                "applicable and not_applicable_with_rationale both represent a real human "
                "decision and require decided_by and decided_at.",
            )
        object.__setattr__(
            self, "decided_by", _text(self.decided_by, "decided_by", MAXIMUM_PRINCIPAL_ID_LENGTH)
        )
        object.__setattr__(self, "decided_at", _datetime(self.decided_at, "decided_at"))

        if self.applicability_status is ApplicabilityStatus.NOT_APPLICABLE_WITH_RATIONALE:
            if self.rationale is None:
                raise ComplianceScopeError(
                    "compliance_scope_not_applicable_requires_rationale",
                    "not_applicable_with_rationale requires the rationale itself, not just the status.",
                )
            object.__setattr__(self, "rationale", _text(self.rationale, "rationale", MAXIMUM_RATIONALE_LENGTH))
        elif self.rationale is not None:
            object.__setattr__(self, "rationale", _text(self.rationale, "rationale", MAXIMUM_RATIONALE_LENGTH))

    def to_dict(self) -> dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "framework_id": self.framework_id,
            "control_id": self.control_id,
            "applicability_status": self.applicability_status.value,
            "rationale": self.rationale,
            "decided_by": self.decided_by,
            "decided_at": _timestamp(self.decided_at) if self.decided_at is not None else None,
            "created_at": _timestamp(self.created_at),
            "updated_at": _timestamp(self.updated_at),
        }


__all__ = [
    "ApplicabilityStatus",
    "ComplianceScopeError",
    "ScopedControlImplementation",
]
