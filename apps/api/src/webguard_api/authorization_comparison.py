"""Authorization-comparison plan storage for IDOR/BOLA differential
scanning (Slice 8).

An `AuthorizationComparisonPlanRecord` contains references only -- an
organization, a target, an authorization, exactly two already-registered
`AuthenticationContext` IDs, the single active check it authorizes
(always `active.authorization.idor` this slice), a bounded,
operator-supplied resource scope, and safety bounds. It never contains
cookies, passwords, bearer tokens, or API keys -- those live only in the
authentication contexts it references, resolved separately at scan time.

This is the "smallest clean mechanism" chosen for authorization-
comparison scans (per this slice's own instruction to first inspect the
existing permit architecture rather than reinterpret the singular
`authentication_context_id` claim): a signed permit claim
(`authorization_comparison_plan_id`) references *this* plan, and this
plan in turn references the two identities to compare. Two independent
signed references, two independent responsibilities.

Storage is in-memory only, for the same reasons `authentication_contexts.py`
gives for its own store: no secret material is safe to persist to SQLite
as a stand-in for real KMS-backed storage (this plan holds no secrets at
all, but it does reference two authentication contexts whose own secret
material lives in exactly that kind of store), and a throwaway SQLite
schema for this metadata now would be rework once the project's own
planned PostgreSQL migration happens. The repository interface is kept
narrow and swappable for that reason.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from uuid import uuid4


class AuthorizationComparisonError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AuthorizationComparisonPlanStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


MAXIMUM_RESOURCE_PAIRS_PER_PLAN = 10
MAXIMUM_COMPARISONS_PER_PLAN = 20  # 2 cross-checks per resource pair


@dataclass(frozen=True, slots=True)
class ResourcePairSpec:
    """One operator-supplied pair of resources to compare -- an explicit,
    controlled test-resource specification (never generated, never
    enumerated). Both endpoints are full paths/URLs the operator already
    knows point at real, controlled fixture/test resources."""

    resource_type: str
    method: str
    primary_endpoint: str
    secondary_endpoint: str
    identifier_location: str  # "path" | "query" | "none"
    identifier_name: str
    expected_access: str  # "private_to_owner" | "shared" | "public" | "unknown"

    def to_dict(self) -> dict[str, str]:
        return {
            "resource_type": self.resource_type,
            "method": self.method,
            "primary_endpoint": self.primary_endpoint,
            "secondary_endpoint": self.secondary_endpoint,
            "identifier_location": self.identifier_location,
            "identifier_name": self.identifier_name,
            "expected_access": self.expected_access,
        }

    @classmethod
    def from_dict(cls, value: dict) -> "ResourcePairSpec":
        try:
            return cls(
                resource_type=value["resource_type"],
                method=str(value["method"]).upper(),
                primary_endpoint=value["primary_endpoint"],
                secondary_endpoint=value["secondary_endpoint"],
                identifier_location=value["identifier_location"],
                identifier_name=value.get("identifier_name", ""),
                expected_access=value.get("expected_access", "private_to_owner"),
            )
        except (KeyError, TypeError) as exc:
            raise AuthorizationComparisonError(
                "authorization_comparison_resource_spec_invalid",
                "Each resource pair requires resource_type, method, "
                "primary_endpoint, secondary_endpoint, and identifier_location.",
            ) from exc


@dataclass(frozen=True, slots=True)
class AuthorizationComparisonPlanRecord:
    comparison_plan_id: str
    organization_id: str
    target: str
    authorization_id: str
    primary_context_id: str
    secondary_context_id: str
    permitted_active_check: str
    allowed_http_methods: tuple[str, ...]
    resource_scope: tuple[ResourcePairSpec, ...]
    maximum_resources: int
    maximum_comparisons: int
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    # Slice 9: when set, the executor additionally runs an authenticated
    # resource-discovery crawl for each identity and feeds any
    # structurally-eligible discovered pairs into the same detector
    # call, alongside (not instead of) any explicit resource_scope
    # entries above. discovery_login_page_marker is an optional,
    # operator-supplied string (e.g. a fixture's own login-page marker)
    # used only to detect an expired session during that crawl -- never
    # a resource identifier itself, and never required.
    enable_discovery: bool = False
    discovery_login_page_marker: str = ""

    def status_at(self, now: datetime) -> AuthorizationComparisonPlanStatus:
        if self.revoked_at is not None:
            return AuthorizationComparisonPlanStatus.REVOKED
        if now >= self.expires_at:
            return AuthorizationComparisonPlanStatus.EXPIRED
        return AuthorizationComparisonPlanStatus.ACTIVE

    def to_public_dict(self, *, now: datetime) -> dict[str, object]:
        return {
            "comparison_plan_id": self.comparison_plan_id,
            "organization_id": self.organization_id,
            "target": self.target,
            "authorization_id": self.authorization_id,
            "primary_context_id": self.primary_context_id,
            "secondary_context_id": self.secondary_context_id,
            "permitted_active_check": self.permitted_active_check,
            "allowed_http_methods": list(self.allowed_http_methods),
            "resource_scope": [spec.to_dict() for spec in self.resource_scope],
            "maximum_resources": self.maximum_resources,
            "maximum_comparisons": self.maximum_comparisons,
            "enable_discovery": self.enable_discovery,
            "status": self.status_at(now).value,
            "created_at": self.created_at.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
            "expires_at": self.expires_at.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
            "revoked_at": None
            if self.revoked_at is None
            else self.revoked_at.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
        }


class AuthorizationComparisonPlanRepository:
    """In-memory plan storage. Holds no secrets -- see module docstring."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._plans: dict[str, AuthorizationComparisonPlanRecord] = {}

    def create(
        self,
        *,
        organization_id: str,
        target: str,
        authorization_id: str,
        primary_context_id: str,
        secondary_context_id: str,
        permitted_active_check: str,
        allowed_http_methods: tuple[str, ...],
        resource_scope: tuple[ResourcePairSpec, ...],
        expires_at: datetime,
        now: datetime,
        enable_discovery: bool = False,
        discovery_login_page_marker: str = "",
    ) -> AuthorizationComparisonPlanRecord:
        if primary_context_id == secondary_context_id:
            raise AuthorizationComparisonError(
                "authorization_comparison_identities_not_distinct",
                "primary_context_id and secondary_context_id must reference "
                "two distinct authentication contexts.",
            )
        if not resource_scope and not enable_discovery:
            raise AuthorizationComparisonError(
                "authorization_comparison_resource_scope_empty",
                "A comparison plan requires at least one resource pair, "
                "unless enable_discovery is set.",
            )
        if len(resource_scope) > MAXIMUM_RESOURCE_PAIRS_PER_PLAN:
            raise AuthorizationComparisonError(
                "authorization_comparison_too_many_resources",
                f"{len(resource_scope)} resource pairs exceed the "
                f"{MAXIMUM_RESOURCE_PAIRS_PER_PLAN}-pair limit.",
            )
        if len(resource_scope) * 2 > MAXIMUM_COMPARISONS_PER_PLAN:
            raise AuthorizationComparisonError(
                "authorization_comparison_too_many_comparisons",
                f"{len(resource_scope) * 2} comparisons exceed the "
                f"{MAXIMUM_COMPARISONS_PER_PLAN}-comparison limit.",
            )
        if expires_at <= now:
            raise AuthorizationComparisonError(
                "authorization_comparison_expiry_invalid",
                "expires_at must be later than the current time.",
            )
        record = AuthorizationComparisonPlanRecord(
            comparison_plan_id=str(uuid4()),
            organization_id=organization_id,
            target=target,
            authorization_id=authorization_id,
            primary_context_id=primary_context_id,
            secondary_context_id=secondary_context_id,
            permitted_active_check=permitted_active_check,
            allowed_http_methods=allowed_http_methods,
            resource_scope=resource_scope,
            maximum_resources=len(resource_scope),
            maximum_comparisons=len(resource_scope) * 2,
            created_at=now,
            expires_at=expires_at,
            enable_discovery=enable_discovery,
            discovery_login_page_marker=discovery_login_page_marker,
        )
        with self._lock:
            self._plans[record.comparison_plan_id] = record
        return record

    def get(self, comparison_plan_id: str) -> AuthorizationComparisonPlanRecord:
        with self._lock:
            record = self._plans.get(comparison_plan_id)
        if record is None:
            raise AuthorizationComparisonError(
                "authorization_comparison_plan_not_found",
                "No authorization-comparison plan matches the requested ID.",
            )
        return record

    def revoke(
        self, comparison_plan_id: str, *, now: datetime
    ) -> AuthorizationComparisonPlanRecord:
        with self._lock:
            record = self._plans.get(comparison_plan_id)
            if record is None:
                raise AuthorizationComparisonError(
                    "authorization_comparison_plan_not_found",
                    "No authorization-comparison plan matches the requested ID.",
                )
            if record.revoked_at is None:
                record = AuthorizationComparisonPlanRecord(
                    comparison_plan_id=record.comparison_plan_id,
                    organization_id=record.organization_id,
                    target=record.target,
                    authorization_id=record.authorization_id,
                    primary_context_id=record.primary_context_id,
                    secondary_context_id=record.secondary_context_id,
                    permitted_active_check=record.permitted_active_check,
                    allowed_http_methods=record.allowed_http_methods,
                    resource_scope=record.resource_scope,
                    maximum_resources=record.maximum_resources,
                    maximum_comparisons=record.maximum_comparisons,
                    created_at=record.created_at,
                    expires_at=record.expires_at,
                    revoked_at=now,
                    enable_discovery=record.enable_discovery,
                    discovery_login_page_marker=record.discovery_login_page_marker,
                )
                self._plans[comparison_plan_id] = record
        return record

    def require_bound(
        self,
        comparison_plan_id: str,
        *,
        organization_id: str,
        target: str,
        authorization_id: str,
        now: datetime,
    ) -> AuthorizationComparisonPlanRecord:
        record = self.get(comparison_plan_id)
        if record.organization_id != organization_id:
            raise AuthorizationComparisonError(
                "authorization_comparison_organization_mismatch",
                "Authorization-comparison plan does not belong to this organization.",
            )
        if record.target != target:
            raise AuthorizationComparisonError(
                "authorization_comparison_target_mismatch",
                "Authorization-comparison plan is not bound to this target.",
            )
        if record.authorization_id != authorization_id:
            raise AuthorizationComparisonError(
                "authorization_comparison_authorization_mismatch",
                "Authorization-comparison plan is not bound to this authorization.",
            )
        status = record.status_at(now)
        if status is not AuthorizationComparisonPlanStatus.ACTIVE:
            raise AuthorizationComparisonError(
                f"authorization_comparison_plan_{status.value}",
                f"Authorization-comparison plan is {status.value} and cannot be used.",
            )
        return record


__all__ = [
    "MAXIMUM_COMPARISONS_PER_PLAN",
    "MAXIMUM_RESOURCE_PAIRS_PER_PLAN",
    "AuthorizationComparisonError",
    "AuthorizationComparisonPlanRecord",
    "AuthorizationComparisonPlanRepository",
    "AuthorizationComparisonPlanStatus",
    "ResourcePairSpec",
]
