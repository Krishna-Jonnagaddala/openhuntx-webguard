"""PostgreSQL-backed authorization-comparison-plan repository (Slice
13 requirement 10).

Status: POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED. Closes
the cross-process limitation the in-memory
``AuthorizationComparisonPlanRepository`` has always documented (a
plan registered by one process is invisible to another) for whichever
future slice wires IDOR/BOLA workflows into the production runtime --
this class is not part of this slice's live execution path. No
credential material belongs here, and none is ever accepted: every
field mirrors ``AuthorizationComparisonPlanRecord`` exactly (target,
authorization, identity *references* by ID, resource/discovery policy,
expiry, revocation) -- the two authentication contexts it references
are looked up by ID only, never embedded.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from .authorization_comparison import (
    AuthorizationComparisonError,
    AuthorizationComparisonPlanRecord,
    AuthorizationComparisonPlanStatus,
    ResourcePairSpec,
)
from .postgres_pool import WebGuardPostgresPool

_COLUMNS = (
    "comparison_plan_id, organization_id, target, authorization_id, primary_context_id, "
    "secondary_context_id, permitted_active_check, allowed_http_methods, resource_scope, "
    "maximum_resources, maximum_comparisons, enable_discovery, discovery_login_page_marker, "
    "created_at, expires_at, revoked_at"
)


class PostgresAuthorizationComparisonPlanRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple) -> AuthorizationComparisonPlanRecord:
        (
            plan_id, organization_id, target, authorization_id, primary_context_id,
            secondary_context_id, permitted_active_check, allowed_http_methods, resource_scope,
            maximum_resources, maximum_comparisons, enable_discovery, discovery_login_page_marker,
            created_at, expires_at, revoked_at,
        ) = row
        return AuthorizationComparisonPlanRecord(
            comparison_plan_id=str(plan_id),
            organization_id=str(organization_id),
            target=target,
            authorization_id=authorization_id,
            primary_context_id=str(primary_context_id),
            secondary_context_id=str(secondary_context_id),
            permitted_active_check=permitted_active_check,
            allowed_http_methods=tuple(allowed_http_methods),
            resource_scope=tuple(ResourcePairSpec.from_dict(item) for item in resource_scope),
            maximum_resources=maximum_resources,
            maximum_comparisons=maximum_comparisons,
            created_at=created_at.astimezone(timezone.utc),
            expires_at=expires_at.astimezone(timezone.utc),
            revoked_at=revoked_at.astimezone(timezone.utc) if revoked_at else None,
            enable_discovery=enable_discovery,
            discovery_login_page_marker=discovery_login_page_marker,
        )

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
                "A comparison plan requires at least one resource pair, unless enable_discovery is set.",
            )
        if expires_at <= now:
            raise AuthorizationComparisonError(
                "authorization_comparison_expiry_invalid",
                "expires_at must be later than the current time.",
            )
        plan_id = str(uuid4())
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO authorization_comparison_plans (
                    comparison_plan_id, organization_id, target, authorization_id,
                    primary_context_id, secondary_context_id, permitted_active_check,
                    allowed_http_methods, resource_scope, maximum_resources, maximum_comparisons,
                    enable_discovery, discovery_login_page_marker, created_at, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    plan_id, organization_id, target, authorization_id, primary_context_id,
                    secondary_context_id, permitted_active_check, list(allowed_http_methods),
                    json.dumps([spec.to_dict() for spec in resource_scope]),
                    len(resource_scope), len(resource_scope) * 2, enable_discovery,
                    discovery_login_page_marker, now, expires_at,
                ),
            )
        return self.get(plan_id)

    def get(self, comparison_plan_id: str) -> AuthorizationComparisonPlanRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM authorization_comparison_plans WHERE comparison_plan_id = %s",  # noqa: S608
                (comparison_plan_id,),
            ).fetchone()
        if row is None:
            raise AuthorizationComparisonError(
                "authorization_comparison_plan_not_found", "No authorization-comparison plan matches the requested ID."
            )
        return self._record_from_row(row)

    def revoke(self, comparison_plan_id: str, *, now: datetime) -> AuthorizationComparisonPlanRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT revoked_at FROM authorization_comparison_plans WHERE comparison_plan_id = %s",
                (comparison_plan_id,),
            ).fetchone()
            if row is None:
                raise AuthorizationComparisonError(
                    "authorization_comparison_plan_not_found", "No authorization-comparison plan matches the requested ID."
                )
            if row[0] is None:
                connection.execute(
                    "UPDATE authorization_comparison_plans SET revoked_at = %s WHERE comparison_plan_id = %s",
                    (now, comparison_plan_id),
                )
        return self.get(comparison_plan_id)

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
                f"authorization_comparison_{status.value}",
                f"Authorization-comparison plan is {status.value} and cannot be used.",
            )
        return record


__all__ = ["PostgresAuthorizationComparisonPlanRepository"]
