"""PostgreSQL-backed module entitlement repository (platform expansion,
docs/PLATFORM_SCOPE.md and docs/adr/0033-platform-expansion-module-boundaries.md).
Satisfies the same method surface, and the same ``ModuleEntitlement``/
``ModuleEntitlementError`` types, as
``module_entitlements.InMemoryModuleEntitlementRepository``, see that
module's docstring for the production-boundary rationale and why a
missing row is a defect to fail closed against, not a state
application code relies on.

P1-2 Phase H follow-on: this table has no worker_tenant_data or
scheduler_tenant_data ambiguity to resolve, since it was designed
tenant-scoped from the start rather than retrofitted. Every method
here is genuinely API-only (organization/module entitlement is an
administrative, API-serve-process concern; no worker, scheduler, or
callback path ever reads or writes it), so every method runs under
api_tenant_data via ``tenant_connection``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from webguard_contracts import ModuleEntitlement, ModuleEntitlementStatus, PlatformModule

from .module_entitlements import ModuleEntitlementError
from .postgres_pool import API_TENANT_DATA_ROLE, WebGuardPostgresPool

_COLUMNS = (
    "organization_id, module, status, updated_at, enabled_at, enabled_by, "
    "disabled_at, disabled_by"
)

_DEFAULT_STATUS_BY_MODULE = {
    PlatformModule.WEBGUARD: ModuleEntitlementStatus.ENABLED,
    PlatformModule.SOC: ModuleEntitlementStatus.DISABLED,
    PlatformModule.COMPLIANCE: ModuleEntitlementStatus.DISABLED,
}


def _record_from_row(row: tuple) -> ModuleEntitlement:
    (
        organization_id, module, status, updated_at, enabled_at, enabled_by,
        disabled_at, disabled_by,
    ) = row
    return ModuleEntitlement(
        organization_id=str(organization_id),
        module=PlatformModule(module),
        status=ModuleEntitlementStatus(status),
        updated_at=updated_at.astimezone(timezone.utc),
        enabled_at=enabled_at.astimezone(timezone.utc) if enabled_at else None,
        enabled_by=str(enabled_by) if enabled_by else None,
        disabled_at=disabled_at.astimezone(timezone.utc) if disabled_at else None,
        disabled_by=str(disabled_by) if disabled_by else None,
    )


class PostgresModuleEntitlementRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    def grant_default_entitlements(
        self, organization_id: str, *, now: datetime
    ) -> tuple[ModuleEntitlement, ...]:
        moment = now.astimezone(timezone.utc)
        records = []
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            with connection.transaction():
                for module, status in _DEFAULT_STATUS_BY_MODULE.items():
                    row = connection.execute(
                        f"""
                        INSERT INTO module_entitlements
                            (organization_id, module, status, updated_at, enabled_at)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING {_COLUMNS}
                        """,  # noqa: S608
                        (
                            organization_id,
                            module.value,
                            status.value,
                            moment,
                            moment if status is ModuleEntitlementStatus.ENABLED else None,
                        ),
                    ).fetchone()
                    records.append(_record_from_row(row))
        return tuple(records)

    def set_entitlement(
        self,
        organization_id: str,
        module: PlatformModule,
        *,
        status: ModuleEntitlementStatus,
        now: datetime,
        changed_by: str | None = None,
    ) -> ModuleEntitlement:
        moment = now.astimezone(timezone.utc)
        if status in (ModuleEntitlementStatus.ENABLED, ModuleEntitlementStatus.TRIAL):
            update_clause = "status = %s, updated_at = %s, enabled_at = %s, enabled_by = %s"
            parameters = (status.value, moment, moment, changed_by)
        else:
            update_clause = "status = %s, updated_at = %s, disabled_at = %s, disabled_by = %s"
            parameters = (status.value, moment, moment, changed_by)
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"""
                UPDATE module_entitlements SET {update_clause}
                WHERE organization_id = %s AND module = %s
                RETURNING {_COLUMNS}
                """,  # noqa: S608
                (*parameters, organization_id, module.value),
            ).fetchone()
        if row is None:
            raise ModuleEntitlementError(
                "module_entitlement_not_found",
                "No module entitlement record exists for this organization and module.",
            )
        return _record_from_row(row)

    def get_entitlement(self, organization_id: str, module: PlatformModule) -> ModuleEntitlement:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM module_entitlements "  # noqa: S608
                "WHERE organization_id = %s AND module = %s",
                (organization_id, module.value),
            ).fetchone()
        if row is None:
            raise ModuleEntitlementError(
                "module_entitlement_not_found",
                "No module entitlement record exists for this organization and module.",
            )
        return _record_from_row(row)

    def list_entitlements(self, organization_id: str) -> tuple[ModuleEntitlement, ...]:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM module_entitlements "  # noqa: S608
                "WHERE organization_id = %s ORDER BY module",
                (organization_id,),
            ).fetchall()
        return tuple(_record_from_row(row) for row in rows)

    def has_module_access(self, organization_id: str, module: PlatformModule) -> bool:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT status FROM module_entitlements WHERE organization_id = %s AND module = %s",
                (organization_id, module.value),
            ).fetchone()
        return row is not None and row[0] in (
            ModuleEntitlementStatus.ENABLED.value,
            ModuleEntitlementStatus.TRIAL.value,
        )


__all__ = ["PostgresModuleEntitlementRepository"]
