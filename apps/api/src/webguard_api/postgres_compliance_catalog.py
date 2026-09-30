"""PostgreSQL-backed compliance framework/master-control catalog
(platform expansion, docs/PLATFORM_SCOPE.md,
docs/adr/0034-compliance-catalog-is-global-reference-data.md).

Unlike every other repository in this codebase, this one is not
tenant-scoped: frameworks and their master controls are global
reference data, identical for every organization, so there is no
organization_id to set tenant context with. Reads run under
api_tenant_data via role_scoped_connection (role-only, no GUC), the
same "no tenant to scope by" treatment postgres_identity.py's
get_principal already uses. Writes (adding a framework or control to
the catalog) are an OpenHuntX-operator concern, never a customer-
facing one, so they run on the unrestricted connection, mirroring
postgres_identity.py's assign_authorization/revoke_token precedent for
CLI/operator-only methods with no live API-serve-process caller.
"""

from __future__ import annotations

from datetime import datetime, timezone

from webguard_contracts import Framework, FrameworkStatus, MasterControl

from .postgres_pool import API_TENANT_DATA_ROLE, WebGuardPostgresPool

_FRAMEWORK_COLUMNS = "framework_id, name, version, status, source_reference, created_at, updated_at"
_CONTROL_COLUMNS = (
    "control_id, framework_id, control_number, title, description, category, "
    "created_at, updated_at"
)


class ComplianceCatalogError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _framework_from_row(row: tuple) -> Framework:
    framework_id, name, version, status, source_reference, created_at, updated_at = row
    return Framework(
        framework_id=framework_id,
        name=name,
        version=version,
        status=FrameworkStatus(status),
        source_reference=source_reference,
        created_at=created_at.astimezone(timezone.utc),
        updated_at=updated_at.astimezone(timezone.utc),
    )


def _control_from_row(row: tuple) -> MasterControl:
    (
        control_id, framework_id, control_number, title, description, category,
        created_at, updated_at,
    ) = row
    return MasterControl(
        control_id=control_id,
        framework_id=framework_id,
        control_number=control_number,
        title=title,
        description=description,
        category=category,
        created_at=created_at.astimezone(timezone.utc),
        updated_at=updated_at.astimezone(timezone.utc),
    )


class PostgresComplianceCatalogRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    def list_frameworks(self) -> tuple[Framework, ...]:
        with self._pool.role_scoped_connection(API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_FRAMEWORK_COLUMNS} FROM frameworks ORDER BY framework_id"  # noqa: S608
            ).fetchall()
        return tuple(_framework_from_row(row) for row in rows)

    def get_framework(self, framework_id: str) -> Framework:
        with self._pool.role_scoped_connection(API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"SELECT {_FRAMEWORK_COLUMNS} FROM frameworks WHERE framework_id = %s",  # noqa: S608
                (framework_id,),
            ).fetchone()
        if row is None:
            raise ComplianceCatalogError("framework_not_found", "Framework was not found.")
        return _framework_from_row(row)

    def list_master_controls(self, framework_id: str) -> tuple[MasterControl, ...]:
        with self._pool.role_scoped_connection(API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_CONTROL_COLUMNS} FROM master_controls "  # noqa: S608
                "WHERE framework_id = %s ORDER BY control_number",
                (framework_id,),
            ).fetchall()
        return tuple(_control_from_row(row) for row in rows)

    def create_framework(
        self,
        framework_id: str,
        *,
        name: str,
        version: str,
        status: FrameworkStatus,
        source_reference: str,
        now: datetime,
    ) -> Framework:
        """Operator/CLI-only: no organization ever creates a framework
        definition through the API serve process. Unrestricted
        connection, matching assign_authorization/revoke_token."""

        moment = now.astimezone(timezone.utc)
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO frameworks (framework_id, name, version, status, source_reference, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (framework_id, name, version, status.value, source_reference, moment, moment),
            )
        return self.get_framework(framework_id)

    def create_master_control(
        self,
        control_id: str,
        framework_id: str,
        *,
        control_number: str,
        title: str,
        now: datetime,
        description: str | None = None,
        category: str | None = None,
    ) -> MasterControl:
        """Operator/CLI-only, same rationale as create_framework."""

        moment = now.astimezone(timezone.utc)
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO master_controls
                    (control_id, framework_id, control_number, title, description, category,
                     created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (control_id, framework_id, control_number, title, description, category, moment, moment),
            )
        with self._pool.role_scoped_connection(API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"SELECT {_CONTROL_COLUMNS} FROM master_controls WHERE control_id = %s",  # noqa: S608
                (control_id,),
            ).fetchone()
        return _control_from_row(row)


__all__ = ["ComplianceCatalogError", "PostgresComplianceCatalogRepository"]
