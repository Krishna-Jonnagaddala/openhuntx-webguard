"""PostgreSQL-backed scoped control implementation repository
(platform expansion, docs/PLATFORM_SCOPE.md, handoff section 10.1-10.2).
See webguard_contracts.compliance_scope's module docstring for what
this table is (one organization's own applicability decision against
one master control) and is not (an assertion, a test, or evidence).

Postgres-only for this slice, unlike module_entitlements which ships
both an in-memory and a Postgres backend: every row here references a
real master_controls row via its control_id foreign key, and an
in-memory backend faithful to that relationship would need to either
duplicate the framework catalog in memory or accept silent drift from
it. Deferred rather than built on a shaky foundation, the same
"Postgres-only, no in-memory backend" call the framework catalog
itself already made (test_compliance_catalog_repository_contract.py's
own module docstring) and for a closely related reason: this table
depends on that same catalog being real, not faked.

framework_id is never stored on this table (see the migration's own
comment) and is always derived here by joining to master_controls, so
every read is guaranteed consistent with the catalog rather than
trusting a second, independently written copy of the same fact.
"""

from __future__ import annotations

from datetime import datetime, timezone

from webguard_contracts import ApplicabilityStatus, ScopedControlImplementation

from .postgres_pool import API_TENANT_DATA_ROLE, WebGuardPostgresPool

_COLUMNS = (
    "sci.organization_id, sci.control_id, mc.framework_id, sci.applicability_status, "
    "sci.rationale, sci.decided_by, sci.decided_at, sci.created_at, sci.updated_at"
)

_JOIN = "FROM scoped_control_implementations sci JOIN master_controls mc ON mc.control_id = sci.control_id"


class ScopedControlImplementationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _record_from_row(row: tuple) -> ScopedControlImplementation:
    (
        organization_id, control_id, framework_id, applicability_status,
        rationale, decided_by, decided_at, created_at, updated_at,
    ) = row
    return ScopedControlImplementation(
        organization_id=str(organization_id),
        framework_id=framework_id,
        control_id=control_id,
        applicability_status=ApplicabilityStatus(applicability_status),
        created_at=created_at.astimezone(timezone.utc),
        updated_at=updated_at.astimezone(timezone.utc),
        rationale=rationale,
        decided_by=str(decided_by) if decided_by else None,
        decided_at=decided_at.astimezone(timezone.utc) if decided_at is not None else None,
    )


class PostgresComplianceScopeRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    def set_applicability(
        self,
        organization_id: str,
        control_id: str,
        *,
        applicability_status: ApplicabilityStatus,
        now: datetime,
        rationale: str | None = None,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> ScopedControlImplementation:
        """Creates or revises this organization's applicability
        decision for one control. A control_id with no matching
        master_controls row fails on the table's own foreign key, the
        same unwrapped-IntegrityError shape create_master_control's own
        framework_id reference already accepts in this codebase."""

        moment = now.astimezone(timezone.utc)
        decided_moment = decided_at.astimezone(timezone.utc) if decided_at is not None else None
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            connection.execute(
                """
                INSERT INTO scoped_control_implementations
                    (organization_id, control_id, applicability_status, rationale,
                     decided_by, decided_at, created_at, updated_at)
                VALUES (%(organization_id)s, %(control_id)s, %(status)s, %(rationale)s,
                        %(decided_by)s, %(decided_at)s, %(now)s, %(now)s)
                ON CONFLICT (organization_id, control_id) DO UPDATE SET
                    applicability_status = EXCLUDED.applicability_status,
                    rationale = EXCLUDED.rationale,
                    decided_by = EXCLUDED.decided_by,
                    decided_at = EXCLUDED.decided_at,
                    updated_at = EXCLUDED.updated_at
                """,
                {
                    "organization_id": organization_id,
                    "control_id": control_id,
                    "status": applicability_status.value,
                    "rationale": rationale,
                    "decided_by": decided_by,
                    "decided_at": decided_moment,
                    "now": moment,
                },
            )
        return self.get_applicability(organization_id, control_id)

    def get_applicability(self, organization_id: str, control_id: str) -> ScopedControlImplementation:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} {_JOIN} "  # noqa: S608
                "WHERE sci.organization_id = %s AND sci.control_id = %s",
                (organization_id, control_id),
            ).fetchone()
        if row is None:
            raise ScopedControlImplementationError(
                "scoped_control_implementation_not_found",
                "No applicability decision has been recorded for this organization and control.",
            )
        return _record_from_row(row)

    def list_applicability_for_framework(
        self, organization_id: str, framework_id: str
    ) -> tuple[ScopedControlImplementation, ...]:
        """Returns only controls this organization has actually
        recorded a decision for, never a synthesized default for every
        control the framework defines. A missing row means this
        control has never been brought into this organization's scope
        at all, a fact distinct from an explicit 'unresolved' decision;
        collapsing the two would misrepresent this organization's real
        review coverage, exactly what handoff section 10.2's
        denominator rules exist to prevent."""

        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} {_JOIN} "  # noqa: S608
                "WHERE sci.organization_id = %s AND mc.framework_id = %s "
                "ORDER BY mc.control_number",
                (organization_id, framework_id),
            ).fetchall()
        return tuple(_record_from_row(row) for row in rows)


__all__ = ["PostgresComplianceScopeRepository", "ScopedControlImplementationError"]
