"""PostgreSQL-backed Coverage Truth Map repository (product vision
pillar 5). See coverage_store.py's module docstring for v1 scope and
what is and is not populated.

P1-2 Phase H follow-on: coverage_records has no worker_tenant_data or
scheduler_tenant_data ambiguity to resolve, unlike the pre-existing
Phase H arc's own files, since this table is new and was designed
tenant-scoped from the start rather than retrofitted. record_coverage
runs under worker_tenant_data (its only caller is executor.py, the
worker, mirroring record_finding's own role exactly). list_coverage_for_asset
runs under api_tenant_data: no HTTP endpoint calls it yet (no API/
report surface exists this slice), but it is a real, test-exercised
method today, the same "converted anyway for consistency" precedent
postgres_scans.py's list_scans_scoped already established.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .coverage_store import CoverageRecord, CoverageStatus
from .postgres_pool import API_TENANT_DATA_ROLE, WORKER_TENANT_DATA_ROLE, WebGuardPostgresPool

_COLUMNS = (
    "organization_id, asset, path, http_method, identity_label, check_id, status, "
    "scanner_version, check_version, last_scan_id, last_finding_id, "
    "first_observed_at, last_observed_at"
)


def _record_from_row(row: tuple) -> CoverageRecord:
    (
        organization_id, asset, path, http_method, identity_label, check_id, status,
        scanner_version, check_version, last_scan_id, last_finding_id,
        first_observed_at, last_observed_at,
    ) = row
    return CoverageRecord(
        organization_id=str(organization_id),
        asset=asset,
        path=path,
        http_method=http_method,
        identity_label=identity_label,
        check_id=check_id,
        status=CoverageStatus(status),
        scanner_version=scanner_version,
        check_version=check_version,
        last_scan_id=str(last_scan_id) if last_scan_id else None,
        last_finding_id=str(last_finding_id) if last_finding_id else None,
        first_observed_at=first_observed_at.astimezone(timezone.utc),
        last_observed_at=last_observed_at.astimezone(timezone.utc),
    )


class PostgresCoverageRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    def record_coverage(
        self,
        *,
        organization_id: str,
        asset: str,
        path: str,
        http_method: str,
        identity_label: str,
        check_id: str,
        status: CoverageStatus,
        scanner_version: str,
        now: datetime,
        check_version: str | None = None,
        scan_id: str | None = None,
        finding_id: str | None = None,
    ) -> CoverageRecord:
        with self._pool.tenant_connection(organization_id, role=WORKER_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"""
                INSERT INTO coverage_records (
                    organization_id, asset, path, http_method, identity_label, check_id,
                    status, scanner_version, check_version, last_scan_id, last_finding_id,
                    first_observed_at, last_observed_at
                ) VALUES (
                    %(organization_id)s, %(asset)s, %(path)s, %(http_method)s,
                    %(identity_label)s, %(check_id)s, %(status)s, %(scanner_version)s,
                    %(check_version)s, %(scan_id)s, %(finding_id)s, %(now)s, %(now)s
                )
                ON CONFLICT (organization_id, asset, path, http_method, identity_label, check_id)
                DO UPDATE SET
                    status = EXCLUDED.status,
                    scanner_version = EXCLUDED.scanner_version,
                    check_version = EXCLUDED.check_version,
                    last_scan_id = EXCLUDED.last_scan_id,
                    last_finding_id = EXCLUDED.last_finding_id,
                    last_observed_at = EXCLUDED.last_observed_at
                RETURNING {_COLUMNS}
                """,  # noqa: S608
                {
                    "organization_id": organization_id,
                    "asset": asset,
                    "path": path,
                    "http_method": http_method,
                    "identity_label": identity_label,
                    "check_id": check_id,
                    "status": status.value,
                    "scanner_version": scanner_version,
                    "check_version": check_version,
                    "scan_id": scan_id,
                    "finding_id": finding_id,
                    "now": now,
                },
            ).fetchone()
        return _record_from_row(row)

    def list_coverage_for_asset(
        self, organization_id: str, asset: str
    ) -> tuple[CoverageRecord, ...]:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM coverage_records "  # noqa: S608
                "WHERE organization_id = %s AND asset = %s "
                "ORDER BY path, http_method, identity_label, check_id",
                (organization_id, asset),
            ).fetchall()
        return tuple(_record_from_row(row) for row in rows)


__all__ = ["PostgresCoverageRepository"]
