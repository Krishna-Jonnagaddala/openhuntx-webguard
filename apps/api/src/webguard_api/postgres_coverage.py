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

    def list_coverage_for_asset_page(
        self,
        organization_id: str,
        asset: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
    ) -> tuple[tuple[CoverageRecord, ...], bool]:
        """Same (last_observed_at DESC, path, http_method,
        identity_label, check_id) ordering and Unit-Separator-joined
        composite cursor key as InMemoryCoverageRepository's own
        list_coverage_for_asset_page (coverage_store.py's own
        coverage_cursor_key), so the service layer's pagination logic
        is identical for both backends."""

        clauses = ["organization_id = %(organization_id)s", "asset = %(asset)s"]
        params: dict[str, object] = {"organization_id": organization_id, "asset": asset, "limit": limit + 1}
        if after is not None:
            clauses.append(
                "(last_observed_at, path || chr(31) || http_method || chr(31) || "
                "identity_label || chr(31) || check_id) < (%(after_at)s, %(after_key)s)"
            )
            params["after_at"] = after[0]
            params["after_key"] = after[1]
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM coverage_records "  # noqa: S608
                f"WHERE {' AND '.join(clauses)} "
                "ORDER BY last_observed_at DESC, path DESC, http_method DESC, identity_label DESC, check_id DESC "
                "LIMIT %(limit)s",
                params,
            ).fetchall()
        records = tuple(_record_from_row(row) for row in rows)
        has_more = len(records) > limit
        return records[:limit], has_more

    def count_coverage_by_status(self, organization_id: str, asset: str) -> dict[str, int]:
        """Page-independent totals; see InMemoryCoverageRepository's
        own docstring for why this exists alongside the paginated
        list."""

        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                "SELECT status, count(*) FROM coverage_records "
                "WHERE organization_id = %s AND asset = %s GROUP BY status",
                (organization_id, asset),
            ).fetchall()
        return {status: count for status, count in rows}


__all__ = ["PostgresCoverageRepository"]
