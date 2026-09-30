"""PostgreSQL-backed scan-record repository (Slice 13 requirement 2).
Satisfies the same ``ScanRepository`` surface, and the same
``ScanRecord``/``ScanStoreError`` types, as
``scan_store.InMemoryScanRepository``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from .postgres_pool import API_TENANT_DATA_ROLE, WORKER_TENANT_DATA_ROLE, WebGuardPostgresPool
from .scan_store import ScanRecord, ScanStoreError

_COLUMNS = (
    "scan_id, organization_id, job_id, target, authorization_id, mode, status, "
    "scanner_version, created_at, permit_id, permit_fingerprint, requested_checks, "
    "started_at, completed_at, report_ref, cancellation_requested, cancelled_at, finding_count"
)


class PostgresScanRepository:
    """P1-2 Phase H: api_tenant_data has only SELECT on scan_records;
    worker_tenant_data has SELECT, INSERT, UPDATE. create_scan and
    complete_scan (both called only from executor.py, the worker) run
    under worker_tenant_data. get_scan_scoped, list_scans_scoped, and
    list_scans_scoped_page (called from service.py, or in
    get_scan_scoped's case also internally by create_scan's own
    post-write re-read) run under api_tenant_data, a SELECT already
    granted to both roles, so it works identically regardless of which
    role inserted the row it reads back."""

    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple) -> ScanRecord:
        (
            scan_id, organization_id, job_id, target, authorization_id, mode, status,
            scanner_version, created_at, permit_id, permit_fingerprint, requested_checks,
            started_at, completed_at, report_ref, cancellation_requested, cancelled_at,
            finding_count,
        ) = row
        return ScanRecord(
            scan_id=str(scan_id),
            organization_id=str(organization_id),
            job_id=str(job_id),
            target=target,
            authorization_id=authorization_id,
            mode=mode,
            status=status,
            scanner_version=scanner_version,
            created_at=created_at.astimezone(timezone.utc),
            permit_id=str(permit_id) if permit_id else None,
            permit_fingerprint=permit_fingerprint,
            requested_checks=tuple(requested_checks or ()),
            started_at=started_at.astimezone(timezone.utc) if started_at else None,
            completed_at=completed_at.astimezone(timezone.utc) if completed_at else None,
            report_ref=report_ref,
            cancellation_requested=bool(cancellation_requested),
            cancelled_at=cancelled_at.astimezone(timezone.utc) if cancelled_at else None,
            finding_count=finding_count,
        )

    def create_scan(
        self,
        *,
        organization_id: str,
        job_id: str,
        target: str,
        authorization_id: str,
        mode: str,
        scanner_version: str,
        now: datetime,
        permit_id: str | None = None,
        permit_fingerprint: str | None = None,
        requested_checks: tuple[str, ...] = (),
        scan_id: str | None = None,
    ) -> ScanRecord:
        effective_id = str(uuid4()) if scan_id is None else scan_id
        with self._pool.tenant_connection(organization_id, role=WORKER_TENANT_DATA_ROLE) as connection:
            connection.execute(
                """
                INSERT INTO scan_records (
                    scan_id, organization_id, job_id, target, authorization_id, mode,
                    status, scanner_version, created_at, permit_id, permit_fingerprint,
                    requested_checks, started_at
                ) VALUES (%s, %s, %s, %s, %s, %s, 'running', %s, %s, %s, %s, %s, %s)
                """,
                (
                    effective_id, organization_id, job_id, target, authorization_id, mode,
                    scanner_version, now, permit_id, permit_fingerprint,
                    json.dumps(list(requested_checks)), now,
                ),
            )
        return self.get_scan_scoped(effective_id, organization_id=organization_id)

    def complete_scan(
        self,
        scan_id: str,
        *,
        organization_id: str,
        status: str,
        report_ref: str | None,
        finding_count: int,
        now: datetime,
    ) -> ScanRecord:
        with self._pool.tenant_connection(organization_id, role=WORKER_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                """
                UPDATE scan_records
                SET status = %s, completed_at = %s, report_ref = %s, finding_count = %s
                WHERE scan_id = %s AND organization_id = %s
                RETURNING """ + _COLUMNS,  # noqa: S608
                (status, now, report_ref, finding_count, scan_id, organization_id),
            ).fetchone()
        if row is None:
            raise ScanStoreError("scan_not_found", "Scan record was not found.")
        return self._record_from_row(row)

    def get_scan_scoped(self, scan_id: str, *, organization_id: str) -> ScanRecord:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM scan_records WHERE scan_id = %s AND organization_id = %s",  # noqa: S608
                (scan_id, organization_id),
            ).fetchone()
        if row is None:
            raise ScanStoreError("scan_not_found", "Scan record was not found.")
        return self._record_from_row(row)

    def list_scans_scoped(self, organization_id: str) -> tuple[ScanRecord, ...]:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM scan_records WHERE organization_id = %s ORDER BY created_at DESC",  # noqa: S608
                (organization_id,),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    def list_scans_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        target: str | None = None,
        status: str | None = None,
    ) -> tuple[tuple[ScanRecord, ...], bool]:
        clauses = ["organization_id = %s"]
        parameters: list[object] = [organization_id]
        if target is not None:
            clauses.append("target = %s")
            parameters.append(target)
        if status is not None:
            clauses.append("status = %s")
            parameters.append(status)
        if after is not None:
            clauses.append("(created_at < %s OR (created_at = %s AND scan_id::text < %s))")
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"""
                SELECT {_COLUMNS} FROM scan_records
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at DESC, scan_id DESC
                LIMIT %s
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        has_more = len(rows) > limit
        return tuple(self._record_from_row(row) for row in rows[:limit]), has_more


__all__ = ["PostgresScanRepository"]
