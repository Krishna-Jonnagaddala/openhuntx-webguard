"""PostgreSQL-backed scan-record repository (Slice 13 requirement 2).
Satisfies the same ``ScanRepository`` surface, and the same
``ScanRecord``/``ScanStoreError`` types, as
``scan_store.InMemoryScanRepository``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from .postgres_pool import WebGuardPostgresPool
from .scan_store import ScanRecord, ScanStoreError

_COLUMNS = (
    "scan_id, organization_id, job_id, target, authorization_id, mode, status, "
    "scanner_version, created_at, permit_id, permit_fingerprint, requested_checks, "
    "started_at, completed_at, report_ref, cancellation_requested, cancelled_at, finding_count"
)


class PostgresScanRepository:
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
        with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM scan_records WHERE scan_id = %s AND organization_id = %s",  # noqa: S608
                (scan_id, organization_id),
            ).fetchone()
        if row is None:
            raise ScanStoreError("scan_not_found", "Scan record was not found.")
        return self._record_from_row(row)

    def list_scans_scoped(self, organization_id: str) -> tuple[ScanRecord, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM scan_records WHERE organization_id = %s ORDER BY created_at DESC",  # noqa: S608
                (organization_id,),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)


__all__ = ["PostgresScanRepository"]
