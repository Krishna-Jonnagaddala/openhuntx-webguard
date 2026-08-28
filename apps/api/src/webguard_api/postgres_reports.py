"""PostgreSQL-backed report-metadata repository (Slice 13 requirement
12). Satisfies the same surface as
``report_store.InMemoryReportRepository``. Status:
POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from .postgres_pool import WebGuardPostgresPool
from .report_store import ReportRecord, ReportStoreError

_COLUMNS = "report_id, organization_id, scan_id, format, state, report_ref, created_at, checksum"


class PostgresReportRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple) -> ReportRecord:
        report_id, organization_id, scan_id, fmt, state, report_ref, created_at, checksum = row
        return ReportRecord(
            report_id=str(report_id),
            organization_id=str(organization_id),
            scan_id=str(scan_id) if scan_id else "",
            format=fmt,
            state=state,
            report_ref=report_ref,
            created_at=created_at.astimezone(timezone.utc),
            checksum=checksum,
        )

    def create_report(
        self,
        *,
        organization_id: str,
        scan_id: str,
        report_ref: str,
        now: datetime,
        format: str = "json",
        state: str = "generated",
        checksum: str | None = None,
        report_id: str | None = None,
    ) -> ReportRecord:
        effective_id = str(uuid4()) if report_id is None else report_id
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO reports (
                    report_id, organization_id, scan_id, title, prepared_by,
                    report_ref, created_at, format, state, checksum
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (effective_id, organization_id, scan_id, None, None, report_ref, now, format, state, checksum),
            )
        return self.get_report_scoped(effective_id, organization_id=organization_id)

    def get_report_scoped(self, report_id: str, *, organization_id: str) -> ReportRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM reports WHERE report_id = %s AND organization_id = %s",  # noqa: S608
                (report_id, organization_id),
            ).fetchone()
        if row is None:
            raise ReportStoreError("report_not_found", "Report was not found.")
        return self._record_from_row(row)

    def list_reports_scoped(self, organization_id: str) -> tuple[ReportRecord, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM reports WHERE organization_id = %s ORDER BY created_at DESC",  # noqa: S608
                (organization_id,),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)


__all__ = ["PostgresReportRepository"]
