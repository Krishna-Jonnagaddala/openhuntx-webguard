"""PostgreSQL-backed report-metadata repository (Slice 13 requirement
12; live-wired into the production API in Slice 14 requirement 5).
Satisfies the same surface as ``report_store.InMemoryReportRepository``.
Large report bodies (HTML/PDF/JSON) stay out of PostgreSQL -- only the
artifact reference and checksum are stored here; the body itself lives
wherever ``artifact_store.py``'s ``ArtifactStore`` put it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from .postgres_pool import WebGuardPostgresPool
from .report_store import ReportRecord, ReportStoreError

_COLUMNS = (
    "report_id, organization_id, scan_id, format, state, report_ref, "
    "created_at, checksum, completed_at"
)


class PostgresReportRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple) -> ReportRecord:
        report_id, organization_id, scan_id, fmt, state, report_ref, created_at, checksum, completed_at = row
        return ReportRecord(
            report_id=str(report_id),
            organization_id=str(organization_id),
            scan_id=str(scan_id) if scan_id else "",
            format=fmt,
            state=state,
            report_ref=report_ref,
            created_at=created_at.astimezone(timezone.utc),
            checksum=checksum,
            completed_at=completed_at.astimezone(timezone.utc) if completed_at else None,
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
        completed_at: datetime | None = None,
    ) -> ReportRecord:
        effective_id = str(uuid4()) if report_id is None else report_id
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO reports (
                    report_id, organization_id, scan_id, title, prepared_by,
                    report_ref, created_at, format, state, checksum, completed_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    effective_id, organization_id, scan_id, None, None, report_ref,
                    now, format, state, checksum, completed_at,
                ),
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

    def list_reports_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        scan_id: str | None = None,
    ) -> tuple[tuple[ReportRecord, ...], bool]:
        clauses = ["organization_id = %s"]
        parameters: list[object] = [organization_id]
        if scan_id is not None:
            clauses.append("scan_id = %s")
            parameters.append(scan_id)
        if after is not None:
            clauses.append("(created_at < %s OR (created_at = %s AND report_id::text < %s))")
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT {_COLUMNS} FROM reports
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at DESC, report_id DESC
                LIMIT %s
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        has_more = len(rows) > limit
        return tuple(self._record_from_row(row) for row in rows[:limit]), has_more


__all__ = ["PostgresReportRepository"]
