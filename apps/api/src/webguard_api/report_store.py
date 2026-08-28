"""Report metadata persistence (Slice 13 requirement 12).

Status: POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED. A new
entity -- no prior SQLite table exists for it, since report artifacts
have only ever been filesystem files referenced by ``report_ref`` (see
``ScanJobRecord.report_ref``). This repository stores only metadata
*about* a report (format, state, artifact reference, checksum) --
never the report body itself; large HTML/PDF/JSON report bodies stay
out of PostgreSQL this slice, per the brief's explicit instruction
("object storage comes later").
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4


class ReportStoreError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class ReportRecord:
    report_id: str
    organization_id: str
    scan_id: str
    format: str
    state: str
    report_ref: str
    created_at: datetime
    checksum: str | None = None
    completed_at: datetime | None = None


class InMemoryReportRepository:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reports: dict[str, ReportRecord] = {}

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
        record = ReportRecord(
            report_id=str(uuid4()) if report_id is None else report_id,
            organization_id=organization_id,
            scan_id=scan_id,
            format=format,
            state=state,
            report_ref=report_ref,
            created_at=now,
            checksum=checksum,
            completed_at=completed_at,
        )
        with self._lock:
            self._reports[record.report_id] = record
        return record

    def get_report_scoped(self, report_id: str, *, organization_id: str) -> ReportRecord:
        with self._lock:
            record = self._reports.get(report_id)
        if record is None or record.organization_id != organization_id:
            raise ReportStoreError("report_not_found", "Report was not found.")
        return record

    def list_reports_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        scan_id: str | None = None,
    ) -> tuple[tuple[ReportRecord, ...], bool]:
        with self._lock:
            values = [r for r in self._reports.values() if r.organization_id == organization_id]
        if scan_id is not None:
            values = [r for r in values if r.scan_id == scan_id]
        values.sort(key=lambda r: (r.created_at, r.report_id), reverse=True)
        if after is not None:
            values = [
                r for r in values if (r.created_at.isoformat(), r.report_id) < (after[0], after[1])
            ]
        has_more = len(values) > limit
        return tuple(values[:limit]), has_more


__all__ = ["InMemoryReportRepository", "ReportRecord", "ReportStoreError"]
