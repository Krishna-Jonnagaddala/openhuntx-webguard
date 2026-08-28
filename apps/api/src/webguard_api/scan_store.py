"""Scan-record persistence (Slice 13 requirement 2): the durable
record of one scan *run* -- distinct from the job (the queue/lease
entity in ``store.py``/``postgres_jobs.py``) that triggered it. A job
transitions QUEUED -> RUNNING -> terminal; a scan record is created the
moment execution actually begins and is completed once the scanner
finishes, carrying the permit reference, requested checks, and
summary/count metadata a Scans page needs.

``InMemoryScanRepository`` is the local/unit/lab backend (a new entity
with no prior SQLite table to preserve, same production-boundary
pattern as ``targets.py``); ``PostgresScanRepository``
(``postgres_scans.py``) is production. Both satisfy ``ScanRepository``
in ``repository_contracts.py``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from uuid import uuid4


class ScanStoreError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class ScanRecord:
    scan_id: str
    organization_id: str
    job_id: str
    target: str
    authorization_id: str
    mode: str
    status: str
    scanner_version: str
    created_at: datetime
    permit_id: str | None = None
    permit_fingerprint: str | None = None
    requested_checks: tuple[str, ...] = ()
    started_at: datetime | None = None
    completed_at: datetime | None = None
    report_ref: str | None = None
    cancellation_requested: bool = False
    cancelled_at: datetime | None = None
    finding_count: int = 0


class InMemoryScanRepository:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scans: dict[str, ScanRecord] = {}

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
        record = ScanRecord(
            scan_id=str(uuid4()) if scan_id is None else scan_id,
            organization_id=organization_id,
            job_id=job_id,
            target=target,
            authorization_id=authorization_id,
            mode=mode,
            status="running",
            scanner_version=scanner_version,
            created_at=now,
            permit_id=permit_id,
            permit_fingerprint=permit_fingerprint,
            requested_checks=tuple(requested_checks),
            started_at=now,
        )
        with self._lock:
            self._scans[record.scan_id] = record
        return record

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
        with self._lock:
            record = self._scans.get(scan_id)
            if record is None or record.organization_id != organization_id:
                raise ScanStoreError("scan_not_found", "Scan record was not found.")
            updated = replace(
                record,
                status=status,
                completed_at=now,
                report_ref=report_ref,
                finding_count=finding_count,
            )
            self._scans[scan_id] = updated
        return updated

    def get_scan_scoped(self, scan_id: str, *, organization_id: str) -> ScanRecord:
        with self._lock:
            record = self._scans.get(scan_id)
        if record is None or record.organization_id != organization_id:
            raise ScanStoreError("scan_not_found", "Scan record was not found.")
        return record

    def list_scans_scoped(self, organization_id: str) -> tuple[ScanRecord, ...]:
        with self._lock:
            values = [r for r in self._scans.values() if r.organization_id == organization_id]
        return tuple(sorted(values, key=lambda r: r.created_at, reverse=True))

    def list_scans_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        target: str | None = None,
        status: str | None = None,
    ) -> tuple[tuple[ScanRecord, ...], bool]:
        with self._lock:
            values = [r for r in self._scans.values() if r.organization_id == organization_id]
        if target is not None:
            values = [r for r in values if r.target == target]
        if status is not None:
            values = [r for r in values if r.status == status]
        values.sort(key=lambda r: (r.created_at, r.scan_id), reverse=True)
        if after is not None:
            values = [
                r for r in values if (r.created_at.isoformat(), r.scan_id) < (after[0], after[1])
            ]
        has_more = len(values) > limit
        return tuple(values[:limit]), has_more


__all__ = ["InMemoryScanRepository", "ScanRecord", "ScanStoreError"]
