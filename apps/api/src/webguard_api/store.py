"""SQLite-backed persistent scan-job queue."""

from __future__ import annotations

import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from webguard_contracts import (
    ScanJobMode,
    ScanJobRecord,
    ScanJobRequest,
    ScanJobState,
    ScanStatus,
)


DATABASE_SCHEMA_VERSION = 1


class JobStoreError(ValueError):
    """Controlled persistent job-store failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


class ScanJobStore:
    """A small transactional queue using one SQLite database file."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()
        self._prepare_path()
        self._initialize()

    def _prepare_path(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.path.parent, 0o700)
        except OSError as exc:
            raise JobStoreError(
                "job_store_directory_create_failed",
                f"Unable to create job-store directory {self.path.parent}.",
            ) from exc
        try:
            exists = os.path.lexists(self.path)
        except OSError as exc:
            raise JobStoreError(
                "job_store_path_inspection_failed",
                f"Unable to inspect job-store path {self.path}.",
            ) from exc
        if exists:
            try:
                metadata = self.path.lstat()
            except OSError as exc:
                raise JobStoreError(
                    "job_store_path_inspection_failed",
                    f"Unable to inspect job-store path {self.path}.",
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise JobStoreError(
                    "job_store_symlink_not_allowed",
                    "Job-store database cannot be a symbolic link.",
                )
            if not stat.S_ISREG(metadata.st_mode):
                raise JobStoreError(
                    "job_store_not_regular_file",
                    "Job-store path must be a regular file.",
                )

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=5.0,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise JobStoreError(
                "job_store_open_failed",
                "Unable to open the scan-job database.",
            ) from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS service_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_fingerprint TEXT NOT NULL,
                    target TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    authorization_sha256 TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    state TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    cancellation_requested INTEGER NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    scan_id TEXT,
                    result_status TEXT,
                    report_ref TEXT,
                    audit_ref TEXT,
                    error_code TEXT,
                    error_message TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_scan_jobs_queue
                    ON scan_jobs(state, submitted_at, job_id);
                INSERT OR IGNORE INTO service_metadata(key, value)
                    VALUES ('schema_version', '1');
                COMMIT;
                """
            )
            row = connection.execute(
                "SELECT value FROM service_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or int(row["value"]) != DATABASE_SCHEMA_VERSION:
                raise JobStoreError(
                    "job_store_schema_unsupported",
                    "The job-store schema version is unsupported.",
                )
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_initialize_failed",
                "Unable to initialize the scan-job database.",
            ) from exc
        finally:
            connection.close()
        try:
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise JobStoreError(
                "job_store_permissions_failed",
                "Unable to apply owner-only database permissions.",
            ) from exc

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> ScanJobRecord:
        request = ScanJobRequest(
            idempotency_key=row["idempotency_key"],
            target=row["target"],
            authorization_id=row["authorization_id"],
            authorization_sha256=row["authorization_sha256"],
            mode=ScanJobMode(row["mode"]),
            submitted_at=_parse_timestamp(row["submitted_at"]),
        )
        assert request.submitted_at is not None
        result_status = (
            None
            if row["result_status"] is None
            else ScanStatus(row["result_status"])
        )
        updated_at = _parse_timestamp(row["updated_at"])
        assert updated_at is not None
        return ScanJobRecord(
            job_id=row["job_id"],
            request=request,
            state=ScanJobState(row["state"]),
            updated_at=updated_at,
            revision=row["revision"],
            cancellation_requested=bool(row["cancellation_requested"]),
            started_at=_parse_timestamp(row["started_at"]),
            completed_at=_parse_timestamp(row["completed_at"]),
            scan_id=row["scan_id"],
            result_status=result_status,
            report_ref=row["report_ref"],
            audit_ref=row["audit_ref"],
            error_code=row["error_code"],
            error_message=row["error_message"],
        )

    def submit(
        self,
        request: ScanJobRequest,
        *,
        job_id: str | None = None,
    ) -> tuple[ScanJobRecord, bool]:
        """Insert a queued job or return the idempotent existing job."""

        if not isinstance(request, ScanJobRequest):
            raise JobStoreError(
                "job_store_request_invalid",
                "request must be a ScanJobRequest value.",
            )
        effective_job_id = str(uuid4()) if job_id is None else job_id
        record = ScanJobRecord(
            job_id=effective_job_id,
            request=request,
            state=ScanJobState.QUEUED,
            updated_at=request.submitted_at,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM scan_jobs WHERE idempotency_key = ?",
                (request.idempotency_key,),
            ).fetchone()
            if existing is not None:
                existing_record = self._record_from_row(existing)
                if existing["request_fingerprint"] != request.fingerprint:
                    raise JobStoreError(
                        "job_idempotency_conflict",
                        "The idempotency key was already used for a different request.",
                    )
                connection.execute("COMMIT")
                return existing_record, False
            connection.execute(
                """
                INSERT INTO scan_jobs (
                    job_id, idempotency_key, request_fingerprint,
                    target, authorization_id, authorization_sha256, mode,
                    submitted_at, state, updated_at, revision,
                    cancellation_requested
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.job_id,
                    request.idempotency_key,
                    request.fingerprint,
                    request.target,
                    request.authorization_id,
                    request.authorization_sha256,
                    request.mode.value,
                    _timestamp(request.submitted_at),
                    record.state.value,
                    _timestamp(record.updated_at),
                    record.revision,
                    0,
                ),
            )
            connection.execute("COMMIT")
            return record, True
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_submit_failed",
                "Unable to persist the scan job.",
            ) from exc
        finally:
            connection.close()

    def get(self, job_id: str) -> ScanJobRecord:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "job_store_read_failed",
                "Unable to read scan-job metadata.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise JobStoreError("job_not_found", "Scan job was not found.")
        return self._record_from_row(row)

    def claim_next(self, *, now: datetime) -> ScanJobRecord | None:
        timestamp = _timestamp(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM scan_jobs
                WHERE state = ?
                ORDER BY submitted_at, job_id
                LIMIT 1
                """,
                (ScanJobState.QUEUED.value,),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            revision = int(row["revision"]) + 1
            updated = connection.execute(
                """
                UPDATE scan_jobs
                SET state = ?, started_at = ?, updated_at = ?, revision = ?
                WHERE job_id = ? AND state = ? AND revision = ?
                """,
                (
                    ScanJobState.RUNNING.value,
                    timestamp,
                    timestamp,
                    revision,
                    row["job_id"],
                    ScanJobState.QUEUED.value,
                    row["revision"],
                ),
            )
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            claimed = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (row["job_id"],),
            ).fetchone()
            connection.execute("COMMIT")
            assert claimed is not None
            return self._record_from_row(claimed)
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_claim_failed",
                "Unable to claim the next scan job.",
            ) from exc
        finally:
            connection.close()

    def request_cancellation(
        self,
        job_id: str,
        *,
        now: datetime,
    ) -> ScanJobRecord:
        timestamp = _timestamp(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobStoreError("job_not_found", "Scan job was not found.")
            record = self._record_from_row(row)
            if record.state.is_terminal:
                connection.execute("COMMIT")
                return record
            revision = record.revision + 1
            if record.state is ScanJobState.QUEUED:
                connection.execute(
                    """
                    UPDATE scan_jobs
                    SET state = ?, cancellation_requested = 1,
                        completed_at = ?, updated_at = ?, revision = ?
                    WHERE job_id = ? AND revision = ?
                    """,
                    (
                        ScanJobState.CANCELLED.value,
                        timestamp,
                        timestamp,
                        revision,
                        job_id,
                        record.revision,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE scan_jobs
                    SET cancellation_requested = 1,
                        updated_at = ?, revision = ?
                    WHERE job_id = ? AND revision = ?
                    """,
                    (timestamp, revision, job_id, record.revision),
                )
            updated = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert updated is not None
            return self._record_from_row(updated)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_cancel_failed",
                "Unable to request scan-job cancellation.",
            ) from exc
        finally:
            connection.close()

    def is_cancellation_requested(self, job_id: str) -> bool:
        return self.get(job_id).cancellation_requested

    def finish_result(
        self,
        job_id: str,
        *,
        scan_id: str,
        result_status: ScanStatus,
        report_ref: str,
        audit_ref: str,
        now: datetime,
    ) -> ScanJobRecord:
        state_by_status = {
            ScanStatus.COMPLETED: ScanJobState.COMPLETED,
            ScanStatus.COMPLETED_WITH_ERRORS: ScanJobState.COMPLETED_WITH_ERRORS,
            ScanStatus.FAILED: ScanJobState.FAILED,
            ScanStatus.CANCELLED: ScanJobState.CANCELLED,
        }
        try:
            state = state_by_status[result_status]
        except KeyError as exc:
            raise JobStoreError(
                "job_store_result_status_invalid",
                "Queued or running scan results cannot finish a job.",
            ) from exc
        return self._terminal_update(
            job_id,
            state=state,
            now=now,
            scan_id=scan_id,
            result_status=result_status,
            report_ref=report_ref,
            audit_ref=audit_ref,
        )

    def complete(
        self,
        job_id: str,
        *,
        state: ScanJobState,
        scan_id: str,
        result_status: ScanStatus,
        report_ref: str,
        audit_ref: str,
        now: datetime,
    ) -> ScanJobRecord:
        if state not in {
            ScanJobState.COMPLETED,
            ScanJobState.COMPLETED_WITH_ERRORS,
        }:
            raise JobStoreError(
                "job_store_completion_state_invalid",
                "Completed jobs require a completed job state.",
            )
        expected = {
            ScanJobState.COMPLETED: ScanStatus.COMPLETED,
            ScanJobState.COMPLETED_WITH_ERRORS: ScanStatus.COMPLETED_WITH_ERRORS,
        }[state]
        if result_status is not expected:
            raise JobStoreError(
                "job_store_completion_status_mismatch",
                "Job completion state and scan status do not match.",
            )
        return self.finish_result(
            job_id,
            scan_id=scan_id,
            result_status=result_status,
            report_ref=report_ref,
            audit_ref=audit_ref,
            now=now,
        )

    def fail(
        self,
        job_id: str,
        *,
        error_code: str,
        error_message: str,
        now: datetime,
    ) -> ScanJobRecord:
        return self._terminal_update(
            job_id,
            state=ScanJobState.FAILED,
            now=now,
            error_code=error_code,
            error_message=error_message,
        )

    def cancel_running(self, job_id: str, *, now: datetime) -> ScanJobRecord:
        return self._terminal_update(
            job_id,
            state=ScanJobState.CANCELLED,
            now=now,
        )

    def _terminal_update(
        self,
        job_id: str,
        *,
        state: ScanJobState,
        now: datetime,
        scan_id: str | None = None,
        result_status: ScanStatus | None = None,
        report_ref: str | None = None,
        audit_ref: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> ScanJobRecord:
        timestamp = _timestamp(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobStoreError("job_not_found", "Scan job was not found.")
            record = self._record_from_row(row)
            if record.state is not ScanJobState.RUNNING:
                raise JobStoreError(
                    "job_state_transition_invalid",
                    "Only running jobs can enter a terminal worker state.",
                )
            revision = record.revision + 1
            connection.execute(
                """
                UPDATE scan_jobs
                SET state = ?, completed_at = ?, updated_at = ?, revision = ?,
                    scan_id = ?, result_status = ?, report_ref = ?, audit_ref = ?,
                    error_code = ?, error_message = ?
                WHERE job_id = ? AND state = ? AND revision = ?
                """,
                (
                    state.value,
                    timestamp,
                    timestamp,
                    revision,
                    scan_id,
                    None if result_status is None else result_status.value,
                    report_ref,
                    audit_ref,
                    error_code,
                    error_message,
                    job_id,
                    ScanJobState.RUNNING.value,
                    record.revision,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert updated is not None
            return self._record_from_row(updated)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_transition_failed",
                "Unable to persist the scan-job state transition.",
            ) from exc
        finally:
            connection.close()


__all__ = [
    "DATABASE_SCHEMA_VERSION",
    "JobStoreError",
    "ScanJobStore",
]
