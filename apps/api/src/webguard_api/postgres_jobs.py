"""PostgreSQL-backed scan-job repository (Slice 13 requirements 1-4).

Satisfies the exact method surface, signatures, and ``JobStoreError``
error codes that ``WebGuardJobService``, ``ScanJobExecutor``, and
``ScanJobWorker`` already depend on from the SQLite ``ScanJobStore`` --
this is the "refactor the existing service/domain layer to depend on
repository contracts" the slice asks for, applied pragmatically: rather
than inventing a new interface and updating three call sites' every
attribute access, this class *is* a structurally-compatible
implementation of the same interface ``ScanJobStore`` already defines
by convention, so the existing service/executor/worker code runs
against it completely unmodified (see ``JobRepository`` in
``repository_contracts.py`` for the formal ``Protocol`` declaration
those three classes are now typed against).

Concurrency model (requirement 3-4): identical to the SQLite design's
proven approach -- optimistic concurrency via a ``revision`` counter,
plus a fenced worker lease (``worker_id`` + ``lease_token`` +
``lease_expires_at``) that every terminal transition must present and
that ``_require_active_lease`` validates before any write. The one
adaptation for Postgres: claiming the next queued job uses
``SELECT ... FOR UPDATE SKIP LOCKED`` (a real Postgres queue idiom)
so concurrent workers never even attempt to claim a job another
worker's transaction is already looking at, rather than relying purely
on the CAS-style ``UPDATE ... WHERE revision = ...`` to lose the race
after wasted work -- both layers are present, matching the SQLite
design's own belt-and-suspenders use of a transaction-scoped read plus
a conditional update.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from webguard_contracts import (
    ScanJobMode,
    ScanJobRecord,
    ScanJobRequest,
    ScanJobState,
    ScanStatus,
    SignedTrustScanPermit,
    load_signed_trustscan_permit_json,
)

from .db_errors import DatabaseIntegrityError
from .permits import PersistedTrustScanPermit
from .postgres_pool import WebGuardPostgresPool
from .store import JobStoreError, LeasedScanJob, LeaseRecoverySummary

DEFAULT_LEASE_SECONDS = 30.0
DEFAULT_MAXIMUM_ATTEMPTS = 3


def _ts(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


def _worker_id(value: object) -> str:
    if not isinstance(value, str):
        raise JobStoreError("job_worker_id_invalid", "worker_id must be a non-empty string.")
    result = value.strip()
    if (
        not result
        or len(result) > 128
        or any(ord(char) < 33 or ord(char) > 126 for char in result)
    ):
        raise JobStoreError(
            "job_worker_id_invalid", "worker_id must contain 1 to 128 visible ASCII characters."
        )
    return result


def _lease_seconds(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JobStoreError("job_lease_duration_invalid", "lease_seconds must be numeric.")
    result = float(value)
    if not 0.1 <= result <= 3600.0:
        raise JobStoreError(
            "job_lease_duration_invalid", "lease_seconds must be from 0.1 to 3600 seconds."
        )
    return result


def _maximum_attempts(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
        raise JobStoreError(
            "job_maximum_attempts_invalid", "maximum_attempts must be from 1 to 100."
        )
    return value


class PostgresJobRepository:
    """Production job/permit store. See module docstring for the
    compatibility contract with ``ScanJobStore``."""

    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    # -- config validation (ScanJobWorker calls these on `self.store`
    # to keep worker and persistence validation rules aligned -- see
    # worker.py's `_validate_configuration`) --

    @staticmethod
    def _worker_id(value: object) -> str:
        return _worker_id(value)

    @staticmethod
    def _lease_seconds(value: object) -> float:
        return _lease_seconds(value)

    @staticmethod
    def _maximum_attempts(value: object) -> int:
        return _maximum_attempts(value)

    # -- permits -----------------------------------------------------

    @staticmethod
    def _permit_from_row(row: tuple) -> PersistedTrustScanPermit:
        try:
            permit = load_signed_trustscan_permit_json(row[11])
        except ValueError as exc:
            raise JobStoreError(
                "trustscan_permit_document_invalid",
                "Persisted TrustScan permit document is invalid.",
            ) from exc
        return PersistedTrustScanPermit(
            permit=permit,
            revoked_at=row[12].astimezone(timezone.utc) if row[12] else None,
            revoked_by=str(row[13]) if row[13] else None,
        )

    def create_scan_permit(self, permit: SignedTrustScanPermit) -> PersistedTrustScanPermit:
        claims = permit.claims
        try:
            with self._pool.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO scan_permits (
                        permit_id, organization_id, authorization_id, authorization_sha256,
                        target, issued_by, issued_at, not_before, expires_at, permit_sha256,
                        signing_key_id, document_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        claims.permit_id,
                        claims.organization_id,
                        claims.authorization_id,
                        claims.authorization_sha256,
                        claims.target,
                        claims.issued_by,
                        claims.issued_at,
                        claims.not_before,
                        claims.expires_at,
                        permit.fingerprint,
                        permit.signing_key_id,
                        permit.to_json(),
                    ),
                )
        except DatabaseIntegrityError as exc:
            raise JobStoreError(
                "trustscan_permit_conflict",
                "TrustScan permit conflicts with an existing permit.",
            ) from exc
        return self.get_scan_permit(claims.permit_id)

    def get_scan_permit(self, permit_id: str) -> PersistedTrustScanPermit:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT permit_id, organization_id, authorization_id, authorization_sha256,
                       target, issued_by, issued_at, not_before, expires_at, permit_sha256,
                       signing_key_id, document_json, revoked_at, revoked_by
                FROM scan_permits WHERE permit_id = %s
                """,
                (permit_id,),
            ).fetchone()
        if row is None:
            raise JobStoreError("trustscan_permit_not_found", "TrustScan permit was not found.")
        return self._permit_from_row(row)

    def get_scan_permit_scoped(
        self, permit_id: str, organization_id: str
    ) -> PersistedTrustScanPermit:
        record = self.get_scan_permit(permit_id)
        if record.permit.claims.organization_id != organization_id:
            raise JobStoreError("trustscan_permit_not_found", "TrustScan permit was not found.")
        return record

    def revoke_scan_permit_scoped(
        self, permit_id: str, organization_id: str, *, revoked_by: str, now: datetime
    ) -> PersistedTrustScanPermit:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT revoked_at FROM scan_permits WHERE permit_id = %s AND organization_id = %s",
                (permit_id, organization_id),
            ).fetchone()
            if row is None:
                raise JobStoreError(
                    "trustscan_permit_not_found", "TrustScan permit was not found."
                )
            if row[0] is None:
                connection.execute(
                    """
                    UPDATE scan_permits SET revoked_at = %s, revoked_by = %s
                    WHERE permit_id = %s AND organization_id = %s AND revoked_at IS NULL
                    """,
                    (_ts(now), revoked_by, permit_id, organization_id),
                )
        return self.get_scan_permit(permit_id)

    def get_job_permit_binding(self, job_id: str) -> tuple[str, str] | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT permit_id, permit_sha256 FROM job_permits WHERE job_id = %s",
                (job_id,),
            ).fetchone()
        return None if row is None else (str(row[0]), row[1])

    # -- schedules: POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED --
    #
    # Schedule persistence has a real, contract-tested implementation
    # this slice (`PostgresScheduleRepository`, in
    # `postgres_schedules.py`) -- it is simply not the object injected
    # here. `WebGuardJobService`'s schedule-handling HTTP methods call
    # these same method names on whatever `store` it was constructed
    # with; in production mode that is this class, so every schedule
    # operation fails closed with one clear, fixed error rather than
    # an `AttributeError` or a silent no-op. This is the deliberate
    # scope boundary confirmed for this slice: the live `/v1/...` path
    # covers organizations/principals/targets/authorizations/scans/
    # jobs/findings/audit only.

    @staticmethod
    def _schedules_not_available() -> JobStoreError:
        return JobStoreError(
            "schedule_runtime_wiring_deferred",
            "Schedule management is not yet wired into the production PostgreSQL runtime.",
        )

    def create_schedule(self, *args, **kwargs):
        raise self._schedules_not_available()

    def get_schedule_scoped(self, *args, **kwargs):
        raise self._schedules_not_available()

    def list_schedules_scoped_page(self, *args, **kwargs):
        raise self._schedules_not_available()

    def pause_schedule_scoped(self, *args, **kwargs):
        raise self._schedules_not_available()

    def resume_schedule_scoped(self, *args, **kwargs):
        raise self._schedules_not_available()

    def get_schedule_permit_binding(self, schedule_id: str) -> tuple[str, str] | None:
        raise self._schedules_not_available()

    def get_job_safety_receipt(self, job_id: str) -> tuple[str, str] | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT receipt_ref, receipt_sha256 FROM job_safety_receipts WHERE job_id = %s",
                (job_id,),
            ).fetchone()
        return None if row is None else (row[0], row[1])

    # -- jobs ----------------------------------------------------------

    @staticmethod
    def _record_from_row(row: tuple) -> ScanJobRecord:
        (
            job_id, target, authorization_id, authorization_sha256, mode, state,
            revision, cancellation_requested, submitted_at, updated_at, started_at,
            completed_at, scan_id, result_status, report_ref, audit_ref, error_code,
            error_message, idempotency_key,
        ) = row
        try:
            request = ScanJobRequest(
                idempotency_key=idempotency_key,
                target=target,
                authorization_id=authorization_id,
                authorization_sha256=authorization_sha256,
                mode=ScanJobMode(mode),
                submitted_at=submitted_at.astimezone(timezone.utc),
            )
            return ScanJobRecord(
                job_id=str(job_id),
                request=request,
                state=ScanJobState(state),
                updated_at=updated_at.astimezone(timezone.utc),
                revision=revision,
                cancellation_requested=bool(cancellation_requested),
                started_at=started_at.astimezone(timezone.utc) if started_at else None,
                completed_at=completed_at.astimezone(timezone.utc) if completed_at else None,
                scan_id=str(scan_id) if scan_id else None,
                result_status=ScanStatus(result_status) if result_status else None,
                report_ref=report_ref,
                audit_ref=audit_ref,
                error_code=error_code,
                error_message=error_message,
            )
        except (TypeError, ValueError) as exc:
            raise JobStoreError(
                "job_store_persisted_state_invalid", "Persisted job-store state is invalid."
            ) from exc

    _RECORD_COLUMNS = (
        "job_id, target, authorization_id, authorization_sha256, mode, state, "
        "revision, cancellation_requested, submitted_at, updated_at, started_at, "
        "completed_at, scan_id, result_status, report_ref, audit_ref, error_code, "
        "error_message, idempotency_key"
    )

    def submit(
        self,
        request: ScanJobRequest,
        *,
        job_id: str | None = None,
        organization_id: str | None = None,
        submitted_by: str | None = None,
        permit_id: str | None = None,
        permit_sha256: str | None = None,
    ) -> tuple[ScanJobRecord, bool]:
        if not isinstance(request, ScanJobRequest):
            raise JobStoreError("job_store_request_invalid", "request must be a ScanJobRequest value.")
        if (organization_id is None) != (submitted_by is None):
            raise JobStoreError(
                "job_scope_invalid", "organization_id and submitted_by must be supplied together."
            )
        if (permit_id is None) != (permit_sha256 is None):
            raise JobStoreError(
                "trustscan_job_binding_invalid",
                "permit_id and permit_sha256 must be supplied together.",
            )
        if permit_id is not None and organization_id is None:
            raise JobStoreError(
                "trustscan_job_binding_invalid",
                "TrustScan job binding requires organization scope.",
            )
        effective_job_id = str(uuid4()) if job_id is None else job_id

        with self._pool.connection() as connection:
            if request.idempotency_key is not None:
                existing = connection.execute(
                    f"SELECT {self._RECORD_COLUMNS}, request_fingerprint "  # noqa: S608
                    "FROM scan_jobs WHERE idempotency_key = %s",
                    (request.idempotency_key,),
                ).fetchone()
                if existing is not None:
                    existing_record = self._record_from_row(existing[:-1])
                    if existing[-1] != request.fingerprint:
                        raise JobStoreError(
                            "job_idempotency_conflict",
                            "The idempotency key was already used for a different request.",
                        )
                    if organization_id is not None:
                        scope = connection.execute(
                            "SELECT organization_id FROM scan_jobs WHERE job_id = %s",
                            (existing_record.job_id,),
                        ).fetchone()
                        if scope is None or str(scope[0]) != organization_id:
                            raise JobStoreError(
                                "job_idempotency_conflict",
                                "The idempotency key was already used outside this organization.",
                            )
                    if permit_id is not None:
                        binding = self.get_job_permit_binding(existing_record.job_id)
                        if binding is None or binding != (permit_id, permit_sha256):
                            raise JobStoreError(
                                "job_idempotency_conflict",
                                "The idempotency key was already used with a different TrustScan permit.",
                            )
                    return existing_record, False

            try:
                connection.execute(
                    """
                    INSERT INTO scan_jobs (
                        job_id, organization_id, submitted_by, idempotency_key,
                        request_fingerprint, target, authorization_id, authorization_sha256,
                        mode, submitted_at, state, updated_at, revision, cancellation_requested
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, FALSE)
                    """,
                    (
                        effective_job_id,
                        organization_id,
                        submitted_by,
                        request.idempotency_key,
                        request.fingerprint,
                        request.target,
                        request.authorization_id,
                        request.authorization_sha256,
                        request.mode.value,
                        request.submitted_at,
                        ScanJobState.QUEUED.value,
                        request.submitted_at,
                    ),
                )
            except DatabaseIntegrityError as exc:
                raise JobStoreError(
                    "job_store_submit_failed", "Unable to persist the scan job."
                ) from exc
            if permit_id is not None:
                permit_row = connection.execute(
                    "SELECT organization_id, permit_sha256 FROM scan_permits WHERE permit_id = %s",
                    (permit_id,),
                ).fetchone()
                if (
                    permit_row is None
                    or str(permit_row[0]) != organization_id
                    or permit_row[1] != permit_sha256
                ):
                    raise JobStoreError(
                        "trustscan_permit_not_found",
                        "TrustScan permit was not found for this organization.",
                    )
                connection.execute(
                    "INSERT INTO job_permits (job_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                    (effective_job_id, permit_id, permit_sha256),
                )
            row = connection.execute(
                f"SELECT {self._RECORD_COLUMNS} FROM scan_jobs WHERE job_id = %s",  # noqa: S608
                (effective_job_id,),
            ).fetchone()
        return self._record_from_row(row), True

    def get(self, job_id: str) -> ScanJobRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {self._RECORD_COLUMNS} FROM scan_jobs WHERE job_id = %s", (job_id,)  # noqa: S608
            ).fetchone()
        if row is None:
            raise JobStoreError("job_not_found", "Scan job was not found.")
        return self._record_from_row(row)

    def get_scope(self, job_id: str) -> tuple[str, str] | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT organization_id, submitted_by FROM scan_jobs WHERE job_id = %s",
                (job_id,),
            ).fetchone()
        if row is None or row[0] is None:
            return None
        return str(row[0]), str(row[1])

    def get_scoped(self, job_id: str, organization_id: str) -> ScanJobRecord:
        record = self.get(job_id)
        scope = self.get_scope(job_id)
        if scope is None or scope[0] != organization_id:
            raise JobStoreError("job_not_found", "Scan job was not found.")
        return record

    def organization_id_for_job(self, job_id: str) -> str | None:
        scope = self.get_scope(job_id)
        return None if scope is None else scope[0]

    def list_jobs_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        state: ScanJobState | None = None,
        mode: ScanJobMode | None = None,
    ) -> tuple[tuple[ScanJobRecord, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise JobStoreError("job_list_limit_invalid", "Job list limit must be from 1 to 100.")
        clauses = ["organization_id = %s"]
        parameters: list[object] = [organization_id]
        if state is not None:
            clauses.append("state = %s")
            parameters.append(state.value)
        if mode is not None:
            clauses.append("mode = %s")
            parameters.append(mode.value)
        if after is not None:
            if (
                not isinstance(after, tuple)
                or len(after) != 2
                or not all(isinstance(value, str) and value for value in after)
            ):
                raise JobStoreError("job_list_cursor_invalid", "Job cursor position is invalid.")
            clauses.append("(submitted_at < %s OR (submitted_at = %s AND job_id::text < %s))")
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT {self._RECORD_COLUMNS} FROM scan_jobs
                WHERE {' AND '.join(clauses)}
                ORDER BY submitted_at DESC, job_id DESC
                LIMIT %s
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        has_more = len(rows) > limit
        return tuple(self._record_from_row(row) for row in rows[:limit]), has_more

    def request_cancellation_scoped(
        self, job_id: str, organization_id: str, *, now: datetime
    ) -> ScanJobRecord:
        self.get_scoped(job_id, organization_id)
        return self.request_cancellation(job_id, now=now)

    def request_cancellation(self, job_id: str, *, now: datetime) -> ScanJobRecord:
        timestamp = _ts(now)
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {self._RECORD_COLUMNS} FROM scan_jobs WHERE job_id = %s", (job_id,)  # noqa: S608
            ).fetchone()
            if row is None:
                raise JobStoreError("job_not_found", "Scan job was not found.")
            record = self._record_from_row(row)
            if record.state.is_terminal:
                return record
            if record.state is ScanJobState.QUEUED:
                connection.execute(
                    """
                    UPDATE scan_jobs
                    SET state = %s, cancellation_requested = TRUE,
                        completed_at = %s, updated_at = %s, revision = revision + 1
                    WHERE job_id = %s AND revision = %s
                    """,
                    (ScanJobState.CANCELLED.value, timestamp, timestamp, job_id, record.revision),
                )
            else:
                connection.execute(
                    """
                    UPDATE scan_jobs
                    SET cancellation_requested = TRUE, updated_at = %s, revision = revision + 1
                    WHERE job_id = %s AND revision = %s
                    """,
                    (timestamp, job_id, record.revision),
                )
            updated = connection.execute(
                f"SELECT {self._RECORD_COLUMNS} FROM scan_jobs WHERE job_id = %s", (job_id,)  # noqa: S608
            ).fetchone()
        return self._record_from_row(updated)

    def is_cancellation_requested(self, job_id: str) -> bool:
        return self.get(job_id).cancellation_requested

    # -- leases ----------------------------------------------------------

    @classmethod
    def _lease_from_row(cls, row: tuple, *, worker_id, lease_token, lease_expires_at, attempt_count) -> LeasedScanJob:
        return LeasedScanJob(
            record=cls._record_from_row(row),
            worker_id=worker_id,
            lease_token=lease_token,
            lease_expires_at=lease_expires_at.astimezone(timezone.utc),
            attempt_count=attempt_count,
        )

    def claim_next_leased(
        self, *, now: datetime, worker_id: str, lease_seconds: float
    ) -> LeasedScanJob | None:
        effective_worker_id = _worker_id(worker_id)
        duration = float(lease_seconds) if lease_seconds else DEFAULT_LEASE_SECONDS
        timestamp = _ts(now)
        expires_at = timestamp + timedelta(seconds=duration)
        lease_token = str(uuid4())
        with self._pool.connection() as connection:
            with connection.transaction():
                # Mirrors ScanJobStore._select_claimable_row's
                # "identity_ready" predicate exactly: a job whose
                # authorization is no longer assigned to its
                # organization (revoked/reassigned after submission),
                # or whose bound permit is revoked/expired/not-yet-
                # active, or whose bound permit is already driving
                # another RUNNING job, must never be claimed -- this is
                # a real safety property (defense against a stale
                # queued job outliving the authorization/permit that
                # justified accepting it), not an incidental ordering
                # detail.
                row = connection.execute(
                    """
                    SELECT jobs.job_id, jobs.revision
                    FROM scan_jobs AS jobs
                    LEFT JOIN job_permits AS binding
                      ON binding.job_id = jobs.job_id
                    WHERE jobs.state = %(queued)s
                      AND jobs.cancellation_requested = FALSE
                      AND (
                        jobs.organization_id IS NULL
                        OR EXISTS (
                            SELECT 1 FROM organization_authorizations AS assignment
                            WHERE assignment.organization_id = jobs.organization_id
                              AND assignment.authorization_id = jobs.authorization_id
                        )
                      )
                      AND (
                        binding.permit_id IS NULL
                        OR (
                            EXISTS (
                                SELECT 1 FROM scan_permits AS permit
                                WHERE permit.permit_id = binding.permit_id
                                  AND permit.permit_sha256 = binding.permit_sha256
                                  AND permit.revoked_at IS NULL
                                  AND permit.not_before <= %(timestamp)s
                                  AND %(timestamp)s < permit.expires_at
                            )
                            AND NOT EXISTS (
                                SELECT 1 FROM scan_jobs AS running
                                JOIN job_permits AS running_binding
                                  ON running_binding.job_id = running.job_id
                                WHERE running.state = %(running)s
                                  AND running_binding.permit_id = binding.permit_id
                            )
                        )
                      )
                    ORDER BY jobs.submitted_at, jobs.job_id
                    LIMIT 1
                    FOR UPDATE OF jobs SKIP LOCKED
                    """,
                    {
                        "queued": ScanJobState.QUEUED.value,
                        "running": ScanJobState.RUNNING.value,
                        "timestamp": timestamp,
                    },
                ).fetchone()
                if row is None:
                    return None
                job_id, revision = row
                updated = connection.execute(
                    """
                    UPDATE scan_jobs
                    SET state = %s, started_at = %s, updated_at = %s, revision = %s,
                        worker_id = %s, lease_token = %s, lease_expires_at = %s,
                        heartbeat_at = %s, attempt_count = attempt_count + 1
                    WHERE job_id = %s AND state = %s AND revision = %s
                    """,
                    (
                        ScanJobState.RUNNING.value, timestamp, timestamp, revision + 1,
                        effective_worker_id, lease_token, expires_at, timestamp,
                        job_id, ScanJobState.QUEUED.value, revision,
                    ),
                )
                if updated.rowcount != 1:
                    return None
                claimed = connection.execute(
                    f"SELECT {self._RECORD_COLUMNS}, attempt_count FROM scan_jobs WHERE job_id = %s",  # noqa: S608
                    (job_id,),
                ).fetchone()
        return self._lease_from_row(
            claimed[:-1],
            worker_id=effective_worker_id,
            lease_token=lease_token,
            lease_expires_at=expires_at,
            attempt_count=claimed[-1],
        )

    @staticmethod
    def _require_active_lease(state: str, row_worker_id, row_lease_token, lease_expires_at, *, worker_id, lease_token, now) -> None:
        if (
            state != ScanJobState.RUNNING.value
            or row_worker_id != worker_id
            or row_lease_token != lease_token
        ):
            raise JobStoreError("job_lease_lost", "The worker lease is no longer current.")
        if lease_expires_at is None or lease_expires_at.astimezone(timezone.utc) <= now.astimezone(timezone.utc):
            raise JobStoreError("job_lease_expired", "The worker lease has expired.")

    def renew_lease(
        self, job_id: str, *, worker_id: str, lease_token: str, now: datetime, lease_seconds: float
    ) -> LeasedScanJob:
        effective_worker_id = _worker_id(worker_id)
        duration = float(lease_seconds) if lease_seconds else DEFAULT_LEASE_SECONDS
        timestamp = _ts(now)
        expires_at = timestamp + timedelta(seconds=duration)
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT state, worker_id, lease_token, lease_expires_at, revision, attempt_count "
                "FROM scan_jobs WHERE job_id = %s",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobStoreError("job_not_found", "Scan job was not found.")
            state, row_worker_id, row_lease_token, lease_expires_at, revision, attempt_count = row
            self._require_active_lease(
                state, row_worker_id, row_lease_token, lease_expires_at,
                worker_id=effective_worker_id, lease_token=lease_token, now=now,
            )
            updated = connection.execute(
                """
                UPDATE scan_jobs
                SET heartbeat_at = %s, lease_expires_at = %s, updated_at = %s, revision = %s
                WHERE job_id = %s AND state = %s AND revision = %s
                    AND worker_id = %s AND lease_token = %s
                """,
                (
                    timestamp, expires_at, timestamp, revision + 1, job_id,
                    ScanJobState.RUNNING.value, revision, effective_worker_id, lease_token,
                ),
            )
            if updated.rowcount != 1:
                raise JobStoreError("job_lease_lost", "The worker lease is no longer current.")
            renewed = connection.execute(
                f"SELECT {self._RECORD_COLUMNS}, attempt_count FROM scan_jobs WHERE job_id = %s",  # noqa: S608
                (job_id,),
            ).fetchone()
        return self._lease_from_row(
            renewed[:-1],
            worker_id=effective_worker_id,
            lease_token=lease_token,
            lease_expires_at=expires_at,
            attempt_count=renewed[-1],
        )

    def recover_expired_leases(self, *, now: datetime, maximum_attempts: int) -> LeaseRecoverySummary:
        limit = int(maximum_attempts) if maximum_attempts else DEFAULT_MAXIMUM_ATTEMPTS
        timestamp = _ts(now)
        requeued = cancelled = failed = 0
        with self._pool.connection() as connection:
            with connection.transaction():
                rows = connection.execute(
                    """
                    SELECT job_id, revision, lease_token, cancellation_requested, attempt_count
                    FROM scan_jobs
                    WHERE state = %s AND lease_expires_at IS NOT NULL AND lease_expires_at <= %s
                    ORDER BY lease_expires_at, job_id
                    FOR UPDATE SKIP LOCKED
                    """,
                    (ScanJobState.RUNNING.value, timestamp),
                ).fetchall()
                for job_id, revision, lease_token, cancellation_requested, attempt_count in rows:
                    common = (job_id, ScanJobState.RUNNING.value, revision, lease_token)
                    if cancellation_requested:
                        result = connection.execute(
                            """
                            UPDATE scan_jobs
                            SET state = %s, completed_at = %s, updated_at = %s, revision = revision + 1,
                                worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
                            WHERE job_id = %s AND state = %s AND revision = %s AND lease_token = %s
                            """,
                            (ScanJobState.CANCELLED.value, timestamp, timestamp, *common),
                        )
                        cancelled += result.rowcount
                    elif attempt_count >= limit:
                        result = connection.execute(
                            """
                            UPDATE scan_jobs
                            SET state = %s, completed_at = %s, updated_at = %s, revision = revision + 1,
                                worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL,
                                error_code = %s, error_message = %s
                            WHERE job_id = %s AND state = %s AND revision = %s AND lease_token = %s
                            """,
                            (
                                ScanJobState.FAILED.value, timestamp, timestamp,
                                "worker_lease_attempts_exhausted",
                                "The scan job exceeded the permitted worker recovery attempts.",
                                *common,
                            ),
                        )
                        failed += result.rowcount
                    else:
                        result = connection.execute(
                            """
                            UPDATE scan_jobs
                            SET state = %s, started_at = NULL, updated_at = %s, revision = revision + 1,
                                worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
                            WHERE job_id = %s AND state = %s AND revision = %s AND lease_token = %s
                            """,
                            (ScanJobState.QUEUED.value, timestamp, *common),
                        )
                        requeued += result.rowcount
        return LeaseRecoverySummary(requeued=requeued, cancelled=cancelled, failed=failed)

    def _terminal_update(
        self,
        job_id: str,
        *,
        state: ScanJobState,
        now: datetime,
        worker_id: str | None = None,
        lease_token: str | None = None,
        scan_id: str | None = None,
        result_status: ScanStatus | None = None,
        report_ref: str | None = None,
        audit_ref: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> ScanJobRecord:
        if (safety_receipt_ref is None) != (safety_receipt_sha256 is None):
            raise JobStoreError(
                "trustscan_safety_receipt_metadata_invalid",
                "Safety receipt reference and digest must be supplied together.",
            )
        if (worker_id is None) != (lease_token is None):
            raise JobStoreError(
                "job_lease_credentials_invalid", "worker_id and lease_token must be supplied together."
            )
        effective_worker_id = None if worker_id is None else _worker_id(worker_id)
        timestamp = _ts(now)
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT state, worker_id, lease_token, lease_expires_at, revision FROM scan_jobs WHERE job_id = %s",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobStoreError("job_not_found", "Scan job was not found.")
            row_state, row_worker_id, row_lease_token, lease_expires_at, revision = row
            if row_state != ScanJobState.RUNNING.value:
                raise JobStoreError(
                    "job_state_transition_invalid", "Only running jobs can enter a terminal worker state."
                )
            if row_lease_token is not None:
                if effective_worker_id is None or lease_token is None:
                    raise JobStoreError(
                        "job_lease_required", "A current worker lease is required for this transition."
                    )
                self._require_active_lease(
                    row_state, row_worker_id, row_lease_token, lease_expires_at,
                    worker_id=effective_worker_id, lease_token=lease_token, now=now,
                )
            elif effective_worker_id is not None:
                raise JobStoreError("job_lease_lost", "The worker lease is no longer current.")

            lease_predicate = ""
            parameters: list[object] = [
                state.value, timestamp, timestamp, revision + 1, scan_id,
                None if result_status is None else result_status.value,
                report_ref, audit_ref, error_code, error_message,
                job_id, ScanJobState.RUNNING.value, revision,
            ]
            if effective_worker_id is not None:
                lease_predicate = " AND worker_id = %s AND lease_token = %s"
                parameters.extend([effective_worker_id, lease_token])
            updated = connection.execute(
                f"""
                UPDATE scan_jobs
                SET state = %s, completed_at = %s, updated_at = %s, revision = %s,
                    scan_id = %s, result_status = %s, report_ref = %s, audit_ref = %s,
                    error_code = %s, error_message = %s, worker_id = NULL,
                    lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
                WHERE job_id = %s AND state = %s AND revision = %s{lease_predicate}
                """,  # noqa: S608
                tuple(parameters),
            )
            if updated.rowcount != 1:
                code = "job_lease_lost" if effective_worker_id is not None else "job_state_transition_conflict"
                message = (
                    "The worker lease is no longer current."
                    if effective_worker_id is not None
                    else "The scan-job state changed before the transition completed."
                )
                raise JobStoreError(code, message)
            if safety_receipt_ref is not None:
                if (
                    not isinstance(safety_receipt_ref, str)
                    or not safety_receipt_ref
                    or safety_receipt_ref.startswith("/")
                    or ".." in safety_receipt_ref.split("/")
                ):
                    raise JobStoreError(
                        "trustscan_safety_receipt_reference_invalid",
                        "Safety receipt reference must be a safe relative path.",
                    )
                if (
                    not isinstance(safety_receipt_sha256, str)
                    or len(safety_receipt_sha256) != 64
                    or any(c not in "0123456789abcdef" for c in safety_receipt_sha256)
                ):
                    raise JobStoreError(
                        "trustscan_safety_receipt_digest_invalid",
                        "Safety receipt digest must be a lower-case SHA-256 value.",
                    )
                connection.execute(
                    "INSERT INTO job_safety_receipts (job_id, receipt_ref, receipt_sha256, created_at) "
                    "VALUES (%s, %s, %s, %s)",
                    (job_id, safety_receipt_ref, safety_receipt_sha256, timestamp),
                )
            updated_row = connection.execute(
                f"SELECT {self._RECORD_COLUMNS} FROM scan_jobs WHERE job_id = %s", (job_id,)  # noqa: S608
            ).fetchone()
        return self._record_from_row(updated_row)

    def finish_result(
        self,
        job_id: str,
        *,
        scan_id: str,
        result_status: ScanStatus,
        report_ref: str,
        audit_ref: str,
        now: datetime,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> ScanJobRecord:
        return self.finish_result_leased(
            job_id,
            worker_id=None,
            lease_token=None,
            scan_id=scan_id,
            result_status=result_status,
            report_ref=report_ref,
            audit_ref=audit_ref,
            now=now,
            safety_receipt_ref=safety_receipt_ref,
            safety_receipt_sha256=safety_receipt_sha256,
        )

    def finish_result_leased(
        self,
        job_id: str,
        *,
        worker_id: str | None,
        lease_token: str | None,
        scan_id: str,
        result_status: ScanStatus,
        report_ref: str,
        audit_ref: str,
        now: datetime,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
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
                "job_store_result_status_invalid", "Queued or running scan results cannot finish a job."
            ) from exc
        return self._terminal_update(
            job_id, state=state, now=now, worker_id=worker_id, lease_token=lease_token,
            scan_id=scan_id, result_status=result_status, report_ref=report_ref, audit_ref=audit_ref,
            safety_receipt_ref=safety_receipt_ref, safety_receipt_sha256=safety_receipt_sha256,
        )

    def fail_leased(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_token: str,
        error_code: str,
        error_message: str,
        now: datetime,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> ScanJobRecord:
        return self._terminal_update(
            job_id, state=ScanJobState.FAILED, now=now, worker_id=worker_id, lease_token=lease_token,
            error_code=error_code, error_message=error_message,
            safety_receipt_ref=safety_receipt_ref, safety_receipt_sha256=safety_receipt_sha256,
        )

    def cancel_running_leased(
        self, job_id: str, *, worker_id: str, lease_token: str, now: datetime
    ) -> ScanJobRecord:
        return self._terminal_update(
            job_id, state=ScanJobState.CANCELLED, now=now, worker_id=worker_id, lease_token=lease_token
        )

    def cancel_running(self, job_id: str, *, now: datetime) -> ScanJobRecord:
        return self._terminal_update(job_id, state=ScanJobState.CANCELLED, now=now)


__all__ = ["PostgresJobRepository"]
