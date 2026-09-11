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
``lease_expires_at``) that every terminal transition must present.
``renew_lease`` and ``_terminal_update`` validate it before any write
(P1-2 Phase H: now inside ``webguard_control.renew_lease``/
``terminal_transition`` themselves, run under ``worker_tenant_data``,
not in this class's own Python). The one adaptation for Postgres:
claiming the next queued job uses
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
from datetime import datetime, timezone
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
from .postgres_pool import WORKER_TENANT_DATA_ROLE, WebGuardPostgresPool
from .postgres_schedules import PostgresScheduleRepository
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
        # Slice 14 requirement 3: schedule-shaped methods delegate to the
        # one real implementation (`postgres_schedules.py`) rather than
        # duplicating its SQL here -- `WebGuardJobService` and
        # `ScanScheduleCoordinator` both call these method names on
        # whatever `store` they were constructed with, so in production
        # that is this class, and this class simply is not where the
        # schedule SQL lives.
        self._schedules = PostgresScheduleRepository(pool)

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
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        atomically scoped by ``organization_id`` in the SQL predicate
        itself, not a two-step unscoped fetch plus Python-level compare
        -- ``permit_id`` reaches this method directly from a caller-
        supplied HTTP path parameter (see ``service.py``'s
        ``_permit_record``)."""

        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT permit_id, organization_id, authorization_id, authorization_sha256,
                       target, issued_by, issued_at, not_before, expires_at, permit_sha256,
                       signing_key_id, document_json, revoked_at, revoked_by
                FROM scan_permits WHERE permit_id = %s AND organization_id = %s
                """,
                (permit_id, organization_id),
            ).fetchone()
        if row is None:
            raise JobStoreError("trustscan_permit_not_found", "TrustScan permit was not found.")
        return self._permit_from_row(row)

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
        """Unscoped -- retained for internal/system callers that already
        hold an independently-verified ``job_id`` (see
        ``get_job_permit_binding_scoped`` for the customer/service-facing
        equivalent, which is what ``service.py`` must use)."""

        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT permit_id, permit_sha256 FROM job_permits WHERE job_id = %s",
                (job_id,),
            ).fetchone()
        return None if row is None else (str(row[0]), row[1])

    def get_job_permit_binding_scoped(
        self, job_id: str, organization_id: str
    ) -> tuple[str, str] | None:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        ``job_permits`` carries no ``organization_id`` column of its own
        (it is a pure ``job_id -> permit_id`` binding table), so tenant
        scope can only be proven by joining to ``scan_jobs`` -- the
        authoritative job/organization relation -- inside this one
        query, rather than trusting that whatever record the caller
        already fetched actually corresponds to this same job_id."""

        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT binding.permit_id, binding.permit_sha256
                FROM job_permits AS binding
                JOIN scan_jobs AS jobs ON jobs.job_id = binding.job_id
                WHERE binding.job_id = %s AND jobs.organization_id = %s
                """,
                (job_id, organization_id),
            ).fetchone()
        return None if row is None else (str(row[0]), row[1])

    # -- schedules (Slice 14 requirement 3): every method below is a
    # one-line delegation to the one real implementation
    # (`PostgresScheduleRepository`) -- see `__init__`'s comment. This
    # class does not duplicate schedule SQL; it is the object
    # `WebGuardJobService` and `ScanScheduleCoordinator` are constructed
    # with in production, and this is how it satisfies both.

    def create_schedule(self, *args, **kwargs):
        return self._schedules.create_schedule(*args, **kwargs)

    def get_schedule_scoped(self, *args, **kwargs):
        return self._schedules.get_schedule_scoped(*args, **kwargs)

    def list_schedules_scoped_page(self, *args, **kwargs):
        return self._schedules.list_schedules_scoped_page(*args, **kwargs)

    def pause_schedule_scoped(self, *args, **kwargs):
        return self._schedules.pause_schedule_scoped(*args, **kwargs)

    def resume_schedule_scoped(self, *args, **kwargs):
        return self._schedules.resume_schedule_scoped(*args, **kwargs)

    def get_schedule_permit_binding(self, schedule_id: str) -> tuple[str, str] | None:
        return self._schedules.get_schedule_permit_binding(schedule_id)

    def get_schedule_permit_binding_scoped(
        self, schedule_id: str, organization_id: str
    ) -> tuple[str, str] | None:
        return self._schedules.get_schedule_permit_binding_scoped(schedule_id, organization_id)

    def list_due_schedules(self, *args, **kwargs):
        return self._schedules.list_due_schedules(*args, **kwargs)

    def enqueue_due_schedule(self, *args, **kwargs):
        return self._schedules.enqueue_due_schedule(*args, **kwargs)

    def block_due_schedule(self, *args, **kwargs):
        return self._schedules.block_due_schedule(*args, **kwargs)

    def get_job_safety_receipt_scoped(
        self, job_id: str, organization_id: str
    ) -> tuple[str, str] | None:
        """P1-C1: ``job_safety_receipts`` carries no ``organization_id``
        column of its own -- mirrors ``get_job_permit_binding_scoped``'s
        join-to-``scan_jobs`` rationale exactly."""

        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT receipt.receipt_ref, receipt.receipt_sha256
                FROM job_safety_receipts AS receipt
                JOIN scan_jobs AS jobs ON jobs.job_id = receipt.job_id
                WHERE receipt.job_id = %s AND jobs.organization_id = %s
                """,
                (job_id, organization_id),
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
        """P1-2 Phase H gap, not yet closed: webguard_control.resolve_job_organization
        exists and is exactly what this method's own current live
        caller (executor.py, which only ever reads the organization_id
        half) needs, but this method's own contract also returns
        submitted_by, which that function does not. worker_tenant_data
        has zero table-level grant on scan_jobs at all (unlike
        api_tenant_data's identity tables, there is no ordinary
        tenant-scoped refetch available here either), so there is no
        way to resolve submitted_by under the restricted role today.
        This raw query works only because every WebGuard process still
        runs as webguard, unrestricted. organization_id_for_job (the
        one caller that only needs the scalar this function already
        returns) could convert standalone without this constraint, but
        has no external caller of its own to prove the conversion
        against."""

        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT organization_id, submitted_by FROM scan_jobs WHERE job_id = %s",
                (job_id,),
            ).fetchone()
        if row is None or row[0] is None:
            return None
        return str(row[0]), str(row[1])

    def get_scoped(self, job_id: str, organization_id: str) -> ScanJobRecord:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        atomically scoped by ``organization_id`` in the SQL predicate
        itself, not two separate unscoped fetches plus a Python-level
        compare -- this is the primary tenant-facing job lookup
        (``service.py`` calls it directly with a caller-supplied
        ``job_id``, and every ``_scoped`` mutation below it, e.g.
        ``request_cancellation_scoped``, relies on it failing closed)."""

        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {self._RECORD_COLUMNS} FROM scan_jobs "  # noqa: S608
                "WHERE job_id = %s AND organization_id = %s",
                (job_id, organization_id),
            ).fetchone()
        if row is None:
            raise JobStoreError("job_not_found", "Scan job was not found.")
        return self._record_from_row(row)

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
        """P1-2 Phase H: worker_tenant_data has no table-level grant on
        scan_jobs at all. This method is intentionally cross-tenant
        (a worker claims the next queued job for ANY organization), so
        it now runs entirely through webguard_control.claim_next_job,
        an exact reproduction of this method's own predicate/CAS/
        lease-issuance sequence (down to the identity_ready predicate's
        exact shape). The function generates its own lease_token and
        lease_expires_at server-side rather than accepting ones
        computed here, and its return columns cover this method's full
        contract, so no follow-up query is needed."""

        effective_worker_id = _worker_id(worker_id)
        duration = float(lease_seconds) if lease_seconds else DEFAULT_LEASE_SECONDS
        timestamp = _ts(now)
        with self._pool.role_scoped_connection(WORKER_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                (effective_worker_id, duration, timestamp),
            ).fetchone()
        if row is None:
            return None
        return self._lease_from_row(
            row[:19],
            worker_id=row[19],
            lease_token=row[20],
            lease_expires_at=row[21],
            attempt_count=row[22],
        )

    def renew_lease(
        self, job_id: str, *, worker_id: str, lease_token: str, now: datetime, lease_seconds: float
    ) -> LeasedScanJob:
        """P1-2 Phase H: mirrors claim_next_leased's shape. Runs
        entirely through webguard_control.renew_lease, which
        reproduces this method's own lease-validation sequence exactly
        and reports which outcome it hit (not_found, lease_lost,
        lease_expired, ok) through its own outcome column, since a
        single null-vs-not-null return can't disambiguate the three
        distinct error codes this method raises."""

        effective_worker_id = _worker_id(worker_id)
        duration = float(lease_seconds) if lease_seconds else DEFAULT_LEASE_SECONDS
        timestamp = _ts(now)
        with self._pool.role_scoped_connection(WORKER_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT * FROM webguard_control.renew_lease(%s, %s, %s, %s, %s::numeric)",
                (job_id, effective_worker_id, lease_token, timestamp, duration),
            ).fetchone()
        outcome = row[0]
        if outcome == "not_found":
            raise JobStoreError("job_not_found", "Scan job was not found.")
        if outcome in ("lease_lost", "worker_id_invalid"):
            raise JobStoreError("job_lease_lost", "The worker lease is no longer current.")
        if outcome == "lease_expired":
            raise JobStoreError("job_lease_expired", "The worker lease has expired.")
        return self._lease_from_row(
            row[1:20],
            worker_id=row[20],
            lease_token=row[21],
            lease_expires_at=row[22],
            attempt_count=row[23],
        )

    def recover_expired_leases(self, *, now: datetime, maximum_attempts: int) -> LeaseRecoverySummary:
        """P1-2 Phase H: cross-tenant by design (sweeps every
        organization's expired leases at once), mirrors
        claim_next_leased's shape. Runs entirely through
        webguard_control.recover_expired_leases, an exact reproduction
        of this method's own per-row cancel/fail/requeue branching,
        including the scan_records status touch-up."""

        limit = int(maximum_attempts) if maximum_attempts else DEFAULT_MAXIMUM_ATTEMPTS
        timestamp = _ts(now)
        with self._pool.role_scoped_connection(WORKER_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT * FROM webguard_control.recover_expired_leases(%s, %s)",
                (timestamp, limit),
            ).fetchone()
        requeued, cancelled, failed = row
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
        """P1-2 Phase H: mirrors claim_next_leased's shape. Runs
        entirely through webguard_control.terminal_transition, an
        exact reproduction of this method's own validation/lease/CAS/
        safety-receipt sequence, including the scan_records
        reconciliation and the receipt INSERT, all in the one
        transaction the function itself runs as. The function's own
        SQL comment addresses the one visible reordering (it validates
        the safety-receipt format before the lease/CAS work, where
        this method used to validate it after): both orderings are
        observably identical, since a failure either way aborts with
        zero writes. Reports which outcome it hit through its own
        outcome column, since a SQL function can't raise the many
        distinct JobStoreError codes this method raises."""

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
        with self._pool.role_scoped_connection(WORKER_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT * FROM webguard_control.terminal_transition"
                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    job_id, state.value, timestamp, effective_worker_id, lease_token,
                    scan_id, None if result_status is None else result_status.value,
                    report_ref, audit_ref, error_code, error_message,
                    safety_receipt_ref, safety_receipt_sha256,
                ),
            ).fetchone()
        outcome = row[0]
        if outcome == "ok":
            return self._record_from_row(row[1:20])
        if outcome == "not_found":
            raise JobStoreError("job_not_found", "Scan job was not found.")
        if outcome == "invalid_state":
            raise JobStoreError(
                "job_state_transition_invalid", "Only running jobs can enter a terminal worker state."
            )
        if outcome == "lease_required":
            raise JobStoreError("job_lease_required", "A current worker lease is required for this transition.")
        if outcome == "lease_expired":
            raise JobStoreError("job_lease_expired", "The worker lease has expired.")
        if outcome == "transition_conflict":
            raise JobStoreError(
                "job_state_transition_conflict", "The scan-job state changed before the transition completed."
            )
        if outcome == "safety_receipt_reference_invalid":
            raise JobStoreError(
                "trustscan_safety_receipt_reference_invalid",
                "Safety receipt reference must be a safe relative path.",
            )
        if outcome == "safety_receipt_digest_invalid":
            raise JobStoreError(
                "trustscan_safety_receipt_digest_invalid",
                "Safety receipt digest must be a lower-case SHA-256 value.",
            )
        # lease_lost, worker_id_invalid, receipt_metadata_invalid, and
        # lease_credentials_invalid are the remaining outcomes: the
        # last three are unreachable from this call site since Python
        # already validated the identical conditions above before ever
        # reaching the database, and lease_lost is the correct code
        # for every remaining case (identity mismatch or a lost CAS
        # race under a supplied lease).
        raise JobStoreError("job_lease_lost", "The worker lease is no longer current.")

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
