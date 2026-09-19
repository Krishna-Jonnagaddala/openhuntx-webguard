"""PostgreSQL-backed schedule repository (Slice 13 requirement 5; live-
wired into the production scheduler in Slice 14 requirement 3).

Fully implemented and contract-tested against a real database, matching
``ScanScheduleRecord`` and ``ScanJobStore``'s schedule method surface
exactly. ``ScanScheduleCoordinator`` (the scheduler process) is
constructed against ``PostgresJobRepository`` in production, which
delegates every schedule-shaped method to an internal instance of this
class (see ``postgres_jobs.py``) -- there is exactly one real
implementation of schedule persistence, not a second one duplicated
across two files.

Duplicate-execution note (requirement 4): two independent database
guarantees make double-materializing one due occurrence impossible,
not merely unlikely:

1. ``enqueue_due_schedule``'s optimistic-concurrency ``revision``
   column -- the schedule row is read once per scheduler pass, and the
   final ``UPDATE ... WHERE revision = %s`` that both advances
   ``next_run_at`` and records the new job only succeeds if no other
   transaction touched the row first. A concurrent scheduler racing for
   the same schedule loses this compare-and-swap and affects zero rows,
   exactly like ``PostgresJobRepository``'s job-claim CAS.
2. ``scan_jobs.idempotency_key``'s database-level ``UNIQUE`` index
   (migration 0005) -- the job inserted for one occurrence uses
   ``f"schedule:{schedule_id}:{scheduled_for}"`` as its idempotency
   key, so even if two processes somehow both passed the revision
   check (they cannot, under Postgres's transaction isolation, but this
   is defense in depth, not reliance on a single mechanism), the second
   job insert would fail the unique constraint rather than create a
   duplicate.

What this does *not* solve, honestly: a full highly-available scheduler
where multiple scheduler *processes* each independently poll and need
to agree on which schedules they own (as opposed to safely colliding
and letting the database reject the loser, which is what happens
today) is a distinct problem. Today's model is "any number of scheduler
processes may poll concurrently and will never double-materialize an
occurrence," which is what this requirement actually asks for; it is
not "exactly one scheduler process does the polling," which is a
leader-election problem requiring Redis or another distributed-lock
mechanism -- see this slice's audit doc and
``docs/production/INFRASTRUCTURE_REQUIREMENTS.md``'s Redis section for
why that remains explicitly out of scope until a second real Redis
consumer exists.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from webguard_contracts import (
    ScanJobMode,
    ScanJobRecord,
    ScanJobRequest,
    ScanJobState,
    ScanScheduleRecord,
    ScanScheduleState,
    ScanStatus,
)

from .db_errors import DatabaseIntegrityError
from .postgres_pool import API_TENANT_DATA_ROLE, SCHEDULER_TENANT_DATA_ROLE, WebGuardPostgresPool
from .store import JobStoreError

_COLUMNS = (
    "schedule_id, organization_id, created_by, name, target, authorization_id, "
    "authorization_sha256, mode, interval_seconds, state, created_at, updated_at, "
    "next_run_at, revision, last_enqueued_at, last_job_id, last_error_code, last_error_at"
)

_JOB_COLUMNS = (
    "job_id, target, authorization_id, authorization_sha256, mode, state, "
    "revision, cancellation_requested, submitted_at, updated_at, started_at, "
    "completed_at, scan_id, result_status, report_ref, audit_ref, error_code, "
    "error_message, idempotency_key"
)


def _job_record_from_row(row: tuple) -> ScanJobRecord:
    (
        job_id, target, authorization_id, authorization_sha256, mode, state,
        revision, cancellation_requested, submitted_at, updated_at, started_at,
        completed_at, scan_id, result_status, report_ref, audit_ref, error_code,
        error_message, idempotency_key,
    ) = row
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


class PostgresScheduleRepository:
    """P1-2 Phase H: scan_schedules and schedule_permits have no
    scheduler_tenant_data grant at all (list_due_schedules's and
    block_due_schedule's own docstrings already document this); only
    api_tenant_data can touch them. Every ordinary method that reads
    or writes those two tables runs under api_tenant_data via
    tenant_connection. get_schedule_permit_binding is a genuine,
    unclosed gap in the same shape postgres_jobs.py's
    get_job_permit_binding documents: its only caller anywhere in this
    codebase is scheduler.py, the scheduler process, but
    schedule_permits has no scheduler_tenant_data grant, so no role is
    both this method's true caller and actually able to run the
    query. It stays on the unrestricted connection."""

    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple) -> ScanScheduleRecord:
        (
            schedule_id, organization_id, created_by, name, target, authorization_id,
            authorization_sha256, mode, interval_seconds, state, created_at, updated_at,
            next_run_at, revision, last_enqueued_at, last_job_id, last_error_code, last_error_at,
        ) = row
        return ScanScheduleRecord(
            schedule_id=str(schedule_id),
            organization_id=str(organization_id),
            created_by=str(created_by),
            name=name,
            target=target,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
            mode=ScanJobMode(mode),
            interval_seconds=interval_seconds,
            state=ScanScheduleState(state),
            created_at=created_at.astimezone(timezone.utc),
            updated_at=updated_at.astimezone(timezone.utc),
            next_run_at=next_run_at.astimezone(timezone.utc),
            revision=revision,
            last_enqueued_at=last_enqueued_at.astimezone(timezone.utc) if last_enqueued_at else None,
            last_job_id=str(last_job_id) if last_job_id else None,
            last_error_code=last_error_code,
            last_error_at=last_error_at.astimezone(timezone.utc) if last_error_at else None,
        )

    def create_schedule(
        self,
        *,
        organization_id: str,
        created_by: str,
        name: str,
        target: str,
        authorization_id: str,
        authorization_sha256: str,
        mode: ScanJobMode,
        interval_seconds: int,
        starts_at: datetime,
        now: datetime,
        schedule_id: str | None = None,
        permit_id: str | None = None,
        permit_sha256: str | None = None,
    ) -> ScanScheduleRecord:
        if (permit_id is None) != (permit_sha256 is None):
            raise JobStoreError(
                "trustscan_schedule_binding_invalid",
                "permit_id and permit_sha256 must be supplied together.",
            )
        effective_id = str(uuid4()) if schedule_id is None else schedule_id
        try:
            with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
                connection.execute(
                    """
                    INSERT INTO scan_schedules (
                        schedule_id, organization_id, created_by, name, target,
                        authorization_id, authorization_sha256, mode, interval_seconds,
                        state, created_at, updated_at, next_run_at, revision
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0)
                    """,
                    (
                        effective_id, organization_id, created_by, name, target,
                        authorization_id, authorization_sha256, mode.value, interval_seconds,
                        ScanScheduleState.ACTIVE.value, now, now, starts_at,
                    ),
                )
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
                        "INSERT INTO schedule_permits (schedule_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                        (effective_id, permit_id, permit_sha256),
                    )
        except DatabaseIntegrityError as exc:
            raise JobStoreError(
                "schedule_conflict", "The scan schedule conflicts with an existing record."
            ) from exc
        return self.get_schedule_scoped(effective_id, organization_id)

    def get_schedule_scoped(self, schedule_id: str, organization_id: str) -> ScanScheduleRecord:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM scan_schedules WHERE schedule_id = %s AND organization_id = %s",  # noqa: S608
                (schedule_id, organization_id),
            ).fetchone()
        if row is None:
            raise JobStoreError("schedule_not_found", "Scan schedule was not found.")
        return self._record_from_row(row)

    def list_schedules_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        state: ScanScheduleState | None = None,
        target: str | None = None,
    ) -> tuple[tuple[ScanScheduleRecord, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise JobStoreError("schedule_list_limit_invalid", "Schedule list limit must be from 1 to 100.")
        clauses = ["organization_id = %s"]
        parameters: list[object] = [organization_id]
        if state is not None:
            clauses.append("state = %s")
            parameters.append(state.value)
        if target is not None:
            clauses.append("target = %s")
            parameters.append(target)
        if after is not None:
            clauses.append("(created_at < %s OR (created_at = %s AND schedule_id::text < %s))")
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"""
                SELECT {_COLUMNS} FROM scan_schedules
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at DESC, schedule_id DESC
                LIMIT %s
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        has_more = len(rows) > limit
        return tuple(self._record_from_row(row) for row in rows[:limit]), has_more

    def list_schedules_scoped(self, organization_id: str, *, limit: int = 100) -> tuple[ScanScheduleRecord, ...]:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM scan_schedules WHERE organization_id = %s ORDER BY created_at, schedule_id LIMIT %s",  # noqa: S608
                (organization_id, limit),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    def _set_schedule_state(
        self,
        schedule_id: str,
        organization_id: str,
        *,
        state: ScanScheduleState,
        now: datetime,
        next_run_at: datetime | None,
    ) -> ScanScheduleRecord:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT revision, next_run_at FROM scan_schedules WHERE schedule_id = %s AND organization_id = %s",
                (schedule_id, organization_id),
            ).fetchone()
            if row is None:
                raise JobStoreError("schedule_not_found", "Scan schedule was not found.")
            revision, current_next_run_at = row
            effective_next = current_next_run_at if next_run_at is None else next_run_at
            updated = connection.execute(
                """
                UPDATE scan_schedules
                SET state = %s, updated_at = %s, next_run_at = %s, revision = %s,
                    last_error_code = NULL, last_error_at = NULL
                WHERE schedule_id = %s AND organization_id = %s AND revision = %s
                """,
                (state.value, now, effective_next, revision + 1, schedule_id, organization_id, revision),
            )
            if updated.rowcount != 1:
                raise JobStoreError("schedule_update_failed", "Unable to update the scan schedule.")
        return self.get_schedule_scoped(schedule_id, organization_id)

    def pause_schedule_scoped(self, schedule_id: str, organization_id: str, *, now: datetime) -> ScanScheduleRecord:
        return self._set_schedule_state(
            schedule_id, organization_id, state=ScanScheduleState.PAUSED, now=now, next_run_at=None
        )

    def resume_schedule_scoped(self, schedule_id: str, organization_id: str, *, now: datetime) -> ScanScheduleRecord:
        current = self.get_schedule_scoped(schedule_id, organization_id)
        return self._set_schedule_state(
            schedule_id,
            organization_id,
            state=ScanScheduleState.ACTIVE,
            now=now,
            next_run_at=now + timedelta(seconds=current.interval_seconds),
        )

    def get_schedule_permit_binding(self, schedule_id: str) -> tuple[str, str] | None:
        """Unscoped -- retained for internal/system callers; see
        ``get_schedule_permit_binding_scoped`` for the customer/
        service-facing equivalent.

        P1-2 Phase H gap closed: webguard_control.resolve_schedule_permit_binding
        is a new SECURITY DEFINER function, the same shape as
        postgres_jobs.py's resolve_job_permit_binding: owned by
        scheduler_function_owner, reusing its existing SELECT grant on
        schedule_permits (Phase E, originally for enqueue_due_schedule's
        own binding check) and that grant's existing unconditional RLS
        policy, since schedule_permits has no organization_id column to
        predicate a tenant-scoped policy on. Granted EXECUTE to
        scheduler_tenant_data, its one true caller (scheduler.py)."""

        with self._pool.role_scoped_connection(SCHEDULER_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT * FROM webguard_control.resolve_schedule_permit_binding(%s)",
                (schedule_id,),
            ).fetchone()
        return None if row is None else (str(row[0]), row[1])

    def get_schedule_permit_binding_scoped(
        self, schedule_id: str, organization_id: str
    ) -> tuple[str, str] | None:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        ``schedule_permits`` carries no ``organization_id`` column of its
        own, so tenant scope is proven by joining to ``scan_schedules``
        -- the authoritative schedule/organization relation -- inside
        this one query."""

        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                """
                SELECT binding.permit_id, binding.permit_sha256
                FROM schedule_permits AS binding
                JOIN scan_schedules AS schedules ON schedules.schedule_id = binding.schedule_id
                WHERE binding.schedule_id = %s AND schedules.organization_id = %s
                """,
                (schedule_id, organization_id),
            ).fetchone()
        return None if row is None else (str(row[0]), row[1])

    # -- occurrence materialization (requirements 3-4) ------------------

    def list_due_schedules(self, *, now: datetime, limit: int = 100) -> tuple[ScanScheduleRecord, ...]:
        """P1-2 Phase H: cross-tenant by design (polls every
        organization's due schedules at once). scheduler_tenant_data
        has no table-level grant on scan_schedules at all, so this
        runs entirely through webguard_control.list_due_schedules,
        whose return columns exactly match this method's own SELECT."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise JobStoreError("schedule_batch_limit_invalid", "Schedule batch limit must be from 1 to 1000.")
        with self._pool.role_scoped_connection(SCHEDULER_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                "SELECT * FROM webguard_control.list_due_schedules(%s, %s)",
                (now, limit),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    def enqueue_due_schedule(
        self,
        schedule_id: str,
        *,
        expected_revision: int,
        authorization_sha256: str,
        permit_id: str,
        permit_sha256: str,
        now: datetime,
    ) -> tuple[ScanScheduleRecord, ScanJobRecord] | None:
        """Materialize one due occurrence into a normal scan job --
        the identical ``scan_jobs``/``job_permits`` rows a user-triggered
        submission would create (requirement 3: no parallel scheduling
        execution path) -- atomically with advancing the schedule's own
        ``next_run_at``/``revision``. Returns ``None`` if the schedule
        was concurrently modified, disabled, not yet due, or its
        authorization/permit binding no longer checks out; the caller
        (``ScanScheduleCoordinator``) treats that as "raced" or "blocked"
        exactly as it already does for the SQLite backend.

        P1-2 Phase H gap closed: webguard_control.enqueue_due_schedule's
        own RETURNS TABLE is now widened (DROP FUNCTION/CREATE FUNCTION,
        not CREATE OR REPLACE, see the SQL file's own comment on why)
        to every column this method's ScanScheduleRecord/ScanJobRecord
        reconstruction needs, appended after the original 8-column
        outcome summary so scheduler.py's run_once and every existing
        test call site that reads those first 8 columns positionally
        keeps working unchanged. Widening the SQL function's own return
        columns was chosen over narrowing this method's Python contract
        to what run_once alone reads (job_id): this repository method's
        return type is shared, by convention, with the SQLite backend
        of the same repository_contracts.py interface, and
        tests/unit/test_schedule_store.py and this project's
        transaction/race/authority contract tests
        (test_phase3_revocation_cancellation_races.py,
        test_phase3_transaction_schedule_safety.py,
        test_phase4_scheduler_authority_toc.py) all exercise the full
        pair against that backend, and narrowing only the Postgres
        backend's shape would make the two backends silently diverge.
        The function's own transactional logic (the FOR UPDATE read,
        the revision CAS, the idempotency-key race handling, the
        schedule-advancement UPDATE) is completely unchanged, so the
        existing concurrency tests for it keep proving what they always
        proved. outcome branches to the exact same return-or-raise
        shape this method always had: 'not_due' / 'authorization_not_assigned'
        / 'permit_invalid' / 'raced' return None; 'binding_changed'
        raises trustscan_schedule_binding_changed;
        'schedule_conflict' raises schedule_enqueue_conflict; 'ok'
        returns the full (ScanScheduleRecord, ScanJobRecord) pair."""

        with self._pool.role_scoped_connection(SCHEDULER_TENANT_DATA_ROLE) as connection:
            # request_fingerprint must be computed in Python (the one
            # reviewed implementation of ScanJobRequest's canonical-JSON
            # algorithm; see the SQL function's own comment on why
            # this is not reimplemented in PL/pgSQL), which needs
            # target/authorization_id/mode. Those are immutable for a
            # schedule's entire lifetime (no method anywhere in this
            # codebase ever changes them after create_schedule), but
            # scheduler_tenant_data has no table-level grant on
            # scan_schedules to read them directly, hence this small,
            # dedicated resolver, called before the main function.
            shape = connection.execute(
                "SELECT * FROM webguard_control.resolve_schedule_request_shape(%s)",
                (schedule_id,),
            ).fetchone()
            if shape is None:
                return None
            request = ScanJobRequest(
                # Only used transiently to compute .fingerprint below;
                # never persisted, since the SQL function computes and
                # stores its own idempotency_key internally, from the
                # schedule's actual next_run_at.
                idempotency_key=f"schedule:{schedule_id}:fingerprint-only",
                target=shape[0],
                authorization_id=shape[1],
                authorization_sha256=authorization_sha256,
                mode=ScanJobMode(shape[2]),
                submitted_at=now,
            )
            row = connection.execute(
                """
                SELECT
                    outcome,
                    schedule_id, schedule_organization_id, schedule_created_by, schedule_name,
                    schedule_target, schedule_authorization_id, schedule_authorization_sha256,
                    schedule_mode, schedule_interval_seconds, schedule_state, schedule_created_at,
                    schedule_updated_at, schedule_next_run_at, schedule_revision,
                    schedule_last_enqueued_at, schedule_last_job_id, schedule_last_error_code,
                    schedule_last_error_at,
                    job_id, job_target, job_authorization_id, job_authorization_sha256, job_mode,
                    job_state, job_revision, job_cancellation_requested, job_submitted_at,
                    job_updated_at, job_started_at, job_completed_at, job_scan_id,
                    job_result_status, job_report_ref, job_audit_ref, job_error_code,
                    job_error_message, job_idempotency_key
                FROM webguard_control.enqueue_due_schedule(%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    schedule_id, expected_revision, authorization_sha256, permit_id,
                    permit_sha256, now, request.fingerprint,
                ),
            ).fetchone()

        outcome = row[0]
        if outcome == "binding_changed":
            raise JobStoreError(
                "trustscan_schedule_binding_changed",
                "TrustScan schedule permit binding changed before enqueue.",
            )
        if outcome == "schedule_conflict":
            raise JobStoreError(
                "schedule_enqueue_conflict", "The scheduled run conflicts with an existing job."
            )
        if outcome != "ok":
            # not_due / authorization_not_assigned / permit_invalid / raced.
            return None

        schedule_record = self._record_from_row(tuple(row[1:19]))
        job_record = _job_record_from_row(tuple(row[19:38]))
        return schedule_record, job_record

    def block_due_schedule(
        self, schedule_id: str, *, expected_revision: int, error_code: str, now: datetime
    ) -> ScanScheduleRecord | None:
        """P1-2 Phase H: mirrors list_due_schedules's shape. Runs
        entirely through webguard_control.block_due_schedule, whose
        return columns exactly match this method's own SELECT. A lost
        CAS (concurrently modified, already inactive) returns zero
        rows, matching this method's existing None-on-lost-race
        contract."""

        with self._pool.role_scoped_connection(SCHEDULER_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT * FROM webguard_control.block_due_schedule(%s, %s, %s, %s)",
                (schedule_id, expected_revision, error_code, now),
            ).fetchone()
        return None if row is None else self._record_from_row(row)


__all__ = ["PostgresScheduleRepository"]
