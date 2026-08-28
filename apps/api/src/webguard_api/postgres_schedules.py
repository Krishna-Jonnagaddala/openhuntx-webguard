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
from .postgres_pool import WebGuardPostgresPool
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
            with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT permit_id, permit_sha256 FROM schedule_permits WHERE schedule_id = %s",
                (schedule_id,),
            ).fetchone()
        return None if row is None else (str(row[0]), row[1])

    # -- occurrence materialization (requirements 3-4) ------------------

    def list_due_schedules(self, *, now: datetime, limit: int = 100) -> tuple[ScanScheduleRecord, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise JobStoreError("schedule_batch_limit_invalid", "Schedule batch limit must be from 1 to 1000.")
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT {_COLUMNS} FROM scan_schedules
                WHERE state = %s AND next_run_at <= %s
                ORDER BY next_run_at, schedule_id
                LIMIT %s
                """,  # noqa: S608
                (ScanScheduleState.ACTIVE.value, now, limit),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    @staticmethod
    def _next_schedule_time(scheduled_for: datetime, *, interval_seconds: int, now: datetime) -> datetime:
        interval = timedelta(seconds=interval_seconds)
        next_run = scheduled_for + interval
        if next_run > now:
            return next_run
        intervals = ((now - scheduled_for) // interval) + 1
        return scheduled_for + (interval * intervals)

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
        exactly as it already does for the SQLite backend."""

        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM scan_schedules WHERE schedule_id = %s FOR UPDATE",  # noqa: S608
                (schedule_id,),
            ).fetchone()
            if row is None:
                return None
            schedule = self._record_from_row(row)
            if (
                schedule.state is not ScanScheduleState.ACTIVE
                or schedule.revision != expected_revision
                or schedule.next_run_at > now
            ):
                return None

            assignment = connection.execute(
                "SELECT 1 FROM organization_authorizations WHERE organization_id = %s AND authorization_id = %s",
                (schedule.organization_id, schedule.authorization_id),
            ).fetchone()
            if assignment is None:
                return None

            binding = connection.execute(
                "SELECT permit_id, permit_sha256 FROM schedule_permits WHERE schedule_id = %s",
                (schedule.schedule_id,),
            ).fetchone()
            if binding is None or str(binding[0]) != permit_id or binding[1] != permit_sha256:
                raise JobStoreError(
                    "trustscan_schedule_binding_changed",
                    "TrustScan schedule permit binding changed before enqueue.",
                )

            permit_row = connection.execute(
                """
                SELECT permit_id FROM scan_permits
                WHERE permit_id = %s AND organization_id = %s AND permit_sha256 = %s
                  AND revoked_at IS NULL AND not_before <= %s AND %s < expires_at
                """,
                (permit_id, schedule.organization_id, permit_sha256, now, now),
            ).fetchone()
            if permit_row is None:
                return None

            scheduled_for = schedule.next_run_at
            scheduled_for_key = (
                scheduled_for.astimezone(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
            idempotency_key = f"schedule:{schedule.schedule_id}:{scheduled_for_key}"
            request = ScanJobRequest(
                idempotency_key=idempotency_key,
                target=schedule.target,
                authorization_id=schedule.authorization_id,
                authorization_sha256=authorization_sha256,
                mode=schedule.mode,
                submitted_at=now,
            )
            job_id = str(uuid4())
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
                        job_id, schedule.organization_id, schedule.created_by,
                        request.idempotency_key, request.fingerprint, request.target,
                        request.authorization_id, request.authorization_sha256,
                        request.mode.value, now, ScanJobState.QUEUED.value, now,
                    ),
                )
            except DatabaseIntegrityError:
                # The unique idempotency-key index rejected a duplicate
                # occurrence -- a second layer of protection behind the
                # revision CAS above (requirement 4). Whoever inserted
                # first wins; this caller sees "raced," identically to a
                # lost revision race.
                return None
            connection.execute(
                "INSERT INTO job_permits (job_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                (job_id, permit_id, permit_sha256),
            )
            next_run_at = self._next_schedule_time(
                scheduled_for, interval_seconds=schedule.interval_seconds, now=now
            )
            updated = connection.execute(
                """
                UPDATE scan_schedules
                SET authorization_sha256 = %s, updated_at = %s, next_run_at = %s,
                    revision = revision + 1, last_enqueued_at = %s, last_job_id = %s,
                    last_error_code = NULL, last_error_at = NULL
                WHERE schedule_id = %s AND revision = %s AND state = %s
                """,
                (
                    authorization_sha256, now, next_run_at, now, job_id,
                    schedule.schedule_id, expected_revision, ScanScheduleState.ACTIVE.value,
                ),
            )
            if updated.rowcount != 1:
                # Lost the CAS despite the row lock above -- unreachable
                # under `FOR UPDATE` in practice, but fail closed rather
                # than assert it can never happen.
                raise JobStoreError(
                    "schedule_enqueue_conflict", "The scheduled run conflicts with an existing job."
                )
            job_row = connection.execute(
                f"SELECT {_JOB_COLUMNS} FROM scan_jobs WHERE job_id = %s", (job_id,)  # noqa: S608
            ).fetchone()
        return self.get_schedule_scoped(schedule.schedule_id, schedule.organization_id), _job_record_from_row(job_row)

    def block_due_schedule(
        self, schedule_id: str, *, expected_revision: int, error_code: str, now: datetime
    ) -> ScanScheduleRecord | None:
        with self._pool.connection() as connection:
            updated = connection.execute(
                """
                UPDATE scan_schedules
                SET state = %s, updated_at = %s, revision = revision + 1,
                    last_error_code = %s, last_error_at = %s
                WHERE schedule_id = %s AND revision = %s AND state = %s
                """,
                (
                    ScanScheduleState.PAUSED.value, now, error_code, now,
                    schedule_id, expected_revision, ScanScheduleState.ACTIVE.value,
                ),
            )
            if updated.rowcount != 1:
                return None
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM scan_schedules WHERE schedule_id = %s", (schedule_id,)  # noqa: S608
            ).fetchone()
        return None if row is None else self._record_from_row(row)


__all__ = ["PostgresScheduleRepository"]
