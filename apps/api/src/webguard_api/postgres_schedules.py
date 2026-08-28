"""PostgreSQL-backed schedule repository (Slice 13 requirement 5).

Status: POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED (per
the confirmed Slice 13 scope). Fully implemented and contract-tested
against a real database, matching ``ScanScheduleRecord`` and
``ScanJobStore``'s schedule method surface exactly -- but
``ScanScheduleCoordinator`` (the scheduler process) is not constructed
against this class anywhere in this slice's production startup path;
that remains SQLite-only, matching ``PostgresJobRepository``'s own
schedule methods, which raise a controlled deferred-wiring error
rather than silently delegating here.

Duplicate-execution note (requirement 5): this repository's
optimistic-concurrency ``revision`` column already prevents two
scheduler instances from double-materializing the *same* schedule row
into two jobs from a concurrent read -- an UPDATE ... WHERE revision =
? that loses the race affects zero rows, exactly like
``PostgresJobRepository``'s job-claim CAS. A full highly-available
scheduler (multiple scheduler *processes* coordinating which schedules
each owns) is a distinct problem this repository does not solve by
itself; see this slice's audit doc for why that boundary is honestly
deferred to Redis/distributed-lock infrastructure rather than
simulated here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from webguard_contracts import ScanJobMode, ScanScheduleRecord, ScanScheduleState

from .db_errors import DatabaseIntegrityError
from .postgres_pool import WebGuardPostgresPool
from .store import JobStoreError

_COLUMNS = (
    "schedule_id, organization_id, created_by, name, target, authorization_id, "
    "authorization_sha256, mode, interval_seconds, state, created_at, updated_at, "
    "next_run_at, revision, last_enqueued_at, last_job_id, last_error_code, last_error_at"
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
    ) -> tuple[tuple[ScanScheduleRecord, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise JobStoreError("schedule_list_limit_invalid", "Schedule list limit must be from 1 to 100.")
        clauses = ["organization_id = %s"]
        parameters: list[object] = [organization_id]
        if state is not None:
            clauses.append("state = %s")
            parameters.append(state.value)
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


__all__ = ["PostgresScheduleRepository"]
