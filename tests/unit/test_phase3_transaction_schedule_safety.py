from __future__ import annotations

from contextlib import closing

import queue
import sqlite3
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    AuthorizationRepository,
    IdentityStore,
    JobStoreError,
    ScanJobStore,
    ScanScheduleCoordinator,
)
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    ScanScheduleState,
    ScanStatus,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    create_trustscan_permit,
    trustscan_signer,
    write_authorization,
)


SCHEDULE_ID = "11111111-aaaa-4bbb-8ccc-111111111111"


def request(key: str) -> ScanJobRequest:
    auth = authorization()
    return ScanJobRequest(
        idempotency_key=key,
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256=auth.fingerprint,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


class PauseBeforeEnqueueStore(ScanJobStore):
    """Expose the scheduler validation -> enqueue race deterministically."""

    def __init__(self, path: Path) -> None:
        self.before_enqueue = threading.Event()
        self.continue_enqueue = threading.Event()
        super().__init__(path)

    def enqueue_due_schedule(self, *args, **kwargs):
        self.before_enqueue.set()

        if not self.continue_enqueue.wait(timeout=10):
            raise RuntimeError(
                "Timed out waiting to continue schedule enqueue."
            )

        return super().enqueue_due_schedule(*args, **kwargs)


class Phase3TransactionScheduleSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"
        self.auth_dir = self.root / "authorizations"

        write_authorization(self.auth_dir)

        self.store = ScanJobStore(self.path)
        self.identity = IdentityStore(self.path)

        self.identity.create_organization(
            "Phase 3 Tenant",
            now=NOW,
            organization_id=ORG_ID,
        )
        self.identity.create_principal(
            ORG_ID,
            "Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )
        self.identity.assign_authorization(
            ORG_ID,
            AUTH_ID,
            assigned_by=OWNER_ID,
            now=NOW,
        )

        self.permit = create_trustscan_permit(self.store)
        self.signer = trustscan_signer(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_schedule(
        self,
        *,
        store: ScanJobStore | None = None,
        schedule_id: str = SCHEDULE_ID,
        starts_at=NOW,
    ):
        effective_store = self.store if store is None else store

        return effective_store.create_schedule(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name="Phase 3 transaction schedule",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL,
            interval_seconds=3600,
            starts_at=starts_at,
            now=NOW,
            schedule_id=schedule_id,
            permit_id=self.permit.permit.claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
        )

    def coordinator(
        self,
        *,
        store: ScanJobStore | None = None,
        now=NOW,
    ) -> ScanScheduleCoordinator:
        effective_store = self.store if store is None else store

        return ScanScheduleCoordinator(
            store=effective_store,
            authorizations=AuthorizationRepository(self.auth_dir),
            identity=IdentityStore(self.path),
            trustscan_signer=trustscan_signer(effective_store),
            clock=lambda: now,
        )

    def test_schedule_materialization_failure_rolls_back_everything(
        self,
    ) -> None:
        schedule = self.create_schedule()

        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER phase3_fail_job_scope_insert
                BEFORE INSERT ON job_scopes
                BEGIN
                    SELECT RAISE(ABORT, 'phase3 injected failure');
                END
                """
            )
            connection.commit()

        with self.assertRaises(JobStoreError) as caught:
            self.store.enqueue_due_schedule(
                schedule.schedule_id,
                expected_revision=schedule.revision,
                authorization_sha256=authorization().fingerprint,
                permit_id=self.permit.permit.claims.permit_id,
                permit_sha256=self.permit.permit.fingerprint,
                now=NOW,
            )

        self.assertEqual(
            caught.exception.code,
            "schedule_enqueue_conflict",
        )

        with closing(sqlite3.connect(self.path)) as connection, connection:
            job_count = connection.execute(
                "SELECT COUNT(*) FROM scan_jobs"
            ).fetchone()[0]

            scope_count = connection.execute(
                "SELECT COUNT(*) FROM job_scopes"
            ).fetchone()[0]

            job_permit_count = connection.execute(
                "SELECT COUNT(*) FROM job_permits"
            ).fetchone()[0]

            persisted = connection.execute(
                """
                SELECT revision, next_run_at, last_job_id,
                       last_enqueued_at
                FROM scan_schedules
                WHERE schedule_id = ?
                """,
                (schedule.schedule_id,),
            ).fetchone()

        self.assertEqual(job_count, 0)
        self.assertEqual(scope_count, 0)
        self.assertEqual(job_permit_count, 0)

        self.assertEqual(persisted[0], schedule.revision)
        self.assertEqual(
            persisted[1],
            schedule.next_run_at.isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z"),
        )
        self.assertIsNone(persisted[2])
        self.assertIsNone(persisted[3])

    def test_terminal_update_failure_rolls_back_job_and_receipt(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase3-terminal-rollback")
        )

        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="phase3-terminal-worker",
            lease_seconds=30,
        )
        self.assertIsNotNone(lease)
        assert lease is not None

        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER phase3_fail_receipt_insert
                BEFORE INSERT ON job_safety_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'phase3 injected receipt failure');
                END
                """
            )
            connection.commit()

        with self.assertRaises(JobStoreError) as caught:
            self.store.finish_result_leased(
                record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                scan_id="22222222-aaaa-4bbb-8ccc-222222222222",
                result_status=ScanStatus.COMPLETED,
                report_ref=f"jobs/{record.job_id}/report.json",
                audit_ref=(
                    f"jobs/{record.job_id}/authorization-audit.json"
                ),
                safety_receipt_ref=(
                    f"jobs/{record.job_id}/trustscan-safety-receipt.json"
                ),
                safety_receipt_sha256="a" * 64,
                now=NOW,
            )

        self.assertEqual(
            caught.exception.code,
            "job_store_transition_failed",
        )

        persisted = self.store.get(record.job_id)

        self.assertIs(persisted.state, ScanJobState.RUNNING)
        self.assertIsNone(persisted.scan_id)
        self.assertIsNone(persisted.result_status)
        self.assertIsNone(persisted.report_ref)
        self.assertIsNone(persisted.audit_ref)

        with closing(sqlite3.connect(self.path)) as connection, connection:
            row = connection.execute(
                """
                SELECT worker_id, lease_token, attempt_count
                FROM scan_jobs
                WHERE job_id = ?
                """,
                (record.job_id,),
            ).fetchone()

            receipt_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM job_safety_receipts
                WHERE job_id = ?
                """,
                (record.job_id,),
            ).fetchone()[0]

        self.assertEqual(row[0], lease.worker_id)
        self.assertEqual(row[1], lease.lease_token)
        self.assertEqual(row[2], 1)
        self.assertEqual(receipt_count, 0)

    def test_recovery_failure_rolls_back_entire_expired_batch(
        self,
    ) -> None:
        records = []

        for index in range(2):
            record, _ = self.store.submit(
                request(f"phase3-recovery-rollback-{index}")
            )
            records.append(record)

        leases = []

        for index in range(2):
            lease = self.store.claim_next_leased(
                now=NOW,
                worker_id=f"phase3-dead-worker-{index}",
                lease_seconds=1,
            )
            self.assertIsNotNone(lease)
            assert lease is not None
            leases.append(lease)

        ordered_ids = sorted(record.job_id for record in records)
        failing_id = ordered_ids[1]

        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                f"""
                CREATE TRIGGER phase3_fail_second_recovery
                BEFORE UPDATE ON scan_jobs
                WHEN OLD.job_id = '{failing_id}'
                  AND OLD.state = 'running'
                  AND NEW.state = 'queued'
                BEGIN
                    SELECT RAISE(ABORT, 'phase3 injected recovery failure');
                END
                """
            )
            connection.commit()

        with self.assertRaises(JobStoreError) as caught:
            self.store.recover_expired_leases(
                now=NOW + timedelta(seconds=2),
                maximum_attempts=3,
            )

        self.assertEqual(
            caught.exception.code,
            "job_store_lease_recovery_failed",
        )

        for record in records:
            persisted = self.store.get(record.job_id)
            self.assertIs(
                persisted.state,
                ScanJobState.RUNNING,
            )

        with closing(sqlite3.connect(self.path)) as connection, connection:
            rows = connection.execute(
                """
                SELECT job_id, worker_id, lease_token,
                       attempt_count, state
                FROM scan_jobs
                ORDER BY job_id
                """
            ).fetchall()

        self.assertEqual(len(rows), 2)

        for row in rows:
            self.assertIsNotNone(row[1])
            self.assertIsNotNone(row[2])
            self.assertEqual(row[3], 1)
            self.assertEqual(row[4], ScanJobState.RUNNING.value)

    def test_paused_schedule_never_materializes_work(self) -> None:
        schedule = self.create_schedule()

        paused = self.store.pause_schedule_scoped(
            schedule.schedule_id,
            ORG_ID,
            now=NOW,
        )

        self.assertIs(
            paused.state,
            ScanScheduleState.PAUSED,
        )

        result = self.coordinator().run_once()

        self.assertEqual(result.inspected, 0)
        self.assertEqual(result.enqueued, 0)

        with closing(sqlite3.connect(self.path)) as connection, connection:
            job_count = connection.execute(
                "SELECT COUNT(*) FROM scan_jobs"
            ).fetchone()[0]

        self.assertEqual(job_count, 0)

    def test_pause_winning_scheduler_race_prevents_enqueue(
        self,
    ) -> None:
        race_store = PauseBeforeEnqueueStore(self.path)

        schedule = self.create_schedule(
            store=race_store,
        )

        coordinator = self.coordinator(
            store=race_store,
        )

        outcomes: queue.Queue[object] = queue.Queue()

        def scheduler_pass() -> None:
            try:
                outcomes.put(coordinator.run_once())
            except BaseException as exc:
                outcomes.put(exc)

        thread = threading.Thread(
            target=scheduler_pass,
            daemon=True,
        )
        thread.start()

        self.assertTrue(
            race_store.before_enqueue.wait(timeout=10),
            "Scheduler did not reach the enqueue boundary.",
        )

        pause_store = ScanJobStore(self.path)
        paused = pause_store.pause_schedule_scoped(
            schedule.schedule_id,
            ORG_ID,
            now=NOW,
        )

        self.assertIs(
            paused.state,
            ScanScheduleState.PAUSED,
        )

        race_store.continue_enqueue.set()

        thread.join(timeout=15)

        if thread.is_alive():
            self.fail("Pause/scheduler race did not terminate.")

        result = outcomes.get_nowait()

        if isinstance(result, BaseException):
            self.fail(
                f"Unexpected scheduler race exception: {result!r}"
            )

        self.assertEqual(result.enqueued, 0)
        self.assertEqual(result.raced, 1)

        persisted = self.store.get_schedule_scoped(
            schedule.schedule_id,
            ORG_ID,
        )
        self.assertIs(
            persisted.state,
            ScanScheduleState.PAUSED,
        )

        with closing(sqlite3.connect(self.path)) as connection, connection:
            job_count = connection.execute(
                "SELECT COUNT(*) FROM scan_jobs"
            ).fetchone()[0]

        self.assertEqual(job_count, 0)

    def test_overdue_schedule_catches_up_with_only_one_job(
        self,
    ) -> None:
        schedule = self.create_schedule(
            starts_at=NOW,
        )

        catchup_time = NOW + timedelta(hours=10)

        coordinator = self.coordinator(
            now=catchup_time,
        )

        first = coordinator.run_once()
        second = coordinator.run_once()

        self.assertEqual(first.enqueued, 1)
        self.assertEqual(second.enqueued, 0)

        persisted = self.store.get_schedule_scoped(
            schedule.schedule_id,
            ORG_ID,
        )

        self.assertGreater(
            persisted.next_run_at,
            catchup_time,
        )

        with closing(sqlite3.connect(self.path)) as connection, connection:
            job_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM scan_jobs
                """
            ).fetchone()[0]

            binding_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM job_permits
                """
            ).fetchone()[0]

        self.assertEqual(job_count, 1)
        self.assertEqual(binding_count, 1)


if __name__ == "__main__":
    unittest.main()
