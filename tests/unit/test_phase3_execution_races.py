from __future__ import annotations

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
    TrustScanRuntimeSafetyEngine,
    TrustScanRuntimeSafetyError,
)
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobState,
    ScanStatus,
)
from webguard_scanner import SafeHttpResponse, ValidatedTarget

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


SCAN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SCHEDULE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def request(key: str) -> object:
    from webguard_contracts import ScanJobRequest

    return ScanJobRequest(
        idempotency_key=key,
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256="a" * 64,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


def runtime_target() -> ValidatedTarget:
    from urllib.parse import urlsplit

    parsed = urlsplit(TARGET)
    return ValidatedTarget(
        original_url=TARGET,
        normalised_url=TARGET,
        scheme=parsed.scheme,
        hostname=parsed.hostname or "",
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        resolved_addresses=("203.0.113.10",),
    )


def runtime_response() -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(),
        body=b"",
        connected_address="203.0.113.10",
        elapsed_milliseconds=1,
    )


class BarrierScheduleStore(ScanJobStore):
    """Force concurrent schedulers to observe the same due-schedule snapshot."""

    def __init__(self, path: Path, barrier: threading.Barrier):
        self._phase3_barrier = barrier
        super().__init__(path)

    def list_due_schedules(self, *, now, limit=100):
        schedules = super().list_due_schedules(now=now, limit=limit)
        self._phase3_barrier.wait(timeout=10)
        return schedules


class Phase3ExecutionRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _run_threads(*targets) -> list[tuple[str, object]]:
        results: queue.Queue[tuple[str, object]] = queue.Queue()
        barrier = threading.Barrier(len(targets))

        def invoke(name, target):
            try:
                barrier.wait(timeout=10)
                results.put((name, target()))
            except BaseException as exc:
                results.put((name, exc))

        threads = [
            threading.Thread(
                target=invoke,
                args=(f"thread-{index}", target),
                daemon=True,
            )
            for index, target in enumerate(targets)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
            if thread.is_alive():
                self.fail("Phase 3 adversarial thread did not terminate.")

        return [results.get_nowait() for _ in threads]

    def test_two_workers_cannot_claim_one_job_concurrently(self) -> None:
        record, _ = self.store.submit(request("phase3-one-job-race"))

        store_a = ScanJobStore(self.path)
        store_b = ScanJobStore(self.path)

        outcomes = self._run_threads(
            lambda: store_a.claim_next_leased(
                now=NOW,
                worker_id="phase3-worker-a",
                lease_seconds=30,
            ),
            lambda: store_b.claim_next_leased(
                now=NOW,
                worker_id="phase3-worker-b",
                lease_seconds=30,
            ),
        )

        errors = [value for _, value in outcomes if isinstance(value, BaseException)]
        self.assertEqual(errors, [])

        claims = [value for _, value in outcomes if value is not None]
        misses = [value for _, value in outcomes if value is None]

        self.assertEqual(len(claims), 1)
        self.assertEqual(len(misses), 1)
        self.assertEqual(claims[0].record.job_id, record.job_id)

        persisted = self.store.get(record.job_id)
        self.assertIs(persisted.state, ScanJobState.RUNNING)

        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """
                SELECT worker_id, lease_token, attempt_count
                FROM scan_jobs
                WHERE job_id = ?
                """,
                (record.job_id,),
            ).fetchone()

        self.assertIsNotNone(row)
        self.assertIn(row[0], {"phase3-worker-a", "phase3-worker-b"})
        self.assertIsNotNone(row[1])
        self.assertEqual(row[2], 1)

    def test_same_permit_cannot_run_two_jobs_concurrently(self) -> None:
        permit = create_trustscan_permit(self.store)

        first, _ = self.store.submit(
            request("phase3-permit-race-a"),
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )
        second, _ = self.store.submit(
            request("phase3-permit-race-b"),
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )

        store_a = ScanJobStore(self.path)
        store_b = ScanJobStore(self.path)

        outcomes = self._run_threads(
            lambda: store_a.claim_next_leased(
                now=NOW,
                worker_id="phase3-permit-worker-a",
                lease_seconds=30,
            ),
            lambda: store_b.claim_next_leased(
                now=NOW,
                worker_id="phase3-permit-worker-b",
                lease_seconds=30,
            ),
        )

        errors = [value for _, value in outcomes if isinstance(value, BaseException)]
        self.assertEqual(errors, [])

        claims = [value for _, value in outcomes if value is not None]
        self.assertEqual(len(claims), 1)

        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(
                """
                SELECT jobs.job_id, jobs.state
                FROM scan_jobs AS jobs
                JOIN job_permits AS binding
                  ON binding.job_id = jobs.job_id
                WHERE binding.permit_id = ?
                ORDER BY jobs.job_id
                """,
                (permit.permit.claims.permit_id,),
            ).fetchall()

        self.assertEqual({row[0] for row in rows}, {first.job_id, second.job_id})
        self.assertEqual(
            sorted(row[1] for row in rows),
            [ScanJobState.QUEUED.value, ScanJobState.RUNNING.value],
        )

    def test_expired_lease_renewal_cannot_race_recovery_back_to_running(self) -> None:
        record, _ = self.store.submit(request("phase3-renew-recovery-race"))
        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="phase3-expired-worker",
            lease_seconds=1,
        )
        assert lease is not None

        renew_store = ScanJobStore(self.path)
        recovery_store = ScanJobStore(self.path)
        race_time = NOW + timedelta(seconds=2)

        outcomes = self._run_threads(
            lambda: renew_store.renew_lease(
                record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                now=race_time,
                lease_seconds=30,
            ),
            lambda: recovery_store.recover_expired_leases(
                now=race_time,
                maximum_attempts=3,
            ),
        )

        renew_values = []
        recovery_values = []

        for _, value in outcomes:
            if isinstance(value, JobStoreError):
                renew_values.append(value)
            elif hasattr(value, "requeued"):
                recovery_values.append(value)
            elif isinstance(value, BaseException):
                self.fail(f"Unexpected race exception: {value!r}")
            else:
                renew_values.append(value)

        self.assertEqual(len(recovery_values), 1)
        self.assertEqual(recovery_values[0].requeued, 1)

        self.assertEqual(len(renew_values), 1)
        self.assertIsInstance(renew_values[0], JobStoreError)
        self.assertIn(
            renew_values[0].code,
            {"job_lease_expired", "job_lease_lost"},
        )

        persisted = self.store.get(record.job_id)
        self.assertIs(persisted.state, ScanJobState.QUEUED)

        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """
                SELECT worker_id, lease_token, lease_expires_at, attempt_count
                FROM scan_jobs
                WHERE job_id = ?
                """,
                (record.job_id,),
            ).fetchone()

        self.assertEqual(row, (None, None, None, 1))

    def test_stale_completion_and_recovery_have_one_atomic_winner(self) -> None:
        record, _ = self.store.submit(request("phase3-finish-recovery-race"))
        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="phase3-finishing-worker",
            lease_seconds=1,
        )
        assert lease is not None

        finish_store = ScanJobStore(self.path)
        recovery_store = ScanJobStore(self.path)

        outcomes = self._run_threads(
            lambda: finish_store.finish_result_leased(
                record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                scan_id=SCAN_ID,
                result_status=ScanStatus.COMPLETED,
                report_ref=f"jobs/{record.job_id}/report.json",
                audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
                now=NOW + timedelta(milliseconds=500),
            ),
            lambda: recovery_store.recover_expired_leases(
                now=NOW + timedelta(seconds=2),
                maximum_attempts=3,
            ),
        )

        finished = None
        recovery = None
        finish_error = None

        for _, value in outcomes:
            if isinstance(value, JobStoreError):
                finish_error = value
            elif hasattr(value, "requeued"):
                recovery = value
            elif hasattr(value, "state"):
                finished = value
            elif isinstance(value, BaseException):
                self.fail(f"Unexpected race exception: {value!r}")

        self.assertIsNotNone(recovery)

        persisted = self.store.get(record.job_id)
        self.assertNotEqual(persisted.state, ScanJobState.RUNNING)

        if finished is not None:
            self.assertIsNone(finish_error)
            self.assertIs(finished.state, ScanJobState.COMPLETED)
            self.assertEqual(recovery.total, 0)
            self.assertIs(persisted.state, ScanJobState.COMPLETED)
        else:
            self.assertIsNotNone(finish_error)
            self.assertIn(
                finish_error.code,
                {
                    "job_lease_expired",
                    "job_lease_lost",
                    "job_state_transition_invalid",
                },
            )
            self.assertEqual(recovery.requeued, 1)
            self.assertIs(persisted.state, ScanJobState.QUEUED)

    def test_two_schedulers_materialize_due_schedule_only_once(self) -> None:
        auth_dir = self.root / "authorizations"
        write_authorization(auth_dir)

        identity = IdentityStore(self.path)
        identity.create_organization(
            "Phase 3 Tenant",
            now=NOW,
            organization_id=ORG_ID,
        )
        identity.create_principal(
            ORG_ID,
            "Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )
        identity.assign_authorization(
            ORG_ID,
            AUTH_ID,
            assigned_by=OWNER_ID,
            now=NOW,
        )

        permit = create_trustscan_permit(self.store)

        self.store.create_schedule(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name="Phase 3 race",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL,
            interval_seconds=3600,
            starts_at=NOW,
            now=NOW,
            schedule_id=SCHEDULE_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )

        snapshot_barrier = threading.Barrier(2)
        store_a = BarrierScheduleStore(self.path, snapshot_barrier)
        store_b = BarrierScheduleStore(self.path, snapshot_barrier)

        coordinator_a = ScanScheduleCoordinator(
            store=store_a,
            authorizations=AuthorizationRepository(auth_dir),
            identity=IdentityStore(self.path),
            trustscan_signer=trustscan_signer(store_a),
            clock=lambda: NOW,
        )
        coordinator_b = ScanScheduleCoordinator(
            store=store_b,
            authorizations=AuthorizationRepository(auth_dir),
            identity=IdentityStore(self.path),
            trustscan_signer=trustscan_signer(store_b),
            clock=lambda: NOW,
        )

        outcomes: queue.Queue[object] = queue.Queue()

        def run(coordinator):
            try:
                outcomes.put(coordinator.run_once())
            except BaseException as exc:
                outcomes.put(exc)

        threads = [
            threading.Thread(target=run, args=(coordinator_a,), daemon=True),
            threading.Thread(target=run, args=(coordinator_b,), daemon=True),
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
            if thread.is_alive():
                self.fail("Concurrent scheduler did not terminate.")

        summaries = [outcomes.get_nowait() for _ in threads]

        errors = [item for item in summaries if isinstance(item, BaseException)]
        self.assertEqual(errors, [])
        self.assertEqual(sum(item.enqueued for item in summaries), 1)

        with sqlite3.connect(self.path) as connection:
            job_count = connection.execute(
                "SELECT COUNT(*) FROM scan_jobs"
            ).fetchone()[0]

            binding_count = connection.execute(
                "SELECT COUNT(*) FROM job_permits"
            ).fetchone()[0]

            schedule = connection.execute(
                """
                SELECT last_job_id
                FROM scan_schedules
                WHERE schedule_id = ?
                """,
                (SCHEDULE_ID,),
            ).fetchone()

        self.assertEqual(job_count, 1)
        self.assertEqual(binding_count, 1)
        self.assertIsNotNone(schedule)
        self.assertIsNotNone(schedule[0])

    def test_runtime_concurrency_limit_is_atomic_across_threads(self) -> None:
        # TrustScan Permit v1 fixes maximum_concurrency at 1.
        permit = create_trustscan_permit(self.store)
        signer = trustscan_signer(self.store)

        engine = TrustScanRuntimeSafetyEngine(
            permit=permit,
            signer=signer,
            organization_id=ORG_ID,
            job_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            scan_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            target=TARGET,
            revalidate=lambda: None,
            clock=lambda: NOW,
            monotonic=lambda: 0.0,
            sleeper=lambda _seconds: None,
        )

        start = threading.Barrier(2)
        permitted = threading.Event()
        blocked = threading.Event()
        release = threading.Event()
        outcomes: queue.Queue[tuple[str, str]] = queue.Queue()

        def request_worker(name: str) -> None:
            start.wait(timeout=10)
            try:
                engine.before_request(runtime_target(), "GET")
                outcomes.put((name, "permitted"))
                permitted.set()

                if not release.wait(timeout=10):
                    raise RuntimeError("Timed out waiting to release permitted request.")

                engine.after_request(
                    runtime_target(),
                    "GET",
                    runtime_response(),
                    None,
                )
            except TrustScanRuntimeSafetyError as exc:
                outcomes.put((name, exc.code))
                blocked.set()

        threads = [
            threading.Thread(
                target=request_worker,
                args=("worker-a",),
                daemon=True,
            ),
            threading.Thread(
                target=request_worker,
                args=("worker-b",),
                daemon=True,
            ),
        ]

        for thread in threads:
            thread.start()

        self.assertTrue(permitted.wait(timeout=10))
        self.assertTrue(blocked.wait(timeout=10))
        release.set()

        for thread in threads:
            thread.join(timeout=15)
            if thread.is_alive():
                self.fail("Runtime safety concurrency thread did not terminate.")

        results = [outcomes.get_nowait() for _ in range(2)]
        statuses = sorted(status for _, status in results)

        self.assertEqual(
            statuses,
            ["permitted", "trustscan_runtime_concurrency_exceeded"],
        )
        self.assertEqual(engine.requests_attempted, 2)
        self.assertEqual(engine.requests_permitted, 1)
        self.assertEqual(engine.requests_blocked, 1)
        self.assertEqual(engine.peak_concurrency, 1)


if __name__ == "__main__":
    unittest.main()
