"""P1-11 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
real-PostgreSQL proofs that a transient database outage no longer
permanently kills the recurring-schedule coordinator, mirroring
test_postgres_worker_outage_resilience.py's P1-10 methodology for the
worker but adapted to scheduler semantics, which are genuinely
different: enqueue_due_schedule() has no "already-completed work that
must eventually persist somehow" the way a worker's terminal-state
write does, because the whole operation (job INSERT, permit INSERT,
schedule-advancement UPDATE) was proven -- empirically, in this same
suite -- to be atomic under a mid-method connection failure. That is
what justifies run_forever()'s fix having no nested bounded-retry
helper analogous to worker.py's _persist_terminal_state(): a failed
attempt leaves nothing behind to retry-in-place, so the outer poll
loop re-driving the whole batch on the next iteration is sufficient.

Deliberately real Docker-controlled outages (docker stop/start against
a real, disposable Postgres container), not mocked. Requires a real
database (WEBGUARD_RUN_INTEGRATION=1 and a reachable
WEBGUARD_POSTGRES_TEST_DSN) AND requires `docker` on PATH able to
control a container literally named by
WEBGUARD_P1_11_POSTGRES_CONTAINER -- these tests stop and start that
specific container.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
CONTAINER = os.environ.get("WEBGUARD_P1_11_POSTGRES_CONTAINER")
RUN_OUTAGE_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN) and bool(CONTAINER)
NOW = datetime.now(timezone.utc)


def _docker(*args: str) -> None:
    subprocess.run(["docker", *args], check=False, capture_output=True)


def _stop_postgres() -> None:
    _docker("stop", CONTAINER)


def _start_postgres() -> None:
    _docker("start", CONTAINER)
    for _ in range(20):
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "pg_isready", "-U", "webguard"],
            capture_output=True,
        )
        if result.returncode == 0:
            break
        time.sleep(1)
    # See test_postgres_worker_outage_resilience.py's identical comment:
    # pg_isready succeeding proves the raw server is reachable;
    # WebGuardPostgresPool's own pool can still need a little longer to
    # fully re-establish. This margin is a test-harness concern only.
    time.sleep(3)


@unittest.skipUnless(
    RUN_OUTAGE_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1, WEBGUARD_POSTGRES_TEST_DSN, and "
    "WEBGUARD_P1_11_POSTGRES_CONTAINER (the exact container name these "
    "tests are allowed to docker stop/start) to run this suite.",
)
class PostgresSchedulerOutageResilienceTests(unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.authorizations import AuthorizationRepository
        from webguard_api.permits import TrustScanSigner
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.scheduler import ScanScheduleCoordinator
        from webguard_contracts import OrganizationRole, PrincipalType

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=20)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self.identity = PostgresIdentityRepository(self.pool)
        self.jobs = PostgresJobRepository(self.pool)
        self.signer = TrustScanSigner(os.urandom(32))
        self.addCleanup(self._ensure_postgres_running)

        org = self.identity.create_organization(f"P1-11 Outage Org {uuid.uuid4().hex[:8]}", now=NOW)
        owner = self.identity.create_principal(
            org.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        self.organization_id = org.organization_id
        self.owner_id = owner.principal_id

        self.auth_dir = Path(self._tmp_dir()) / "authorizations"
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.auth_dir, 0o700)
        self.authorizations = AuthorizationRepository(self.auth_dir)

    def _ensure_postgres_running(self) -> None:
        # Belt-and-braces: if a test fails mid-outage, don't leave the
        # container down for the rest of the suite.
        _start_postgres()

    def _tmp_dir(self) -> str:
        import tempfile

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return temp.name

    def _write_authorization(self, *, authorization_id: str, target: str, host: str):
        from webguard_contracts import (
            OwnedTargetAuthorization,
            OwnedTargetLimits,
            write_owned_target_authorization_file,
        )

        auth = OwnedTargetAuthorization(
            authorization_id=authorization_id,
            organization="P1-11 Outage Org",
            authorized_by="Krishna Jonnagaddala",
            target=target,
            allowed_hosts=(host,),
            issued_at=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=30),
            purpose="P1-11 scheduler outage-resilience test fixture",
            limits=OwnedTargetLimits(),
        )
        path = self.auth_dir / f"{uuid.uuid4().hex}.json"
        write_owned_target_authorization_file(auth, path)
        os.chmod(path, 0o600)
        self.identity.assign_authorization(
            self.organization_id, authorization_id, assigned_by=self.owner_id, now=NOW
        )
        return auth

    def _issue_permit(self, *, authorization, permit_id: str | None = None):
        from webguard_contracts import ScanJobMode, TrustScanPermitClaims

        claims = TrustScanPermitClaims(
            permit_id=str(uuid.uuid4()) if permit_id is None else permit_id,
            organization_id=self.organization_id,
            authorization_id=authorization.authorization_id,
            authorization_sha256=authorization.fingerprint,
            target=authorization.target,
            issued_by=self.owner_id,
            issued_at=NOW,
            not_before=NOW,
            expires_at=NOW + timedelta(days=7),
            permitted_modes=(ScanJobMode.CRAWL, ScanJobMode.SINGLE_PAGE),
            allowed_http_methods=("GET", "HEAD"),
            maximum_request_attempts=3,
            maximum_requests_per_second=1.0,
            maximum_concurrency=1,
            active_checks=(),
        )
        signed = self.signer.sign(claims)
        return self.jobs.create_scan_permit(signed)

    def _create_due_schedule(self, *, next_run_at: datetime | None = None, interval_seconds: int = 3600):
        from webguard_contracts import ScanJobMode

        authorization_id = str(uuid.uuid4())
        host = f"{uuid.uuid4().hex[:8]}.example"
        target = f"https://{host}/"
        authorization = self._write_authorization(authorization_id=authorization_id, target=target, host=host)
        permit = self._issue_permit(authorization=authorization)
        schedule = self.jobs.create_schedule(
            organization_id=self.organization_id, created_by=self.owner_id,
            name="P1-11 outage schedule", target=target, authorization_id=authorization_id,
            authorization_sha256=authorization.fingerprint, mode=ScanJobMode.SINGLE_PAGE,
            interval_seconds=interval_seconds, starts_at=next_run_at or (NOW - timedelta(seconds=5)),
            now=NOW, permit_id=permit.permit.claims.permit_id, permit_sha256=permit.permit.fingerprint,
        )
        return schedule

    def _coordinator(self, **overrides) -> "object":
        from webguard_api.scheduler import ScanScheduleCoordinator

        kwargs = dict(
            store=self.jobs, authorizations=self.authorizations, identity=self.identity,
            trustscan_signer=self.signer, poll_seconds=0.5, batch_size=10, clock=lambda: NOW,
        )
        kwargs.update(overrides)
        return ScanScheduleCoordinator(**kwargs)

    def _job_count(self, organization_id: str | None = None) -> int:
        with self.pool.connection() as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM scan_jobs WHERE organization_id = %s",
                (organization_id or self.organization_id,),
            ).fetchone()[0]

    def _schedule_revision(self, schedule_id: str) -> int:
        with self.pool.connection() as connection:
            return connection.execute(
                "SELECT revision FROM scan_schedules WHERE schedule_id = %s", (schedule_id,)
            ).fetchone()[0]

    def _job_count_with_retry(self, organization_id: str | None = None, *, attempts: int = 10) -> int:
        """WebGuardPostgresPool's own pool can need a little longer than
        pg_isready to fully re-establish after a container restart -- a
        test-harness concern only, mirroring
        test_postgres_worker_outage_resilience.py's _get_with_retry."""
        last_exc: Exception | None = None
        for _ in range(attempts):
            try:
                return self._job_count(organization_id)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                time.sleep(1)
        raise AssertionError(f"could not read job count after Postgres recovery: {last_exc!r}")

    # -- 1: DB unavailable before iteration -----------------------------
    def test_01_run_once_raises_when_postgres_unavailable_before_any_read(self) -> None:
        from webguard_api.db_errors import DatabaseError

        coordinator = self._coordinator()
        _stop_postgres()
        try:
            with self.assertRaises(DatabaseError):
                coordinator.run_once()
        finally:
            _start_postgres()

    # -- 2: same loop survives an outage and resumes on DB return, without restart --
    def test_02_run_forever_survives_startup_outage_and_resumes_without_restart(self) -> None:
        schedule = self._create_due_schedule()
        coordinator = self._coordinator(poll_seconds=0.5)
        stop_event = threading.Event()
        died = {"value": None}

        def run() -> None:
            try:
                coordinator.run_forever(stop_event)
            except Exception as exc:  # noqa: BLE001
                died["value"] = exc

        _stop_postgres()
        thread = threading.Thread(target=run, name="p1-11-startup-outage", daemon=True)
        thread.start()
        time.sleep(2.0)
        self.assertTrue(thread.is_alive(), "run_forever() must survive an outage present since before it even started")

        _start_postgres()
        time.sleep(4.0)
        self.assertTrue(thread.is_alive(), "the same instance must still be alive after Postgres recovers")

        materialized = self._wait_for_job_count(schedule.organization_id, expected=1, attempts=15)
        self.assertTrue(materialized, "the same, never-restarted loop must resume and materialize the occurrence")

        stop_event.set()
        thread.join(timeout=3.0)
        self.assertFalse(thread.is_alive())
        self.assertIsNone(died["value"])

    def _wait_for_job_count(self, organization_id: str, *, expected: int, attempts: int = 10) -> bool:
        for _ in range(attempts):
            try:
                if self._job_count(organization_id) >= expected:
                    return True
            except Exception:  # noqa: BLE001 - transient reconnect window
                pass
            time.sleep(1)
        return False

    # -- 3: standalone process (main-thread run_forever) survives an outage present since before it even started --
    def test_03_standalone_main_thread_process_survives_outage(self) -> None:
        # Pre-P1-11, this same script would have exited (non-zero, an
        # uncaught DatabaseError traceback on stderr) the moment
        # run_forever() hit the first list_due_schedules() call -- that
        # was the exact defect this fix closes for `webguard-api
        # scheduler`'s standalone/main-thread deployment mode, not just
        # the threaded `serve` mode. Post-fix, the whole process must
        # now stay up and keep retrying instead.
        script = f"""
import sys, threading
sys.path.insert(0, {str(Path("apps/api/src").resolve())!r})
sys.path.insert(0, {str(Path("packages/contracts/python/src").resolve())!r})
from webguard_api.postgres_pool import WebGuardPostgresPool
from webguard_api.postgres_jobs import PostgresJobRepository
from webguard_api.scheduler import ScanScheduleCoordinator

pool = WebGuardPostgresPool({POSTGRES_TEST_DSN!r})
store = PostgresJobRepository(pool)
scheduler = ScanScheduleCoordinator(
    store=store, authorizations=object(), identity=object(),
    trustscan_signer=object(), poll_seconds=0.5, batch_size=10,
)
stop_event = threading.Event()
print("READY", flush=True)
scheduler.run_forever(stop_event)
print("UNEXPECTED: returned normally", flush=True)
"""
        _stop_postgres()
        proc = subprocess.Popen(
            [sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            ready_line = proc.stdout.readline()
            self.assertEqual(ready_line.strip(), "READY")
            time.sleep(5.0)
            self.assertIsNone(proc.poll(), "the standalone process must still be running, not exited, after an outage")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            _start_postgres()

    # -- 4: combined-mode scheduler thread dies in isolation; it must not take other threads down --
    def test_04_daemon_thread_isolation_matches_combined_serve_mode(self) -> None:
        # Uses the same construction cli.py's `serve` uses for the
        # scheduler thread (daemon=True, target=run_forever) -- an
        # uncaught exception on that thread must not propagate to, or
        # kill, any other thread (mirroring worker/HTTP-server threads
        # staying up in combined `serve` mode).
        def other_thread_work(flag: dict) -> None:
            for _ in range(6):
                time.sleep(0.5)
            flag["completed"] = True

        flag: dict = {"completed": False}
        other = threading.Thread(target=other_thread_work, args=(flag,), daemon=True)
        other.start()

        coordinator = self._coordinator(poll_seconds=0.5)
        stop_event = threading.Event()

        def crash_immediately() -> None:
            raise RuntimeError("simulated unexpected programming error, not a DatabaseError")

        coordinator.run_once = crash_immediately  # type: ignore[method-assign]
        scheduler_thread = threading.Thread(target=coordinator.run_forever, args=(stop_event,), daemon=True)
        scheduler_thread.start()
        scheduler_thread.join(timeout=2.0)
        self.assertFalse(scheduler_thread.is_alive(), "an unexpected exception must still end the scheduler thread")

        other.join(timeout=5.0)
        self.assertTrue(flag["completed"], "other threads (worker/HTTP server) must be unaffected by the scheduler thread's death")

    # -- 5: outage during due-schedule listing (a plain read) ----------
    def test_05_outage_during_list_due_schedules_is_clean(self) -> None:
        from webguard_api.db_errors import DatabaseError

        self._create_due_schedule()
        coordinator = self._coordinator()
        _stop_postgres()
        try:
            with self.assertRaises(DatabaseError):
                coordinator.run_once()
        finally:
            _start_postgres()
        # A read-only failure must leave nothing behind to clean up
        # (checked only once Postgres is back, not while it's still down).
        self.assertEqual(self._job_count_with_retry(), 0)

    # -- 6: outage during job/permit materialization (mid-enqueue, before schedule UPDATE) --
    def test_06_outage_during_materialization_leaves_no_orphan_job(self) -> None:
        import psycopg
        from unittest.mock import patch
        from webguard_api.db_errors import DatabaseError

        schedule = self._create_due_schedule()
        coordinator = self._coordinator()
        real_execute = psycopg.Connection.execute

        def faulty_execute(self_conn, query, params=None, **kwargs):
            text = query if isinstance(query, str) else query.as_string(self_conn)
            if "UPDATE scan_schedules" in text:
                raise psycopg.OperationalError("simulated connection loss before schedule UPDATE")
            return real_execute(self_conn, query, params, **kwargs)

        with patch.object(psycopg.Connection, "execute", faulty_execute):
            with self.assertRaises(DatabaseError):
                coordinator.run_once()

        self.assertEqual(self._job_count(schedule.organization_id), 0, "the scan_jobs INSERT must have rolled back")
        self.assertEqual(self._schedule_revision(schedule.schedule_id), 0, "the schedule must be untouched")

    # -- 7: outage while updating schedule state (after UPDATE, before implicit commit) --
    def test_07_outage_after_schedule_update_before_commit_rolls_back_everything(self) -> None:
        import psycopg
        from unittest.mock import patch
        from webguard_api.db_errors import DatabaseError

        schedule = self._create_due_schedule()
        coordinator = self._coordinator()
        real_execute = psycopg.Connection.execute
        state = {"update_ran": False}

        def faulty_execute(self_conn, query, params=None, **kwargs):
            text = query if isinstance(query, str) else query.as_string(self_conn)
            if state["update_ran"]:
                raise psycopg.OperationalError("simulated connection loss right after the schedule UPDATE")
            result = real_execute(self_conn, query, params, **kwargs)
            if "UPDATE scan_schedules" in text:
                state["update_ran"] = True
            return result

        with patch.object(psycopg.Connection, "execute", faulty_execute):
            with self.assertRaises(DatabaseError):
                coordinator.run_once()

        self.assertEqual(self._job_count(schedule.organization_id), 0, "even a late-stage failure rolls back the whole transaction")
        self.assertEqual(self._schedule_revision(schedule.schedule_id), 0, "revision must not have advanced")

    # -- 8: recovery after a partial attempt -- the SAME occurrence completes cleanly next time --
    def test_08_recovery_after_partial_attempt_completes_the_same_occurrence(self) -> None:
        import psycopg
        from unittest.mock import patch
        from webguard_api.db_errors import DatabaseError

        schedule = self._create_due_schedule()
        coordinator = self._coordinator()
        real_execute = psycopg.Connection.execute

        def faulty_execute(self_conn, query, params=None, **kwargs):
            text = query if isinstance(query, str) else query.as_string(self_conn)
            if "UPDATE scan_schedules" in text:
                raise psycopg.OperationalError("simulated failure")
            return real_execute(self_conn, query, params, **kwargs)

        with patch.object(psycopg.Connection, "execute", faulty_execute):
            with self.assertRaises(DatabaseError):
                coordinator.run_once()

        summary = coordinator.run_once()
        self.assertEqual(summary.enqueued, 1)
        self.assertEqual(self._job_count(schedule.organization_id), 1)
        self.assertEqual(self._schedule_revision(schedule.schedule_id), 1)

    # -- 9: repeated outage does not busy-loop -------------------------
    def test_09_repeated_outage_does_not_busy_loop(self) -> None:
        call_count = {"n": 0}
        coordinator = self._coordinator(poll_seconds=1.0)
        original_run_once = coordinator.run_once

        from webguard_api.db_errors import DatabaseUnavailableError

        def counting_run_once():
            call_count["n"] += 1
            raise DatabaseUnavailableError("simulated_persistent_outage", "simulated persistent outage")

        coordinator.run_once = counting_run_once  # type: ignore[method-assign]
        stop_event = threading.Event()
        thread = threading.Thread(target=coordinator.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        time.sleep(3.5)
        stop_event.set()
        thread.join(timeout=2.0)
        # poll_seconds=1.0 over ~3.5s: at most ~4-5 attempts, never
        # hundreds -- a busy-loop would produce thousands in this window.
        self.assertLessEqual(call_count["n"], 6, f"expected a handful of bounded attempts, got {call_count['n']} (busy-loop?)")
        self.assertGreaterEqual(call_count["n"], 2)

    # -- 10: stop_event stays responsive during an outage backoff wait --
    def test_10_stop_event_responsive_during_outage_backoff(self) -> None:
        coordinator = self._coordinator(poll_seconds=10.0)  # long poll interval

        from webguard_api.db_errors import DatabaseUnavailableError

        def failing_run_once():
            raise DatabaseUnavailableError("simulated_outage", "simulated outage")

        coordinator.run_once = failing_run_once  # type: ignore[method-assign]
        stop_event = threading.Event()
        thread = threading.Thread(target=coordinator.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        time.sleep(0.5)  # let it enter the backoff wait
        started = time.monotonic()
        stop_event.set()
        thread.join(timeout=3.0)
        elapsed = time.monotonic() - started
        self.assertFalse(thread.is_alive())
        self.assertLess(elapsed, 3.0, "stop_event.set() must interrupt the backoff wait promptly, not block for the full poll_seconds")

    # -- 11: a semantic JobStoreError is not treated as an infrastructure retry --
    def test_11_semantic_error_is_not_retried_as_infrastructure(self) -> None:
        from webguard_api.store import JobStoreError

        coordinator = self._coordinator(poll_seconds=0.2)
        call_count = {"n": 0}

        def raising_run_once():
            call_count["n"] += 1
            raise JobStoreError("schedule_enqueue_conflict", "simulated semantic conflict")

        coordinator.run_once = raising_run_once  # type: ignore[method-assign]
        stop_event = threading.Event()
        died = {"value": None}

        def run() -> None:
            try:
                coordinator.run_forever(stop_event)
            except JobStoreError as exc:
                died["value"] = exc

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=2.0)
        self.assertFalse(thread.is_alive(), "a semantic JobStoreError must end the loop, not be silently retried")
        self.assertIsInstance(died["value"], JobStoreError)
        self.assertEqual(call_count["n"], 1, "must not have retried a semantic error")

    # -- 12: an unexpected programming error keeps its existing visibility --
    def test_12_unexpected_programming_error_is_not_absorbed(self) -> None:
        coordinator = self._coordinator(poll_seconds=0.2)

        def raising_run_once():
            raise TypeError("simulated unexpected programming error")

        coordinator.run_once = raising_run_once  # type: ignore[method-assign]
        stop_event = threading.Event()
        died = {"value": None}

        def run() -> None:
            try:
                coordinator.run_forever(stop_event)
            except TypeError as exc:
                died["value"] = exc

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=2.0)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(died["value"], TypeError)

    # -- 13: concurrent scheduler instances after recovery don't duplicate one occurrence --
    def test_13_concurrent_instances_after_recovery_do_not_duplicate(self) -> None:
        schedule = self._create_due_schedule()
        _stop_postgres()
        _start_postgres()
        # Warm the shared pool back up before racing -- _start_postgres()'s
        # margin covers a single connection's worth of reconnection, not
        # necessarily two concurrent ones landing in the same instant.
        self._job_count_with_retry(schedule.organization_id)

        coordinator_a = self._coordinator()
        coordinator_b = self._coordinator()
        results: dict[str, object] = {}
        errors: dict[str, BaseException] = {}
        barrier = threading.Barrier(2)

        def attempt(name: str, coordinator) -> None:
            barrier.wait()
            try:
                results[name] = coordinator.run_once()
            except BaseException as exc:  # noqa: BLE001
                errors[name] = exc

        t1 = threading.Thread(target=attempt, args=("A", coordinator_a))
        t2 = threading.Thread(target=attempt, args=("B", coordinator_b))
        t1.start(); t2.start()
        t1.join(); t2.join()

        self.assertEqual(errors, {}, f"neither racing instance should raise once Postgres has recovered: {errors}")
        total_enqueued = sum(r.enqueued for r in results.values())
        self.assertEqual(total_enqueued, 1, "exactly one of the two racing instances must materialize the occurrence")
        self.assertEqual(self._job_count_with_retry(schedule.organization_id), 1)

    # -- 14: revision CAS intact -----------------------------------------
    def test_14_revision_cas_increments_exactly_once(self) -> None:
        schedule = self._create_due_schedule()
        coordinator = self._coordinator()
        self.assertEqual(self._schedule_revision(schedule.schedule_id), 0)
        summary = coordinator.run_once()
        self.assertEqual(summary.enqueued, 1)
        self.assertEqual(self._schedule_revision(schedule.schedule_id), 1)

    # -- 15: idempotency-key / revision-CAS protection intact ------------
    def test_15_stale_revision_rejects_a_duplicate_enqueue_attempt(self) -> None:
        schedule = self._create_due_schedule()
        permit_id, permit_sha256 = self.jobs.get_schedule_permit_binding(schedule.schedule_id)
        result = self.jobs.enqueue_due_schedule(
            schedule.schedule_id, expected_revision=0, authorization_sha256=schedule.authorization_sha256,
            permit_id=permit_id, permit_sha256=permit_sha256, now=NOW,
        )
        self.assertIsNotNone(result)
        # Same (now-stale) expected_revision=0 again: the CAS rejects it (returns None).
        again = self.jobs.enqueue_due_schedule(
            schedule.schedule_id, expected_revision=0, authorization_sha256=schedule.authorization_sha256,
            permit_id=permit_id, permit_sha256=permit_sha256, now=NOW,
        )
        self.assertIsNone(again)
        self.assertEqual(self._job_count(schedule.organization_id), 1)

    # -- 16: a previously created job is not recreated after a later retry --
    def test_16_previously_created_job_not_recreated_after_retry(self) -> None:
        schedule = self._create_due_schedule()
        coordinator = self._coordinator()
        first = coordinator.run_once()
        self.assertEqual(first.enqueued, 1)
        second = coordinator.run_once()
        self.assertEqual(second.inspected, 0, "the schedule is no longer due immediately after being enqueued")
        self.assertEqual(self._job_count(schedule.organization_id), 1)

    # -- 17: no occurrence is skipped solely because of the new error handling --
    def test_17_no_occurrence_skipped_by_new_error_handling(self) -> None:
        import psycopg
        from unittest.mock import patch
        from webguard_api.db_errors import DatabaseError

        schedule = self._create_due_schedule()
        coordinator = self._coordinator(poll_seconds=0.3)
        real_execute = psycopg.Connection.execute
        fail_once = {"done": False}

        def faulty_execute(self_conn, query, params=None, **kwargs):
            text = query if isinstance(query, str) else query.as_string(self_conn)
            if not fail_once["done"] and "UPDATE scan_schedules" in text:
                fail_once["done"] = True
                raise psycopg.OperationalError("simulated one-time outage")
            return real_execute(self_conn, query, params, **kwargs)

        stop_event = threading.Event()
        with patch.object(psycopg.Connection, "execute", faulty_execute):
            thread = threading.Thread(target=coordinator.run_forever, args=(stop_event,), daemon=True)
            thread.start()
            time.sleep(2.0)
        stop_event.set()
        thread.join(timeout=2.0)

        self.assertEqual(self._job_count(schedule.organization_id), 1, "the occurrence must eventually materialize exactly once, never skipped")
        self.assertEqual(self._schedule_revision(schedule.schedule_id), 1)


if __name__ == "__main__":
    unittest.main()
