"""P1-10 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
real-PostgreSQL proofs that a transient database outage no longer
permanently kills the worker, at every point this batch's live
investigation found the same exception-boundary problem: before a job
is even claimed, during terminal-state persistence (finish/fail/
cancel), and during heartbeat/lease renewal.

Deliberately real Docker-controlled outages (docker stop/start against
a real, disposable Postgres container), not mocked -- the claim this
suite proves is about actual worker-process/thread survival, which a
fake database object cannot demonstrate. The retry-logic MECHANICS
themselves (exact bounded attempt counts, no-retry-on-semantic-error,
no busy-loop, stop_event responsiveness) are proven fast and
deterministically in tests/unit/test_worker_outage_resilience.py
instead; this file exists to prove the real end-to-end claim on top of
that.

Requires a real database (WEBGUARD_RUN_INTEGRATION=1 and a reachable
WEBGUARD_POSTGRES_TEST_DSN) AND requires `docker` on PATH able to
control a container literally named by WEBGUARD_P1_10_POSTGRES_CONTAINER
(defaults to "webguard-p110-postgres") -- these tests stop and start
that specific container. They are skipped unless both the standard
integration-DSN gate and that container name are explicitly set, since
unlike every other Postgres integration test in this repository, these
also assume ownership of the container's lifecycle, not just its
schema.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
CONTAINER = os.environ.get("WEBGUARD_P1_10_POSTGRES_CONTAINER")
RUN_OUTAGE_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN) and bool(CONTAINER)
NOW = datetime.now(timezone.utc)

# P1-2 Phase H: claim_next_leased and recover_expired_leases now run
# entirely through webguard_control functions under worker_tenant_data
# (see postgres_pool.py's role_scoped_connection and postgres_jobs.py's
# own methods), so this file needs the same role/ACL/function/
# runtime-grant bootstrap tests/contract/test_identity_repository_contract.py's
# own setUpClass applies, in the same order.
_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
_ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
_TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
_FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
_CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"
_RUNTIME_GRANT_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_runtime_grant.sql"
_ALL_BOOTSTRAP_ROLES = (
    "api_tenant_data",
    "worker_tenant_data",
    "scheduler_tenant_data",
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
)


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
    # pg_isready succeeding proves the server accepts TCP connections;
    # WebGuardPostgresPool's own connection pool can still need a
    # little longer to fully re-establish (its background connection
    # thread reconnects on its own schedule). A few seconds of margin
    # here is a test-harness concern -- it keeps a single test from
    # needing two independent retry windows back to back (e.g. a claim
    # immediately followed by a terminal-persistence write) to both
    # land after the pool is genuinely ready, not just after the raw
    # server is.
    time.sleep(3)


@unittest.skipUnless(
    RUN_OUTAGE_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1, WEBGUARD_POSTGRES_TEST_DSN, and "
    "WEBGUARD_P1_10_POSTGRES_CONTAINER (the exact container name these "
    "tests are allowed to docker stop/start) to run this suite.",
)
class PostgresWorkerOutageResilienceTests(unittest.TestCase):
    @classmethod
    def _connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def setUpClass(cls) -> None:
        for sql_path in (
            _ROLES_SQL_PATH,
            _TENANT_ACL_SQL_PATH,
            _FUNCTION_ACL_SQL_PATH,
            _CONTROL_FUNCTIONS_SQL_PATH,
            _RUNTIME_GRANT_SQL_PATH,
        ):
            with cls._connect() as connection:
                connection.execute(sql_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        with cls._connect() as connection:
            connection.autocommit = True
            connection.execute("DROP SCHEMA IF EXISTS webguard_control CASCADE")
            for role in _ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_findings import PostgresFindingRepository

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=20)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self.identity = PostgresIdentityRepository(self.pool)
        self.jobs = PostgresJobRepository(self.pool)
        self.findings = PostgresFindingRepository(self.pool)
        self.organization_id, self.owner_id = self._make_organization_and_owner()
        self.addCleanup(self._ensure_postgres_running)

    def _ensure_postgres_running(self) -> None:
        # Belt-and-braces: if a test fails mid-outage, don't leave the
        # container down for the rest of the suite.
        _start_postgres()

    def _make_organization_and_owner(self):
        from webguard_contracts import OrganizationRole, PrincipalType

        org = self.identity.create_organization(f"P1-10 Outage Org {uuid4().hex[:8]}", now=NOW)
        owner = self.identity.create_principal(
            org.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        return org.organization_id, owner.principal_id

    def _submit_claimable_job(self, *, idempotency_key: str | None = None):
        from webguard_contracts import ScanJobMode, ScanJobRequest

        authorization_id = str(uuid4())
        self.identity.assign_authorization(self.organization_id, authorization_id, assigned_by=self.owner_id, now=NOW)
        request = ScanJobRequest(
            idempotency_key=idempotency_key or f"p1-10-outage-{uuid4().hex}",
            target="https://p1-10-outage.example/", authorization_id=authorization_id,
            authorization_sha256="a" * 64, mode=ScanJobMode.SINGLE_PAGE, submitted_at=NOW,
        )
        record, _ = self.jobs.submit(request, organization_id=self.organization_id, submitted_by=self.owner_id)
        return record

    def _get_with_retry(self, job_id: str, *, attempts: int = 10):
        """_start_postgres() already waits for pg_isready, but
        WebGuardPostgresPool's own connection pool can need a little
        longer to actually re-establish after the container restarts.
        A short local retry here is a test-harness concern, not
        something the fix itself needs -- by the time a real
        deployment's pool reconnects, the worker has already moved on."""

        last_exc = None
        for _ in range(attempts):
            try:
                return self.jobs.get(job_id)
            except Exception as exc:  # noqa: BLE001 - deliberately broad, this is a test-harness retry
                last_exc = exc
                time.sleep(1)
        raise AssertionError(f"could not read job {job_id} after Postgres recovery: {last_exc!r}")

    def _worker(self, executor, **overrides):
        from webguard_api.worker import ScanJobWorker

        kwargs = dict(
            store=self.jobs, executor=executor, worker_id=f"p1-10-outage-{uuid4().hex[:8]}",
            lease_seconds=30, terminal_persistence_maximum_attempts=3,
            terminal_persistence_retry_backoff_seconds=0.5, heartbeat_retry_backoff_seconds=0.5,
        )
        kwargs.update(overrides)
        return ScanJobWorker(**kwargs)

    @staticmethod
    def _succeeding_outcome():
        from webguard_contracts import ScanStatus

        return SimpleNamespace(
            report=SimpleNamespace(scan_id=str(uuid4()), status=ScanStatus.COMPLETED),
            report_ref="jobs/x/report.json", audit_ref="jobs/x/audit.json",
            safety_receipt_ref=None, safety_receipt_sha256=None,
        )

    # -- A/B: Postgres unavailable before recover_expired_leases()/claim_next_leased() --
    def test_a_b_run_once_raises_when_postgres_unavailable_before_any_claim(self) -> None:
        """A raw run_once() call (e.g. `--once` CLI mode) legitimately
        still raises here -- by design, see worker.py's own module
        docstring: neither call holds in-progress work a retry could
        lose, so resilience for this case lives at run_forever()'s
        boundary (proven separately below), not inside run_once()
        itself."""

        worker = self._worker(SimpleNamespace(execute=lambda *a, **k: self.fail("must not be reached")))
        _stop_postgres()
        try:
            from webguard_api.db_errors import DatabaseError

            with self.assertRaises(DatabaseError):
                worker.run_once()
        finally:
            _start_postgres()

    # -- C: Postgres unavailable at worker startup, recovers, SAME run_forever() instance resumes --
    def test_c_run_forever_survives_startup_outage_and_resumes_without_restart(self) -> None:
        record = self._submit_claimable_job()
        worker = self._worker(SimpleNamespace(execute=lambda *a, **k: self._succeeding_outcome()), poll_seconds=0.25)
        stop_event = threading.Event()
        died = {"value": None}

        def run():
            try:
                worker.run_forever(stop_event)
            except Exception as exc:
                died["value"] = exc

        _stop_postgres()
        thread = threading.Thread(target=run, name="p1-10-c", daemon=True)
        thread.start()
        time.sleep(2.0)
        self.assertTrue(thread.is_alive(), "run_forever() must survive an outage present since before it even started")
        _start_postgres()
        time.sleep(3.0)
        self.assertTrue(thread.is_alive(), "the same instance must still be alive after Postgres recovers")

        final = self._get_with_retry(record.job_id)
        self.assertEqual(final.state.value, "completed", "the same worker must have resumed and completed the job without a restart")

        stop_event.set()
        thread.join(timeout=3.0)
        self.assertFalse(thread.is_alive())
        self.assertIsNone(died["value"])

    # -- D: executor raises, DB healthy -> normal FAILED behavior unchanged --
    def test_d_normal_failure_unchanged_when_postgres_healthy(self) -> None:
        record = self._submit_claimable_job()
        worker = self._worker(SimpleNamespace(execute=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bug"))))
        processed = worker.run_once()
        self.assertTrue(processed)
        final = self._get_with_retry(record.job_id)
        self.assertEqual(final.state.value, "failed")
        self.assertEqual(final.error_code, "worker_internal_error")

    # -- E: executor raises, DB unavailable during _fail() -> worker survives, job recoverable --
    def test_e_executor_raises_during_outage_worker_survives_job_recoverable(self) -> None:
        record = self._submit_claimable_job()

        def slow_raising_execute(*args, **kwargs):
            time.sleep(1.2)
            raise RuntimeError("simulated bug, not Postgres-caused")

        worker = self._worker(SimpleNamespace(execute=slow_raising_execute))
        threading.Thread(target=lambda: (time.sleep(0.4), _stop_postgres()), daemon=True).start()
        try:
            processed = worker.run_once()
            self.assertTrue(processed, "run_once() must return normally, not raise")
        finally:
            _start_postgres()
        final = self._get_with_retry(record.job_id)
        self.assertEqual(final.state.value, "running", "the job must be left RUNNING, not falsely FAILED")
        self.assertIsNone(final.error_code)

    # -- F: executor succeeds, DB unavailable during _finish_result() -> worker survives, no false completion --
    def test_f_finish_result_during_outage_no_false_completion(self) -> None:
        record = self._submit_claimable_job()
        lease = self.jobs.claim_next_leased(now=NOW, worker_id="p1-10-f-worker", lease_seconds=30)
        outcome = self._succeeding_outcome()
        worker = self._worker(SimpleNamespace(execute=lambda *a, **k: outcome), worker_id="p1-10-f-worker")

        _stop_postgres()
        try:
            result = worker._finish_result(lease, outcome)
            self.assertFalse(result, "must report the write did NOT succeed")
        finally:
            _start_postgres()
        final = self._get_with_retry(record.job_id)
        self.assertEqual(final.state.value, "running")
        self.assertIsNone(final.result_status)

    # -- G: cancellation terminal persistence during outage -> worker survives, no fabricated CANCELLED --
    def test_g_cancellation_persistence_during_outage_no_fabricated_state(self) -> None:
        record = self._submit_claimable_job()

        def cancellation_aware_execute(record_arg, *, cancellation_token=None):
            time.sleep(1.0)
            from webguard_api.executor import JobExecutionError

            if cancellation_token is not None and cancellation_token.is_cancelled:
                raise JobExecutionError("job_cancelled_before_execution", "Cancelled.")
            raise AssertionError("cancellation was not observed by the executor")

        worker = self._worker(SimpleNamespace(execute=cancellation_aware_execute), heartbeat_seconds=1.0, poll_seconds=0.1)

        def cancel_then_kill():
            time.sleep(0.3)
            self.jobs.request_cancellation(record.job_id, now=datetime.now(timezone.utc))
            time.sleep(0.3)
            _stop_postgres()

        threading.Thread(target=cancel_then_kill, daemon=True).start()
        try:
            processed = worker.run_once()
            self.assertTrue(processed)
        finally:
            _start_postgres()
        final = self._get_with_retry(record.job_id)
        self.assertEqual(final.state.value, "running", "must not fabricate CANCELLED if it was never durably persisted")

    # -- H: lease renewal transient outage -> monitor thread survives --
    def test_h_lease_renewal_transient_outage_monitor_survives(self) -> None:
        record = self._submit_claimable_job()

        def slow_execute(*args, **kwargs):
            time.sleep(3.0)
            return self._succeeding_outcome()

        worker = self._worker(SimpleNamespace(execute=slow_execute), heartbeat_seconds=1.0, poll_seconds=0.1)

        def kill_briefly():
            time.sleep(1.2)
            _stop_postgres()
            time.sleep(1.0)
            _start_postgres()

        threading.Thread(target=kill_briefly, daemon=True).start()
        processed = worker.run_once()
        self.assertTrue(processed)
        final = self._get_with_retry(record.job_id)
        self.assertEqual(final.state.value, "completed", "the main loop must be unaffected by the transient renewal outage")

    # -- J: Postgres recovers before retry budget exhausted -> terminal result persists normally --
    def test_j_postgres_recovers_within_retry_budget_persists_normally(self) -> None:
        record = self._submit_claimable_job()
        # Real wall-clock time, not the module-level NOW constant --
        # this test constructs a real ScanJobWorker, whose own
        # _finish_result() compares the lease's expiry against real
        # self.clock() (actual current time), not the synthetic NOW
        # this suite's other, purely-repository-level tests use.
        claim_now = datetime.now(timezone.utc)
        lease = self.jobs.claim_next_leased(now=claim_now, worker_id="p1-10-j-worker", lease_seconds=30)
        outcome = self._succeeding_outcome()
        worker = self._worker(
            SimpleNamespace(execute=lambda *a, **k: outcome), worker_id="p1-10-j-worker",
            terminal_persistence_maximum_attempts=3, terminal_persistence_retry_backoff_seconds=0.5,
        )

        _stop_postgres()

        def recover_mid_retry():
            time.sleep(1.0)  # inside the retry window, before all 3 attempts exhaust
            _start_postgres()

        threading.Thread(target=recover_mid_retry, daemon=True).start()
        result = worker._finish_result(lease, outcome)
        self.assertTrue(result, "recovery within the retry budget must let the write succeed")
        final = self._get_with_retry(record.job_id)
        self.assertEqual(final.state.value, "completed")

    # -- L: lease expires after abandonment -> recovery requeues job --
    def test_l_lease_expires_after_abandonment_recovery_requeues(self) -> None:
        record = self._submit_claimable_job()
        lease = self.jobs.claim_next_leased(now=NOW, worker_id="p1-10-l-worker", lease_seconds=1)
        outcome = self._succeeding_outcome()
        worker = self._worker(SimpleNamespace(execute=lambda *a, **k: outcome), worker_id="p1-10-l-worker")

        _stop_postgres()
        try:
            result = worker._finish_result(lease, outcome)
            self.assertFalse(result)
        finally:
            _start_postgres()

        summary = self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=3), maximum_attempts=3)
        self.assertEqual(summary.requeued, 1, "the abandoned attempt must be reclaimable via the existing lease-expiry mechanism")
        requeued = self._get_with_retry(record.job_id)
        self.assertEqual(requeued.state.value, "queued")

    # -- M/N: second worker reclaims (one winner), stale original worker rejected --
    def test_m_n_second_worker_reclaims_and_original_stale_worker_is_rejected(self) -> None:
        record = self._submit_claimable_job()
        lease_a = self.jobs.claim_next_leased(now=NOW, worker_id="p1-10-mn-a", lease_seconds=1)
        outcome = self._succeeding_outcome()

        _stop_postgres()
        try:
            worker_a = self._worker(SimpleNamespace(execute=lambda *a, **k: outcome), worker_id="p1-10-mn-a")
            self.assertFalse(worker_a._finish_result(lease_a, outcome))
        finally:
            _start_postgres()

        self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=3), maximum_attempts=3)
        lease_b = self.jobs.claim_next_leased(now=NOW + timedelta(seconds=4), worker_id="p1-10-mn-b", lease_seconds=30)
        self.assertIsNotNone(lease_b, "the reclaiming worker must win the requeued job")

        finished = self.jobs.finish_result_leased(
            record.job_id, worker_id=lease_b.worker_id, lease_token=lease_b.lease_token,
            scan_id=outcome.report.scan_id, result_status=outcome.report.status,
            report_ref="x.json", audit_ref="x.json", now=NOW + timedelta(seconds=5),
        )
        self.assertEqual(finished.state.value, "completed")

        from webguard_api.store import JobStoreError

        with self.assertRaises(JobStoreError) as caught:
            self.jobs.finish_result_leased(
                record.job_id, worker_id=lease_a.worker_id, lease_token=lease_a.lease_token,
                scan_id=outcome.report.scan_id, result_status=outcome.report.status,
                report_ref="y.json", audit_ref="y.json", now=NOW + timedelta(seconds=6),
            )
        # Worker B already moved the job to COMPLETED, so
        # _terminal_update()'s own state check ("only running jobs can
        # enter a terminal worker state") fires before the lease/CAS
        # check ever runs -- still an unconditional rejection of the
        # stale worker's attempt, just via the row's state rather than
        # its lease fields specifically.
        self.assertEqual(caught.exception.code, "job_state_transition_invalid", "the original, now-stale worker must be rejected by the unchanged CAS")

    # -- O: duplicate execution from a lost heartbeat -> at most one persisted result, dedup intact --
    def test_o_duplicate_execution_from_expired_lease_dedup_intact(self) -> None:
        """Simulates the scenario this batch's own investigation named
        under DUPLICATE-EXECUTION RISK: a lease lapses (here, directly,
        without needing a real multi-second heartbeat-outage window) while
        the "original" worker is still conceptually executing; a second
        worker reclaims and finishes first; the original's later
        completion attempt must be rejected, and if both had recorded the
        identical finding, the tenant-scoped upsert must still leave
        exactly one row."""

        from webguard_api.postgres_scans import PostgresScanRepository

        scans = PostgresScanRepository(self.pool)
        record = self._submit_claimable_job()
        fingerprint = f"p1-10-dup-{uuid4().hex}"
        lease_a = self.jobs.claim_next_leased(now=NOW, worker_id="p1-10-o-a", lease_seconds=1)

        scan_a = scans.create_scan(
            organization_id=self.organization_id, job_id=record.job_id, target="https://p1-10-outage.example/",
            authorization_id=record.request.authorization_id, mode="single_page", scanner_version="0.1.0", now=NOW,
        )
        self.findings.record_finding(
            organization_id=self.organization_id, scan_id=scan_a.scan_id, fingerprint=fingerprint,
            check_id="active.ssrf.callback.confirmed", scanner_version="0.1.0", title="SSRF finding",
            severity="high", confidence="confirmed", asset="https://p1-10-outage.example/",
            endpoint="/fetch", http_method="GET", now=NOW,
        )

        # Original worker's lease lapses (simulating a lost-heartbeat
        # window); a second worker reclaims and finishes first.
        self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        lease_b = self.jobs.claim_next_leased(now=NOW + timedelta(seconds=3), worker_id="p1-10-o-b", lease_seconds=30)
        self.assertIsNotNone(lease_b)
        scan_b = scans.create_scan(
            organization_id=self.organization_id, job_id=record.job_id, target="https://p1-10-outage.example/",
            authorization_id=record.request.authorization_id, mode="single_page", scanner_version="0.1.0",
            now=NOW + timedelta(seconds=3),
        )
        self.findings.record_finding(
            organization_id=self.organization_id, scan_id=scan_b.scan_id, fingerprint=fingerprint,
            check_id="active.ssrf.callback.confirmed", scanner_version="0.1.0", title="SSRF finding",
            severity="high", confidence="confirmed", asset="https://p1-10-outage.example/",
            endpoint="/fetch", http_method="GET", now=NOW + timedelta(seconds=3),
        )
        self.jobs.finish_result_leased(
            record.job_id, worker_id=lease_b.worker_id, lease_token=lease_b.lease_token,
            scan_id=scan_b.scan_id, result_status=__import__("webguard_contracts").ScanStatus.COMPLETED,
            report_ref="b.json", audit_ref="b.json", now=NOW + timedelta(seconds=4),
        )

        # The stale original worker's own later completion attempt.
        from webguard_api.store import JobStoreError

        with self.assertRaises(JobStoreError) as caught:
            self.jobs.finish_result_leased(
                record.job_id, worker_id=lease_a.worker_id, lease_token=lease_a.lease_token,
                scan_id=scan_a.scan_id, result_status=__import__("webguard_contracts").ScanStatus.COMPLETED,
                report_ref="a.json", audit_ref="a.json", now=NOW + timedelta(seconds=5),
            )
        # Same reasoning as test_m_n: worker B already completed the
        # job, so the state check rejects worker A before the lease
        # check is reached.
        self.assertEqual(caught.exception.code, "job_state_transition_invalid")

        with self.pool.connection() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM findings WHERE organization_id = %s AND fingerprint = %s",
                (self.organization_id, fingerprint),
            ).fetchone()[0]
        self.assertEqual(count, 1, "the tenant-scoped upsert must leave exactly one finding row, never a duplicate")

    # -- P: one problematic job/outage does not permanently prevent later jobs from processing --
    def test_p_one_bad_outage_does_not_prevent_later_jobs_once_postgres_returns(self) -> None:
        record_1 = self._submit_claimable_job(idempotency_key=f"p1-10-p-first-{uuid4().hex}")
        record_2 = self._submit_claimable_job(idempotency_key=f"p1-10-p-second-{uuid4().hex}")

        call_count = {"n": 0}

        def execute(record_arg, *, cancellation_token=None):
            call_count["n"] += 1
            if call_count["n"] == 1:
                time.sleep(1.2)
                raise RuntimeError("first job hits a bug during the outage")
            return self._succeeding_outcome()

        # A larger internal retry budget than this suite's other tests
        # use -- this specific test's second run_once() call needs the
        # connection pool ready for BOTH the claim step and the finish
        # step back to back, immediately after container restart; a
        # generous budget absorbs pool-warmup variance within
        # run_once()'s own retry loop rather than needing the test's
        # outer retry-the-whole-call loop to help (which it can't: a
        # successfully-abandoned attempt makes run_once() return True,
        # not raise, so the outer loop has nothing to retry on).
        worker = self._worker(
            SimpleNamespace(execute=execute), poll_seconds=0.1,
            terminal_persistence_maximum_attempts=5, terminal_persistence_retry_backoff_seconds=1.0,
        )
        threading.Thread(target=lambda: (time.sleep(0.4), _stop_postgres()), daemon=True).start()
        try:
            worker.run_once()  # first job: executor raises while Postgres is down; abandoned safely
        finally:
            _start_postgres()

        # Later run_once() calls, once Postgres is back, must still be
        # able to process jobs normally. Call it repeatedly (bounded)
        # rather than assuming exactly one call suffices: record_1 was
        # abandoned RUNNING with its own still-live lease, submitted
        # before record_2, so a call that happens to land after enough
        # wall-clock time has passed for record_1's lease to expire may
        # legitimately reclaim record_1 first (claim_next_leased()
        # always picks the oldest submitted QUEUED job) rather than
        # reaching record_2 on its very first opportunity -- that is
        # correct, expected recovery behavior (A2), not a failure of
        # this fix. What this test actually asserts is that record_2
        # eventually processes normally, not that one specific call
        # reaches it. The connection pool can also need a little
        # longer than pg_isready to fully re-establish, so failed
        # attempts are retried too.
        final_2 = None
        last_exc = None
        for _ in range(15):
            try:
                worker.run_once()
            except Exception as exc:  # noqa: BLE001 - test-harness retry for pool reconnection lag
                last_exc = exc
                time.sleep(1)
                continue
            final_2 = self.jobs.get(record_2.job_id)
            if final_2.state.value != "queued":
                break
            time.sleep(0.5)
        self.assertIsNotNone(final_2, f"run_once() never succeeded after recovery: {last_exc!r}")
        self.assertEqual(final_2.state.value, "completed", "a later job must process normally once Postgres returns")

    # -- P1-B1: structured events during a REAL outage/recovery, edge-triggered --
    def test_p1b1_database_outage_events_are_edge_triggered_during_a_real_outage(self) -> None:
        """Does not alter run_forever()'s actual outage-survival
        outcome (proven unchanged by every other test in this suite) --
        purely layers a structured-logging assertion on top of the
        identical real docker stop/start cycle test_c above already
        uses, to prove database_outage_detected/_recovered fire
        exactly once each against a genuine outage, not a mock."""
        import io
        import json

        from webguard_api.structured_logging import configure_structured_logging

        buf = io.StringIO()
        configure_structured_logging(service="worker", stream=buf)

        worker = self._worker(SimpleNamespace(execute=lambda *a, **k: self._succeeding_outcome()), poll_seconds=0.25)
        stop_event = threading.Event()
        _stop_postgres()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), name="p1b1-worker-events", daemon=True)
        thread.start()
        time.sleep(2.0)
        self.assertTrue(thread.is_alive())
        _start_postgres()
        time.sleep(3.0)
        self.assertTrue(thread.is_alive())
        stop_event.set()
        thread.join(timeout=3.0)

        lines = [json.loads(line) for line in buf.getvalue().splitlines() if line]
        detected = [line for line in lines if line.get("event") == "database_outage_detected"]
        recovered = [line for line in lines if line.get("event") == "database_outage_recovered"]
        self.assertEqual(len(detected), 1, f"expected exactly one detected event, got {len(detected)}")
        self.assertEqual(len(recovered), 1, f"expected exactly one recovered event, got {len(recovered)}")

    def test_p1b2_internal_healthz_stays_up_and_ready_flips_during_a_real_outage(self) -> None:
        """Does not alter run_forever()'s actual outage-survival
        outcome -- layers a real HealthServer, wired exactly the way
        cli.py::_worker_command wires it (progress_healthy() for
        liveness, progress_healthy() AND a health-bounded
        pool.check_connectivity() for readiness), on top of the
        identical real docker stop/start cycle the rest of this suite
        already uses.

        Pre-commit correction: samples /healthz repeatedly across a
        real outage lasting ~9s -- longer than the corrected
        DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS (7.0s) -- since
        an earlier, shorter (2s) single check did not actually exercise
        the gap a real (not fake-injected) DatabaseError from
        run_once()'s own first DB call can legitimately produce."""
        from webguard_api.health_server import HealthServer

        worker = self._worker(SimpleNamespace(execute=lambda *a, **k: self._succeeding_outcome()), poll_seconds=0.25)

        def liveness():
            return worker.progress_healthy(), "worker_progress_stalled"

        def readiness():
            if not worker.progress_healthy():
                return False, "worker_progress_stalled"
            try:
                self.pool.check_connectivity(timeout_seconds=1.0)
            except Exception:  # noqa: BLE001 - matches cli.py's own composition exactly
                return False, "worker_dependency_unavailable"
            return True, "ready"

        health = HealthServer(service="worker", liveness_check=liveness, readiness_check=readiness, port=0)
        health.start()
        self.addCleanup(health.stop)

        stop_event = threading.Event()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), name="p1b2-worker-health", daemon=True)
        thread.start()
        self.addCleanup(lambda: (stop_event.set(), thread.join(timeout=3.0)))

        import json
        import urllib.error
        import urllib.request

        def _get(path: str):
            try:
                response = urllib.request.urlopen(health.base_url + path, timeout=8)
                return response.status, json.loads(response.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        status, _ = _get("ready")
        self.assertEqual(status, 200, "must be ready before the outage starts")

        _stop_postgres()
        healthz_statuses = []
        deadline = time.monotonic() + 9.0
        while time.monotonic() < deadline:
            status, _ = _get("healthz")
            healthz_statuses.append(status)
            time.sleep(1.0)
        self.assertTrue(thread.is_alive())
        self.assertTrue(
            all(status == 200 for status in healthz_statuses),
            f"liveness must stay healthy throughout a real ~9s outage (the loop is still turning, just slower "
            f"than usual), got {healthz_statuses}",
        )
        status, body = _get("ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["reason"], "worker_dependency_unavailable")

        _start_postgres()
        time.sleep(3.0)
        self.assertTrue(thread.is_alive())
        status, body = _get("ready")
        self.assertEqual(status, 200, "must recover in the SAME process, no restart")


if __name__ == "__main__":
    unittest.main()
