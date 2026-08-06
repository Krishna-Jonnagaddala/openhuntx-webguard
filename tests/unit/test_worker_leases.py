from __future__ import annotations

import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_api import (
    JobExecutionError,
    JobExecutionOutcome,
    ScanJobStore,
    ScanJobWorker,
)
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanJobState

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    TARGET,
    authorization,
    completed_report,
)


class CountingStore(ScanJobStore):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.renewed = threading.Event()
        self.renew_count = 0

    def renew_lease(self, *args, **kwargs):
        result = super().renew_lease(*args, **kwargs)
        self.renew_count += 1
        self.renewed.set()
        return result


class FakeExecutor:
    def __init__(self, outcome=None):
        self.outcome = outcome
        self.calls = []

    def execute(self, record, *, cancellation_token):
        self.calls.append((record, cancellation_token))
        return self.outcome


class BlockingExecutor:
    def __init__(self, store: CountingStore, outcome) -> None:
        self.store = store
        self.outcome = outcome

    def execute(self, record, *, cancellation_token):
        if not self.store.renewed.wait(timeout=1.0):
            raise RuntimeError("worker lease heartbeat was not observed")
        return self.outcome


class CancellationHeartbeatExecutor:
    def __init__(self, store: CountingStore) -> None:
        self.store = store

    def execute(self, record, *, cancellation_token):
        self.store.request_cancellation(
            record.job_id,
            now=datetime.now(timezone.utc),
        )
        self.store.renewed.clear()
        deadline = time.monotonic() + 1.0
        while not cancellation_token.is_cancelled and time.monotonic() < deadline:
            time.sleep(0.005)
        if not cancellation_token.is_cancelled:
            raise RuntimeError("worker cancellation was not observed")
        if not self.store.renewed.wait(timeout=1.0):
            raise RuntimeError("lease heartbeat stopped after cancellation")
        raise JobExecutionError(
            "job_cancelled_before_execution",
            "The scan job was cancelled.",
        )


class WorkerLeaseRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        auth = authorization()
        self.request = ScanJobRequest(
            idempotency_key="worker-lease-recovery",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_new_worker_recovers_expired_job_and_completes_it(self) -> None:
        record, _ = self.store.submit(self.request)
        first = self.store.claim_next_leased(
            now=NOW,
            worker_id="dead-worker",
            lease_seconds=1,
        )
        assert first is not None

        report = completed_report("11111111-2222-4333-8444-555555555555")
        executor = FakeExecutor(
            JobExecutionOutcome(
                report=report,
                report_ref=f"jobs/{record.job_id}/report.json",
                audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
            )
        )
        worker = ScanJobWorker(
            store=self.store,
            executor=executor,
            worker_id="replacement-worker",
            lease_seconds=30,
            heartbeat_seconds=10,
            maximum_attempts=3,
            clock=lambda: NOW + timedelta(seconds=2),
        )

        self.assertTrue(worker.run_once())
        self.assertEqual(worker.last_recovery_summary.requeued, 1)
        completed = self.store.get(record.job_id)
        self.assertIs(completed.state, ScanJobState.COMPLETED)
        self.assertEqual(len(executor.calls), 1)

    def test_worker_renews_lease_while_execution_is_running(self) -> None:
        counting_store = CountingStore(self.root / "heartbeat.sqlite3")
        record, _ = counting_store.submit(self.request)
        report = completed_report("11111111-2222-4333-8444-555555555555")
        outcome = JobExecutionOutcome(
            report=report,
            report_ref=f"jobs/{record.job_id}/report.json",
            audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
        )
        worker = ScanJobWorker(
            store=counting_store,
            executor=BlockingExecutor(counting_store, outcome),
            worker_id="heartbeat-worker",
            poll_seconds=0.01,
            lease_seconds=1.0,
            heartbeat_seconds=0.05,
            maximum_attempts=3,
        )

        self.assertTrue(worker.run_once())
        self.assertGreaterEqual(counting_store.renew_count, 1)
        self.assertIs(
            counting_store.get(record.job_id).state,
            ScanJobState.COMPLETED,
        )

    def test_worker_keeps_lease_alive_after_cancellation_is_observed(self) -> None:
        counting_store = CountingStore(self.root / "cancel-heartbeat.sqlite3")
        record, _ = counting_store.submit(self.request)
        worker = ScanJobWorker(
            store=counting_store,
            executor=CancellationHeartbeatExecutor(counting_store),
            worker_id="cancellation-heartbeat-worker",
            poll_seconds=0.01,
            lease_seconds=1.0,
            heartbeat_seconds=0.05,
            maximum_attempts=3,
        )

        self.assertTrue(worker.run_once())
        self.assertGreaterEqual(counting_store.renew_count, 1)
        cancelled = counting_store.get(record.job_id)
        self.assertIs(cancelled.state, ScanJobState.CANCELLED)
        self.assertTrue(cancelled.cancellation_requested)

    def test_expired_job_at_attempt_limit_is_failed_without_execution(self) -> None:
        record, _ = self.store.submit(self.request)
        self.store.claim_next_leased(
            now=NOW,
            worker_id="dead-worker",
            lease_seconds=1,
        )
        executor = FakeExecutor()
        worker = ScanJobWorker(
            store=self.store,
            executor=executor,
            worker_id="replacement-worker",
            lease_seconds=30,
            heartbeat_seconds=10,
            maximum_attempts=1,
            clock=lambda: NOW + timedelta(seconds=2),
        )

        self.assertFalse(worker.run_once())
        self.assertEqual(worker.last_recovery_summary.failed, 1)
        failed = self.store.get(record.job_id)
        self.assertIs(failed.state, ScanJobState.FAILED)
        self.assertEqual(failed.error_code, "worker_lease_attempts_exhausted")
        self.assertEqual(executor.calls, [])

    def test_expired_cancelled_job_is_not_reexecuted(self) -> None:
        record, _ = self.store.submit(self.request)
        self.store.claim_next_leased(
            now=NOW,
            worker_id="dead-worker",
            lease_seconds=1,
        )
        self.store.request_cancellation(
            record.job_id,
            now=NOW + timedelta(milliseconds=500),
        )
        executor = FakeExecutor()
        worker = ScanJobWorker(
            store=self.store,
            executor=executor,
            worker_id="replacement-worker",
            lease_seconds=30,
            heartbeat_seconds=10,
            maximum_attempts=3,
            clock=lambda: NOW + timedelta(seconds=2),
        )

        self.assertFalse(worker.run_once())
        cancelled = self.store.get(record.job_id)
        self.assertIs(cancelled.state, ScanJobState.CANCELLED)
        self.assertEqual(executor.calls, [])


if __name__ == "__main__":
    unittest.main()
