from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    JobExecutionError,
    JobExecutionOutcome,
    ScanJobStore,
    ScanJobWorker,
)
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanJobState, ScanStatus

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET, authorization, completed_report


class FakeExecutor:
    def __init__(self, outcome=None, error=None):
        self.outcome = outcome
        self.error = error
        self.calls = []

    def execute(self, record, *, cancellation_token):
        self.calls.append((record, cancellation_token))
        if self.error is not None:
            raise self.error
        return self.outcome


class ScanJobWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        auth = authorization()
        self.request = ScanJobRequest(
            idempotency_key="internstack-worker",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_empty_queue_returns_false(self) -> None:
        worker = ScanJobWorker(
            store=self.store,
            executor=FakeExecutor(),
            clock=lambda: NOW,
        )
        self.assertFalse(worker.run_once())

    def test_completed_outcome_updates_store(self) -> None:
        record, _ = self.store.submit(self.request)
        report = completed_report("b6a39765-16c6-42b4-91f0-998bf07f1912")
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
            clock=lambda: NOW,
        )
        self.assertTrue(worker.run_once())
        stored = self.store.get(record.job_id)
        self.assertIs(stored.state, ScanJobState.COMPLETED)
        self.assertEqual(stored.scan_id, report.scan_id)
        self.assertEqual(len(executor.calls), 1)

    def test_controlled_execution_failure_updates_store(self) -> None:
        record, _ = self.store.submit(self.request)
        worker = ScanJobWorker(
            store=self.store,
            executor=FakeExecutor(
                error=JobExecutionError(
                    "authorization_not_found",
                    "Authorization not found.",
                )
            ),
            clock=lambda: NOW,
        )
        worker.run_once()
        stored = self.store.get(record.job_id)
        self.assertIs(stored.state, ScanJobState.FAILED)
        self.assertEqual(stored.error_code, "authorization_not_found")

    def test_unexpected_exception_is_redacted(self) -> None:
        record, _ = self.store.submit(self.request)
        worker = ScanJobWorker(
            store=self.store,
            executor=FakeExecutor(error=RuntimeError("secret stack data")),
            clock=lambda: NOW,
        )
        worker.run_once()
        stored = self.store.get(record.job_id)
        self.assertEqual(stored.error_code, "worker_internal_error")
        self.assertNotIn("secret", stored.error_message or "")

    def test_queued_cancelled_job_is_not_claimed(self) -> None:
        record, _ = self.store.submit(self.request)
        self.store.request_cancellation(record.job_id, now=NOW)
        executor = FakeExecutor()
        worker = ScanJobWorker(
            store=self.store,
            executor=executor,
            clock=lambda: NOW,
        )
        self.assertFalse(worker.run_once())
        self.assertEqual(executor.calls, [])


if __name__ == "__main__":
    unittest.main()
