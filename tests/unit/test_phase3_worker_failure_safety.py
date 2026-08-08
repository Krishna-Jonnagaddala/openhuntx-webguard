from __future__ import annotations

import tempfile
import threading
import time
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    JobExecutionError,
    JobExecutionOutcome,
    ScanJobStore,
    ScanJobWorker,
)
from webguard_contracts import (
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    completed_report,
    create_trustscan_permit,
)


class Phase3WorkerFailureSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)
        self.permit = create_trustscan_permit(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def submit(self, key: str):
        auth = authorization()

        record, _ = self.store.submit(
            ScanJobRequest(
                idempotency_key=key,
                target=TARGET,
                authorization_id=AUTH_ID,
                authorization_sha256=auth.fingerprint,
                mode=ScanJobMode.CRAWL,
                submitted_at=NOW,
            ),
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=self.permit.permit.claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
        )

        return record

    def worker(self, executor, *, worker_id: str):
        return ScanJobWorker(
            store=self.store,
            executor=executor,
            poll_seconds=0.01,
            worker_id=worker_id,
            lease_seconds=1.0,
            heartbeat_seconds=0.05,
            maximum_attempts=3,
            clock=lambda: NOW,
        )

    @staticmethod
    def outcome(job_id: str) -> JobExecutionOutcome:
        scan_id = "11111111-2222-4333-8444-555555555555"

        return JobExecutionOutcome(
            report=completed_report(scan_id),
            report_ref=f"jobs/{job_id}/report.json",
            audit_ref=f"jobs/{job_id}/authorization-audit.json",
        )

    def test_unexpected_executor_exception_is_generic_and_secret_is_not_persisted(
        self,
    ) -> None:
        record = self.submit("phase3-unexpected-worker-error")

        class CrashingExecutor:
            def execute(self, _record, *, cancellation_token=None):
                raise RuntimeError(
                    "database-password=super-secret-phase3-value"
                )

        worker = self.worker(
            CrashingExecutor(),
            worker_id="phase3-crash-worker",
        )

        processed = worker.run_once()

        self.assertTrue(processed)

        persisted = self.store.get(record.job_id)

        self.assertIs(
            persisted.state,
            ScanJobState.FAILED,
        )
        self.assertEqual(
            persisted.error_code,
            "worker_internal_error",
        )
        self.assertEqual(
            persisted.error_message,
            "The scanner worker encountered an unexpected internal error.",
        )
        self.assertNotIn(
            "super-secret-phase3-value",
            persisted.error_message or "",
        )
        self.assertIsNone(
            self.store.get_job_safety_receipt(record.job_id)
        )

    def test_controlled_execution_error_preserves_code_and_receipt_metadata(
        self,
    ) -> None:
        record = self.submit("phase3-controlled-worker-error")

        receipt_ref = (
            f"jobs/{record.job_id}/trustscan-safety-receipt.json"
        )
        receipt_sha256 = "a" * 64

        class ControlledExecutor:
            def execute(self, _record, *, cancellation_token=None):
                raise JobExecutionError(
                    "trustscan_runtime_circuit_open",
                    "TrustScan runtime circuit breaker blocked execution.",
                    safety_receipt_ref=receipt_ref,
                    safety_receipt_sha256=receipt_sha256,
                )

        worker = self.worker(
            ControlledExecutor(),
            worker_id="phase3-controlled-worker",
        )

        self.assertTrue(worker.run_once())

        persisted = self.store.get(record.job_id)

        self.assertIs(
            persisted.state,
            ScanJobState.FAILED,
        )
        self.assertEqual(
            persisted.error_code,
            "trustscan_runtime_circuit_open",
        )
        self.assertEqual(
            self.store.get_job_safety_receipt(record.job_id),
            (
                receipt_ref,
                receipt_sha256,
            ),
        )

    def test_cancellation_wins_over_controlled_execution_failure(
        self,
    ) -> None:
        record = self.submit("phase3-cancel-vs-error")

        entered = threading.Event()

        class CancellationAwareExecutor:
            def execute(self, _record, *, cancellation_token=None):
                assert cancellation_token is not None
                entered.set()

                deadline = time.monotonic() + 3.0

                while not cancellation_token.is_cancelled:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "Cancellation token was not signalled."
                        )
                    time.sleep(0.005)

                raise JobExecutionError(
                    "scanner_error_after_cancellation",
                    "This failure must not override cancellation.",
                )

        worker = self.worker(
            CancellationAwareExecutor(),
            worker_id="phase3-cancel-worker",
        )

        outcomes: list[object] = []

        def run_worker() -> None:
            try:
                outcomes.append(worker.run_once())
            except BaseException as exc:
                outcomes.append(exc)

        thread = threading.Thread(
            target=run_worker,
            daemon=True,
        )
        thread.start()

        self.assertTrue(
            entered.wait(timeout=2),
            "Worker did not enter executor.",
        )

        self.store.request_cancellation(
            record.job_id,
            now=NOW,
        )

        thread.join(timeout=5)

        if thread.is_alive():
            self.fail(
                "Cancellation-vs-error worker did not terminate."
            )

        self.assertEqual(outcomes, [True])

        persisted = self.store.get(record.job_id)

        self.assertIs(
            persisted.state,
            ScanJobState.CANCELLED,
        )
        self.assertTrue(persisted.cancellation_requested)
        self.assertIsNone(persisted.error_code)
        self.assertIsNone(
            self.store.get_job_safety_receipt(record.job_id)
        )

    def test_lease_loss_during_execution_prevents_stale_success_commit(
        self,
    ) -> None:
        record = self.submit("phase3-lease-loss-success")

        entered = threading.Event()

        class SlowSuccessfulExecutor:
            def execute(self, running, *, cancellation_token=None):
                assert cancellation_token is not None
                entered.set()

                deadline = time.monotonic() + 3.0

                while not cancellation_token.is_cancelled:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "Lease-loss cancellation was not signalled."
                        )
                    time.sleep(0.005)

                # Simulate stale execution returning success after its
                # worker lease has already been lost.
                return Phase3WorkerFailureSafetyTests.outcome(
                    running.job_id
                )

        worker = self.worker(
            SlowSuccessfulExecutor(),
            worker_id="phase3-stale-success-worker",
        )

        outcomes: list[object] = []

        def run_worker() -> None:
            try:
                outcomes.append(worker.run_once())
            except BaseException as exc:
                outcomes.append(exc)

        thread = threading.Thread(
            target=run_worker,
            daemon=True,
        )
        thread.start()

        self.assertTrue(
            entered.wait(timeout=2),
            "Worker did not enter slow executor.",
        )

        recovery_store = ScanJobStore(self.path)

        recovered = recovery_store.recover_expired_leases(
            now=NOW + timedelta(seconds=2),
            maximum_attempts=3,
        )

        self.assertEqual(recovered.requeued, 1)

        thread.join(timeout=5)

        if thread.is_alive():
            self.fail(
                "Lease-loss success worker did not terminate."
            )

        self.assertEqual(outcomes, [True])

        persisted = self.store.get(record.job_id)

        self.assertIs(
            persisted.state,
            ScanJobState.QUEUED,
        )
        self.assertIsNone(persisted.scan_id)
        self.assertIsNone(persisted.result_status)
        self.assertIsNone(persisted.report_ref)
        self.assertIsNone(persisted.audit_ref)

    def test_lease_loss_during_execution_prevents_stale_failure_commit(
        self,
    ) -> None:
        record = self.submit("phase3-lease-loss-failure")

        entered = threading.Event()

        class SlowFailingExecutor:
            def execute(self, _record, *, cancellation_token=None):
                assert cancellation_token is not None
                entered.set()

                deadline = time.monotonic() + 3.0

                while not cancellation_token.is_cancelled:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "Lease-loss cancellation was not signalled."
                        )
                    time.sleep(0.005)

                raise JobExecutionError(
                    "stale_worker_failure",
                    "A stale worker must not persist this error.",
                )

        worker = self.worker(
            SlowFailingExecutor(),
            worker_id="phase3-stale-failure-worker",
        )

        outcomes: list[object] = []

        def run_worker() -> None:
            try:
                outcomes.append(worker.run_once())
            except BaseException as exc:
                outcomes.append(exc)

        thread = threading.Thread(
            target=run_worker,
            daemon=True,
        )
        thread.start()

        self.assertTrue(
            entered.wait(timeout=2),
            "Worker did not enter slow failing executor.",
        )

        recovery_store = ScanJobStore(self.path)

        recovered = recovery_store.recover_expired_leases(
            now=NOW + timedelta(seconds=2),
            maximum_attempts=3,
        )

        self.assertEqual(recovered.requeued, 1)

        thread.join(timeout=5)

        if thread.is_alive():
            self.fail(
                "Lease-loss failure worker did not terminate."
            )

        self.assertEqual(outcomes, [True])

        persisted = self.store.get(record.job_id)

        self.assertIs(
            persisted.state,
            ScanJobState.QUEUED,
        )
        self.assertIsNone(persisted.error_code)
        self.assertIsNone(persisted.error_message)

    def test_successful_worker_completion_still_uses_current_lease(
        self,
    ) -> None:
        record = self.submit("phase3-normal-success-control")

        class SuccessfulExecutor:
            def execute(self, running, *, cancellation_token=None):
                return Phase3WorkerFailureSafetyTests.outcome(
                    running.job_id
                )

        worker = self.worker(
            SuccessfulExecutor(),
            worker_id="phase3-success-control-worker",
        )

        self.assertTrue(worker.run_once())

        persisted = self.store.get(record.job_id)

        self.assertIs(
            persisted.state,
            ScanJobState.COMPLETED,
        )
        self.assertIsNotNone(persisted.scan_id)
        self.assertIsNotNone(persisted.report_ref)
        self.assertIsNotNone(persisted.audit_ref)


if __name__ == "__main__":
    unittest.main()
