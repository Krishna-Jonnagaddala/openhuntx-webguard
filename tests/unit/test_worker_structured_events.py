"""P1-B1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
call-site proofs that ScanJobWorker emits the required structured
events with the right structured fields (not human prose) at the
right moments, including edge-triggered (not per-poll-cycle) outage
detection/recovery. Reuses test_worker_outage_resilience.py's own
fast, real-SQLite fixture pattern.
"""

from __future__ import annotations

import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from webguard_api import ScanJobStore
from webguard_api.db_errors import DatabaseError, DatabaseUnavailableError
from webguard_api.structured_logging import configure_structured_logging
from webguard_api.worker import ScanJobWorker
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanStatus

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET


def _request(key: str) -> ScanJobRequest:
    return ScanJobRequest(
        idempotency_key=key, target=TARGET, authorization_id=AUTH_ID,
        authorization_sha256="a" * 64, mode=ScanJobMode.CRAWL, submitted_at=NOW,
    )


class _SucceedingExecutor:
    def execute(self, record, *, cancellation_token=None):
        return SimpleNamespace(
            report=SimpleNamespace(scan_id=str(uuid4()), status=ScanStatus.COMPLETED),
            report_ref="jobs/x/report.json", audit_ref="jobs/x/audit.json",
            safety_receipt_ref=None, safety_receipt_sha256=None,
        )


class _RaisingExecutor:
    def execute(self, record, *, cancellation_token=None):
        raise RuntimeError("simulated application-level bug")


def _lines(buf: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def _events(buf: io.StringIO, name: str) -> list[dict]:
    return [line for line in _lines(buf) if line.get("event") == name]


class WorkerStructuredEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")
        self.buf = io.StringIO()
        configure_structured_logging(service="worker", stream=self.buf)

    def _worker(self, executor, **overrides) -> ScanJobWorker:
        kwargs = dict(
            store=self.store, executor=executor, worker_id="unit-worker", lease_seconds=30,
            terminal_persistence_maximum_attempts=3, terminal_persistence_retry_backoff_seconds=0.001,
            sleep=lambda s: None,
        )
        kwargs.update(overrides)
        return ScanJobWorker(**kwargs)

    def test_job_claimed_and_completed_have_correct_fields(self) -> None:
        record, _ = self.store.submit(_request("unit-claimed-completed"))
        worker = self._worker(_SucceedingExecutor())
        worker.run_once()

        claimed = _events(self.buf, "job_claimed")
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["job_id"], record.job_id)
        self.assertEqual(claimed[0]["worker_id"], "unit-worker")
        self.assertEqual(claimed[0]["level"], "info")
        self.assertEqual(claimed[0]["service"], "worker")

        completed = _events(self.buf, "job_completed")
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["job_id"], record.job_id)
        self.assertIn("scan_id", completed[0])

    def test_job_failed_has_error_code_and_diagnostic_fields(self) -> None:
        record, _ = self.store.submit(_request("unit-failed"))
        worker = self._worker(_RaisingExecutor())
        worker.run_once()

        failed = _events(self.buf, "job_failed")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["job_id"], record.job_id)
        self.assertEqual(failed[0]["error_code"], "worker_internal_error")
        self.assertEqual(failed[0]["exception_type"], "RuntimeError")
        self.assertEqual(failed[0]["level"], "error")
        # No raw exception message anywhere in the line.
        self.assertNotIn("simulated application-level bug", json.dumps(failed[0]))

    def test_worker_started_and_stopped_bracket_run_forever(self) -> None:
        worker = self._worker(_SucceedingExecutor())
        stop_event = threading.Event()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        time.sleep(0.1)
        stop_event.set()
        thread.join(timeout=3)

        self.assertEqual(len(_events(self.buf, "worker_started")), 1)
        self.assertEqual(len(_events(self.buf, "worker_stopped")), 1)

    def test_database_outage_detected_and_recovered_are_edge_triggered(self) -> None:
        worker = self._worker(_SucceedingExecutor(), poll_seconds=0.01)
        real_recover = self.store.recover_expired_leases
        state = {"fail": True}

        def flaky_recover(*args, **kwargs):
            if state["fail"]:
                raise DatabaseUnavailableError("database_unavailable", "simulated outage")
            return real_recover(*args, **kwargs)

        self.store.recover_expired_leases = flaky_recover  # type: ignore[method-assign]
        stop_event = threading.Event()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        time.sleep(0.15)  # several failed iterations while state["fail"] is True
        self.assertEqual(
            len(_events(self.buf, "database_outage_detected")), 1,
            "must be exactly one event for the whole outage episode, not one per poll cycle",
        )
        self.assertEqual(len(_events(self.buf, "database_outage_recovered")), 0)

        state["fail"] = False
        time.sleep(0.15)  # let a successful iteration land
        stop_event.set()
        thread.join(timeout=3)

        self.assertEqual(len(_events(self.buf, "database_outage_detected")), 1)
        self.assertEqual(len(_events(self.buf, "database_outage_recovered")), 1)

    def test_terminal_persistence_retry_and_exhausted(self) -> None:
        record, _ = self.store.submit(_request("unit-terminal-retry"))
        worker = self._worker(_SucceedingExecutor(), terminal_persistence_maximum_attempts=3)
        real_finish = self.store.finish_result_leased

        def always_fail(*args, **kwargs):
            raise DatabaseUnavailableError("database_unavailable", "simulated outage")

        self.store.finish_result_leased = always_fail  # type: ignore[method-assign]
        worker.run_once()

        retries = _events(self.buf, "terminal_persistence_retry")
        self.assertEqual(len(retries), 2, "attempts 1 and 2 retry; attempt 3 exhausts")
        self.assertEqual([r["attempt"] for r in retries], [1, 2])

        exhausted = _events(self.buf, "terminal_persistence_exhausted")
        self.assertEqual(len(exhausted), 1)
        self.assertEqual(exhausted[0]["attempt"], 3)
        self.assertEqual(exhausted[0]["reason_code"], "terminal_persistence_unavailable")
        self.assertEqual(len(_events(self.buf, "job_completed")), 0, "must not fabricate completion")


if __name__ == "__main__":
    unittest.main()
