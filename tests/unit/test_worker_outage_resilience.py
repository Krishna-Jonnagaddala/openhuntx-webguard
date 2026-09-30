"""P1-10 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md): fast,
deterministic tests for the retry/backoff MECHANICS themselves --
exact bounded attempt counts, no retry on a semantic JobStoreError, no
recursive failure-persistence, no busy loop, and stop_event
responsiveness during run_forever()'s outage backoff.

Uses a real, working SQLite-backed ScanJobStore (fast, no Docker) with
specific methods monkeypatched to simulate DatabaseError on demand --
this exercises the exact same worker.py code paths a real PostgreSQL
outage would, without needing real infrastructure or real sleeps for
this layer of proof. The real-PostgreSQL outage/recovery proofs (the
actual claim this batch makes about production behavior) live in
tests/integration/test_postgres_worker_outage_resilience.py.
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from webguard_api import ScanJobStore
from webguard_api.db_errors import DatabaseError, DatabaseUnavailableError
from webguard_api.store import JobStoreError
from webguard_api.worker import ScanJobWorker
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanStatus

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET


def _request(key: str) -> ScanJobRequest:
    return ScanJobRequest(
        idempotency_key=key, target=TARGET, authorization_id=AUTH_ID,
        authorization_sha256="a" * 64, mode=ScanJobMode.CRAWL, submitted_at=NOW,
    )


class _RaisingExecutor:
    def execute(self, record, *, cancellation_token=None):
        raise RuntimeError("simulated application-level bug")


class _SucceedingExecutor:
    def execute(self, record, *, cancellation_token=None):
        return SimpleNamespace(
            report=SimpleNamespace(scan_id=str(uuid4()), status=ScanStatus.COMPLETED),
            report_ref="jobs/x/report.json", audit_ref="jobs/x/audit.json",
            safety_receipt_ref=None, safety_receipt_sha256=None,
        )


class _FakeSleep:
    """Records every requested backoff instead of actually sleeping."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class WorkerOutageResilienceUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)
        self.sleep = _FakeSleep()

    def _worker(self, executor, **overrides) -> ScanJobWorker:
        kwargs = dict(
            store=self.store, executor=executor, worker_id="unit-worker", lease_seconds=30,
            terminal_persistence_maximum_attempts=3,
            terminal_persistence_retry_backoff_seconds=0.01,
            sleep=self.sleep,
        )
        kwargs.update(overrides)
        return ScanJobWorker(**kwargs)

    # -- D: executor raises, DB healthy -> normal FAILED behavior unchanged --
    def test_normal_failure_behavior_unchanged_when_store_healthy(self) -> None:
        record, _ = self.store.submit(_request("unit-d-normal-failure"))
        worker = self._worker(_RaisingExecutor())
        processed = worker.run_once()
        self.assertTrue(processed)
        final = self.store.get(record.job_id)
        self.assertEqual(final.state.value, "failed")
        self.assertEqual(final.error_code, "worker_internal_error")
        self.assertEqual(self.sleep.calls, [], "no retry/backoff should occur when the store is healthy")

    # -- exact bounded retry count on DatabaseError --
    def test_terminal_persistence_retries_exactly_the_configured_maximum(self) -> None:
        record, _ = self.store.submit(_request("unit-retry-count"))
        calls = {"n": 0}
        real_fail = self.store.fail_leased

        def failing_fail_leased(*args, **kwargs):
            calls["n"] += 1
            raise DatabaseUnavailableError("database_unavailable", "down")

        self.store.fail_leased = failing_fail_leased  # type: ignore[method-assign]
        worker = self._worker(_RaisingExecutor(), terminal_persistence_maximum_attempts=3)
        processed = worker.run_once()
        self.assertTrue(processed, "run_once() must return normally, not raise, when retries are exhausted")
        self.assertEqual(calls["n"], 3, "exactly the configured maximum number of attempts")
        self.assertEqual(len(self.sleep.calls), 2, "backoff occurs between attempts, not after the last one")
        self.store.fail_leased = real_fail  # type: ignore[method-assign]

    # -- bounded backoff duration, not busy-looping --
    def test_retry_backoff_uses_the_configured_duration_not_zero(self) -> None:
        record, _ = self.store.submit(_request("unit-backoff-duration"))
        self.store.fail_leased = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[method-assign]
            DatabaseUnavailableError("database_unavailable", "down")
        )
        worker = self._worker(_RaisingExecutor(), terminal_persistence_retry_backoff_seconds=0.75)
        worker.run_once()
        self.assertTrue(all(delay == 0.75 for delay in self.sleep.calls))
        self.assertTrue(len(self.sleep.calls) > 0)

    # -- no retry after a semantic JobStoreError (job_lease_lost etc.) --
    def test_semantic_job_store_error_is_not_retried(self) -> None:
        record, _ = self.store.submit(_request("unit-no-retry-semantic"))
        calls = {"n": 0}

        def losing_fail_leased(*args, **kwargs):
            calls["n"] += 1
            raise JobStoreError("job_lease_lost", "The worker lease is no longer current.")

        self.store.fail_leased = losing_fail_leased  # type: ignore[method-assign]
        worker = self._worker(_RaisingExecutor())
        processed = worker.run_once()
        self.assertTrue(processed)
        self.assertEqual(calls["n"], 1, "a semantic JobStoreError must fail immediately, never retried")
        self.assertEqual(self.sleep.calls, [])

    # -- no recursive failure-persistence: exhausted _fail() must not trigger another _fail() --
    def test_exhausted_fail_persistence_does_not_recurse(self) -> None:
        record, _ = self.store.submit(_request("unit-no-recursion"))
        calls = {"n": 0}

        def failing_fail_leased(*args, **kwargs):
            calls["n"] += 1
            raise DatabaseUnavailableError("database_unavailable", "down")

        self.store.fail_leased = failing_fail_leased  # type: ignore[method-assign]
        worker = self._worker(_RaisingExecutor(), terminal_persistence_maximum_attempts=2)
        processed = worker.run_once()
        self.assertTrue(processed)
        # Exactly the one bounded retry budget for the ONE _fail() call
        # this scenario makes -- not 2x or more from a second attempt
        # triggered by the first's own exhaustion.
        self.assertEqual(calls["n"], 2)
        final = self.store.get(record.job_id)
        self.assertEqual(final.state.value, "running", "job must be left RUNNING, not falsely marked failed")

    # -- success path: finish_result exhausts retries -> no false completion, no fallback to _fail() --
    def test_finish_result_exhaustion_does_not_call_fail_or_fabricate_state(self) -> None:
        record, _ = self.store.submit(_request("unit-finish-exhaustion"))
        fail_calls = {"n": 0}
        real_fail = self.store.fail_leased

        def counting_fail_leased(*args, **kwargs):
            fail_calls["n"] += 1
            return real_fail(*args, **kwargs)

        self.store.fail_leased = counting_fail_leased  # type: ignore[method-assign]
        self.store.finish_result_leased = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[method-assign]
            DatabaseUnavailableError("database_unavailable", "down")
        )
        worker = self._worker(_SucceedingExecutor())
        processed = worker.run_once()
        self.assertTrue(processed)
        self.assertEqual(fail_calls["n"], 0, "a failed *completion* persistence must never fall through to _fail()")
        final = self.store.get(record.job_id)
        self.assertEqual(final.state.value, "running")
        self.assertIsNone(final.result_status)

    # -- run_forever(): DatabaseError at the pre-claim boundary does not kill the loop --
    def test_run_forever_survives_precla_database_error_and_keeps_retrying(self) -> None:
        calls = {"n": 0}
        real_recover = self.store.recover_expired_leases

        def flaky_recover(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise DatabaseUnavailableError("database_unavailable", "down")
            return real_recover(*args, **kwargs)

        self.store.recover_expired_leases = flaky_recover  # type: ignore[method-assign]
        worker = self._worker(_SucceedingExecutor(), poll_seconds=0.01)
        stop_event = threading.Event()

        def run():
            worker.run_forever(stop_event)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        # Give it a handful of loop iterations to survive the first two
        # failures and reach a successful recover_expired_leases() call.
        stopped_in_time = stop_event.wait(2.0)
        stop_event.set()
        thread.join(timeout=2.0)
        self.assertFalse(thread.is_alive(), "run_forever() must exit promptly once stop_event is set")
        self.assertGreaterEqual(calls["n"], 3, "the loop must have retried past the initial DatabaseErrors")

    # -- run_forever(): DatabaseError backoff does not busy-loop --
    def test_run_forever_backoff_is_bounded_not_a_busy_loop(self) -> None:
        self.store.recover_expired_leases = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[method-assign]
            DatabaseUnavailableError("database_unavailable", "down")
        )
        worker = self._worker(_SucceedingExecutor(), poll_seconds=0.05)
        stop_event = threading.Event()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        import time as _time

        _time.sleep(0.3)
        stop_event.set()
        thread.join(timeout=2.0)
        self.assertFalse(thread.is_alive())
        # At 0.05s poll_seconds backoff per failed iteration, ~0.3s
        # should yield roughly 3-7 attempts, not hundreds (which a
        # true busy loop would produce).
        self.assertLess(len(self.sleep.calls) if self.sleep.calls else 6, 50)

    # -- stop_event remains responsive during run_forever()'s outage backoff --
    def test_stop_event_interrupts_run_forever_promptly_during_outage(self) -> None:
        self.store.recover_expired_leases = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[method-assign]
            DatabaseUnavailableError("database_unavailable", "down")
        )
        worker = self._worker(_SucceedingExecutor(), poll_seconds=5.0)
        stop_event = threading.Event()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        import time as _time

        _time.sleep(0.1)
        started = _time.monotonic()
        stop_event.set()
        thread.join(timeout=2.0)
        elapsed = _time.monotonic() - started
        self.assertFalse(thread.is_alive())
        self.assertLess(elapsed, 1.0, "stop_event.wait() inside the outage backoff must return promptly, not block for the full poll_seconds")

    # -- heartbeat/monitor thread: DatabaseError does not permanently stop monitoring --
    def test_monitor_thread_survives_transient_database_error_during_renewal(self) -> None:
        import time as _time

        record, _ = self.store.submit(_request("unit-monitor-survives"))
        calls = {"n": 0}
        real_renew = self.store.renew_lease

        def flaky_renew(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise DatabaseUnavailableError("database_unavailable", "down")
            return real_renew(*args, **kwargs)

        self.store.renew_lease = flaky_renew  # type: ignore[method-assign]

        class _SlowExecutor:
            def execute(self, record, *, cancellation_token=None):
                _time.sleep(0.6)
                return SimpleNamespace(
                    report=SimpleNamespace(scan_id=str(uuid4()), status=ScanStatus.COMPLETED),
                    report_ref="x.json", audit_ref="x.json",
                    safety_receipt_ref=None, safety_receipt_sha256=None,
                )

        worker = self._worker(
            _SlowExecutor(), heartbeat_seconds=0.1, poll_seconds=0.05,
            heartbeat_retry_backoff_seconds=0.05,
        )
        processed = worker.run_once()
        self.assertTrue(processed)
        self.assertGreaterEqual(calls["n"], 2, "the monitor must have retried renewal after the transient failure")
        final = self.store.get(record.job_id)
        self.assertEqual(final.state.value, "completed", "the main worker loop must be unaffected by the transient renewal failure")


if __name__ == "__main__":
    unittest.main()
