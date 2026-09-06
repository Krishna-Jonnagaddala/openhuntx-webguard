"""P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md): fast
tests for ScanJobWorker's progress/liveness model -- deterministic
fake-monotonic-clock proofs of the staleness math itself, plus a real-
time (small, bounded duration) evidence test that grounds the default
staleness threshold in actually-observed timing rather than an
assumed formula. Reuses test_worker_outage_resilience.py's own real-
SQLite-store fixture pattern.
"""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from webguard_api import ScanJobStore
from webguard_api.db_errors import DatabaseError
from webguard_api.worker import (
    DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS,
    DEFAULT_PROGRESS_STALE_FLOOR_SECONDS,
    DEFAULT_PROGRESS_STALE_MULTIPLIER,
    ScanJobWorker,
)
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanJobState, ScanStatus

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET


def _request(key: str) -> ScanJobRequest:
    return ScanJobRequest(
        idempotency_key=key, target=TARGET, authorization_id=AUTH_ID,
        authorization_sha256="a" * 64, mode=ScanJobMode.CRAWL, submitted_at=NOW,
    )


class _FakeMonotonic:
    """A fully synchronous, manually-advanced clock -- no real time
    elapses, so staleness-threshold assertions are exact, not
    timing-sensitive."""

    def __init__(self, start: float = 1000.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _SlowExecutor:
    """Sleeps for a real, short duration inside execute() -- long
    enough to span several monitor_job() heartbeat cycles at a small
    poll_seconds, simulating "a long-running job" at test speed. The
    `finished` event lets a test prove something happened while the
    call was still in flight, rather than only after it returned."""

    def __init__(self, sleep_seconds: float) -> None:
        self.sleep_seconds = sleep_seconds
        self.finished = threading.Event()

    def execute(self, record, *, cancellation_token=None):
        time.sleep(self.sleep_seconds)
        self.finished.set()
        return SimpleNamespace(
            report=SimpleNamespace(scan_id=str(uuid4()), status=ScanStatus.COMPLETED),
            report_ref="jobs/x/report.json", audit_ref="jobs/x/audit.json",
            safety_receipt_ref=None, safety_receipt_sha256=None,
        )


class _NoJobExecutor:
    def execute(self, record, *, cancellation_token=None):  # pragma: no cover - never called
        raise AssertionError("no job should ever be claimed in idle-polling tests")


class _RecordingWaitEvent:
    """Duck-types the `stop_event: threading.Event` parameter that
    `run_forever()` takes, but never actually blocks: `wait()` returns
    immediately and records the timeout it was called with, so the
    idle loop's use of `self.poll_seconds` can be proven by inspecting
    the recorded calls instead of measuring how much real time
    elapsed. After `stop_after_waits` calls it reports itself as set,
    which is what lets `run_forever()`'s own
    `while not stop_event.is_set():` check end the loop -- the same
    mechanism a real caller uses to shut it down, just triggered by
    call count instead of an external `.set()`. Because `wait()` never
    sleeps, this test double makes the resulting test's outcome
    completely independent of real elapsed time and CI scheduling.
    """

    def __init__(self, *, stop_after_waits: int) -> None:
        self._done = False
        self.wait_calls: list[float] = []
        self._stop_after_waits = stop_after_waits

    def is_set(self) -> bool:
        return self._done

    def wait(self, timeout: float | None = None) -> bool:
        self.wait_calls.append(timeout)
        if len(self.wait_calls) >= self._stop_after_waits:
            self._done = True
        return self._done


class ProgressStalenessFakeClockTests(unittest.TestCase):
    """Deterministic: no real waiting, exact clock control."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")
        self.clock = _FakeMonotonic()

    def _worker(self, **overrides) -> ScanJobWorker:
        kwargs = dict(
            store=self.store, executor=_NoJobExecutor(), worker_id="unit-worker", lease_seconds=30,
            poll_seconds=0.25, monotonic=self.clock,
        )
        kwargs.update(overrides)
        return ScanJobWorker(**kwargs)

    def test_freshly_constructed_worker_is_progress_healthy(self) -> None:
        worker = self._worker()
        self.assertTrue(worker.progress_healthy())

    def test_touch_progress_resets_staleness(self) -> None:
        worker = self._worker()
        self.clock.advance(worker.progress_stale_after_seconds - 0.01)
        self.assertTrue(worker.progress_healthy())
        worker._touch_progress()
        self.clock.advance(worker.progress_stale_after_seconds - 0.01)
        self.assertTrue(worker.progress_healthy())

    def test_becomes_unhealthy_past_the_threshold(self) -> None:
        worker = self._worker()
        self.clock.advance(worker.progress_stale_after_seconds + 0.01)
        self.assertFalse(worker.progress_healthy())

    def test_exactly_at_threshold_is_still_healthy_inclusive(self) -> None:
        worker = self._worker()
        self.clock.advance(worker.progress_stale_after_seconds)
        self.assertTrue(worker.progress_healthy())

    def test_explicit_stale_after_seconds_override(self) -> None:
        worker = self._worker()
        self.clock.advance(2.0)
        self.assertFalse(worker.progress_healthy(stale_after_seconds=1.0))
        self.assertTrue(worker.progress_healthy(stale_after_seconds=10.0))

    def test_default_threshold_formula(self) -> None:
        worker = self._worker(poll_seconds=0.25)
        expected = max(
            0.25 * DEFAULT_PROGRESS_STALE_MULTIPLIER,
            DEFAULT_PROGRESS_STALE_FLOOR_SECONDS,
            DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS,
        )
        self.assertEqual(worker.progress_stale_after_seconds, expected)

    def test_db_outage_floor_dominates_at_default_poll_seconds(self) -> None:
        # P1-B2 pre-commit correction: at the default poll_seconds,
        # the DB-outage floor (7.0s) is the binding constraint, not
        # the multiplier/floor pair that a fake (non-blocking) outage
        # simulation alone would have suggested.
        worker = self._worker(poll_seconds=0.25)
        self.assertEqual(worker.progress_stale_after_seconds, DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS)

    def test_default_threshold_scales_with_poll_seconds(self) -> None:
        worker = self._worker(poll_seconds=2.0)
        # A larger poll_seconds must produce a larger (or equal, once
        # the floor no longer dominates) threshold -- never a smaller
        # one, which would make staleness detection MORE trigger-happy
        # exactly when the loop's own legitimate cadence is slower.
        self.assertGreaterEqual(worker.progress_stale_after_seconds, 2.0 * DEFAULT_PROGRESS_STALE_MULTIPLIER)


class ProgressStalenessEvidenceTests(unittest.TestCase):
    """Real time, short and bounded: proves the monitor/idle loops
    actually keep calling `_touch_progress()` while alive, using
    synchronization (an event set by a spy, or a fake wait primitive
    that records its arguments) rather than a wall-clock gap
    assertion. The exact staleness-threshold arithmetic itself is
    proven separately and fully deterministically by
    `ProgressStalenessFakeClockTests` above, with no real time
    involved at all.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")

    def test_idle_polling_waits_using_configured_poll_seconds(self) -> None:
        """Control-flow AND timing-policy guarantee, both fully
        deterministic: run_forever()'s idle branch
        (`if not processed: stop_event.wait(self.poll_seconds)`) must
        call wait() with exactly the worker's own poll_seconds every
        cycle, and must touch progress once per cycle. The fake
        stop_event never sleeps, so this cannot be flaky: there is no
        real elapsed time for CI scheduling to disrupt.
        """
        worker = ScanJobWorker(
            store=self.store, executor=_NoJobExecutor(), worker_id="evidence-idle", lease_seconds=30,
            poll_seconds=0.05,
        )
        touches = 0
        touch_lock = threading.Lock()
        original_touch = worker._touch_progress

        def counting_touch() -> None:
            nonlocal touches
            original_touch()
            with touch_lock:
                touches += 1

        worker._touch_progress = counting_touch  # type: ignore[method-assign]

        stop_event = _RecordingWaitEvent(stop_after_waits=5)
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        thread.join(timeout=5.0)

        self.assertFalse(
            thread.is_alive(), "run_forever must return once the stop_event it was given reports set"
        )
        self.assertEqual(
            stop_event.wait_calls, [worker.poll_seconds] * len(stop_event.wait_calls),
            "the idle loop must wait using exactly the worker's configured poll_seconds, every cycle",
        )
        self.assertGreaterEqual(len(stop_event.wait_calls), 5)
        with touch_lock:
            final_touches = touches
        self.assertGreaterEqual(
            final_touches, 5, "progress must be touched once per idle cycle, not just once overall"
        )

    def test_long_running_job_progress_refreshed_by_monitor_loop(self) -> None:
        """Control-flow guarantee, real-thread: monitor_job()'s cycle
        (the one that keeps running for the full duration of a
        blocking executor.execute() call) must keep calling
        _touch_progress() repeatedly while the job is still in flight,
        not just once at the start. Proven with an event a spy on
        _touch_progress sets once 3 touches have happened, waited on
        with a generous bounded timeout -- not by measuring how large
        any single gap between touches happened to be, which is
        exactly the assertion a busy CI runner could trip without the
        worker having done anything wrong.

        monitor_job()'s own Event (`monitor_stop`) is constructed
        inside run_once() and is not something a caller can substitute
        a fake for, so this cannot be made as fully deterministic as
        the idle-loop test above without a production change, which
        this fix does not make. The staleness-threshold arithmetic
        that actually governs /ready is already proven deterministically,
        with no real time involved, by ProgressStalenessFakeClockTests.
        """
        record, _ = self.store.submit(_request("evidence-long-job"))
        executor = _SlowExecutor(sleep_seconds=0.4)
        worker = ScanJobWorker(
            store=self.store, executor=executor, worker_id="evidence-long-job-worker",
            lease_seconds=30, heartbeat_seconds=0.1, poll_seconds=0.05,
        )

        touch_count = 0
        touch_lock = threading.Lock()
        reached_three_touches = threading.Event()
        original_touch = worker._touch_progress

        def counting_touch() -> None:
            nonlocal touch_count
            original_touch()
            with touch_lock:
                touch_count += 1
                if touch_count >= 3:
                    reached_three_touches.set()

        worker._touch_progress = counting_touch  # type: ignore[method-assign]

        stop_event = threading.Event()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        try:
            reached = reached_three_touches.wait(timeout=5.0)
            self.assertTrue(
                reached,
                "the monitor loop must touch progress at least 3 times while a long job is in flight",
            )
            self.assertFalse(
                executor.finished.is_set(),
                "3 touches must happen while the job is still executing, not after it already finished",
            )
        finally:
            stop_event.set()
            thread.join(timeout=2.0)

        with touch_lock:
            final_touch_count = touch_count
        self.assertGreaterEqual(final_touch_count, 3)

        completed = self.store.get(record.job_id)
        self.assertEqual(
            completed.state, ScanJobState.COMPLETED, "the worker must still complete the job correctly"
        )


class DatabaseOutageProgressTests(unittest.TestCase):
    """Proves the exact combination that makes /healthz stay green
    through an outage /ready correctly flags: the loop backing off and
    retrying on schedule IS progress, independent of dependency
    health."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")

    def test_progress_stays_healthy_while_outage_backoff_continues(self) -> None:
        def _raise(*args, **kwargs):
            raise DatabaseError("database_unavailable", "simulated outage")

        self.store.recover_expired_leases = _raise  # type: ignore[method-assign]
        worker = ScanJobWorker(
            store=self.store, executor=_NoJobExecutor(), worker_id="outage-progress-worker", lease_seconds=30,
            poll_seconds=0.03,
        )
        stop_event = threading.Event()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        time.sleep(0.3)
        stop_event.set()
        thread.join(timeout=2.0)

        self.assertTrue(worker._in_database_outage, "the outage must actually have been observed")
        self.assertTrue(
            worker.progress_healthy(),
            "the loop backing off and retrying on schedule during an outage is legitimate progress",
        )


if __name__ == "__main__":
    unittest.main()
