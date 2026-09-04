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
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanStatus

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
    poll_seconds, simulating "a long-running job" at test speed."""

    def __init__(self, sleep_seconds: float) -> None:
        self.sleep_seconds = sleep_seconds

    def execute(self, record, *, cancellation_token=None):
        time.sleep(self.sleep_seconds)
        return SimpleNamespace(
            report=SimpleNamespace(scan_id=str(uuid4()), status=ScanStatus.COMPLETED),
            report_ref="jobs/x/report.json", audit_ref="jobs/x/audit.json",
            safety_receipt_ref=None, safety_receipt_sha256=None,
        )


class _NoJobExecutor:
    def execute(self, record, *, cancellation_token=None):  # pragma: no cover - never called
        raise AssertionError("no job should ever be claimed in idle-polling tests")


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
    """Real time, short and bounded: the actual evidence
    `progress_stale_after_seconds`'s derivation (in worker.py's own
    docstring) is grounded in -- every progress-touching wait is
    bounded above by poll_seconds, measured here rather than assumed.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")

    def _max_touch_gap(self, worker: ScanJobWorker, *, run_seconds: float) -> float:
        stop_event = threading.Event()
        thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
        samples: list[float] = []
        thread.start()
        deadline = time.monotonic() + run_seconds
        last_seen = worker._last_progress_monotonic
        while time.monotonic() < deadline:
            current = worker._last_progress_monotonic
            if current != last_seen:
                samples.append(current - last_seen)
                last_seen = current
            time.sleep(0.005)
        stop_event.set()
        thread.join(timeout=2.0)
        return max(samples) if samples else 0.0

    def test_idle_polling_max_gap_is_bounded_by_poll_seconds(self) -> None:
        worker = ScanJobWorker(
            store=self.store, executor=_NoJobExecutor(), worker_id="evidence-idle", lease_seconds=30,
            poll_seconds=0.05,
        )
        max_gap = self._max_touch_gap(worker, run_seconds=0.6)
        # Generous margin over the theoretical poll_seconds bound to
        # absorb OS/GC scheduling jitter on a loaded test machine --
        # still far below progress_stale_after_seconds (0.05*6=0.3,
        # floored to 3.0s), which is exactly the margin this default
        # is meant to provide.
        self.assertLess(max_gap, 0.05 * 4)
        self.assertLess(max_gap, worker.progress_stale_after_seconds)

    def test_long_running_job_progress_refreshed_by_monitor_loop(self) -> None:
        record, _ = self.store.submit(_request("evidence-long-job"))
        worker = ScanJobWorker(
            store=self.store, executor=_SlowExecutor(sleep_seconds=0.4), worker_id="evidence-long-job-worker",
            lease_seconds=30, heartbeat_seconds=0.1, poll_seconds=0.05,
        )
        max_gap = self._max_touch_gap(worker, run_seconds=0.6)
        # The job sleeps for 0.4s straight -- if progress were only
        # touched by run_forever() completing an iteration (the
        # behavior this batch explicitly avoids), the gap would be
        # ~0.4s. monitor_job()'s own per-cycle touch keeps it bounded
        # by poll_seconds throughout, proving the long-job claim in
        # worker.py's docstring rather than just asserting it.
        self.assertLess(max_gap, 0.05 * 4)
        self.assertLess(max_gap, 0.4, "a long job must not look like one big stalled gap")


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
