"""P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md): fast
tests for ScanScheduleCoordinator's progress/liveness model -- the
scheduler equivalent of test_worker_health.py. No monitor-*thread*
equivalent exists here the way worker.py has one -- but run_once()
itself now touches progress once per schedule it actually reaches
(pre-commit correction, see SlowBatchProgressTests below), not only
once per _run_forever() iteration, so a single legitimately slow batch
doesn't look stalled just because the whole call hasn't returned yet.
Reuses test_scheduler.py's own fast, real-SQLite fixture pattern.
"""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from webguard_api import AuthorizationRepository, IdentityStore, ScanJobStore, ScanScheduleCoordinator
from webguard_api.db_errors import DatabaseError
from webguard_api.scheduler import (
    DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS,
    DEFAULT_PROGRESS_STALE_FLOOR_SECONDS,
    DEFAULT_PROGRESS_STALE_MULTIPLIER,
)
from webguard_contracts import OrganizationRole, PrincipalType, ScanJobMode

from tests.unit.service_test_support import AUTH_ID, NOW, ORG_ID, OWNER_ID, trustscan_signer, write_authorization


class _FakeMonotonic:
    def __init__(self, start: float = 1000.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class SchedulerProgressBaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "authorizations"
        write_authorization(self.auth_dir)
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        self.identity = IdentityStore(self.store.path)
        self.identity.create_organization("InternStack", now=NOW, organization_id=ORG_ID)
        self.identity.create_principal(
            ORG_ID, "Owner", principal_type=PrincipalType.USER, role=OrganizationRole.OWNER,
            now=NOW, principal_id=OWNER_ID,
        )
        self.identity.assign_authorization(ORG_ID, AUTH_ID, assigned_by=OWNER_ID, now=NOW)
        self.signer = trustscan_signer(self.store)

    def coordinator(self, **overrides) -> ScanScheduleCoordinator:
        values = dict(
            store=self.store, authorizations=AuthorizationRepository(self.auth_dir), identity=self.identity,
            trustscan_signer=self.signer, clock=lambda: NOW, poll_seconds=0.1,
        )
        values.update(overrides)
        return ScanScheduleCoordinator(**values)


class ProgressStalenessFakeClockTests(SchedulerProgressBaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.clock = _FakeMonotonic()

    def test_freshly_constructed_coordinator_is_progress_healthy(self) -> None:
        coordinator = self.coordinator(monotonic=self.clock)
        self.assertTrue(coordinator.progress_healthy())

    def test_touch_progress_resets_staleness(self) -> None:
        coordinator = self.coordinator(monotonic=self.clock)
        self.clock.advance(coordinator.progress_stale_after_seconds - 0.01)
        self.assertTrue(coordinator.progress_healthy())
        coordinator._touch_progress()
        self.clock.advance(coordinator.progress_stale_after_seconds - 0.01)
        self.assertTrue(coordinator.progress_healthy())

    def test_becomes_unhealthy_past_the_threshold(self) -> None:
        coordinator = self.coordinator(monotonic=self.clock)
        self.clock.advance(coordinator.progress_stale_after_seconds + 0.01)
        self.assertFalse(coordinator.progress_healthy())

    def test_explicit_stale_after_seconds_override(self) -> None:
        coordinator = self.coordinator(monotonic=self.clock)
        self.clock.advance(2.0)
        self.assertFalse(coordinator.progress_healthy(stale_after_seconds=1.0))
        self.assertTrue(coordinator.progress_healthy(stale_after_seconds=10.0))

    def test_default_threshold_formula(self) -> None:
        coordinator = self.coordinator(monotonic=self.clock, poll_seconds=0.5)
        expected = max(
            0.5 * DEFAULT_PROGRESS_STALE_MULTIPLIER,
            DEFAULT_PROGRESS_STALE_FLOOR_SECONDS,
            DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS,
        )
        self.assertEqual(coordinator.progress_stale_after_seconds, expected)

    def test_db_outage_floor_dominates_at_default_poll_seconds(self) -> None:
        # P1-B2 pre-commit correction: at the default poll_seconds,
        # the DB-outage floor (7.0s) is the binding constraint -- a
        # real-outage re-measurement caught the earlier, fake-outage-
        # derived floor as too tight.
        coordinator = self.coordinator(monotonic=self.clock, poll_seconds=0.1)
        self.assertEqual(coordinator.progress_stale_after_seconds, DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS)


class ProgressStalenessEvidenceTests(SchedulerProgressBaseTestCase):
    """Real time, short and bounded -- same evidence-gathering
    approach as test_worker_health.py's own version, applied here
    since the scheduler's own poll_seconds bound is what
    progress_stale_after_seconds is derived from."""

    def test_idle_polling_max_gap_is_bounded_by_poll_seconds(self) -> None:
        coordinator = self.coordinator(poll_seconds=0.1)
        stop_event = threading.Event()
        thread = threading.Thread(target=coordinator.run_forever, args=(stop_event,), daemon=True)
        samples: list[float] = []
        thread.start()
        deadline = time.monotonic() + 0.6
        last_seen = coordinator._last_progress_monotonic
        while time.monotonic() < deadline:
            current = coordinator._last_progress_monotonic
            if current != last_seen:
                samples.append(current - last_seen)
                last_seen = current
            time.sleep(0.005)
        stop_event.set()
        thread.join(timeout=2.0)

        max_gap = max(samples) if samples else 0.0
        self.assertLess(max_gap, 0.1 * 4)
        self.assertLess(max_gap, coordinator.progress_stale_after_seconds)


class DatabaseOutageProgressTests(SchedulerProgressBaseTestCase):
    def test_progress_stays_healthy_while_outage_backoff_continues(self) -> None:
        def _raise(*args, **kwargs):
            raise DatabaseError("database_unavailable", "simulated outage")

        self.store.list_due_schedules = _raise  # type: ignore[method-assign]
        coordinator = self.coordinator(poll_seconds=0.1)
        stop_event = threading.Event()
        thread = threading.Thread(target=coordinator.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        time.sleep(0.3)
        stop_event.set()
        thread.join(timeout=2.0)

        self.assertTrue(coordinator._in_database_outage, "the outage must actually have been observed")
        self.assertTrue(
            coordinator.progress_healthy(),
            "the loop backing off and retrying on schedule during an outage is legitimate progress",
        )


class SlowBatchProgressTests(SchedulerProgressBaseTestCase):
    """P1-B2 pre-commit correction: a single run_once() call processing
    a legitimately slow, full batch (many due schedules, each
    materialization attempt taking real, bounded time) must not look
    progress-stale partway through -- before this fix, only
    _run_forever()'s own post-run_once() touch existed, so the whole
    batch duration counted as one silent gap. Uses a real deterministic
    delay (time.sleep) injected into a real per-schedule DB call, not a
    fake timer thread."""

    def _create_blocked_schedules(self, n: int) -> None:
        for i in range(n):
            self.store.create_schedule(
                organization_id=ORG_ID, created_by=OWNER_ID, name=f"slow-batch-{i}", target="https://example.test/",
                authorization_id=str(uuid.uuid4()), authorization_sha256="a" * 64, mode=ScanJobMode.CRAWL,
                interval_seconds=3600, starts_at=NOW, now=NOW, schedule_id=str(uuid.uuid4()),
            )

    def test_progress_stays_healthy_throughout_a_slow_full_batch(self) -> None:
        coordinator = self.coordinator(poll_seconds=0.1)  # progress_stale_after_seconds == 3.0s
        per_schedule_delay = 0.8
        schedule_count = 10  # 10 * 0.8s == 8.0s total, deliberately > the 7.0s DB-outage floor

        original_check = self.identity.authorization_is_assigned

        def slow_check(*args, **kwargs):
            time.sleep(per_schedule_delay)
            return original_check(*args, **kwargs)

        self.identity.authorization_is_assigned = slow_check  # type: ignore[method-assign]
        self._create_blocked_schedules(schedule_count)

        samples: list[bool] = []
        stop_sampling = threading.Event()

        def sample() -> None:
            while not stop_sampling.is_set():
                samples.append(coordinator.progress_healthy())
                time.sleep(0.1)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        start = time.perf_counter()
        summary = coordinator.run_once()
        elapsed = time.perf_counter() - start
        stop_sampling.set()
        sampler.join(timeout=1.0)

        self.assertGreater(elapsed, coordinator.progress_stale_after_seconds, "the batch must genuinely outlast the threshold for this proof to mean anything")
        self.assertEqual(summary.inspected, schedule_count)
        self.assertTrue(samples, "the sampler must have taken at least one reading during the batch")
        self.assertTrue(all(samples), f"progress must stay healthy throughout the slow batch, got {samples}")
        self.assertTrue(coordinator.progress_healthy())


if __name__ == "__main__":
    unittest.main()
