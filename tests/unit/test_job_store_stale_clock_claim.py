"""Regression coverage for a confirmed race between a job-store
caller's `now` reading and a concurrently-committed job submission.

Root cause: `ScanJobWorker.run_once()` (worker.py) reads `now =
self.clock()` once, in the worker thread, *before* calling
`store.claim_next_leased(now=now, ...)`. That call's own "BEGIN
IMMEDIATE" then has to acquire SQLite's single-writer lock, which can
block behind a concurrent job-submission transaction that reads its
own, later `now` for `ScanJobRequest.submitted_at` and commits first.
`_select_claimable_row` has no `submitted_at <= now` filter at all, so
once unblocked, the worker can still select and claim that row, and
before this fix, it stamped `updated_at`/`started_at` with its own
now-stale `now`, which can be earlier than the row's own
`submitted_at`. `ScanJobRecord.__post_init__` (scan_jobs.py) then
raises `ScanJobValidationError: updated_at cannot precede
submitted_at` while building the return value, *after* the claim's
own COMMIT already succeeded (see claim_next_leased/claim_next: COMMIT
happens before `_lease_from_row`/`_record_from_row` is called) and
uncaught by any of `claim_next_leased`'s own exception handlers (it is
a ValueError subclass, not JobStoreError or sqlite3.Error). That is
exactly what crashed `ScanJobWorker.run_forever`'s thread and a
concurrent `GET /v1/jobs/{id}/result` (service.py's `result()` ->
store.py's `get_scoped()` -> the same `_record_from_row`) in the
reported CI failure.

This test reproduces the underlying condition directly and
deterministically, using a `now` earlier than an already-persisted
job's `submitted_at`, without needing real thread timing, since the
observable defect is a pure function of the values passed to the
store, not of scheduling luck. It does not attempt to reproduce the
SQLite lock-contention timing itself (that is what makes the race rare
in practice); it proves the store's own timestamp arithmetic is now
correct regardless of how a caller arrived at a stale `now`.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_contracts import ScanJobMode, ScanJobRequest, ScanJobState, ScanStatus
from webguard_api import ScanJobStore

SUBMITTED_AT = datetime(2026, 8, 6, 18, 0, tzinfo=timezone.utc)
STALE_NOW = SUBMITTED_AT - timedelta(seconds=5)
AUTH_ID = "8ae6403f-7832-498c-b37e-c0c87be19ea1"


def _request(key: str) -> ScanJobRequest:
    return ScanJobRequest(
        idempotency_key=key,
        target="https://example.com/",
        authorization_id=AUTH_ID,
        authorization_sha256="a" * 64,
        mode=ScanJobMode.SINGLE_PAGE,
        submitted_at=SUBMITTED_AT,
    )


class StaleClockClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)

    def test_claim_next_leased_with_a_now_earlier_than_submitted_at_does_not_violate_the_timestamp_invariant(
        self,
    ) -> None:
        """The exact mechanism behind the reported crash: a caller's
        `now` (STALE_NOW) precedes the job's own submitted_at. Before
        the fix, this raised ScanJobValidationError while building the
        claimed record, after the claim's own transaction had already
        committed. After the fix, updated_at/started_at are floored to
        submitted_at instead."""

        submitted, _ = self.store.submit(_request("stale-clock-leased"))
        leased = self.store.claim_next_leased(
            now=STALE_NOW, worker_id="worker-1", lease_seconds=30.0
        )
        self.assertIsNotNone(leased)
        self.assertEqual(leased.record.job_id, submitted.job_id)
        self.assertIs(leased.record.state, ScanJobState.RUNNING)
        self.assertEqual(leased.record.updated_at, SUBMITTED_AT)
        self.assertEqual(leased.record.started_at, SUBMITTED_AT)
        # The lease still runs the full duration from the floored
        # moment, not from the stale (earlier) reading.
        self.assertEqual(
            leased.lease_expires_at, SUBMITTED_AT + timedelta(seconds=30.0)
        )

    def test_claim_next_with_a_now_earlier_than_submitted_at_does_not_violate_the_timestamp_invariant(
        self,
    ) -> None:
        """Same defect class, the unleased legacy claim path."""

        submitted, _ = self.store.submit(_request("stale-clock-legacy"))
        claimed = self.store.claim_next(now=STALE_NOW)
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed.job_id, submitted.job_id)
        self.assertEqual(claimed.updated_at, SUBMITTED_AT)
        self.assertEqual(claimed.started_at, SUBMITTED_AT)

    def test_renew_lease_with_a_now_earlier_than_submitted_at_does_not_violate_the_timestamp_invariant(
        self,
    ) -> None:
        self.store.submit(_request("stale-clock-renew"))
        leased = self.store.claim_next_leased(
            now=SUBMITTED_AT, worker_id="worker-1", lease_seconds=30.0
        )
        assert leased is not None
        renewed = self.store.renew_lease(
            leased.record.job_id,
            worker_id="worker-1",
            lease_token=leased.lease_token,
            now=STALE_NOW,
            lease_seconds=30.0,
        )
        self.assertEqual(renewed.record.updated_at, SUBMITTED_AT)

    def test_recover_expired_leases_requeue_keeps_the_timestamp_invariant(
        self,
    ) -> None:
        """Unlike the other methods here, this one cannot actually be
        driven into violating the invariant through its own `now`
        parameter: its WHERE clause only ever selects rows whose
        `lease_expires_at <= now`, and `lease_expires_at` is itself
        always >= submitted_at once claim_next_leased/renew_lease
        floor it correctly, so `now >= lease_expires_at >=
        submitted_at` is already guaranteed structurally, before this
        method's own defensive floor ever has anything to correct.
        This test (unlike its siblings in this file) passes both
        before and after the fix; the floor added to this method is
        defense-in-depth for the fix's own stated scope ("check ALL of
        them"), not an independently reproducible bug here."""

        self.store.submit(_request("stale-clock-recover"))
        leased = self.store.claim_next_leased(
            now=SUBMITTED_AT, worker_id="worker-1", lease_seconds=1.0
        )
        assert leased is not None
        summary = self.store.recover_expired_leases(
            now=SUBMITTED_AT + timedelta(seconds=2), maximum_attempts=3
        )
        self.assertEqual(summary.requeued, 1)
        recovered = self.store.get(leased.record.job_id)
        self.assertIs(recovered.state, ScanJobState.QUEUED)
        self.assertGreaterEqual(recovered.updated_at, recovered.request.submitted_at)

    def test_finish_result_leased_with_a_now_earlier_than_submitted_at_does_not_violate_the_timestamp_invariant(
        self,
    ) -> None:
        self.store.submit(_request("stale-clock-finish"))
        leased = self.store.claim_next_leased(
            now=SUBMITTED_AT, worker_id="worker-1", lease_seconds=30.0
        )
        assert leased is not None
        finished = self.store.finish_result_leased(
            leased.record.job_id,
            worker_id="worker-1",
            lease_token=leased.lease_token,
            scan_id="b6a39765-16c6-42b4-91f0-998bf07f1912",
            result_status=ScanStatus.COMPLETED,
            report_ref="reports/x.json",
            audit_ref="audit/x.json",
            now=STALE_NOW,
        )
        self.assertIs(finished.state, ScanJobState.COMPLETED)
        self.assertGreaterEqual(finished.updated_at, finished.request.submitted_at)
        self.assertIsNotNone(finished.completed_at)
        self.assertGreaterEqual(finished.completed_at, finished.started_at)


if __name__ == "__main__":
    unittest.main()
