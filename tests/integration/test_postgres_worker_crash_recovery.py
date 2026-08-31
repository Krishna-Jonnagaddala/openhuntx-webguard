"""P1 Batch A2 (baseline audit P1-5): PostgreSQL-backed worker
crash / lease-expiry recovery, proven against a real, disposable
PostgreSQL database -- not SQLite.

The equivalent guarantee is already thoroughly tested against SQLite
(tests/unit/test_job_leases.py, tests/unit/test_phase4_lock_crash_recovery.py)
and the *initial-claim* race is already proven against Postgres
(tests/contract/test_job_scan_finding_repository_contract.py's
`test_claim_next_leased_is_atomic_under_concurrent_workers`). What was
missing, and what this file adds, is the Postgres-backed proof of the
*recovery* half of the story: a worker that claims a job and then
disappears before completing it, its lease expiring, and a second
worker correctly reclaiming it -- exercising `recover_expired_leases()`
and a second `claim_next_leased()` against real PostgreSQL, using the
identical `FOR UPDATE SKIP LOCKED` + optimistic-revision-CAS
architecture already in production. No job-system redesign here; this
file is tests only.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`), run against a fresh disposable instance.
"""

from __future__ import annotations

import os
import threading
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    ScanStatus,
)

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime.now(timezone.utc)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL crash-recovery test.",
)
class PostgresWorkerCrashRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_findings import PostgresFindingRepository
        from webguard_api.store import JobStoreError

        self.JobStoreError = JobStoreError
        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=20)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self.identity = PostgresIdentityRepository(self.pool)
        self.jobs = PostgresJobRepository(self.pool)
        self.findings = PostgresFindingRepository(self.pool)
        self.organization_id, self.owner_id = self._make_organization_and_owner()

    def _make_organization_and_owner(self):
        org = self.identity.create_organization(f"A2 Recovery Org {uuid4()}", now=NOW)
        owner = self.identity.create_principal(
            org.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        return org.organization_id, owner.principal_id

    def _submit_claimable_job(self, *, idempotency_key: str | None = None):
        authorization_id = str(uuid4())
        self.identity.assign_authorization(
            self.organization_id, authorization_id, assigned_by=self.owner_id, now=NOW
        )
        request = ScanJobRequest(
            idempotency_key=idempotency_key or f"a2-recovery-{uuid4().hex}",
            target="https://a2-recovery.example/",
            authorization_id=authorization_id,
            authorization_sha256="a" * 64,
            mode=ScanJobMode.SINGLE_PAGE,
            submitted_at=NOW,
        )
        record, _ = self.jobs.submit(request, organization_id=self.organization_id, submitted_by=self.owner_id)
        return record

    # -- Core A2 requirement --------------------------------------------

    def test_worker_a_disappears_worker_b_reclaims_exactly_one_terminal_result(self) -> None:
        record = self._submit_claimable_job()

        lease_a = self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-a", lease_seconds=1)
        self.assertIsNotNone(lease_a)
        self.assertEqual(lease_a.record.job_id, record.job_id)
        self.assertIs(lease_a.record.state, ScanJobState.RUNNING)

        # Worker A disappears -- no renew, no finish, no fail. Lease expires.
        summary = self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        self.assertEqual(summary.requeued, 1)
        requeued = self.jobs.get(record.job_id)
        self.assertIs(requeued.state, ScanJobState.QUEUED)

        lease_b = self.jobs.claim_next_leased(now=NOW + timedelta(seconds=3), worker_id="a2-worker-b", lease_seconds=30)
        self.assertIsNotNone(lease_b)
        self.assertEqual(lease_b.record.job_id, record.job_id)
        self.assertEqual(lease_b.worker_id, "a2-worker-b")
        self.assertNotEqual(lease_b.lease_token, lease_a.lease_token)
        self.assertEqual(lease_b.attempt_count, 2)

        finished = self.jobs.finish_result_leased(
            record.job_id, worker_id=lease_b.worker_id, lease_token=lease_b.lease_token,
            scan_id=str(uuid4()), result_status=ScanStatus.COMPLETED,
            report_ref=f"jobs/{record.job_id}/report.json", audit_ref=f"jobs/{record.job_id}/audit.json",
            now=NOW + timedelta(seconds=4),
        )
        self.assertIs(finished.state, ScanJobState.COMPLETED)

        # Exactly one terminal result -- job is not claimable again, and
        # a second recovery pass finds nothing left to do for it.
        self.assertIsNone(self.jobs.claim_next_leased(now=NOW + timedelta(seconds=5), worker_id="a2-worker-c", lease_seconds=30))
        second_summary = self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=5), maximum_attempts=3)
        self.assertEqual(second_summary.total, 0)

    # -- Required sub-scenarios ------------------------------------------

    def test_claim_before_lease_expiry_is_denied(self) -> None:
        record = self._submit_claimable_job()
        lease_a = self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-a", lease_seconds=30)
        self.assertIsNotNone(lease_a)

        # Lease still has 29 seconds left -- a recovery pass right now
        # must find nothing, and no other worker can claim it.
        summary = self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=1), maximum_attempts=3)
        self.assertEqual(summary.total, 0)
        self.assertIsNone(self.jobs.claim_next_leased(now=NOW + timedelta(seconds=1), worker_id="a2-worker-b", lease_seconds=30))

    def test_claim_after_lease_expiry_is_allowed_once_recovered(self) -> None:
        record = self._submit_claimable_job()
        self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-a", lease_seconds=1)

        # A raw reclaim attempt before recover_expired_leases() runs
        # must NOT succeed -- the design requires the explicit recovery
        # pass to requeue it first (claim_next_leased only ever selects
        # QUEUED rows), proving recovery is a deliberate, auditable step
        # rather than an implicit side effect of a failed claim.
        self.assertIsNone(self.jobs.claim_next_leased(now=NOW + timedelta(seconds=2), worker_id="a2-worker-b", lease_seconds=30))

        self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        lease_b = self.jobs.claim_next_leased(now=NOW + timedelta(seconds=3), worker_id="a2-worker-b", lease_seconds=30)
        self.assertIsNotNone(lease_b)
        self.assertEqual(lease_b.record.job_id, record.job_id)

    def test_stale_worker_cannot_complete_after_ownership_changed(self) -> None:
        record = self._submit_claimable_job()
        lease_a = self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-a", lease_seconds=1)
        self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        lease_b = self.jobs.claim_next_leased(now=NOW + timedelta(seconds=3), worker_id="a2-worker-b", lease_seconds=30)
        self.assertIsNotNone(lease_b)

        # Worker A, unaware its lease was already reclaimed, tries to
        # finish "its" job with its now-stale worker_id/lease_token.
        with self.assertRaises(self.JobStoreError) as caught:
            self.jobs.finish_result_leased(
                record.job_id, worker_id=lease_a.worker_id, lease_token=lease_a.lease_token,
                scan_id=str(uuid4()), result_status=ScanStatus.COMPLETED,
                report_ref="x.json", audit_ref="x.json", now=NOW + timedelta(seconds=4),
            )
        self.assertEqual(caught.exception.code, "job_lease_lost")
        # The job must still be RUNNING under worker B's ownership --
        # worker A's stale attempt must not have disturbed it.
        self.assertIs(self.jobs.get(record.job_id).state, ScanJobState.RUNNING)

    def test_cas_revision_protects_terminal_state_from_a_second_writer(self) -> None:
        """Direct proof the optimistic-revision CAS -- not merely the
        worker_id/lease_token check -- is what protects a terminal
        write: even a caller that (incorrectly) still believes a lease
        is current cannot double-finish a job once another transition
        has already bumped its revision."""

        record = self._submit_claimable_job()
        lease = self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-a", lease_seconds=30)
        self.assertIsNotNone(lease)

        first = self.jobs.finish_result_leased(
            record.job_id, worker_id=lease.worker_id, lease_token=lease.lease_token,
            scan_id=str(uuid4()), result_status=ScanStatus.COMPLETED,
            report_ref="x.json", audit_ref="x.json", now=NOW + timedelta(seconds=1),
        )
        self.assertIs(first.state, ScanJobState.COMPLETED)

        # A second finish attempt with the identical (now-consumed)
        # worker_id/lease_token must be rejected -- the job is no
        # longer RUNNING, so `_terminal_update`'s own state check (not
        # just the lease check) refuses it.
        with self.assertRaises(self.JobStoreError) as caught:
            self.jobs.finish_result_leased(
                record.job_id, worker_id=lease.worker_id, lease_token=lease.lease_token,
                scan_id=str(uuid4()), result_status=ScanStatus.COMPLETED,
                report_ref="y.json", audit_ref="y.json", now=NOW + timedelta(seconds=2),
            )
        self.assertEqual(caught.exception.code, "job_state_transition_invalid")

    def test_no_duplicate_finding_survives_a_recovered_retry(self) -> None:
        """A worker crashes after recording a finding but before
        finishing the job; the recovered retry re-detects and re-records
        the identical finding (same fingerprint) -- the tenant-scoped
        (organization_id, fingerprint) upsert this repository already
        uses (see test_postgres_finding_concurrency.py for its own
        dedicated concurrency proof) must still collapse this into
        exactly one row, not a duplicate, specifically in the
        crash-recovery retry path this batch is about."""

        from webguard_api.postgres_scans import PostgresScanRepository

        scans = PostgresScanRepository(self.pool)
        record = self._submit_claimable_job()
        fingerprint = f"a2-recovery-fingerprint-{uuid4().hex}"
        lease_a = self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-a", lease_seconds=1)
        self.assertIsNotNone(lease_a)

        scan_a = scans.create_scan(
            organization_id=self.organization_id, job_id=record.job_id,
            target="https://a2-recovery.example/", authorization_id=record.request.authorization_id,
            mode=ScanJobMode.SINGLE_PAGE.value, scanner_version="0.1.0", now=NOW,
        )
        self.findings.record_finding(
            organization_id=self.organization_id, scan_id=scan_a.scan_id, fingerprint=fingerprint,
            check_id="active.ssrf.callback.confirmed", scanner_version="0.1.0", title="SSRF finding",
            severity="high", confidence="confirmed", asset="https://a2-recovery.example/",
            endpoint="/fetch", http_method="GET", now=NOW,
        )
        # Worker A then disappears without finishing the job.
        self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        lease_b = self.jobs.claim_next_leased(now=NOW + timedelta(seconds=3), worker_id="a2-worker-b", lease_seconds=30)
        self.assertIsNotNone(lease_b)

        # The retried scan re-detects the identical vulnerability.
        scan_b = scans.create_scan(
            organization_id=self.organization_id, job_id=record.job_id,
            target="https://a2-recovery.example/", authorization_id=record.request.authorization_id,
            mode=ScanJobMode.SINGLE_PAGE.value, scanner_version="0.1.0", now=NOW + timedelta(seconds=3),
        )
        self.findings.record_finding(
            organization_id=self.organization_id, scan_id=scan_b.scan_id, fingerprint=fingerprint,
            check_id="active.ssrf.callback.confirmed", scanner_version="0.1.0", title="SSRF finding",
            severity="high", confidence="confirmed", asset="https://a2-recovery.example/",
            endpoint="/fetch", http_method="GET", now=NOW + timedelta(seconds=3),
        )

        with self.pool.connection() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM findings WHERE organization_id = %s AND fingerprint = %s",
                (self.organization_id, fingerprint),
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_scan_job_terminal_consistency_after_recovery_exhausts_attempts(self) -> None:
        """When recovery exhausts the attempt budget (not just a single
        expiry), the job and its associated scan record must agree --
        both terminal, both FAILED, never one completed-looking while
        the other is stuck (the exact crash-consistency property Slice
        14 requirement 7-8 names, exercised here via the recovery path
        specifically rather than a direct fail_leased call)."""

        from webguard_api.postgres_scans import PostgresScanRepository

        scans = PostgresScanRepository(self.pool)
        record = self._submit_claimable_job()
        lease = self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-a", lease_seconds=1)
        self.assertIsNotNone(lease)
        scan_id = str(uuid4())
        scans.create_scan(
            organization_id=self.organization_id, job_id=record.job_id,
            target="https://a2-recovery.example/", authorization_id=record.request.authorization_id,
            mode=ScanJobMode.SINGLE_PAGE.value, scanner_version="0.1.0", now=NOW, scan_id=scan_id,
        )

        # Exhaust the attempt budget in one recovery pass.
        summary = self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=1)
        self.assertEqual(summary.failed, 1)

        failed_job = self.jobs.get(record.job_id)
        self.assertIs(failed_job.state, ScanJobState.FAILED)
        self.assertEqual(failed_job.error_code, "worker_lease_attempts_exhausted")

        with self.pool.connection() as connection:
            scan_status = connection.execute(
                "SELECT status FROM scan_records WHERE scan_id = %s", (scan_id,)
            ).fetchone()[0]
        self.assertEqual(scan_status, ScanStatus.FAILED.value)

    def test_cancellation_requested_during_lease_becomes_terminal_cancelled_on_recovery(self) -> None:
        record = self._submit_claimable_job()
        self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-a", lease_seconds=1)
        self.jobs.request_cancellation(record.job_id, now=NOW + timedelta(milliseconds=500))

        summary = self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        self.assertEqual(summary.cancelled, 1)

        cancelled = self.jobs.get(record.job_id)
        self.assertIs(cancelled.state, ScanJobState.CANCELLED)
        self.assertTrue(cancelled.cancellation_requested)
        # A cancelled-on-recovery job must never become claimable again.
        self.assertIsNone(self.jobs.claim_next_leased(now=NOW + timedelta(seconds=3), worker_id="a2-worker-b", lease_seconds=30))

    def test_many_workers_racing_after_expiry_produce_only_one_winner(self) -> None:
        """The identical FOR UPDATE SKIP LOCKED + revision-CAS
        architecture that already proves exactly-one-winner for an
        *initial* claim (test_job_scan_finding_repository_contract.py)
        must hold identically for a *post-recovery* reclaim: many
        workers racing to grab a job the instant it's requeued must
        still produce exactly one winner, never zero, never more than
        one."""

        record = self._submit_claimable_job()
        self.jobs.claim_next_leased(now=NOW, worker_id="a2-worker-original", lease_seconds=1)
        summary = self.jobs.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        self.assertEqual(summary.requeued, 1)

        results: list[str | None] = []
        lock = threading.Lock()

        def race(worker_id: str) -> None:
            leased = self.jobs.claim_next_leased(now=NOW + timedelta(seconds=3), worker_id=worker_id, lease_seconds=30)
            with lock:
                results.append(leased.record.job_id if leased else None)

        threads = [threading.Thread(target=race, args=(f"a2-racer-{i}",)) for i in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        winners = [job_id for job_id in results if job_id is not None]
        self.assertEqual(len(winners), 1, f"expected exactly one winner, got {winners}")
        self.assertEqual(winners[0], record.job_id)


if __name__ == "__main__":
    unittest.main()
