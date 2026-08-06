from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import DATABASE_SCHEMA_VERSION, JobStoreError, ScanJobStore
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanJobState, ScanStatus

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET


SCAN_ID = "b6a39765-16c6-42b4-91f0-998bf07f1912"


def request(key: str = "lease-test") -> ScanJobRequest:
    return ScanJobRequest(
        idempotency_key=key,
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256="a" * 64,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


class ScanJobLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_database_schema_is_version_two_with_lease_columns(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            version = connection.execute(
                "SELECT value FROM service_metadata WHERE key = 'schema_version'"
            ).fetchone()
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(scan_jobs)")
            }
        finally:
            connection.close()
        self.assertEqual(version, (str(DATABASE_SCHEMA_VERSION),))
        self.assertTrue(
            {
                "worker_id",
                "lease_token",
                "lease_expires_at",
                "heartbeat_at",
                "attempt_count",
            }.issubset(columns)
        )

    def test_leased_claim_records_worker_token_expiry_and_attempt(self) -> None:
        record, _ = self.store.submit(request())
        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=30,
        )
        assert lease is not None
        self.assertEqual(lease.record.job_id, record.job_id)
        self.assertEqual(lease.worker_id, "worker-a")
        self.assertEqual(lease.lease_expires_at, NOW + timedelta(seconds=30))
        self.assertEqual(lease.attempt_count, 1)
        self.assertIs(lease.record.state, ScanJobState.RUNNING)

    def test_second_store_cannot_claim_already_leased_job(self) -> None:
        self.store.submit(request())
        second_store = ScanJobStore(self.path)
        first = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=30,
        )
        second = second_store.claim_next_leased(
            now=NOW,
            worker_id="worker-b",
            lease_seconds=30,
        )
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_renew_lease_extends_expiry_and_revision(self) -> None:
        self.store.submit(request())
        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=30,
        )
        assert lease is not None
        renewed = self.store.renew_lease(
            lease.record.job_id,
            worker_id=lease.worker_id,
            lease_token=lease.lease_token,
            now=NOW + timedelta(seconds=10),
            lease_seconds=30,
        )
        self.assertEqual(
            renewed.lease_expires_at,
            NOW + timedelta(seconds=40),
        )
        self.assertEqual(renewed.record.revision, lease.record.revision + 1)
        self.assertEqual(renewed.attempt_count, 1)

    def test_wrong_worker_or_token_cannot_renew(self) -> None:
        self.store.submit(request())
        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=30,
        )
        assert lease is not None
        with self.assertRaises(JobStoreError) as context:
            self.store.renew_lease(
                lease.record.job_id,
                worker_id="worker-b",
                lease_token=lease.lease_token,
                now=NOW + timedelta(seconds=1),
                lease_seconds=30,
            )
        self.assertEqual(context.exception.code, "job_lease_lost")

    def test_expired_lease_is_requeued_and_can_be_reclaimed(self) -> None:
        record, _ = self.store.submit(request())
        first = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=1,
        )
        assert first is not None
        summary = self.store.recover_expired_leases(
            now=NOW + timedelta(seconds=2),
            maximum_attempts=3,
        )
        self.assertEqual(summary.requeued, 1)
        self.assertEqual(summary.total, 1)
        queued = self.store.get(record.job_id)
        self.assertIs(queued.state, ScanJobState.QUEUED)
        self.assertIsNone(queued.started_at)

        second = self.store.claim_next_leased(
            now=NOW + timedelta(seconds=3),
            worker_id="worker-b",
            lease_seconds=30,
        )
        assert second is not None
        self.assertEqual(second.record.job_id, record.job_id)
        self.assertEqual(second.attempt_count, 2)
        self.assertNotEqual(first.lease_token, second.lease_token)

    def test_stale_worker_cannot_finish_after_recovery(self) -> None:
        record, _ = self.store.submit(request())
        first = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=1,
        )
        assert first is not None
        self.store.recover_expired_leases(
            now=NOW + timedelta(seconds=2),
            maximum_attempts=3,
        )
        second = self.store.claim_next_leased(
            now=NOW + timedelta(seconds=3),
            worker_id="worker-b",
            lease_seconds=30,
        )
        assert second is not None

        with self.assertRaises(JobStoreError) as context:
            self.store.finish_result_leased(
                record.job_id,
                worker_id=first.worker_id,
                lease_token=first.lease_token,
                scan_id=SCAN_ID,
                result_status=ScanStatus.COMPLETED,
                report_ref=f"jobs/{record.job_id}/report.json",
                audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
                now=NOW + timedelta(seconds=4),
            )
        self.assertEqual(context.exception.code, "job_lease_lost")
        self.assertIs(self.store.get(record.job_id).state, ScanJobState.RUNNING)

    def test_current_lease_can_finish_result(self) -> None:
        record, _ = self.store.submit(request())
        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=30,
        )
        assert lease is not None
        finished = self.store.finish_result_leased(
            record.job_id,
            worker_id=lease.worker_id,
            lease_token=lease.lease_token,
            scan_id=SCAN_ID,
            result_status=ScanStatus.COMPLETED,
            report_ref=f"jobs/{record.job_id}/report.json",
            audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
            now=NOW + timedelta(seconds=1),
        )
        self.assertIs(finished.state, ScanJobState.COMPLETED)

    def test_unleased_terminal_transition_is_rejected_for_leased_job(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=30,
        )
        with self.assertRaises(JobStoreError) as context:
            self.store.fail(
                record.job_id,
                error_code="test_error",
                error_message="Test failure.",
                now=NOW + timedelta(seconds=1),
            )
        self.assertEqual(context.exception.code, "job_lease_required")

    def test_expired_cancelled_job_becomes_terminal_cancelled(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=1,
        )
        self.store.request_cancellation(
            record.job_id,
            now=NOW + timedelta(milliseconds=500),
        )
        summary = self.store.recover_expired_leases(
            now=NOW + timedelta(seconds=2),
            maximum_attempts=3,
        )
        self.assertEqual(summary.cancelled, 1)
        cancelled = self.store.get(record.job_id)
        self.assertIs(cancelled.state, ScanJobState.CANCELLED)
        self.assertTrue(cancelled.cancellation_requested)

    def test_attempt_limit_fails_expired_job(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=1,
        )
        summary = self.store.recover_expired_leases(
            now=NOW + timedelta(seconds=2),
            maximum_attempts=1,
        )
        self.assertEqual(summary.failed, 1)
        failed = self.store.get(record.job_id)
        self.assertIs(failed.state, ScanJobState.FAILED)
        self.assertEqual(
            failed.error_code,
            "worker_lease_attempts_exhausted",
        )

    def test_expired_lease_cannot_be_renewed_or_finished(self) -> None:
        record, _ = self.store.submit(request())
        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-a",
            lease_seconds=1,
        )
        assert lease is not None
        with self.assertRaises(JobStoreError) as context:
            self.store.renew_lease(
                record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                now=NOW + timedelta(seconds=2),
                lease_seconds=30,
            )
        self.assertEqual(context.exception.code, "job_lease_expired")


if __name__ == "__main__":
    unittest.main()
