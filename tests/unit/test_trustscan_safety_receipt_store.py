from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from webguard_api import DATABASE_SCHEMA_VERSION, JobStoreError, ScanJobStore
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanJobState, ScanStatus

from tests.unit.service_test_support import AUTH_ID, NOW, ORG_ID, OWNER_ID, TARGET


class TrustScanSafetyReceiptStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def running_job(self):
        request = ScanJobRequest(
            idempotency_key="safety-receipt-store",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256="a" * 64,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )
        queued, _ = self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
        )
        running = self.store.claim_next(now=NOW)
        self.assertIsNotNone(running)
        return running

    def test_current_schema_contains_safety_receipt_table(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            version = connection.execute(
                "SELECT value FROM service_metadata WHERE key = 'schema_version'"
            ).fetchone()
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='job_safety_receipts'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(version, (str(DATABASE_SCHEMA_VERSION),))
        self.assertEqual(table, ("job_safety_receipts",))

    def test_terminal_result_persists_immutable_receipt_reference(self) -> None:
        running = self.running_job()
        completed = self.store.finish_result(
            running.job_id,
            scan_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            result_status=ScanStatus.COMPLETED,
            report_ref=f"jobs/{running.job_id}/report.json",
            audit_ref=f"jobs/{running.job_id}/authorization-audit.json",
            safety_receipt_ref=f"jobs/{running.job_id}/trustscan-safety-receipt.json",
            safety_receipt_sha256="b" * 64,
            now=NOW,
        )
        self.assertIs(completed.state, ScanJobState.COMPLETED)
        self.assertEqual(
            self.store.get_job_safety_receipt(running.job_id),
            (
                f"jobs/{running.job_id}/trustscan-safety-receipt.json",
                "b" * 64,
            ),
        )

    def test_receipt_metadata_must_be_supplied_as_a_pair(self) -> None:
        running = self.running_job()
        with self.assertRaises(JobStoreError) as caught:
            self.store.fail(
                running.job_id,
                error_code="test_failure",
                error_message="test",
                safety_receipt_ref=f"jobs/{running.job_id}/trustscan-safety-receipt.json",
                now=NOW,
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_safety_receipt_metadata_invalid",
        )
        self.assertIs(self.store.get(running.job_id).state, ScanJobState.RUNNING)
        self.assertIsNone(self.store.get_job_safety_receipt(running.job_id))

    def test_unsafe_receipt_reference_rolls_back_terminal_transition(self) -> None:
        running = self.running_job()
        with self.assertRaises(JobStoreError) as caught:
            self.store.fail(
                running.job_id,
                error_code="test_failure",
                error_message="test",
                safety_receipt_ref="../receipt.json",
                safety_receipt_sha256="b" * 64,
                now=NOW,
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_safety_receipt_reference_invalid",
        )
        self.assertIs(self.store.get(running.job_id).state, ScanJobState.RUNNING)
        self.assertIsNone(self.store.get_job_safety_receipt(running.job_id))


if __name__ == "__main__":
    unittest.main()
