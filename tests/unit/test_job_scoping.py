from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webguard_api import JobStoreError, ScanJobStore
from webguard_contracts import ScanJobMode, ScanJobRequest
from tests.unit.service_test_support import AUTH_ID, NOW, ORG_ID, OWNER_ID, TARGET


def request(key="tenant-scope-1"):
    return ScanJobRequest(
        idempotency_key=key,
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256="a" * 64,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


class JobScopingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = ScanJobStore(Path(self.temp.name) / "jobs.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_scoped_submit_persists_organization(self):
        record, created = self.store.submit(
            request(), organization_id=ORG_ID, submitted_by=OWNER_ID
        )
        self.assertTrue(created)
        self.assertEqual(self.store.get_scope(record.job_id), (ORG_ID, OWNER_ID))

    def test_scope_arguments_must_be_paired(self):
        with self.assertRaises(JobStoreError):
            self.store.submit(request(), organization_id=ORG_ID)

    def test_get_scoped_accepts_owner(self):
        record, _ = self.store.submit(request(), organization_id=ORG_ID, submitted_by=OWNER_ID)
        self.assertEqual(self.store.get_scoped(record.job_id, ORG_ID), record)

    def test_get_scoped_hides_other_tenant(self):
        record, _ = self.store.submit(request(), organization_id=ORG_ID, submitted_by=OWNER_ID)
        with self.assertRaises(JobStoreError) as caught:
            self.store.get_scoped(record.job_id, "99999999-9999-4999-8999-999999999999")
        self.assertEqual(caught.exception.code, "job_not_found")

    def test_legacy_job_has_no_scope(self):
        record, _ = self.store.submit(request())
        self.assertIsNone(self.store.get_scope(record.job_id))

    def test_scoped_cancellation_rejects_other_tenant(self):
        record, _ = self.store.submit(request(), organization_id=ORG_ID, submitted_by=OWNER_ID)
        with self.assertRaises(JobStoreError):
            self.store.request_cancellation_scoped(
                record.job_id,
                "99999999-9999-4999-8999-999999999999",
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
