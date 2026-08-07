from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webguard_api import JobStoreError, ScanJobStore
from webguard_contracts import ScanJobMode, ScanJobRequest

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    create_trustscan_permit,
)


class TrustScanPermitStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")
        self.permit = create_trustscan_permit(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(self, key: str) -> ScanJobRequest:
        auth = authorization()
        return ScanJobRequest(
            idempotency_key=key,
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )

    def test_create_read_and_revoke_are_durable(self) -> None:
        permit_id = self.permit.permit.claims.permit_id
        fetched = self.store.get_scan_permit_scoped(permit_id, ORG_ID)
        self.assertEqual(fetched.permit, self.permit.permit)
        revoked = self.store.revoke_scan_permit_scoped(
            permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )
        self.assertEqual(revoked.state_at(NOW), "revoked")
        reopened = ScanJobStore(self.store.path).get_scan_permit_scoped(permit_id, ORG_ID)
        self.assertEqual(reopened.state_at(NOW), "revoked")
        self.assertEqual(reopened.revoked_by, OWNER_ID)

    def test_cross_tenant_permit_read_is_hidden(self) -> None:
        with self.assertRaises(JobStoreError) as caught:
            self.store.get_scan_permit_scoped(
                self.permit.permit.claims.permit_id,
                "77777777-7777-4777-8777-777777777777",
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_not_found")

    def test_job_is_bound_to_exact_permit(self) -> None:
        job, created = self.store.submit(
            self.request("permit-binding-1"),
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=self.permit.permit.claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
        )
        self.assertTrue(created)
        self.assertEqual(
            self.store.get_job_permit_binding(job.job_id),
            (
                self.permit.permit.claims.permit_id,
                self.permit.permit.fingerprint,
            ),
        )

    def test_idempotent_job_cannot_switch_permits(self) -> None:
        request = self.request("permit-binding-idempotency")
        self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=self.permit.permit.claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
        )
        second = create_trustscan_permit(self.store)
        with self.assertRaises(JobStoreError) as caught:
            self.store.submit(
                request,
                organization_id=ORG_ID,
                submitted_by=OWNER_ID,
                permit_id=second.permit.claims.permit_id,
                permit_sha256=second.permit.fingerprint,
            )
        self.assertEqual(caught.exception.code, "job_idempotency_conflict")

    def test_permit_maximum_concurrency_one_is_enforced_at_claim(self) -> None:
        for index in range(2):
            self.store.submit(
                self.request(f"permit-concurrency-{index}"),
                organization_id=ORG_ID,
                submitted_by=OWNER_ID,
                permit_id=self.permit.permit.claims.permit_id,
                permit_sha256=self.permit.permit.fingerprint,
            )
        first = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-one",
            lease_seconds=30,
        )
        self.assertIsNotNone(first)
        second = self.store.claim_next_leased(
            now=NOW,
            worker_id="worker-two",
            lease_seconds=30,
        )
        self.assertIsNone(second)

    def test_permit_maximum_concurrency_one_is_enforced_at_legacy_claim(self) -> None:
        for index in range(2):
            self.store.submit(
                self.request(f"permit-legacy-concurrency-{index}"),
                organization_id=ORG_ID,
                submitted_by=OWNER_ID,
                permit_id=self.permit.permit.claims.permit_id,
                permit_sha256=self.permit.permit.fingerprint,
            )
        first = self.store.claim_next(now=NOW)
        self.assertIsNotNone(first)
        second = self.store.claim_next(now=NOW)
        self.assertIsNone(second)

    def test_signing_key_is_stable_across_reopen(self) -> None:
        first = self.store.trustscan_signing_private_key()
        second = ScanJobStore(self.store.path).trustscan_signing_private_key()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)


if __name__ == "__main__":
    unittest.main()
