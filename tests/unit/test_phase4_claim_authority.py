from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from webguard_api import IdentityStore, ScanJobStore
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
)
from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    create_trustscan_permit,
)


class Phase4ClaimAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / 'jobs.sqlite3'
        self.store = ScanJobStore(self.path)
        self.identity = IdentityStore(self.path)
        self.identity.create_organization(
            'Phase 4 Claim Tenant', now=NOW, organization_id=ORG_ID
        )
        self.identity.create_principal(
            ORG_ID,
            'Phase 4 Owner',
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )
        self.identity.assign_authorization(
            ORG_ID, AUTH_ID, assigned_by=OWNER_ID, now=NOW
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def queued_permit_job(self, key: str):
        permit = create_trustscan_permit(self.store)
        request = ScanJobRequest(
            idempotency_key=key,
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )
        record, created = self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )
        self.assertTrue(created)
        return record

    def remove_assignment(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                '''
                DELETE FROM organization_authorizations
                WHERE organization_id = ?
                  AND authorization_id = ?
                ''',
                (ORG_ID, AUTH_ID),
            )
            connection.commit()
        finally:
            connection.close()

    def test_removed_assignment_blocks_legacy_worker_claim(self) -> None:
        record = self.queued_permit_job('phase4-assignment-legacy-claim')
        self.remove_assignment()
        claimed = self.store.claim_next(now=NOW)
        self.assertIsNone(claimed)
        self.assertIs(self.store.get(record.job_id).state, ScanJobState.QUEUED)

    def test_removed_assignment_blocks_leased_worker_claim(self) -> None:
        record = self.queued_permit_job('phase4-assignment-leased-claim')
        self.remove_assignment()
        claimed = self.store.claim_next_leased(
            now=NOW,
            worker_id='phase4-authority-worker',
            lease_seconds=30,
        )
        self.assertIsNone(claimed)
        self.assertIs(self.store.get(record.job_id).state, ScanJobState.QUEUED)


if __name__ == '__main__':
    unittest.main()
