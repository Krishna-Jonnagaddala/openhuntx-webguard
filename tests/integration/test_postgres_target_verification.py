"""PostgreSQL-backed target-verification repository tests (Slice 15).

Regression coverage for a real bug this slice's browser E2E surfaced:
`PostgresTargetVerificationRepository.get_current()` never populated
`expected_token`, so a client re-fetching a still-pending verification
(the normal path -- the frontend invalidates and refetches rather than
reusing a mutation's own response) lost its own instructions and could
never complete a check. No prior test caught this because every other
test of this feature runs against the in-memory repository.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`).
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone

from webguard_contracts import OrganizationRole, PrincipalType

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class PostgresTargetVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_targets import PostgresTargetRepository
        from webguard_api.postgres_target_verification import PostgresTargetVerificationRepository
        from webguard_api.target_verification import VerificationMethod

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, minimum_connections=2, maximum_connections=5)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")

        self.identity = PostgresIdentityRepository(self.pool)
        self.targets = PostgresTargetRepository(self.pool)
        self.verifications = PostgresTargetVerificationRepository(self.pool)
        self.method = VerificationMethod.WELL_KNOWN_HTTP

        now = datetime.now(timezone.utc)
        organization = self.identity.create_organization("Postgres Verification Test Org", now=now)
        owner = self.identity.create_principal(
            organization.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=now,
        )
        target = self.targets.create_target(
            organization.organization_id, "https://verify-fixture.test/", created_by=owner.principal_id, now=now,
        )
        self.organization_id = organization.organization_id
        self.target_id = target.target_id

    def test_get_current_exposes_the_token_while_genuinely_pending(self) -> None:
        now = datetime.now(timezone.utc)
        initiated = self.verifications.initiate(
            self.target_id, organization_id=self.organization_id, method=self.method, now=now,
        )
        self.assertIsNotNone(initiated.expected_token)

        # The bug: a fresh read of "current" state (exactly what a
        # client re-fetching the asset after `initiate()` performs)
        # must still carry the token while status is pending.
        current = self.verifications.get_current(self.target_id, organization_id=self.organization_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status.value, "pending")
        self.assertEqual(current.expected_token, initiated.expected_token)

    def test_get_current_never_exposes_the_token_once_a_check_has_run(self) -> None:
        now = datetime.now(timezone.utc)
        initiated = self.verifications.initiate(
            self.target_id, organization_id=self.organization_id, method=self.method, now=now,
        )
        self.verifications.record_result(
            initiated.verification_id, organization_id=self.organization_id,
            matched=False, detail="token-mismatch", now=now,
        )
        current = self.verifications.get_current(self.target_id, organization_id=self.organization_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status.value, "failed")
        self.assertIsNone(current.expected_token)


if __name__ == "__main__":
    unittest.main()
