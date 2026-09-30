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
from pathlib import Path

from webguard_contracts import OrganizationRole, PrincipalType

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

# P1-2 Phase H: every PostgresTargetVerificationRepository method now
# runs under api_tenant_data (see postgres_pool.py's tenant_connection
# and postgres_target_verification.py's own methods), so this test
# needs the same role/ACL/function/runtime-grant bootstrap
# tests/contract/test_identity_repository_contract.py's own setUpClass
# applies, in the same order. postgres_targets.py's own methods
# (create_target, used by this file's own fixture setup) need it too.
_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
_ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
_TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
_FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
_CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"
_RUNTIME_GRANT_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_runtime_grant.sql"
_ALL_BOOTSTRAP_ROLES = (
    "api_tenant_data",
    "worker_tenant_data",
    "scheduler_tenant_data",
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class PostgresTargetVerificationTests(unittest.TestCase):
    @classmethod
    def _connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def setUpClass(cls) -> None:
        for sql_path in (
            _ROLES_SQL_PATH,
            _TENANT_ACL_SQL_PATH,
            _FUNCTION_ACL_SQL_PATH,
            _CONTROL_FUNCTIONS_SQL_PATH,
            _RUNTIME_GRANT_SQL_PATH,
        ):
            with cls._connect() as connection:
                connection.execute(sql_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        with cls._connect() as connection:
            connection.autocommit = True
            connection.execute("DROP SCHEMA IF EXISTS webguard_control CASCADE")
            for role in _ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    def setUp(self) -> None:
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_targets import PostgresTargetRepository
        from webguard_api.postgres_target_verification import PostgresTargetVerificationRepository
        from webguard_api.target_verification import VerificationMethod, VerificationStatus

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
        from webguard_api.target_verification import VerificationStatus

        now = datetime.now(timezone.utc)
        initiated = self.verifications.initiate(
            self.target_id, organization_id=self.organization_id, method=self.method, now=now,
        )
        self.verifications.record_result(
            initiated.verification_id, organization_id=self.organization_id,
            status=VerificationStatus.FAILED, detail="token-mismatch", now=now,
        )
        current = self.verifications.get_current(self.target_id, organization_id=self.organization_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status.value, "failed")
        self.assertIsNone(current.expected_token)


if __name__ == "__main__":
    unittest.main()
