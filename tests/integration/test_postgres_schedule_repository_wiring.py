"""P1-2 Phase H: proves postgres_schedules.py's list_due_schedules and
block_due_schedule actually work end to end through
webguard_control.list_due_schedules/block_due_schedule, under a real
restricted scheduler_tenant_data connection, not just that the SQL
functions themselves are correct (test_postgres_control_functions.py
already proves that directly). Neither Python method had any real-
Postgres test coverage calling it as a Python method before this file:
test_postgres_tenant_isolation_slice13.py constructs
PostgresScheduleRepository but never calls either of these two.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`) with the schema migrations, tenant roles,
and full control-function bootstrap applied by this test's own
setUpClass.
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from webguard_contracts import OrganizationRole, PrincipalType, ScanJobMode, ScanScheduleState

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime.now(timezone.utc)

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
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL test.",
)
class PostgresScheduleRepositoryWiringTests(unittest.TestCase):
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
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_schedules import PostgresScheduleRepository

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=8)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self.identity = PostgresIdentityRepository(self.pool)
        self.schedules = PostgresScheduleRepository(self.pool)

        self.organization = self.identity.create_organization(f"Schedule Wiring Org {uuid4()}", now=NOW)
        self.owner = self.identity.create_principal(
            self.organization.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        self.authorization_id = str(uuid4())
        self.identity.assign_authorization(
            self.organization.organization_id, self.authorization_id,
            assigned_by=self.owner.principal_id, now=NOW,
        )

    def _create_schedule(self, *, starts_at: datetime) -> str:
        record = self.schedules.create_schedule(
            organization_id=self.organization.organization_id,
            created_by=self.owner.principal_id,
            name=f"Schedule {uuid4()}",
            target="https://example.com",
            authorization_id=self.authorization_id,
            authorization_sha256="c" * 64,
            mode=ScanJobMode.SINGLE_PAGE,
            interval_seconds=3600,
            starts_at=starts_at,
            now=NOW,
        )
        return record.schedule_id

    def test_list_due_schedules_finds_due_and_excludes_not_yet_due(self) -> None:
        due_id = self._create_schedule(starts_at=NOW - timedelta(seconds=1))
        self._create_schedule(starts_at=NOW + timedelta(hours=1))

        due = self.schedules.list_due_schedules(now=NOW)

        self.assertEqual(len(due), 1)
        self.assertEqual(due[0].schedule_id, due_id)
        self.assertEqual(due[0].organization_id, self.organization.organization_id)
        self.assertEqual(due[0].target, "https://example.com/")
        self.assertEqual(due[0].mode, ScanJobMode.SINGLE_PAGE)
        self.assertEqual(due[0].state, ScanScheduleState.ACTIVE)

    def test_list_due_schedules_respects_limit(self) -> None:
        for _ in range(3):
            self._create_schedule(starts_at=NOW - timedelta(seconds=1))

        due = self.schedules.list_due_schedules(now=NOW, limit=2)

        self.assertEqual(len(due), 2)

    def test_block_due_schedule_pauses_and_records_error_code(self) -> None:
        schedule_id = self._create_schedule(starts_at=NOW - timedelta(seconds=1))

        blocked = self.schedules.block_due_schedule(
            schedule_id, expected_revision=0, error_code="permit_expired", now=NOW
        )

        self.assertIsNotNone(blocked)
        self.assertEqual(blocked.state, ScanScheduleState.PAUSED)
        self.assertEqual(blocked.last_error_code, "permit_expired")
        self.assertEqual(blocked.revision, 1)

        still_due = self.schedules.list_due_schedules(now=NOW)
        self.assertEqual(still_due, ())

    def test_block_due_schedule_returns_none_on_revision_mismatch(self) -> None:
        schedule_id = self._create_schedule(starts_at=NOW - timedelta(seconds=1))

        result = self.schedules.block_due_schedule(
            schedule_id, expected_revision=99, error_code="permit_expired", now=NOW
        )

        self.assertIsNone(result)
        due = self.schedules.list_due_schedules(now=NOW)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0].state, ScanScheduleState.ACTIVE)

    def test_block_due_schedule_returns_none_for_unknown_schedule(self) -> None:
        result = self.schedules.block_due_schedule(
            str(uuid4()), expected_revision=0, error_code="permit_expired", now=NOW
        )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
