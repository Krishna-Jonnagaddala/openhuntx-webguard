"""Contract tests for `TargetRepository` (Slice 12): identical test
bodies against `InMemoryTargetRepository` (local/unit/lab) and
`PostgresTargetRepository` (production).
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from webguard_api.targets import InMemoryTargetRepository, TargetRepositoryError

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
# No hardcoded default DSN -- see test_postgres_connection_pool.py's
# comment on this exact env-var pair.
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)

# P1-2 Phase H: every PostgresTargetRepository method now runs under
# api_tenant_data (see postgres_pool.py's tenant_connection and
# postgres_targets.py's own methods), so this contract test needs the
# same role/ACL/function/runtime-grant bootstrap
# tests/contract/test_identity_repository_contract.py's own setUpClass
# applies, in the same order.
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


class TargetRepositoryContractMixin:
    def make_repository(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def make_organization_id(self) -> str:  # pragma: no cover - overridden
        """In-memory has no foreign key to satisfy; the PostgreSQL
        subclass overrides this to insert a real organizations row
        first, since `targets.organization_id` is FK-constrained."""
        return str(uuid4())

    def make_principal_id(self, organization_id: str) -> str:  # pragma: no cover - overridden
        return str(uuid4())

    def test_create_and_get_round_trips(self) -> None:
        repo = self.make_repository()
        org_id = self.make_organization_id()
        record = repo.create_target(
            org_id,
            "https://example.com/",
            created_by=self.make_principal_id(org_id),
            now=NOW,
            label="Prod",
        )
        fetched = repo.get_target(record.target_id, organization_id=org_id)
        self.assertEqual(fetched.url, "https://example.com/")
        self.assertEqual(fetched.label, "Prod")
        self.assertIsNone(fetched.archived_at)

    def test_duplicate_url_within_organization_conflicts(self) -> None:
        repo = self.make_repository()
        org_id = self.make_organization_id()
        principal_id = self.make_principal_id(org_id)
        repo.create_target(org_id, "https://example.com/", created_by=principal_id, now=NOW)
        with self.assertRaises(TargetRepositoryError) as caught:
            repo.create_target(org_id, "https://example.com/", created_by=principal_id, now=NOW)
        self.assertEqual(caught.exception.code, "target_conflict")

    def test_same_url_allowed_across_different_organizations(self) -> None:
        repo = self.make_repository()
        org_a, org_b = self.make_organization_id(), self.make_organization_id()
        repo.create_target(
            org_a, "https://example.com/", created_by=self.make_principal_id(org_a), now=NOW
        )
        # Should not raise -- uniqueness is per-organization, not global.
        repo.create_target(
            org_b, "https://example.com/", created_by=self.make_principal_id(org_b), now=NOW
        )

    def test_cross_tenant_get_fails_closed_like_unknown(self) -> None:
        repo = self.make_repository()
        org_a, org_b = self.make_organization_id(), self.make_organization_id()
        record = repo.create_target(
            org_a, "https://example.com/", created_by=self.make_principal_id(org_a), now=NOW
        )
        with self.assertRaises(TargetRepositoryError) as own_org_missing:
            repo.get_target(str(uuid4()), organization_id=org_a)
        with self.assertRaises(TargetRepositoryError) as cross_org:
            repo.get_target(record.target_id, organization_id=org_b)
        self.assertEqual(own_org_missing.exception.code, "target_not_found")
        self.assertEqual(cross_org.exception.code, "target_not_found")

    def test_list_targets_is_tenant_scoped_and_excludes_archived_by_default(self) -> None:
        repo = self.make_repository()
        org_a, org_b = self.make_organization_id(), self.make_organization_id()
        first = repo.create_target(
            org_a, "https://a1.example/", created_by=self.make_principal_id(org_a), now=NOW
        )
        repo.create_target(
            org_a, "https://a2.example/", created_by=self.make_principal_id(org_a), now=NOW
        )
        repo.create_target(
            org_b, "https://b1.example/", created_by=self.make_principal_id(org_b), now=NOW
        )

        self.assertEqual(len(repo.list_targets(org_a)), 2)
        self.assertEqual(len(repo.list_targets(org_b)), 1)

        repo.archive_target(first.target_id, organization_id=org_a, now=NOW)
        self.assertEqual(len(repo.list_targets(org_a)), 1)
        self.assertEqual(len(repo.list_targets(org_a, include_archived=True)), 2)

    def test_archive_is_idempotent_and_tenant_scoped(self) -> None:
        repo = self.make_repository()
        org_a, org_b = self.make_organization_id(), self.make_organization_id()
        record = repo.create_target(
            org_a, "https://example.com/", created_by=self.make_principal_id(org_a), now=NOW
        )

        with self.assertRaises(TargetRepositoryError) as caught:
            repo.archive_target(record.target_id, organization_id=org_b, now=NOW)
        self.assertEqual(caught.exception.code, "target_not_found")

        first = repo.archive_target(record.target_id, organization_id=org_a, now=NOW)
        second = repo.archive_target(record.target_id, organization_id=org_a, now=NOW)
        self.assertEqual(first.archived_at, second.archived_at)


class InMemoryTargetRepositoryContractTests(TargetRepositoryContractMixin, unittest.TestCase):
    def make_repository(self) -> InMemoryTargetRepository:
        return InMemoryTargetRepository()


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test.",
)
class PostgresTargetRepositoryContractTests(TargetRepositoryContractMixin, unittest.TestCase):
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

        self._pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=4)
        self.addCleanup(self._pool.close)
        with self._pool.connection() as connection:
            connection.execute("TRUNCATE targets, principals, organizations CASCADE")

    def make_repository(self):
        from webguard_api.postgres_targets import PostgresTargetRepository

        return PostgresTargetRepository(self._pool)

    def make_organization_id(self) -> str:
        org_id = str(uuid4())
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO organizations (organization_id, name, name_key, status, created_at)
                VALUES (%s, %s, %s, 'active', %s)
                """,
                (org_id, f"org-{org_id}", f"org-{org_id}", NOW),
            )
        return org_id

    def make_principal_id(self, organization_id: str) -> str:
        principal_id = str(uuid4())
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO principals
                    (principal_id, organization_id, display_name, principal_type, role, active, created_at)
                VALUES (%s, %s, 'Test Principal', 'user', 'owner', TRUE, %s)
                """,
                (principal_id, organization_id, NOW),
            )
        return principal_id


if __name__ == "__main__":
    unittest.main()
