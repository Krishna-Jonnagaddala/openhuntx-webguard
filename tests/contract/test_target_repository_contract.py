"""Contract tests for `TargetRepository` (Slice 12): identical test
bodies against `InMemoryTargetRepository` (local/unit/lab) and
`PostgresTargetRepository` (production).
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from webguard_api.targets import InMemoryTargetRepository, TargetRepositoryError

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get(
    "WEBGUARD_POSTGRES_TEST_DSN",
    "postgresql://webguard:webguard_dev_only_not_for_production@127.0.0.1:5433/webguard",
)
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


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
    RUN_INTEGRATION, "Set WEBGUARD_RUN_INTEGRATION=1 to run this PostgreSQL contract test."
)
class PostgresTargetRepositoryContractTests(TargetRepositoryContractMixin, unittest.TestCase):
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
