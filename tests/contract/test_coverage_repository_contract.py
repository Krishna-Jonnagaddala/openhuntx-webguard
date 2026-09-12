"""Contract tests for `PostgresCoverageRepository` (product vision
pillar 5, Coverage Truth Map v1). No in-memory backend exists for this
table: it is genuinely new, additive tracking with no pre-existing
local/test behavior to mirror (see coverage_store.py's own module
docstring), so this is a single, direct Postgres-backed test class
rather than the two-backend mixin pattern used elsewhere in this
directory.
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)

# P1-2 Phase H follow-on: record_coverage runs under worker_tenant_data
# and list_coverage_for_asset under api_tenant_data (see
# postgres_coverage.py's own class docstring), so this test needs the
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


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test.",
)
class PostgresCoverageRepositoryContractTests(unittest.TestCase):
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
            connection.execute("TRUNCATE coverage_records, organizations CASCADE")

    def make_repository(self):
        from webguard_api.postgres_coverage import PostgresCoverageRepository

        return PostgresCoverageRepository(self._pool)

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

    def make_scan_id(self, organization_id: str) -> str:
        """coverage_records.last_scan_id is FK-constrained to
        scan_records; a real row is needed to prove that relationship
        actually holds, not just assumed."""

        scan_id = str(uuid4())
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO scan_records
                    (scan_id, organization_id, target, authorization_id, mode,
                     status, scanner_version, started_at)
                VALUES (%s, %s, 'https://example.com', 'auth-1', 'passive', 'running', '1.0.0', %s)
                """,
                (scan_id, organization_id, NOW),
            )
        return scan_id

    def test_record_coverage_creates_a_new_row(self) -> None:
        from webguard_api.coverage_store import CoverageStatus

        repo = self.make_repository()
        org_id = self.make_organization_id()
        record = repo.record_coverage(
            organization_id=org_id,
            asset="https://example.com",
            path="/",
            http_method="GET",
            identity_label="unauthenticated",
            check_id="header_analyzer",
            status=CoverageStatus.COMPLETED,
            scanner_version="1.0.0",
            now=NOW,
        )
        self.assertEqual(record.status, CoverageStatus.COMPLETED)
        self.assertEqual(record.first_observed_at, NOW)
        self.assertEqual(record.last_observed_at, NOW)

        listed = repo.list_coverage_for_asset(org_id, "https://example.com")
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].check_id, "header_analyzer")

    def test_record_coverage_upserts_and_preserves_first_observed_at(self) -> None:
        from webguard_api.coverage_store import CoverageStatus

        repo = self.make_repository()
        org_id = self.make_organization_id()
        first_scan_id = self.make_scan_id(org_id)
        later = NOW + timedelta(days=1)

        repo.record_coverage(
            organization_id=org_id,
            asset="https://example.com",
            path="/login",
            http_method="GET",
            identity_label="unauthenticated",
            check_id="cors_analyzer",
            status=CoverageStatus.BLOCKED,
            scanner_version="1.0.0",
            now=NOW,
            scan_id=first_scan_id,
        )
        second_scan_id = self.make_scan_id(org_id)
        updated = repo.record_coverage(
            organization_id=org_id,
            asset="https://example.com",
            path="/login",
            http_method="GET",
            identity_label="unauthenticated",
            check_id="cors_analyzer",
            status=CoverageStatus.COMPLETED,
            scanner_version="1.1.0",
            now=later,
            scan_id=second_scan_id,
        )

        self.assertEqual(updated.status, CoverageStatus.COMPLETED)
        self.assertEqual(updated.scanner_version, "1.1.0")
        self.assertEqual(updated.last_scan_id, second_scan_id)
        self.assertEqual(updated.first_observed_at, NOW, "first_observed_at must not move on re-observation")
        self.assertEqual(updated.last_observed_at, later)

        listed = repo.list_coverage_for_asset(org_id, "https://example.com")
        self.assertEqual(len(listed), 1, "an upsert must not create a second row")

    def test_distinct_check_ids_are_independent_rows(self) -> None:
        from webguard_api.coverage_store import CoverageStatus

        repo = self.make_repository()
        org_id = self.make_organization_id()
        repo.record_coverage(
            organization_id=org_id,
            asset="https://example.com",
            path="/",
            http_method="GET",
            identity_label="unauthenticated",
            check_id="header_analyzer",
            status=CoverageStatus.COMPLETED,
            scanner_version="1.0.0",
            now=NOW,
        )
        repo.record_coverage(
            organization_id=org_id,
            asset="https://example.com",
            path="/",
            http_method="GET",
            identity_label="unauthenticated",
            check_id="tls_analyzer",
            status=CoverageStatus.UNREACHABLE,
            scanner_version="1.0.0",
            now=NOW,
        )

        listed = repo.list_coverage_for_asset(org_id, "https://example.com")
        self.assertEqual({item.check_id for item in listed}, {"header_analyzer", "tls_analyzer"})

    def test_cross_tenant_listing_is_scoped(self) -> None:
        from webguard_api.coverage_store import CoverageStatus

        repo = self.make_repository()
        org_a, org_b = self.make_organization_id(), self.make_organization_id()
        repo.record_coverage(
            organization_id=org_a,
            asset="https://example.com",
            path="/",
            http_method="GET",
            identity_label="unauthenticated",
            check_id="header_analyzer",
            status=CoverageStatus.COMPLETED,
            scanner_version="1.0.0",
            now=NOW,
        )

        self.assertEqual(len(repo.list_coverage_for_asset(org_a, "https://example.com")), 1)
        self.assertEqual(len(repo.list_coverage_for_asset(org_b, "https://example.com")), 0)


if __name__ == "__main__":
    unittest.main()
