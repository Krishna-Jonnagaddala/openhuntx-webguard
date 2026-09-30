"""Contract tests for the compliance framework/master-control catalog
(platform expansion, docs/adr/0034-compliance-catalog-is-global-reference-data.md).
No organization/tenant concept applies here at all: this table is
global reference data, so unlike every other contract test in this
directory, there is no `make_organization_id` helper and no
cross-tenant isolation test, only catalog read/write correctness and
the migration's own seeded placeholder rows.
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

from webguard_api.postgres_compliance_catalog import (
    ComplianceCatalogError,
    PostgresComplianceCatalogRepository,
)
from webguard_contracts import FrameworkStatus

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)

# P1-2 Phase H follow-on: PostgresComplianceCatalogRepository's reads
# run under api_tenant_data via role_scoped_connection (see the
# repository's own module docstring for why this table has no
# organization_id and no tenant_connection use at all), so this
# contract test needs the same role/ACL/function/runtime-grant
# bootstrap tests/contract/test_identity_repository_contract.py's own
# setUpClass applies, in the same order.
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
class PostgresComplianceCatalogRepositoryContractTests(unittest.TestCase):
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

    def make_repository(self):
        return PostgresComplianceCatalogRepository(self._pool)

    def test_seeded_placeholder_frameworks_are_readable(self) -> None:
        repo = self.make_repository()
        frameworks = repo.list_frameworks()
        by_id = {item.framework_id: item for item in frameworks}
        self.assertIn("soc2", by_id)
        self.assertIn("iso_27001", by_id)
        self.assertIn("hipaa_security_rule", by_id)
        self.assertIn("eu_gdpr", by_id)
        self.assertIn("uk_gdpr", by_id)
        for framework in by_id.values():
            self.assertEqual(framework.status, FrameworkStatus.PLACEHOLDER)
            self.assertTrue(framework.source_reference.startswith("https://"))

    def test_seeded_placeholder_frameworks_have_zero_controls(self) -> None:
        """A placeholder framework must not carry fabricated control
        content: zero master_controls until real, legally-reviewed
        content is loaded in a later, separate PR."""

        repo = self.make_repository()
        for framework_id in ("soc2", "iso_27001", "hipaa_security_rule", "eu_gdpr", "uk_gdpr"):
            self.assertEqual(repo.list_master_controls(framework_id), ())

    def test_get_unknown_framework_fails_closed(self) -> None:
        repo = self.make_repository()
        with self.assertRaises(ComplianceCatalogError) as caught:
            repo.get_framework("does-not-exist")
        self.assertEqual(caught.exception.code, "framework_not_found")

    def test_create_framework_and_master_control_round_trips(self) -> None:
        repo = self.make_repository()
        framework_id = f"test-framework-{id(self)}"
        try:
            created = repo.create_framework(
                framework_id,
                name="Test Framework",
                version="1.0",
                status=FrameworkStatus.CURRENT,
                source_reference="https://example.test/framework",
                now=NOW,
            )
            self.assertEqual(created.framework_id, framework_id)
            fetched = repo.get_framework(framework_id)
            self.assertEqual(fetched.name, "Test Framework")

            control = repo.create_master_control(
                f"{framework_id}-c1",
                framework_id,
                control_number="1.1",
                title="Test control",
                now=NOW,
                description="A synthetic control for contract testing only.",
                category="Test",
            )
            self.assertEqual(control.framework_id, framework_id)

            controls = repo.list_master_controls(framework_id)
            self.assertEqual(len(controls), 1)
            self.assertEqual(controls[0].control_number, "1.1")
        finally:
            with self._pool.connection() as connection:
                connection.execute(
                    "DELETE FROM master_controls WHERE framework_id = %s", (framework_id,)
                )
                connection.execute("DELETE FROM frameworks WHERE framework_id = %s", (framework_id,))


if __name__ == "__main__":
    unittest.main()
