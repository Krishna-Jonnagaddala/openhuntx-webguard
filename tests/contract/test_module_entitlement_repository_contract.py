"""Contract tests for module entitlement (platform expansion,
docs/PLATFORM_SCOPE.md): identical test bodies against
`InMemoryModuleEntitlementRepository` (local/unit/lab) and
`PostgresModuleEntitlementRepository` (production).
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from webguard_api.module_entitlements import ModuleEntitlementError
from webguard_contracts import ModuleEntitlementStatus, PlatformModule

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)

# P1-2 Phase H follow-on: every PostgresModuleEntitlementRepository
# method runs under api_tenant_data (see postgres_pool.py's
# tenant_connection and postgres_module_entitlements.py's own
# methods), so this contract test needs the same role/ACL/function/
# runtime-grant bootstrap tests/contract/test_identity_repository_contract.py's
# own setUpClass applies, in the same order.
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


class ModuleEntitlementRepositoryContractMixin:
    def make_repository(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def make_organization_id(self) -> str:  # pragma: no cover - overridden
        """In-memory has no foreign key to satisfy; the PostgreSQL
        subclass overrides this to insert a real organizations row
        first, since module_entitlements.organization_id is
        FK-constrained."""
        return str(uuid4())

    def test_grant_default_entitlements_creates_webguard_enabled_others_disabled(self) -> None:
        repo = self.make_repository()
        org_id = self.make_organization_id()
        created = repo.grant_default_entitlements(org_id, now=NOW)
        by_module = {item.module: item.status for item in created}
        self.assertEqual(
            by_module,
            {
                PlatformModule.WEBGUARD: ModuleEntitlementStatus.ENABLED,
                PlatformModule.SOC: ModuleEntitlementStatus.DISABLED,
                PlatformModule.COMPLIANCE: ModuleEntitlementStatus.DISABLED,
            },
        )
        webguard = next(item for item in created if item.module is PlatformModule.WEBGUARD)
        self.assertEqual(webguard.enabled_at, NOW)
        soc = next(item for item in created if item.module is PlatformModule.SOC)
        self.assertIsNone(soc.enabled_at)

    def test_set_entitlement_enables_and_disables(self) -> None:
        repo = self.make_repository()
        org_id = self.make_organization_id()
        repo.grant_default_entitlements(org_id, now=NOW)
        principal_id = self.make_principal_id(org_id) if hasattr(self, "make_principal_id") else str(uuid4())

        enabled = repo.set_entitlement(
            org_id, PlatformModule.SOC, status=ModuleEntitlementStatus.ENABLED, now=NOW, changed_by=principal_id
        )
        self.assertEqual(enabled.status, ModuleEntitlementStatus.ENABLED)
        self.assertEqual(enabled.enabled_by, principal_id)
        self.assertIsNone(enabled.disabled_at)

        disabled = repo.set_entitlement(
            org_id, PlatformModule.SOC, status=ModuleEntitlementStatus.DISABLED, now=NOW, changed_by=principal_id
        )
        self.assertEqual(disabled.status, ModuleEntitlementStatus.DISABLED)
        self.assertEqual(disabled.disabled_by, principal_id)

    def test_set_entitlement_on_ungranted_module_fails_closed(self) -> None:
        repo = self.make_repository()
        org_id = self.make_organization_id()
        with self.assertRaises(ModuleEntitlementError) as caught:
            repo.set_entitlement(
                org_id, PlatformModule.SOC, status=ModuleEntitlementStatus.ENABLED, now=NOW
            )
        self.assertEqual(caught.exception.code, "module_entitlement_not_found")

    def test_get_entitlement_on_missing_row_fails_closed(self) -> None:
        repo = self.make_repository()
        org_id = self.make_organization_id()
        with self.assertRaises(ModuleEntitlementError) as caught:
            repo.get_entitlement(org_id, PlatformModule.COMPLIANCE)
        self.assertEqual(caught.exception.code, "module_entitlement_not_found")

    def test_has_module_access_reflects_status_and_missing_row(self) -> None:
        repo = self.make_repository()
        org_id = self.make_organization_id()
        self.assertFalse(repo.has_module_access(org_id, PlatformModule.WEBGUARD))

        repo.grant_default_entitlements(org_id, now=NOW)
        self.assertTrue(repo.has_module_access(org_id, PlatformModule.WEBGUARD))
        self.assertFalse(repo.has_module_access(org_id, PlatformModule.SOC))

        repo.set_entitlement(org_id, PlatformModule.SOC, status=ModuleEntitlementStatus.TRIAL, now=NOW)
        self.assertTrue(repo.has_module_access(org_id, PlatformModule.SOC))

    def test_list_entitlements_is_scoped_per_organization(self) -> None:
        repo = self.make_repository()
        org_a, org_b = self.make_organization_id(), self.make_organization_id()
        repo.grant_default_entitlements(org_a, now=NOW)

        self.assertEqual(len(repo.list_entitlements(org_a)), 3)
        self.assertEqual(len(repo.list_entitlements(org_b)), 0)


class InMemoryModuleEntitlementRepositoryContractTests(
    ModuleEntitlementRepositoryContractMixin, unittest.TestCase
):
    def make_repository(self):
        from webguard_api.module_entitlements import InMemoryModuleEntitlementRepository

        return InMemoryModuleEntitlementRepository()


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test.",
)
class PostgresModuleEntitlementRepositoryContractTests(
    ModuleEntitlementRepositoryContractMixin, unittest.TestCase
):
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
            connection.execute("TRUNCATE organizations CASCADE")

    def make_repository(self):
        from webguard_api.postgres_module_entitlements import PostgresModuleEntitlementRepository

        return PostgresModuleEntitlementRepository(self._pool)

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
