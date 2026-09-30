"""Contract tests for the scoped control implementation repository
(platform expansion, docs/PLATFORM_SCOPE.md, handoff section
10.1-10.2). Postgres-only: see
apps/api/src/webguard_api/postgres_compliance_scope.py's own module
docstring for why no in-memory backend exists for this slice.

Every test seeds and cleans up its own organization and, where a
fresh control is needed, its own master_control row, since this table
has no per-test truncation strategy and its rows are real foreign-key
children of the seeded compliance catalog (docs/adr/0034).
"""

from __future__ import annotations

import os
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from webguard_contracts import ApplicabilityStatus

from webguard_api.postgres_compliance_scope import (
    PostgresComplianceScopeRepository,
    ScopedControlImplementationError,
)

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)

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


def _make_organization_id() -> str:
    return str(uuid.uuid4())


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test.",
)
class PostgresComplianceScopeRepositoryContractTests(unittest.TestCase):
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
        self._organization_id = _make_organization_id()
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (self._organization_id, "Contract Test Org", f"org-{self._organization_id}", "active", NOW),
            )
        self.addCleanup(self._delete_organization)

        # migration 0015 seeds the "soc2" framework itself but zero
        # master_controls under it (no real content is loaded yet, per
        # docs/PLATFORM_SCOPE.md's legal-review blocker), so every test
        # needing a real control_id to reference creates and cleans up
        # its own synthetic one here rather than assuming seeded content.
        self._control_id = f"test-control-{uuid.uuid4()}"
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO master_controls "
                "(control_id, framework_id, control_number, title, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (self._control_id, "soc2", "TEST-1", "Synthetic test control", NOW, NOW),
            )
        self.addCleanup(self._delete_control)

    def _delete_control(self) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "DELETE FROM scoped_control_implementations WHERE control_id = %s",
                (self._control_id,),
            )
            connection.execute("DELETE FROM master_controls WHERE control_id = %s", (self._control_id,))

    def _delete_organization(self) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "DELETE FROM scoped_control_implementations WHERE organization_id = %s",
                (self._organization_id,),
            )
            connection.execute("DELETE FROM principals WHERE organization_id = %s", (self._organization_id,))
            connection.execute(
                "DELETE FROM organizations WHERE organization_id = %s", (self._organization_id,)
            )

    def make_repository(self):
        return PostgresComplianceScopeRepository(self._pool)

    def _make_principal(self, organization_id: str) -> str:
        principal_id = _make_organization_id()
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO principals "
                "(principal_id, organization_id, display_name, principal_type, role, active, created_at) "
                "VALUES (%s, %s, 'Test Reviewer', 'user', 'owner', TRUE, %s)",
                (principal_id, organization_id, NOW),
            )
        return principal_id

    def test_get_unrecorded_control_fails_closed(self) -> None:
        repo = self.make_repository()
        with self.assertRaises(ScopedControlImplementationError) as caught:
            repo.get_applicability(self._organization_id, self._control_id)
        self.assertEqual(caught.exception.code, "scoped_control_implementation_not_found")

    def test_set_applicability_unresolved_round_trips(self) -> None:
        repo = self.make_repository()
        record = repo.set_applicability(
            self._organization_id,
            self._control_id,
            applicability_status=ApplicabilityStatus.UNRESOLVED,
            now=NOW,
        )
        self.assertEqual(record.applicability_status, ApplicabilityStatus.UNRESOLVED)
        self.assertEqual(record.framework_id, "soc2")
        self.assertIsNone(record.decided_by)
        fetched = repo.get_applicability(self._organization_id, self._control_id)
        self.assertEqual(fetched.applicability_status, ApplicabilityStatus.UNRESOLVED)

    def test_set_applicability_then_revise_to_not_applicable(self) -> None:
        repo = self.make_repository()
        decider = self._make_principal(self._organization_id)
        repo.set_applicability(
            self._organization_id,
            self._control_id,
            applicability_status=ApplicabilityStatus.UNRESOLVED,
            now=NOW,
        )
        revised = repo.set_applicability(
            self._organization_id,
            self._control_id,
            applicability_status=ApplicabilityStatus.NOT_APPLICABLE_WITH_RATIONALE,
            now=NOW,
            rationale="This organization processes no cardholder data.",
            decided_by=decider,
            decided_at=NOW,
        )
        self.assertEqual(revised.applicability_status, ApplicabilityStatus.NOT_APPLICABLE_WITH_RATIONALE)
        self.assertEqual(revised.rationale, "This organization processes no cardholder data.")
        self.assertEqual(revised.decided_by, decider)

    def test_list_applicability_for_framework_excludes_unrecorded_controls(self) -> None:
        """A control this organization never scoped must not appear at
        all: not as unresolved, not as any synthesized default. This
        is the denominator honesty handoff section 10.2 requires."""

        repo = self.make_repository()
        repo.set_applicability(
            self._organization_id,
            self._control_id,
            applicability_status=ApplicabilityStatus.UNRESOLVED,
            now=NOW,
        )
        results = repo.list_applicability_for_framework(self._organization_id, "soc2")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].control_id, self._control_id)

    def test_list_applicability_is_scoped_per_organization(self) -> None:
        repo = self.make_repository()
        other_organization_id = _make_organization_id()
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (other_organization_id, "Other Org", f"org-{other_organization_id}", "active", NOW),
            )
        try:
            repo.set_applicability(
                self._organization_id,
                self._control_id,
                applicability_status=ApplicabilityStatus.UNRESOLVED,
                now=NOW,
            )
            repo.set_applicability(
                other_organization_id,
                self._control_id,
                applicability_status=ApplicabilityStatus.UNRESOLVED,
                now=NOW,
            )
            mine = repo.list_applicability_for_framework(self._organization_id, "soc2")
            theirs = repo.list_applicability_for_framework(other_organization_id, "soc2")
            self.assertEqual(len(mine), 1)
            self.assertEqual(len(theirs), 1)
        finally:
            with self._pool.connection() as connection:
                connection.execute(
                    "DELETE FROM scoped_control_implementations WHERE organization_id = %s",
                    (other_organization_id,),
                )
                connection.execute(
                    "DELETE FROM organizations WHERE organization_id = %s", (other_organization_id,)
                )

    def test_set_applicability_rejects_unknown_control(self) -> None:
        """control_id's foreign key to master_controls fails this at
        the database level; unwrapped, matching create_master_control's
        own accepted shape for a bad framework_id reference."""

        repo = self.make_repository()
        with self.assertRaises(Exception):
            repo.set_applicability(
                self._organization_id,
                "does-not-exist",
                applicability_status=ApplicabilityStatus.UNRESOLVED,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
