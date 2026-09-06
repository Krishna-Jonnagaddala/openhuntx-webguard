"""Real-PostgreSQL proof of P1-2 Phase D's ordinary tenant-data table
ACLs (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md):
infra/postgres/bootstrap/tenant_isolation_acl.sql, applied on top of
Phase C's roles (tenant_isolation_roles.sql).

Even after this phase, a role with SELECT on a tenant table and no
row-level-security policy enabled can see every row it has table-level
permission to read, across every tenant. This phase proves only
SERVICE-LEVEL LEAST-PRIVILEGE ACL STRUCTURE -- which service can touch
which table with which command -- not tenant row isolation. RLS
activation is a later phase; nothing here should be read as a tenant-
isolation claim.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`) with the 12 schema migrations already
applied, and a connecting role with CREATE ROLE and GRANT privilege
(see test_postgres_tenant_role_bootstrap.py's own docstring for why
the official postgres Docker image's POSTGRES_USER already satisfies
this in this project's disposable dev/CI Postgres).
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"

TENANT_DATA_ROLES = ["api_tenant_data", "worker_tenant_data", "scheduler_tenant_data"]
FUNCTION_OWNER_ROLES = [
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
]
ALL_BOOTSTRAP_ROLES = TENANT_DATA_ROLES + FUNCTION_OWNER_ROLES

ALL_TABLES = [
    "organizations",
    "principals",
    "memberships",
    "api_tokens",
    "organization_authorizations",
    "security_audit_events",
    "targets",
    "target_verifications",
    "callback_registrations",
    "callback_observations",
    "scan_jobs",
    "scan_schedules",
    "scan_records",
    "findings",
    "reports",
    "authentication_contexts",
    "authorization_comparison_plans",
    "crawl_checkpoints",
    "scan_permits",
    "job_permits",
    "schedule_permits",
    "job_safety_receipts",
    "finding_events",
    "password_credentials",
    "identity_tokens",
    "browser_sessions",
    "auth_rate_limit_events",
]

COMMANDS = ("SELECT", "INSERT", "UPDATE", "DELETE")

# The complete, intended privilege matrix -- every role/table/command
# combination not listed here is expected to be FALSE. Built directly
# from infra/postgres/bootstrap/tenant_isolation_acl.sql; the test
# below proves the actual database catalog state matches this exactly
# in both directions, for all three tenant-data roles AND all four
# (intentionally ungranted) function-owner roles.
EXPECTED_GRANTS: dict[str, dict[str, set[str]]] = {
    "api_tenant_data": {
        "organizations": {"SELECT", "INSERT"},
        "principals": {"SELECT", "INSERT", "UPDATE"},
        "memberships": {"INSERT"},
        "api_tokens": {"SELECT", "INSERT", "UPDATE"},
        "organization_authorizations": {"SELECT"},
        "security_audit_events": {"SELECT", "INSERT"},
        "targets": {"SELECT", "INSERT", "UPDATE"},
        "target_verifications": {"SELECT", "INSERT", "UPDATE"},
        "scan_jobs": {"SELECT", "INSERT", "UPDATE"},
        "job_permits": {"SELECT", "INSERT"},
        "scan_schedules": {"SELECT", "INSERT", "UPDATE"},
        "schedule_permits": {"SELECT", "INSERT"},
        "scan_records": {"SELECT"},
        "findings": {"SELECT", "UPDATE"},
        "finding_events": {"SELECT", "INSERT"},
        "reports": {"SELECT", "INSERT"},
        "authentication_contexts": {"SELECT", "INSERT", "UPDATE"},
        "authorization_comparison_plans": {"SELECT", "INSERT", "UPDATE"},
        "scan_permits": {"SELECT", "INSERT", "UPDATE"},
        "job_safety_receipts": {"SELECT"},
        "password_credentials": {"INSERT", "UPDATE"},
        "identity_tokens": {"INSERT", "UPDATE"},
        "browser_sessions": {"SELECT", "INSERT", "UPDATE"},
        "auth_rate_limit_events": {"SELECT", "INSERT", "DELETE"},
    },
    "worker_tenant_data": {
        "authentication_contexts": {"SELECT"},
        "authorization_comparison_plans": {"SELECT"},
        "callback_registrations": {"SELECT", "INSERT"},
        "callback_observations": {"SELECT"},
        "scan_permits": {"SELECT"},
        "organization_authorizations": {"SELECT"},
        "scan_records": {"SELECT", "INSERT", "UPDATE"},
        "findings": {"SELECT", "INSERT", "UPDATE"},
        "finding_events": {"INSERT"},
    },
    "scheduler_tenant_data": {
        "organization_authorizations": {"SELECT"},
        "scan_permits": {"SELECT"},
    },
    # The four function-owner roles have no entries at all -- every
    # command on every table is expected FALSE for them (Section 16).
}


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class TenantIsolationAclBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.roles_sql = ROLES_SQL_PATH.read_text(encoding="utf-8")
        self.acl_sql = ACL_SQL_PATH.read_text(encoding="utf-8")
        self.addCleanup(self._drop_bootstrap_roles)
        self._apply_roles_and_acl()

    def _connect(self):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    def _drop_bootstrap_roles(self) -> None:
        # Unlike Phase C's own role-only cleanup, these roles now hold
        # real table/schema privileges (that is the whole point of
        # this phase) -- PostgreSQL refuses to DROP ROLE while granted
        # privileges still exist, so DROP OWNED BY (which revokes
        # every privilege the role holds, and would drop any object it
        # owned, though none of these roles own anything) must run
        # first. Purely test hygiene; not part of the ACL bootstrap's
        # own contract.
        with self._connect() as connection:
            connection.autocommit = True
            for role in ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    def _apply_roles_and_acl(self) -> None:
        with self._connect() as connection:
            connection.execute(self.roles_sql)
        with self._connect() as connection:
            connection.execute(self.acl_sql)

    def _apply_acl_only(self) -> None:
        with self._connect() as connection:
            connection.execute(self.acl_sql)

    def _all_actual_privileges(self, connection) -> dict[str, dict[str, set[str]]]:
        """One catalog query covering every role/table/command
        combination at once -- proves the actual database state, not
        the SQL file's own text."""

        rows = connection.execute(
            """
            SELECT r.rolname, t.tablename, cmd
            FROM pg_roles r
            CROSS JOIN pg_tables t
            CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS cmd
            WHERE r.rolname = ANY(%s)
              AND t.schemaname = 'public'
              AND t.tablename = ANY(%s)
              AND has_table_privilege(r.rolname, t.tablename, cmd)
            """,
            (ALL_BOOTSTRAP_ROLES, ALL_TABLES),
        ).fetchall()
        actual: dict[str, dict[str, set[str]]] = {
            role: {table: set() for table in ALL_TABLES} for role in ALL_BOOTSTRAP_ROLES
        }
        for rolname, tablename, cmd in rows:
            actual[rolname][tablename].add(cmd)
        return actual

    # -- Sections 14, 15, 16: the complete positive/negative matrix ---------

    def test_positive_and_negative_privilege_matrix_matches_exactly(self) -> None:
        with self._connect() as connection:
            actual = self._all_actual_privileges(connection)

        positive_assertions = 0
        negative_assertions = 0

        for role in ALL_BOOTSTRAP_ROLES:
            expected_for_role = EXPECTED_GRANTS.get(role, {})
            for table in ALL_TABLES:
                expected_commands = expected_for_role.get(table, set())
                actual_commands = actual[role][table]
                for command in COMMANDS:
                    if command in expected_commands:
                        positive_assertions += 1
                        self.assertIn(
                            command, actual_commands, f"{role} is missing expected {command} on {table}"
                        )
                    else:
                        negative_assertions += 1
                        self.assertNotIn(
                            command, actual_commands, f"{role} unexpectedly has {command} on {table}"
                        )

        total_expected = len(ALL_BOOTSTRAP_ROLES) * len(ALL_TABLES) * len(COMMANDS)
        self.assertEqual(
            positive_assertions + negative_assertions,
            total_expected,
            "every role x table x command combination must be checked exactly once",
        )
        # 7 roles x 27 tables x 4 commands = 756 total checks.
        self.assertEqual(total_expected, 756)

    # -- ACL correction regression: organization_authorizations INSERT ------

    def test_api_tenant_data_cannot_insert_organization_authorizations(self) -> None:
        """assign_authorization's only live caller anywhere in this
        codebase is cli.py's `authorization assign` operator
        subcommand -- the WebGuard API serve process never calls it.
        api_tenant_data must keep SELECT (service.py's
        authorization_is_assigned/list_assigned_authorization_ids
        calls are genuinely API-serve-reachable) without INSERT."""

        with self._connect() as connection:
            can_insert = connection.execute(
                "SELECT has_table_privilege('api_tenant_data', 'organization_authorizations', 'INSERT')"
            ).fetchone()[0]
            can_select = connection.execute(
                "SELECT has_table_privilege('api_tenant_data', 'organization_authorizations', 'SELECT')"
            ).fetchone()[0]
        self.assertFalse(can_insert, "api_tenant_data must not be able to INSERT organization_authorizations")
        self.assertTrue(can_select, "api_tenant_data must still be able to SELECT organization_authorizations")

    # -- Section 9/17: schema privileges -------------------------------------

    def test_tenant_data_roles_have_usage_not_create_on_public(self) -> None:
        with self._connect() as connection:
            for role in TENANT_DATA_ROLES:
                has_usage = connection.execute(
                    "SELECT has_schema_privilege(%s, 'public', 'USAGE')", (role,)
                ).fetchone()[0]
                has_create = connection.execute(
                    "SELECT has_schema_privilege(%s, 'public', 'CREATE')", (role,)
                ).fetchone()[0]
                self.assertTrue(has_usage, f"{role} must have USAGE on public")
                self.assertFalse(has_create, f"{role} must not have CREATE on public")

    def test_function_owner_schema_state_is_unaffected_by_phase_d(self) -> None:
        """Phase D grants nothing to the four function-owner roles at
        all. CREATE on public must still be false for them -- proving
        this ACL file did not accidentally touch them. USAGE on public
        is deliberately not asserted false here: confirmed directly
        against this Postgres 16 instance (\\dn+ public shows an
        `=U/pg_database_owner` entry, and a freshly created role with
        zero explicit grants already has has_schema_privilege(...,
        'USAGE') = true) that PostgreSQL grants USAGE on the public
        schema to the PUBLIC pseudo-role by default -- every role gets
        it for free, unrelated to anything either bootstrap file does.
        Only CREATE was ever revoked from PUBLIC by default (since
        PostgreSQL 15); that is the property this test actually
        proves is untouched."""

        with self._connect() as connection:
            for role in FUNCTION_OWNER_ROLES:
                has_create = connection.execute(
                    "SELECT has_schema_privilege(%s, 'public', 'CREATE')", (role,)
                ).fetchone()[0]
                self.assertFalse(has_create, f"{role} must not have CREATE on public after Phase D")

    # -- Section 12: second run is a safe no-op ------------------------------

    def test_acl_bootstrap_is_safe_to_run_a_second_time(self) -> None:
        with self._connect() as connection:
            before = self._all_actual_privileges(connection)

        self._apply_acl_only()  # second run

        with self._connect() as connection:
            after = self._all_actual_privileges(connection)

        self.assertEqual(before, after, "a second ACL bootstrap run must change nothing")

    # -- Section 18: inherited-privilege proof (optional, extra rigor) ------

    def test_a_login_role_inherits_only_its_granted_tenant_data_privileges(self) -> None:
        """Test-only LOGIN callers, created and dropped entirely within
        this test -- these names must never appear in production
        bootstrap SQL. Proves the actual deployment mechanism a future
        phase depends on: a LOGIN role granted membership in one of
        these NOLOGIN roles inherits exactly that role's privileges,
        nothing more."""

        test_login_roles = {
            "test_api_runtime": "api_tenant_data",
            "test_worker_runtime": "worker_tenant_data",
            "test_scheduler_runtime": "scheduler_tenant_data",
        }
        with self._connect() as connection:
            connection.autocommit = True
            for login_role, base_role in test_login_roles.items():
                connection.execute(f'DROP ROLE IF EXISTS "{login_role}"')
                connection.execute(f'CREATE ROLE "{login_role}" LOGIN NOSUPERUSER IN ROLE "{base_role}"')

        try:
            with self._connect() as connection:
                # test_api_runtime should inherit api_tenant_data's
                # organizations SELECT/INSERT, but not worker_tenant_data's
                # scan_records privileges.
                self.assertTrue(
                    connection.execute(
                        "SELECT has_table_privilege('test_api_runtime', 'organizations', 'SELECT')"
                    ).fetchone()[0]
                )
                self.assertFalse(
                    connection.execute(
                        "SELECT has_table_privilege('test_api_runtime', 'scan_records', 'INSERT')"
                    ).fetchone()[0]
                )
                self.assertTrue(
                    connection.execute(
                        "SELECT has_table_privilege('test_worker_runtime', 'scan_records', 'INSERT')"
                    ).fetchone()[0]
                )
                self.assertFalse(
                    connection.execute(
                        "SELECT has_table_privilege('test_worker_runtime', 'organizations', 'SELECT')"
                    ).fetchone()[0]
                )
                self.assertTrue(
                    connection.execute(
                        "SELECT has_table_privilege('test_scheduler_runtime', 'scan_permits', 'SELECT')"
                    ).fetchone()[0]
                )
                self.assertFalse(
                    connection.execute(
                        "SELECT has_table_privilege('test_scheduler_runtime', 'scan_jobs', 'SELECT')"
                    ).fetchone()[0]
                )
        finally:
            with self._connect() as connection:
                connection.autocommit = True
                for login_role in test_login_roles:
                    connection.execute(f'DROP ROLE IF EXISTS "{login_role}"')


if __name__ == "__main__":
    unittest.main()
