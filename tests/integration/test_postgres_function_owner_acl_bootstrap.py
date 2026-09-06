"""Real-PostgreSQL proof of P1-2 Phase E's function-owner table ACLs
(docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md):
infra/postgres/bootstrap/tenant_isolation_function_acl.sql, applied on
top of Phase C's roles (tenant_isolation_roles.sql) and Phase D's
ordinary tenant-data ACLs (tenant_isolation_acl.sql).

No SECURITY DEFINER function exists yet, so nothing granted here is
reachable from any runtime credential today. This phase proves only
the privilege ceiling the four NOLOGIN function-owner roles will run
under once such functions are written: identity_function_owner is a
pure read resolver boundary, worker_function_owner and
scheduler_function_owner are narrow cross-tenant control-plane
boundaries, callback_function_owner is a narrow public-ingress
boundary. Nothing here is a tenant-isolation claim, and nothing here
touches api_tenant_data, worker_tenant_data, or scheduler_tenant_data.

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
TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"

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

# The complete, intended function-owner privilege matrix -- every
# role/table/command combination not listed here is expected FALSE.
# Built directly from tenant_isolation_function_acl.sql; the test
# below proves the actual database catalog state matches this exactly
# in both directions, for all four function-owner roles.
EXPECTED_FUNCTION_OWNER_GRANTS: dict[str, dict[str, set[str]]] = {
    "identity_function_owner": {
        "api_tokens": {"SELECT"},
        "principals": {"SELECT"},
        "organizations": {"SELECT"},
        "browser_sessions": {"SELECT"},
        "identity_tokens": {"SELECT"},
        "password_credentials": {"SELECT"},
    },
    "worker_function_owner": {
        "scan_jobs": {"SELECT", "UPDATE"},
        "job_permits": {"SELECT"},
        "scan_permits": {"SELECT"},
        "organization_authorizations": {"SELECT"},
        "scan_records": {"SELECT", "UPDATE"},
        "job_safety_receipts": {"INSERT"},
    },
    "scheduler_function_owner": {
        "scan_schedules": {"SELECT", "UPDATE"},
        "organization_authorizations": {"SELECT"},
        "schedule_permits": {"SELECT"},
        "scan_permits": {"SELECT"},
        "scan_jobs": {"SELECT", "INSERT"},
        "job_permits": {"INSERT"},
    },
    "callback_function_owner": {
        "callback_registrations": {"SELECT"},
        "callback_observations": {"INSERT"},
    },
}

# Phase D's own expected matrix (tests/integration/test_postgres_tenant_acl_bootstrap.py),
# reproduced here only to prove Phase E's bootstrap leaves it untouched
# -- not a second source of truth for Phase D itself.
EXPECTED_TENANT_DATA_GRANTS: dict[str, dict[str, set[str]]] = {
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
}


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class FunctionOwnerAclBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.roles_sql = ROLES_SQL_PATH.read_text(encoding="utf-8")
        self.tenant_acl_sql = TENANT_ACL_SQL_PATH.read_text(encoding="utf-8")
        self.function_acl_sql = FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8")
        self.addCleanup(self._drop_bootstrap_roles)
        self._apply_full_bootstrap()

    def _connect(self):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    def _drop_bootstrap_roles(self) -> None:
        # Every one of the seven bootstrap roles holds real privileges
        # by the time this runs (the three tenant-data roles from
        # tenant_acl_sql, the four function-owner roles from
        # function_acl_sql), so DROP OWNED BY must run before DROP
        # ROLE for all seven, not just the four this file itself
        # grants to.
        with self._connect() as connection:
            connection.autocommit = True
            for role in ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    def _apply_full_bootstrap(self) -> None:
        with self._connect() as connection:
            connection.execute(self.roles_sql)
        with self._connect() as connection:
            connection.execute(self.tenant_acl_sql)
        with self._connect() as connection:
            connection.execute(self.function_acl_sql)

    def _apply_function_acl_only(self) -> None:
        with self._connect() as connection:
            connection.execute(self.function_acl_sql)

    def _all_actual_privileges(self, connection, roles: list[str]) -> dict[str, dict[str, set[str]]]:
        """One catalog query covering every role/table/command
        combination at once, for the given roles -- proves the actual
        database state, not the SQL file's own text."""

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
            (roles, ALL_TABLES),
        ).fetchall()
        actual: dict[str, dict[str, set[str]]] = {
            role: {table: set() for table in ALL_TABLES} for role in roles
        }
        for rolname, tablename, cmd in rows:
            actual[rolname][tablename].add(cmd)
        return actual

    # -- Section 16: the complete function-owner positive/negative matrix ---

    def test_positive_and_negative_privilege_matrix_matches_exactly(self) -> None:
        with self._connect() as connection:
            actual = self._all_actual_privileges(connection, FUNCTION_OWNER_ROLES)

        positive_assertions = 0
        negative_assertions = 0

        for role in FUNCTION_OWNER_ROLES:
            expected_for_role = EXPECTED_FUNCTION_OWNER_GRANTS.get(role, {})
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

        total_expected = len(FUNCTION_OWNER_ROLES) * len(ALL_TABLES) * len(COMMANDS)
        self.assertEqual(
            positive_assertions + negative_assertions,
            total_expected,
            "every role x table x command combination must be checked exactly once",
        )
        # 4 roles x 27 tables x 4 commands = 432 total checks.
        self.assertEqual(total_expected, 432)
        self.assertEqual(positive_assertions, 24)
        self.assertEqual(negative_assertions, 408)

    # -- Section 17: Phase D's tenant-data matrix must be untouched ----------

    def test_tenant_data_acl_matrix_is_unchanged_by_phase_e(self) -> None:
        with self._connect() as connection:
            actual = self._all_actual_privileges(connection, TENANT_DATA_ROLES)

        positive_assertions = 0
        negative_assertions = 0
        for role in TENANT_DATA_ROLES:
            expected_for_role = EXPECTED_TENANT_DATA_GRANTS.get(role, {})
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

        total_expected = len(TENANT_DATA_ROLES) * len(ALL_TABLES) * len(COMMANDS)
        # 3 tenant-data roles x 27 tables x 4 commands = 324 total
        # checks (Phase D's own test file additionally checks the four
        # function-owner roles, for 756 total; this file checks only
        # the three tenant-data roles, to prove Phase E left them
        # untouched).
        self.assertEqual(total_expected, 324)
        self.assertEqual(positive_assertions, 71)
        self.assertEqual(negative_assertions, 253)

    # -- Section 18: identity_function_owner is read-only --------------------

    def test_identity_function_owner_cannot_write_anything(self) -> None:
        with self._connect() as connection:
            checks = [
                ("api_tokens", "UPDATE"),
                ("browser_sessions", "UPDATE"),
                ("identity_tokens", "UPDATE"),
                ("principals", "UPDATE"),
                ("password_credentials", "INSERT"),
            ]
            for table, command in checks:
                allowed = connection.execute(
                    "SELECT has_table_privilege('identity_function_owner', %s, %s)",
                    (table, command),
                ).fetchone()[0]
                self.assertFalse(allowed, f"identity_function_owner must not be able to {command} {table}")
            for table in ALL_TABLES:
                allowed = connection.execute(
                    "SELECT has_table_privilege('identity_function_owner', %s, 'DELETE')", (table,)
                ).fetchone()[0]
                self.assertFalse(allowed, f"identity_function_owner must not be able to DELETE {table}")

    # -- Section 19: worker_function_owner cannot do ordinary tenant work ---

    def test_worker_function_owner_cannot_perform_ordinary_tenant_writes(self) -> None:
        with self._connect() as connection:
            checks = [
                ("findings", "INSERT"),
                ("findings", "UPDATE"),
                ("finding_events", "INSERT"),
                ("scan_records", "INSERT"),
                ("scan_jobs", "DELETE"),
                ("scan_records", "DELETE"),
            ]
            for table, command in checks:
                allowed = connection.execute(
                    "SELECT has_table_privilege('worker_function_owner', %s, %s)",
                    (table, command),
                ).fetchone()[0]
                self.assertFalse(allowed, f"worker_function_owner must not be able to {command} {table}")

    # -- Section 20: scheduler_function_owner surface stays narrow -----------

    def test_scheduler_function_owner_surface_is_narrow(self) -> None:
        with self._connect() as connection:
            checks = [
                ("scan_jobs", "UPDATE"),
                ("findings", "SELECT"),
                ("principals", "SELECT"),
                ("password_credentials", "SELECT"),
                ("scan_schedules", "DELETE"),
            ]
            for table, command in checks:
                allowed = connection.execute(
                    "SELECT has_table_privilege('scheduler_function_owner', %s, %s)",
                    (table, command),
                ).fetchone()[0]
                self.assertFalse(allowed, f"scheduler_function_owner must not be able to {command} {table}")

    # -- Section 21: callback_function_owner is SELECT-registration / -------
    # -- INSERT-observation only, nothing else -------------------------------

    def test_callback_function_owner_surface_is_narrow(self) -> None:
        with self._connect() as connection:
            checks = [
                ("callback_observations", "SELECT"),
                ("callback_registrations", "UPDATE"),
                ("callback_registrations", "DELETE"),
                ("callback_observations", "UPDATE"),
                ("callback_observations", "DELETE"),
            ]
            for table, command in checks:
                allowed = connection.execute(
                    "SELECT has_table_privilege('callback_function_owner', %s, %s)",
                    (table, command),
                ).fetchone()[0]
                self.assertFalse(allowed, f"callback_function_owner must not be able to {command} {table}")

    # -- Section 12: schema privileges ---------------------------------------

    def test_function_owner_roles_have_usage_not_create_on_public(self) -> None:
        with self._connect() as connection:
            for role in FUNCTION_OWNER_ROLES:
                has_usage = connection.execute(
                    "SELECT has_schema_privilege(%s, 'public', 'USAGE')", (role,)
                ).fetchone()[0]
                has_create = connection.execute(
                    "SELECT has_schema_privilege(%s, 'public', 'CREATE')", (role,)
                ).fetchone()[0]
                self.assertTrue(has_usage, f"{role} must have USAGE on public")
                self.assertFalse(has_create, f"{role} must not have CREATE on public")

    # -- Section 15: second run is a safe no-op ------------------------------

    def test_function_acl_bootstrap_is_safe_to_run_a_second_time(self) -> None:
        with self._connect() as connection:
            before = self._all_actual_privileges(connection, ALL_BOOTSTRAP_ROLES)

        self._apply_function_acl_only()  # second run

        with self._connect() as connection:
            after = self._all_actual_privileges(connection, ALL_BOOTSTRAP_ROLES)

        self.assertEqual(before, after, "a second function-owner ACL bootstrap run must change nothing")


if __name__ == "__main__":
    unittest.main()
