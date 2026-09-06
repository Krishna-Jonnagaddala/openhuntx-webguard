"""Real-PostgreSQL proof of P1-2 Phase C's cluster-role bootstrap
(docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md):
infra/postgres/bootstrap/tenant_isolation_roles.sql.

This is Phase C of the P1-2 plumbing: the seven roles created here are
completely inert. No table privilege, no schema CREATE privilege, no
function EXECUTE grant, and no role membership exists yet -- this
phase only proves the identities exist, safely, with the exact
attribute profile a later phase's row-level-security policies and
SECURITY DEFINER functions will target.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`) with the 12 schema migrations already
applied, and a connecting role with CREATE ROLE privilege -- the
official postgres Docker image always makes its POSTGRES_USER a full
superuser (see infra/compose/compose.postgres.yml), which is what this
project's disposable dev/CI Postgres already provides and every other
Postgres integration test in this suite already relies on for its own
setup (e.g. TRUNCATE ... CASCADE).
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

BOOTSTRAP_SQL_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "infra" / "postgres" / "bootstrap" / "tenant_isolation_roles.sql"
)

EXPECTED_ROLES = [
    "api_tenant_data",
    "worker_tenant_data",
    "scheduler_tenant_data",
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
]

REPRESENTATIVE_SENSITIVE_TABLES = [
    "organizations",
    "principals",
    "password_credentials",
    "api_tokens",
    "scan_jobs",
    "findings",
    "reports",
    "callback_registrations",
]


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class TenantIsolationRoleBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bootstrap_sql = BOOTSTRAP_SQL_PATH.read_text(encoding="utf-8")
        self.addCleanup(self._drop_bootstrap_roles)

    def _connect(self):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    def _drop_bootstrap_roles(self) -> None:
        # Best-effort test hygiene so repeated local runs of this file
        # don't accumulate roles across test methods -- not part of
        # the bootstrap's own contract.
        with self._connect() as connection:
            connection.autocommit = True
            for role in EXPECTED_ROLES:
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    def _apply_bootstrap(self) -> None:
        with self._connect() as connection:
            connection.execute(self.bootstrap_sql)

    def _role_row(self, connection, role_name: str):
        return connection.execute(
            "SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, "
            "rolcreatedb, rolreplication, rolinherit, oid FROM pg_roles WHERE rolname = %s",
            (role_name,),
        ).fetchone()

    # -- Section 15 scenarios -------------------------------------------

    def test_all_seven_roles_exist_with_the_safe_attribute_profile(self) -> None:
        self._apply_bootstrap()
        with self._connect() as connection:
            for role_name in EXPECTED_ROLES:
                row = self._role_row(connection, role_name)
                self.assertIsNotNone(row, f"{role_name} was not created")
                _, can_login, is_super, bypass_rls, create_role, create_db, replication, inherit, _ = row
                self.assertFalse(can_login, f"{role_name} must be NOLOGIN")
                self.assertFalse(is_super, f"{role_name} must be NOSUPERUSER")
                self.assertFalse(bypass_rls, f"{role_name} must be NOBYPASSRLS")
                self.assertFalse(create_role, f"{role_name} must be NOCREATEROLE")
                self.assertFalse(create_db, f"{role_name} must be NOCREATEDB")
                self.assertFalse(replication, f"{role_name} must be NOREPLICATION")
                self.assertTrue(
                    inherit,
                    "rolinherit is left at CREATE ROLE's own default (true); Phase C creates no "
                    "membership graph requiring it, so the default is intentionally unchanged, not "
                    "explicitly set either way",
                )

    def test_no_unexpected_role_memberships(self) -> None:
        self._apply_bootstrap()
        with self._connect() as connection:
            for role_name in EXPECTED_ROLES:
                is_member_of = connection.execute(
                    """
                    SELECT r.rolname
                    FROM pg_auth_members m
                    JOIN pg_roles r ON r.oid = m.roleid
                    JOIN pg_roles member ON member.oid = m.member
                    WHERE member.rolname = %s
                    """,
                    (role_name,),
                ).fetchall()
                self.assertEqual(is_member_of, [], f"{role_name} must not be a member of any other role")

                members_of_this_role = connection.execute(
                    """
                    SELECT member.rolname
                    FROM pg_auth_members m
                    JOIN pg_roles r ON r.oid = m.roleid
                    JOIN pg_roles member ON member.oid = m.member
                    WHERE r.rolname = %s
                    """,
                    (role_name,),
                ).fetchall()
                self.assertEqual(
                    members_of_this_role, [], f"no role should be granted membership in {role_name} yet"
                )

    def test_no_table_privileges_on_representative_sensitive_tables(self) -> None:
        self._apply_bootstrap()
        with self._connect() as connection:
            for role_name in EXPECTED_ROLES:
                for table_name in REPRESENTATIVE_SENSITIVE_TABLES:
                    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                        has_it = connection.execute(
                            "SELECT has_table_privilege(%s, %s, %s)",
                            (role_name, table_name, privilege),
                        ).fetchone()[0]
                        self.assertFalse(has_it, f"{role_name} must not have {privilege} on {table_name} yet")

    def test_no_create_privilege_on_public_schema(self) -> None:
        self._apply_bootstrap()
        with self._connect() as connection:
            for role_name in EXPECTED_ROLES:
                has_create = connection.execute(
                    "SELECT has_schema_privilege(%s, 'public', 'CREATE')", (role_name,)
                ).fetchone()[0]
                self.assertFalse(has_create, f"{role_name} must not have CREATE on public")

    def test_existing_application_role_behavior_is_unchanged(self) -> None:
        """The connecting role itself (WEBGUARD_POSTGRES_TEST_DSN's own
        role) must be able to do exactly what it could before -- this
        bootstrap must be inert for the existing application, which
        never appears anywhere in the bootstrap SQL at all."""

        with self._connect() as connection:
            before = connection.execute(
                "SELECT has_table_privilege(current_user, 'organizations', 'SELECT')"
            ).fetchone()[0]

        self._apply_bootstrap()

        with self._connect() as connection:
            after = connection.execute(
                "SELECT has_table_privilege(current_user, 'organizations', 'SELECT')"
            ).fetchone()[0]
            connection.execute("SELECT 1 FROM organizations LIMIT 1")

        self.assertEqual(before, after, "the bootstrap must not change the existing connecting role's own privileges")

    def test_bootstrap_is_safe_to_run_a_second_time(self) -> None:
        self._apply_bootstrap()
        with self._connect() as connection:
            before = {role_name: self._role_row(connection, role_name) for role_name in EXPECTED_ROLES}

        self._apply_bootstrap()  # second run

        with self._connect() as connection:
            after = {role_name: self._role_row(connection, role_name) for role_name in EXPECTED_ROLES}

        for role_name in EXPECTED_ROLES:
            self.assertEqual(
                before[role_name],
                after[role_name],
                f"{role_name}'s attributes and oid must be unchanged by a second bootstrap run "
                "(same oid proves the same role object persisted rather than being dropped and recreated)",
            )

    # -- Section 16: unsafe pre-existing role must fail the bootstrap ---

    def test_unsafe_pre_existing_role_with_login_causes_bootstrap_to_fail(self) -> None:
        import psycopg

        with self._connect() as connection:
            connection.autocommit = True
            connection.execute('CREATE ROLE "worker_function_owner" LOGIN')

        with self.assertRaises(psycopg.Error):
            self._apply_bootstrap()

        with self._connect() as connection:
            row = self._role_row(connection, "worker_function_owner")
        self.assertTrue(row[1], "the unsafe pre-existing role must be left exactly as it was, never silently fixed")

    def test_unsafe_pre_existing_role_with_bypassrls_causes_bootstrap_to_fail(self) -> None:
        """The disposable test database's connecting role is a full
        superuser here (the official postgres Docker image always
        makes POSTGRES_USER a superuser), which is what makes it
        possible for this one test to set up a BYPASSRLS role at all.
        This does not mean WebGuard's production bootstrap may ever
        grant BYPASSRLS -- see the bootstrap file's own comment on
        that point, and P1-C2's accepted architecture (round 3 of this
        design), which replaced BYPASSRLS with role-scoped RLS
        policies for exactly this reason: RDS's master user cannot
        grant BYPASSRLS to anything at all."""

        import psycopg

        with self._connect() as connection:
            connection.autocommit = True
            connection.execute('CREATE ROLE "worker_function_owner" NOLOGIN BYPASSRLS')

        with self.assertRaises(psycopg.Error):
            self._apply_bootstrap()

        with self._connect() as connection:
            row = self._role_row(connection, "worker_function_owner")
        self.assertTrue(row[3], "the unsafe pre-existing role must be left exactly as it was, never silently fixed")


if __name__ == "__main__":
    unittest.main()
