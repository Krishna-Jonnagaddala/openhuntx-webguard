"""Real-PostgreSQL proof of P1-2 Phase G (docs/audit/
WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md):
infra/postgres/bootstrap/tenant_isolation_rls_policies.sql, applied on
top of Phase C's roles, Phase D's tenant-data ACLs, Phase E's
function-owner ACLs, and Phase F's control functions.

Phase G defines row-level-security POLICIES only. Production/bootstrap
RLS stays disabled (relrowsecurity = false, relforcerowsecurity =
false) on every table -- this suite's metadata classes prove that
directly against the same bootstrap chain production runs. A separate
behavioral class temporarily ENABLEs and FORCEs RLS inside a
disposable database (never production) purely to prove the policy
model actually isolates tenants the way its predicates claim, using
disposable LOGIN test-caller roles that inherit exactly one ordinary
capability role each.

Requires a real database (WEBGUARD_RUN_INTEGRATION=1 and a reachable
WEBGUARD_POSTGRES_TEST_DSN) with the 12 schema migrations already
applied, and a connecting role with CREATE ROLE and CREATE DATABASE
privilege.
"""

from __future__ import annotations

import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"
RLS_POLICIES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_rls_policies.sql"

GUC_NAME = "webguard.current_organization_id"

TENANT_DATA_ROLES = ["api_tenant_data", "worker_tenant_data", "scheduler_tenant_data"]
FUNCTION_OWNER_ROLES = [
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
]
ALL_BOOTSTRAP_ROLES = TENANT_DATA_ROLES + FUNCTION_OWNER_ROLES

# All tables in the schema. Migrations 0001-0012 gave Phase G its
# original 27; migration 0017 (Compliance Phase 5 of the 2026-09-14
# scope audit) added technical_assertion_collections, reconciled here
# 2026-09-15 alongside its own new RLS policies below.
ALL_TABLES = [
    "organizations", "principals", "memberships", "api_tokens",
    "organization_authorizations", "security_audit_events",
    "targets", "target_verifications",
    "callback_registrations", "callback_observations",
    "scan_permits", "job_permits", "schedule_permits", "job_safety_receipts",
    "scan_jobs", "scan_schedules", "scan_records", "findings", "reports",
    "authentication_contexts", "authorization_comparison_plans", "crawl_checkpoints",
    "finding_events", "password_credentials", "identity_tokens",
    "browser_sessions", "auth_rate_limit_events",
    "technical_assertion_collections",
]
assert len(ALL_TABLES) == 28

# The one non-tenant-owned table: no organization_id column, used only
# on pre-authentication routes, bucket_key never an organization id.
GLOBAL_SYSTEM_TABLES = ["auth_rate_limit_events"]

# Tenant-owned = every table except the one global/system table above.
# This is a claim about DATA OWNERSHIP, independent of whether any
# role currently has an ACL grant on it (crawl_checkpoints is
# tenant-owned -- it carries organization_id directly -- but has zero
# current grantees, so it gets no policy below; that is a statement
# about today's callers, not about who owns the data).
TENANT_OWNED_TABLES = [t for t in ALL_TABLES if t not in GLOBAL_SYSTEM_TABLES]
assert len(TENANT_OWNED_TABLES) == 27

# Tables a policy exists for today (26 of the 27 tenant-owned tables:
# everything except crawl_checkpoints, which has zero ACL grantees on
# any role -- Phase D's own precedent for a dormant table).
ZERO_POLICY_TENANT_OWNED_TABLES = ["crawl_checkpoints"]
RLS_MANAGED_TABLES = [t for t in TENANT_OWNED_TABLES if t not in ZERO_POLICY_TENANT_OWNED_TABLES]
assert len(RLS_MANAGED_TABLES) == 26

# Every table this suite will eventually enable+force RLS on inside
# the disposable database, to prove future enforcement semantics --
# this includes crawl_checkpoints (Section 2: proving default-deny
# with zero policies), unlike RLS_MANAGED_TABLES above.
FUTURE_RLS_TARGET_TABLES = TENANT_OWNED_TABLES
assert len(FUTURE_RLS_TARGET_TABLES) == 27

# Expected (table, role, command) triples, mirroring the SQL file
# exactly (same source classification as the generator that produced
# it). role -> "owner" marks a function-owner true-policy; role ->
# tenant-data role name marks an ordinary tenant-predicate policy.
EXPECTED_POLICIES = [
    ("organizations", "api_tenant_data", "SELECT", False),
    ("organizations", "api_tenant_data", "INSERT", False),
    ("organizations", "identity_function_owner", "SELECT", True),
    ("principals", "api_tenant_data", "SELECT", False),
    ("principals", "api_tenant_data", "INSERT", False),
    ("principals", "api_tenant_data", "UPDATE", False),
    ("principals", "identity_function_owner", "SELECT", True),
    ("memberships", "api_tenant_data", "INSERT", False),
    ("api_tokens", "api_tenant_data", "SELECT", False),
    ("api_tokens", "api_tenant_data", "INSERT", False),
    ("api_tokens", "api_tenant_data", "UPDATE", False),
    ("api_tokens", "identity_function_owner", "SELECT", True),
    ("organization_authorizations", "api_tenant_data", "SELECT", False),
    ("organization_authorizations", "worker_tenant_data", "SELECT", False),
    ("organization_authorizations", "scheduler_tenant_data", "SELECT", False),
    ("organization_authorizations", "worker_function_owner", "SELECT", True),
    ("organization_authorizations", "scheduler_function_owner", "SELECT", True),
    ("security_audit_events", "api_tenant_data", "SELECT", False),
    ("security_audit_events", "api_tenant_data", "INSERT", False),
    ("targets", "api_tenant_data", "SELECT", False),
    ("targets", "api_tenant_data", "INSERT", False),
    ("targets", "api_tenant_data", "UPDATE", False),
    ("target_verifications", "api_tenant_data", "SELECT", False),
    ("target_verifications", "api_tenant_data", "INSERT", False),
    ("target_verifications", "api_tenant_data", "UPDATE", False),
    ("callback_registrations", "worker_tenant_data", "SELECT", False),
    ("callback_registrations", "worker_tenant_data", "INSERT", False),
    ("callback_registrations", "callback_function_owner", "SELECT", True),
    ("callback_observations", "worker_tenant_data", "SELECT", False),
    ("callback_observations", "callback_function_owner", "INSERT", True),
    ("scan_permits", "api_tenant_data", "SELECT", False),
    ("scan_permits", "api_tenant_data", "INSERT", False),
    ("scan_permits", "api_tenant_data", "UPDATE", False),
    ("scan_permits", "worker_tenant_data", "SELECT", False),
    ("scan_permits", "scheduler_tenant_data", "SELECT", False),
    ("scan_permits", "worker_function_owner", "SELECT", True),
    ("scan_permits", "scheduler_function_owner", "SELECT", True),
    ("job_permits", "api_tenant_data", "SELECT", False),
    ("job_permits", "api_tenant_data", "INSERT", False),
    ("job_permits", "worker_function_owner", "SELECT", True),
    ("job_permits", "scheduler_function_owner", "INSERT", True),
    ("job_safety_receipts", "api_tenant_data", "SELECT", False),
    ("job_safety_receipts", "worker_function_owner", "INSERT", True),
    ("scan_jobs", "api_tenant_data", "SELECT", False),
    ("scan_jobs", "api_tenant_data", "INSERT", False),
    ("scan_jobs", "api_tenant_data", "UPDATE", False),
    ("scan_jobs", "worker_function_owner", "SELECT", True),
    ("scan_jobs", "worker_function_owner", "UPDATE", True),
    ("scan_jobs", "scheduler_function_owner", "SELECT", True),
    ("scan_jobs", "scheduler_function_owner", "INSERT", True),
    ("scan_schedules", "api_tenant_data", "SELECT", False),
    ("scan_schedules", "api_tenant_data", "INSERT", False),
    ("scan_schedules", "api_tenant_data", "UPDATE", False),
    ("scan_schedules", "scheduler_function_owner", "SELECT", True),
    ("scan_schedules", "scheduler_function_owner", "UPDATE", True),
    ("schedule_permits", "api_tenant_data", "SELECT", False),
    ("schedule_permits", "api_tenant_data", "INSERT", False),
    ("schedule_permits", "scheduler_function_owner", "SELECT", True),
    ("scan_records", "api_tenant_data", "SELECT", False),
    ("scan_records", "worker_tenant_data", "SELECT", False),
    ("scan_records", "worker_tenant_data", "INSERT", False),
    ("scan_records", "worker_tenant_data", "UPDATE", False),
    ("scan_records", "worker_function_owner", "SELECT", True),
    ("scan_records", "worker_function_owner", "UPDATE", True),
    ("findings", "api_tenant_data", "SELECT", False),
    ("findings", "api_tenant_data", "UPDATE", False),
    ("findings", "worker_tenant_data", "SELECT", False),
    ("findings", "worker_tenant_data", "INSERT", False),
    ("findings", "worker_tenant_data", "UPDATE", False),
    ("finding_events", "api_tenant_data", "SELECT", False),
    ("finding_events", "api_tenant_data", "INSERT", False),
    ("finding_events", "worker_tenant_data", "INSERT", False),
    ("reports", "api_tenant_data", "SELECT", False),
    ("reports", "api_tenant_data", "INSERT", False),
    ("authentication_contexts", "api_tenant_data", "SELECT", False),
    ("authentication_contexts", "api_tenant_data", "INSERT", False),
    ("authentication_contexts", "api_tenant_data", "UPDATE", False),
    ("authentication_contexts", "worker_tenant_data", "SELECT", False),
    ("authorization_comparison_plans", "api_tenant_data", "SELECT", False),
    ("authorization_comparison_plans", "api_tenant_data", "INSERT", False),
    ("authorization_comparison_plans", "api_tenant_data", "UPDATE", False),
    ("authorization_comparison_plans", "worker_tenant_data", "SELECT", False),
    ("identity_tokens", "api_tenant_data", "SELECT", False),
    ("identity_tokens", "api_tenant_data", "INSERT", False),
    ("identity_tokens", "api_tenant_data", "UPDATE", False),
    ("identity_tokens", "identity_function_owner", "SELECT", True),
    ("browser_sessions", "api_tenant_data", "SELECT", False),
    ("browser_sessions", "api_tenant_data", "INSERT", False),
    ("browser_sessions", "api_tenant_data", "UPDATE", False),
    ("browser_sessions", "identity_function_owner", "SELECT", True),
    ("password_credentials", "api_tenant_data", "SELECT", False),
    ("password_credentials", "api_tenant_data", "INSERT", False),
    ("password_credentials", "api_tenant_data", "UPDATE", False),
    ("password_credentials", "identity_function_owner", "SELECT", True),
    ("technical_assertion_collections", "api_tenant_data", "SELECT", False),
    ("technical_assertion_collections", "api_tenant_data", "INSERT", False),
]
# P1-2 Phase-D correction (tenant_isolation_acl.sql): api_tenant_data
# gained narrow column SELECT on both tables (identity_tokens:
# token_id/principal_id/purpose/used_at; password_credentials:
# principal_id only), needed for its own UPDATE/ON-CONFLICT statements
# to satisfy PostgreSQL's SELECT-for-WHERE-clause rule. These two new
# ordinary SELECT policies are that correction's RLS-side counterpart
# -- a DML dependency, not a new business-level read capability, since
# the ACL still withholds table-level SELECT and every sensitive
# column (password_hash, secret_hash) on both tables. 92 + 2 = 94.
# 2026-09-15: +2 for technical_assertion_collections (migration 0017,
# Compliance Phase 5): SELECT/INSERT only, no UPDATE, since a
# collection attempt is immutable once written. 94 + 2 = 96.
assert len(EXPECTED_POLICIES) == 96


def _role_short(role: str) -> str:
    return {
        "api_tenant_data": "api",
        "worker_tenant_data": "worker",
        "scheduler_tenant_data": "scheduler",
        "identity_function_owner": "identity_owner",
        "worker_function_owner": "worker_owner",
        "scheduler_function_owner": "scheduler_owner",
        "callback_function_owner": "callback_owner",
    }[role]


def _expected_policy_name(table: str, role: str, command: str) -> str:
    return f"wg_{_role_short(role)}_{table}_{command.lower()}"


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class RLSPolicyMetadataTests(unittest.TestCase):
    """Sections 21, 22, 39, 40: exact policy inventory, production RLS
    state, no unconditional ordinary-role policy, function-owner
    policy/ACL matrix -- all against the same bootstrap chain
    production actually runs, on the shared integration database."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.roles_sql = ROLES_SQL_PATH.read_text(encoding="utf-8")
        cls.tenant_acl_sql = TENANT_ACL_SQL_PATH.read_text(encoding="utf-8")
        cls.function_acl_sql = FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8")
        cls.control_functions_sql = CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8")
        cls.rls_policies_sql = RLS_POLICIES_SQL_PATH.read_text(encoding="utf-8")
        cls._apply_full_bootstrap()

    @classmethod
    def tearDownClass(cls) -> None:
        with cls._connect() as connection:
            connection.autocommit = True
            for table in RLS_MANAGED_TABLES:
                for table_r, role, command, _owner in EXPECTED_POLICIES:
                    if table_r != table:
                        continue
                    name = _expected_policy_name(table, role, command)
                    connection.execute(f'DROP POLICY IF EXISTS "{name}" ON public.{table}')
            connection.execute("DROP SCHEMA IF EXISTS webguard_control CASCADE")
            for role in ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    @classmethod
    def _connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def _apply_full_bootstrap(cls) -> None:
        with cls._connect() as connection:
            connection.execute(cls.roles_sql)
        with cls._connect() as connection:
            connection.execute(cls.tenant_acl_sql)
        with cls._connect() as connection:
            connection.execute(cls.function_acl_sql)
        with cls._connect() as connection:
            connection.execute(cls.control_functions_sql)
        with cls._connect() as connection:
            connection.execute(cls.rls_policies_sql)

    def test_policy_inventory_matches_expected(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT p.polname, c.relname, p.polcmd, p.polpermissive,
                       array(SELECT rolname FROM pg_roles WHERE oid = ANY(p.polroles)) AS roles,
                       p.polqual IS NOT NULL, p.polwithcheck IS NOT NULL
                FROM pg_policy p
                JOIN pg_class c ON c.oid = p.polrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                """
            ).fetchall()

        actual_by_name = {row[0]: row for row in rows}
        self.assertEqual(len(rows), 96, f"expected exactly 96 policies, got {len(rows)}: {sorted(actual_by_name)}")

        cmd_map = {"r": "SELECT", "a": "INSERT", "w": "UPDATE", "d": "DELETE", "*": "ALL"}
        expected_names = set()
        for table, role, command, is_owner_true in EXPECTED_POLICIES:
            name = _expected_policy_name(table, role, command)
            expected_names.add(name)
            self.assertIn(name, actual_by_name, f"missing expected policy {name}")
            _polname, relname, polcmd, permissive, roles, has_qual, has_check = actual_by_name[name]
            self.assertEqual(relname, table, f"{name}: expected table {table}, got {relname}")
            self.assertEqual(cmd_map[polcmd], command, f"{name}: expected command {command}")
            self.assertTrue(permissive, f"{name}: must be PERMISSIVE, never RESTRICTIVE")
            self.assertEqual(list(roles), [role], f"{name}: expected exactly role {role}, got {roles}")
            if command == "SELECT":
                self.assertTrue(has_qual, f"{name}: SELECT policy must have a USING clause")
                self.assertFalse(has_check, f"{name}: SELECT policy must not have a WITH CHECK clause")
            elif command == "INSERT":
                self.assertFalse(has_qual, f"{name}: INSERT policy must not have a USING clause")
                self.assertTrue(has_check, f"{name}: INSERT policy must have a WITH CHECK clause")
            elif command == "UPDATE":
                self.assertTrue(has_qual, f"{name}: UPDATE policy must have a USING clause")
                self.assertTrue(has_check, f"{name}: UPDATE policy must have a WITH CHECK clause")

        self.assertEqual(set(actual_by_name), expected_names, "no unexpected policy may exist")

    def test_no_public_policies(self) -> None:
        with self._connect() as connection:
            public_policy_count = connection.execute(
                """
                SELECT count(*) FROM pg_policies
                WHERE schemaname = 'public' AND 'public' = ANY(roles)
                """
            ).fetchone()[0]
        self.assertEqual(public_policy_count, 0, "no policy may target the PUBLIC pseudo-role")

    def test_no_unconditional_ordinary_role_policy(self) -> None:
        # Section 39: api_tenant_data/worker_tenant_data/scheduler_tenant_data
        # must never have a policy whose USING or WITH CHECK is the bare
        # literal `true` -- every one of their policies must reference
        # webguard_current_tenant() (directly or through a derived EXISTS
        # subquery against a parent table's organization_id).
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT policyname, unnest(roles) AS role, qual, with_check
                FROM pg_policies
                WHERE schemaname = 'public'
                """
            ).fetchall()
        rows = [row for row in rows if row[1] in TENANT_DATA_ROLES]
        self.assertGreater(len(rows), 0, "expected ordinary-role policies to exist")
        for name, role, qual, check in rows:
            expr = qual or check or ""
            self.assertIn(
                "webguard_current_tenant", expr,
                f"{name} ({role}): ordinary-role policy must reference webguard_current_tenant(), "
                f"got {expr!r} -- an unconditional policy here would be a tenant-isolation bypass",
            )

    def test_function_owner_policies_are_narrow_true_policies(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT policyname, unnest(roles) AS role, tablename, cmd, qual, with_check
                FROM pg_policies
                WHERE schemaname = 'public'
                """
            ).fetchall()
        rows = [row for row in rows if row[1] in FUNCTION_OWNER_ROLES]
        self.assertEqual(len(rows), 24, f"expected exactly 24 function-owner policies, got {len(rows)}")
        for name, role, table, cmd, qual, check in rows:
            expr = qual if cmd in ("SELECT", "UPDATE") else check
            self.assertEqual(expr, "true", f"{name}: function-owner policy must be exactly `true`, got {expr!r}")
            self.assertNotIn(
                role, TENANT_DATA_ROLES,
                f"{name}: a function-owner true-policy must never target an ordinary tenant-data role",
            )

    def test_function_owner_policy_commands_subset_of_acl(self) -> None:
        # Section 15/40: no function-owner policy may authorize a
        # (table, command) pair its Phase-E ACL does not also grant.
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT unnest(roles) AS role, tablename, cmd
                FROM pg_policies
                WHERE schemaname = 'public'
                """
            ).fetchall()
            rows = [row for row in rows if row[0] in FUNCTION_OWNER_ROLES]
            for role, table, command in rows:
                has_priv = connection.execute(
                    "SELECT has_table_privilege(%s, %s, %s)",
                    (role, f"public.{table}", command),
                ).fetchone()[0]
                self.assertTrue(
                    has_priv,
                    f"{role} has a {command} policy on {table} but no {command} table privilege there "
                    "-- a policy must never authorize more than the ACL already grants",
                )

    def test_crawl_checkpoints_is_tenant_owned_but_has_zero_policies(self) -> None:
        # Section 1/12: tenant ownership and current policy coverage
        # are separate questions. crawl_checkpoints carries
        # organization_id directly (tenant-owned) but has no ACL
        # grantee on any role today, so it correctly has zero policies
        # -- this is a statement about today's callers, not a claim
        # that the table is exempt from tenant isolation.
        with self._connect() as connection:
            has_org_column = connection.execute(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = 'crawl_checkpoints' "
                "AND column_name = 'organization_id')"
            ).fetchone()[0]
            self.assertTrue(has_org_column, "crawl_checkpoints must carry organization_id directly")

            policy_count = connection.execute(
                "SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND tablename = 'crawl_checkpoints'"
            ).fetchone()[0]
            self.assertEqual(policy_count, 0, "crawl_checkpoints must have zero policies today")

            for role in TENANT_DATA_ROLES + FUNCTION_OWNER_ROLES:
                for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                    has_priv = connection.execute(
                        "SELECT has_table_privilege(%s, 'public.crawl_checkpoints', %s)", (role, priv)
                    ).fetchone()[0]
                    self.assertFalse(has_priv, f"{role} must not have {priv} on crawl_checkpoints")

    def test_production_rls_state_is_off_for_all_tables(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT relname, relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'
                  AND relname = ANY(%s)
                """,
                (ALL_TABLES,),
            ).fetchall()
        found = {row[0] for row in rows}
        self.assertEqual(found, set(ALL_TABLES), f"expected to find all {len(ALL_TABLES)} tables")
        for relname, rowsecurity, forcerowsecurity in rows:
            self.assertFalse(rowsecurity, f"{relname}: relrowsecurity must be FALSE in the production bootstrap")
            self.assertFalse(forcerowsecurity, f"{relname}: relforcerowsecurity must be FALSE in the production bootstrap")

    def test_policy_bootstrap_is_safe_to_run_a_second_time(self) -> None:
        with self._connect() as connection:
            before = connection.execute(
                """
                SELECT policyname, tablename, cmd, permissive, roles, qual, with_check
                FROM pg_policies
                WHERE schemaname = 'public' ORDER BY tablename, policyname
                """
            ).fetchall()

        with self._connect() as connection:
            connection.execute(self.rls_policies_sql)

        with self._connect() as connection:
            after = connection.execute(
                """
                SELECT policyname, tablename, cmd, permissive, roles, qual, with_check
                FROM pg_policies
                WHERE schemaname = 'public' ORDER BY tablename, policyname
                """
            ).fetchall()

        self.assertEqual(before, after, "a second run of the policy bootstrap must leave policy metadata identical")
        self.assertEqual(len(after), 96, "second run must not create duplicate or missing policies")


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class TwoTenantIsolationTests(unittest.TestCase):
    """Sections 23-41: temporarily ENABLE and FORCE row-level security
    inside a disposable database (never production) and prove the
    policy model actually isolates two tenants the way its predicates
    claim, using disposable LOGIN test-caller roles that inherit
    exactly one ordinary capability role each. Fixture rows are seeded
    for tenant A and tenant B across EVERY one of the 25 tables that
    currently has a policy, plus crawl_checkpoints (tenant-owned, zero
    current policies, tested separately for default-deny). SELECT/
    INSERT/UPDATE coverage is matrix-driven from the real, live ACL
    grants (has_table_privilege), not hand-picked."""

    ORG_A = str(uuid.uuid4())
    ORG_B = str(uuid.uuid4())

    @classmethod
    def setUpClass(cls) -> None:
        import subprocess
        import sys
        from urllib.parse import urlsplit, urlunsplit

        cls._admin_dsn = POSTGRES_TEST_DSN
        parts = urlsplit(POSTGRES_TEST_DSN)
        cls._host_port = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
        cls._db_name = "test_rls_isolation_db"

        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            admin.execute(f'CREATE DATABASE "{cls._db_name}"')
            for role in ALL_BOOTSTRAP_ROLES + [
                "test_api_caller", "test_worker_caller", "test_scheduler_caller", "test_checkpoint_probe",
            ]:
                admin.execute(f'DROP OWNED BY "{role}" CASCADE' if cls._role_exists(admin, role) else "SELECT 1")
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

        db_parts = urlsplit(cls._admin_dsn)
        cls._db_dsn = urlunsplit((db_parts.scheme, db_parts.netloc, f"/{cls._db_name}", "", ""))

        repo_root = Path(__file__).resolve().parent.parent.parent
        env = dict(os.environ)
        env["WEBGUARD_DATABASE_URL"] = cls._db_dsn
        migration_result = subprocess.run(
            [sys.executable, str(repo_root / "scripts" / "run-postgres-migrations.py")],
            env=env, capture_output=True, text=True, cwd=repo_root,
        )
        assert migration_result.returncode == 0, migration_result.stderr

        with psycopg.connect(cls._db_dsn) as connection:
            connection.execute(ROLES_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            connection.execute(TENANT_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            connection.execute(FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            connection.execute(CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            connection.execute(RLS_POLICIES_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()

        # Section 24: disposable LOGIN test-caller roles, each
        # inheriting exactly one ordinary capability role. No
        # superuser, no BYPASSRLS, no CREATEROLE, no CREATEDB.
        with psycopg.connect(cls._db_dsn) as connection:
            connection.autocommit = True
            connection.execute(
                'CREATE ROLE "test_api_caller" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                "PASSWORD 'test-caller-password'"
            )
            connection.execute(
                'CREATE ROLE "test_worker_caller" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                "PASSWORD 'test-caller-password'"
            )
            connection.execute(
                'CREATE ROLE "test_scheduler_caller" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                "PASSWORD 'test-caller-password'"
            )
            connection.execute(
                'CREATE ROLE "test_checkpoint_probe" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                "PASSWORD 'test-caller-password'"
            )
            connection.execute('GRANT api_tenant_data TO "test_api_caller"')
            connection.execute('GRANT worker_tenant_data TO "test_worker_caller"')
            connection.execute('GRANT scheduler_tenant_data TO "test_scheduler_caller"')
            # Section 2: test-only ACL, granted only inside this
            # disposable fixture, never in production bootstrap SQL.
            # Proves default-deny: FORCE RLS with zero matching policy
            # denies every caller regardless of table privilege.
            connection.execute('GRANT SELECT ON crawl_checkpoints TO "test_checkpoint_probe"')

        netloc_fmt = "{user}:test-caller-password@" + cls._host_port
        cls._api_dsn = urlunsplit(("postgresql", netloc_fmt.format(user="test_api_caller"), f"/{cls._db_name}", "", ""))
        cls._worker_dsn = urlunsplit(("postgresql", netloc_fmt.format(user="test_worker_caller"), f"/{cls._db_name}", "", ""))
        cls._scheduler_dsn = urlunsplit(
            ("postgresql", netloc_fmt.format(user="test_scheduler_caller"), f"/{cls._db_name}", "", "")
        )
        cls._checkpoint_probe_dsn = urlunsplit(
            ("postgresql", netloc_fmt.format(user="test_checkpoint_probe"), f"/{cls._db_name}", "", "")
        )

        # Section 23: test-only ENABLE + FORCE RLS, never in production
        # bootstrap SQL. Includes crawl_checkpoints (tenant-owned, zero
        # current policies) to prove future default-deny semantics.
        with psycopg.connect(cls._db_dsn) as connection:
            connection.autocommit = True
            for table in FUTURE_RLS_TARGET_TABLES:
                connection.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
                connection.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")

        # Section 5: derive the real ordinary-role ACL matrix from the
        # live database rather than hand-picking pairs.
        with psycopg.connect(cls._db_dsn) as connection:
            cls.ORDINARY_SELECT_PAIRS = cls._derive_pairs(connection, "SELECT")
            cls.ORDINARY_INSERT_PAIRS = cls._derive_pairs(connection, "INSERT")
            cls.ORDINARY_UPDATE_PAIRS = cls._derive_pairs(connection, "UPDATE")
            cls.ORDINARY_DELETE_PAIRS = cls._derive_pairs(connection, "DELETE")

        # Section 25/29: fixture across every one of the 25 policy
        # tables, seeded as superuser (always bypasses RLS regardless
        # of FORCE), for both tenants.
        cls.FIXTURE = {
            "A": cls._seed_tenant_fixture(cls._db_dsn, cls.ORG_A),
            "B": cls._seed_tenant_fixture(cls._db_dsn, cls.ORG_B),
        }

    @staticmethod
    def _derive_pairs(connection, privilege: str) -> list[tuple[str, str]]:
        pairs = []
        for role in TENANT_DATA_ROLES:
            for table in RLS_MANAGED_TABLES:
                has_priv = connection.execute(
                    "SELECT has_table_privilege(%s, %s, %s)", (role, f"public.{table}", privilege)
                ).fetchone()[0]
                if has_priv:
                    pairs.append((role, table))
        return pairs

    @staticmethod
    def _role_exists(admin_connection, role: str) -> bool:
        return admin_connection.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)", (role,)
        ).fetchone()[0]

    @staticmethod
    def _seed_tenant_fixture(db_dsn: str, org_id: str) -> dict:
        import psycopg

        now = datetime.now(timezone.utc)
        fx: dict = {"org_id": org_id}
        with psycopg.connect(db_dsn) as connection:
            connection.autocommit = True

            # Most tables get exactly one row per tenant. A few also
            # get a "spare" second row (principals, scan_jobs,
            # scan_schedules): job_permits/schedule_permits/
            # password_credentials need an already-committed, still-
            # unlinked parent to prove their INSERT policy denies a
            # cross-tenant reference (the parent must already exist,
            # not be creatable inline, or the parent's OWN policy --
            # not the derived table's -- would be what actually blocks
            # the attempt). The SELECT matrix test below reads the true
            # per-table, per-tenant row count from a superuser
            # connection rather than assuming a fixed "1", so these
            # spares do not make that assertion ambiguous.
            fx["principal_id"] = str(uuid.uuid4())
            fx["spare_principal_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
                "VALUES (%s, %s, %s, 'active', %s)",
                (org_id, f"Org {org_id}", f"org-{org_id}", now),
            )
            for pid in (fx["principal_id"], fx["spare_principal_id"]):
                connection.execute(
                    "INSERT INTO principals (principal_id, organization_id, display_name, principal_type, "
                    "role, active, created_at) VALUES (%s, %s, 'Person', 'user', 'owner', TRUE, %s)",
                    (pid, org_id, now),
                )

            fx["membership_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO memberships (membership_id, organization_id, principal_id, role, assigned_by, assigned_at) "
                "VALUES (%s, %s, %s, 'owner', %s, %s)",
                (fx["membership_id"], org_id, fx["principal_id"], fx["principal_id"], now),
            )

            fx["token_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO api_tokens (token_id, organization_id, principal_id, label, secret_hash, "
                "created_at, expires_at) VALUES (%s, %s, %s, 'test', 'hash', %s, %s)",
                (fx["token_id"], org_id, fx["principal_id"], now, now + timedelta(days=1)),
            )

            fx["authorization_id"] = f"auth-{org_id}"
            connection.execute(
                "INSERT INTO organization_authorizations (organization_id, authorization_id, assigned_by, assigned_at) "
                "VALUES (%s, %s, %s, %s)",
                (org_id, fx["authorization_id"], fx["principal_id"], now),
            )

            fx["audit_event_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO security_audit_events (event_id, request_id, organization_id, principal_id, token_id, "
                "action, resource_type, resource_id, outcome, occurred_at) "
                "VALUES (%s, %s, %s, %s, %s, 'test', 'test', 'test', 'succeeded', %s)",
                (fx["audit_event_id"], str(uuid.uuid4()), org_id, fx["principal_id"], str(uuid.uuid4()), now),
            )

            fx["target_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO targets (target_id, organization_id, url, created_by, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (fx["target_id"], org_id, f"https://{fx['target_id']}.example.com", fx["principal_id"], now),
            )

            fx["verification_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO target_verifications (verification_id, target_id, organization_id, method, status, checked_at) "
                "VALUES (%s, %s, %s, 'dns', 'pending', %s)",
                (fx["verification_id"], fx["target_id"], org_id, now),
            )

            fx["callback_token"] = f"cbtoken-{org_id}"
            connection.execute(
                "INSERT INTO callback_registrations (token_value, organization_id, scan_id, target, "
                "authorization_id, candidate_fingerprint, created_at, expires_at) "
                "VALUES (%s, %s, 'scan-a', 'https://example.com', 'auth', 'fp', %s, %s)",
                (fx["callback_token"], org_id, now, now + timedelta(days=1)),
            )
            fx["callback_observation_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO callback_observations (observation_id, token_value, method, source_class, observed_at) "
                "VALUES (%s, %s, 'GET', 'test', %s)",
                (fx["callback_observation_id"], fx["callback_token"], now),
            )

            fx["permit_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO scan_permits (permit_id, organization_id, authorization_id, authorization_sha256, "
                "target, issued_by, issued_at, not_before, expires_at, permit_sha256, signing_key_id, document_json) "
                "VALUES (%s, %s, 'auth', %s, 'https://example.com', %s, %s, %s, %s, %s, 'key', '{}')",
                (fx["permit_id"], org_id, "a" * 64, fx["principal_id"], now, now, now + timedelta(days=1), "b" * 64),
            )

            fx["job_id"] = str(uuid.uuid4())
            fx["spare_job_id"] = str(uuid.uuid4())
            for jid in (fx["job_id"], fx["spare_job_id"]):
                connection.execute(
                    "INSERT INTO scan_jobs (job_id, organization_id, submitted_by, target, authorization_id, "
                    "mode, state, submitted_at, updated_at) "
                    "VALUES (%s, %s, %s, 'https://example.com', 'auth', 'passive', 'queued', %s, %s)",
                    (jid, org_id, fx["principal_id"], now, now),
                )
            connection.execute(
                "INSERT INTO job_permits (job_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                (fx["job_id"], fx["permit_id"], "b" * 64),
            )
            connection.execute(
                "INSERT INTO job_safety_receipts (job_id, receipt_ref, receipt_sha256, created_at) "
                "VALUES (%s, 'ref', %s, %s)",
                (fx["job_id"], "c" * 64, now),
            )

            fx["scan_record_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO scan_records (scan_id, organization_id, target, authorization_id, mode, status, "
                "scanner_version, started_at) VALUES (%s, %s, 'https://example.com', 'auth', 'passive', "
                "'running', 'v1', %s)",
                (fx["scan_record_id"], org_id, now),
            )

            fx["finding_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO findings (finding_id, organization_id, fingerprint, check_id, severity, confidence, "
                "asset, endpoint, http_method, scanner_version, first_seen_at, last_seen_at) "
                "VALUES (%s, %s, %s, 'check', 'medium', 'high', 'asset', '/', 'GET', 'v1', %s, %s)",
                (fx["finding_id"], org_id, f"fp-{fx['finding_id']}", now, now),
            )
            fx["finding_event_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO finding_events (event_id, finding_id, organization_id, previous_status, new_status, "
                "created_at) VALUES (%s, %s, %s, 'open', 'confirmed', %s)",
                (fx["finding_event_id"], fx["finding_id"], org_id, now),
            )

            fx["report_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO reports (report_id, organization_id, report_ref, created_at) VALUES (%s, %s, %s, %s)",
                (fx["report_id"], org_id, f"ref-{fx['report_id']}", now),
            )

            fx["auth_context_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO authentication_contexts (authentication_context_id, organization_id, target, "
                "authorization_id, identity_label, method, created_at, expires_at) "
                "VALUES (%s, %s, 'https://example.com', 'auth', 'label', 'method', %s, %s)",
                (fx["auth_context_id"], org_id, now, now + timedelta(days=1)),
            )

            fx["comparison_plan_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO authorization_comparison_plans (comparison_plan_id, organization_id, target, "
                "authorization_id, primary_context_id, secondary_context_id, permitted_active_check, "
                "allowed_http_methods, resource_scope, maximum_resources, maximum_comparisons, created_at, expires_at) "
                "VALUES (%s, %s, 'https://example.com', 'auth', %s, %s, 'check', ARRAY['GET'], '{}', 10, 10, %s, %s)",
                (fx["comparison_plan_id"], org_id, str(uuid.uuid4()), str(uuid.uuid4()), now, now + timedelta(days=1)),
            )

            fx["schedule_id"] = str(uuid.uuid4())
            fx["spare_schedule_id"] = str(uuid.uuid4())
            for sid in (fx["schedule_id"], fx["spare_schedule_id"]):
                connection.execute(
                    "INSERT INTO scan_schedules (schedule_id, organization_id, created_by, name, target, "
                    "authorization_id, authorization_sha256, mode, interval_seconds, state, created_at, "
                    "updated_at, next_run_at) "
                    "VALUES (%s, %s, %s, 'sched', 'https://example.com', 'auth', %s, 'passive', 3600, "
                    "'active', %s, %s, %s)",
                    (sid, org_id, fx["principal_id"], "d" * 64, now, now, now - timedelta(minutes=1)),
                )
            connection.execute(
                "INSERT INTO schedule_permits (schedule_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                (fx["schedule_id"], fx["permit_id"], "e" * 64),
            )

            fx["identity_token_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO identity_tokens (token_id, principal_id, organization_id, purpose, secret_hash, "
                "created_at, expires_at) VALUES (%s, %s, %s, 'email_verification', 'hash', %s, %s)",
                (fx["identity_token_id"], fx["principal_id"], org_id, now, now + timedelta(days=1)),
            )

            fx["browser_session_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO browser_sessions (session_id, principal_id, organization_id, secret_hash, csrf_hash, "
                "assurance_level, issued_at, idle_expires_at, absolute_expires_at) "
                "VALUES (%s, %s, %s, 'hash', 'csrf', 'level', %s, %s, %s)",
                (fx["browser_session_id"], fx["principal_id"], org_id, now, now + timedelta(hours=1), now + timedelta(days=1)),
            )

            connection.execute(
                "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at) "
                "VALUES (%s, 'argon2', 'hash', %s, %s)",
                (fx["principal_id"], now, now),
            )

            fx["checkpoint_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO crawl_checkpoints (checkpoint_id, organization_id, job_id, checkpoint_ref, created_at) "
                "VALUES (%s, %s, %s, 'ref', %s)",
                (fx["checkpoint_id"], org_id, fx["job_id"], now),
            )

            fx["assertion_collection_id"] = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO technical_assertion_collections (collection_id, organization_id, assertion_id, "
                "assertion_version, evidence_source, evidence_provenance, collection_status, raw_evidence, "
                "outcome, collected_by, collected_at, evaluated_at) "
                "VALUES (%s, %s, 'entra_conditional_access_policy_mode', 'v1', 'fixture', 'fixture:seed', "
                "'succeeded', '{}', 'satisfied', %s, %s, %s)",
                (fx["assertion_collection_id"], org_id, fx["principal_id"], now, now),
            )
        return fx

    @classmethod
    def tearDownClass(cls) -> None:
        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            roles = [
                "test_api_caller", "test_worker_caller", "test_scheduler_caller", "test_checkpoint_probe",
            ] + ALL_BOOTSTRAP_ROLES
            for role in roles:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

    def _connect(self, dsn: str):
        import psycopg

        return psycopg.connect(dsn)

    def _set_tenant(self, connection, organization_id: str) -> None:
        connection.execute("SELECT set_config(%s, %s, true)", (GUC_NAME, organization_id))

    def _dsn_for_role(self, role: str) -> str:
        return {
            "api_tenant_data": self._api_dsn,
            "worker_tenant_data": self._worker_dsn,
            "scheduler_tenant_data": self._scheduler_dsn,
        }[role]

    # -- Section 26: no-context fail-closed, write side ----------------------

    def test_no_context_fail_closed_write(self) -> None:
        with self._connect(self._api_dsn) as connection:
            with self.assertRaises(Exception) as ctx:
                connection.execute(
                    "INSERT INTO targets (target_id, organization_id, url, created_by, created_at) "
                    "VALUES (%s, %s, 'https://new.example.com', %s, now())",
                    (str(uuid.uuid4()), self.ORG_A, self.FIXTURE["A"]["principal_id"]),
                )
            self.assertIn("row-level security", str(ctx.exception).lower())

    # -- Section 5: exhaustive ordinary SELECT matrix ------------------------

    # Derived tables (no organization_id column) that appear in the
    # ordinary SELECT matrix need a JOIN back to their direct-tenant
    # parent to compute ground truth; every other table is direct.
    _SELECT_GROUND_TRUTH_QUERY = {
        "callback_observations": (
            "SELECT cr.organization_id, count(*) FROM callback_observations co "
            "JOIN callback_registrations cr ON cr.token_value = co.token_value "
            "WHERE cr.organization_id IN (%s, %s) GROUP BY cr.organization_id"
        ),
        "job_permits": (
            "SELECT j.organization_id, count(*) FROM job_permits jp "
            "JOIN scan_jobs j ON j.job_id = jp.job_id "
            "WHERE j.organization_id IN (%s, %s) GROUP BY j.organization_id"
        ),
        "schedule_permits": (
            "SELECT s.organization_id, count(*) FROM schedule_permits sp "
            "JOIN scan_schedules s ON s.schedule_id = sp.schedule_id "
            "WHERE s.organization_id IN (%s, %s) GROUP BY s.organization_id"
        ),
        "job_safety_receipts": (
            "SELECT j.organization_id, count(*) FROM job_safety_receipts r "
            "JOIN scan_jobs j ON j.job_id = r.job_id "
            "WHERE j.organization_id IN (%s, %s) GROUP BY j.organization_id"
        ),
    }

    def test_ordinary_select_matrix_no_context_tenant_a_tenant_b(self) -> None:
        # 2026-09-15: +1 for ("api_tenant_data", "technical_assertion_collections"). 30 + 1 = 31.
        self.assertEqual(len(self.ORDINARY_SELECT_PAIRS), 31, f"{self.ORDINARY_SELECT_PAIRS}")
        # Ground truth per table/tenant, read via superuser (always
        # bypasses RLS). Most tables carry exactly one row per tenant,
        # but a few also carry an extra "spare" row used elsewhere
        # (job_permits/schedule_permits/password_credentials' own
        # INSERT-denial tests need an already-committed, unlinked
        # parent) -- reading the true count directly, rather than
        # assuming 1 everywhere, keeps this assertion accurate
        # regardless of how many fixture rows a given table happens to
        # carry for reasons unrelated to tenant isolation.
        import psycopg

        ground_truth = {}
        with psycopg.connect(self._db_dsn) as admin_connection:
            admin_connection.autocommit = True
            for _role, table in self.ORDINARY_SELECT_PAIRS:
                if table in ground_truth:
                    continue
                query = self._SELECT_GROUND_TRUTH_QUERY.get(
                    table,
                    f"SELECT organization_id, count(*) FROM {table} "  # noqa: S608
                    f"WHERE organization_id IN (%s, %s) GROUP BY organization_id",
                )
                rows = admin_connection.execute(query, (self.ORG_A, self.ORG_B)).fetchall()
                by_org = {str(org): n for org, n in rows}
                ground_truth[table] = (by_org.get(self.ORG_A, 0), by_org.get(self.ORG_B, 0))

        no_context_tested = tenant_a_tested = tenant_b_tested = 0
        for role, table in self.ORDINARY_SELECT_PAIRS:
            expected_a, expected_b = ground_truth[table]
            with self.subTest(role=role, table=table):
                with self._connect(self._dsn_for_role(role)) as connection:
                    no_ctx = connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
                    self.assertEqual(no_ctx, 0, f"{role}/{table}: no tenant context must return zero rows")
                    no_context_tested += 1

                with self._connect(self._dsn_for_role(role)) as connection:
                    self._set_tenant(connection, self.ORG_A)
                    count_a = connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
                    self.assertEqual(count_a, expected_a, f"{role}/{table}: tenant A row count must match ground truth")
                    tenant_a_tested += 1

                with self._connect(self._dsn_for_role(role)) as connection:
                    self._set_tenant(connection, self.ORG_B)
                    count_b = connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
                    self.assertEqual(count_b, expected_b, f"{role}/{table}: tenant B row count must match ground truth")
                    tenant_b_tested += 1
        self.assertEqual(no_context_tested, 31)
        self.assertEqual(tenant_a_tested, 31)
        self.assertEqual(tenant_b_tested, 31)

    # -- Section 8: exhaustive ordinary INSERT matrix ------------------------

    @staticmethod
    def _insert_row_spec(table: str, fx: dict) -> tuple[str, tuple]:
        org = fx["org_id"]
        principal = fx["principal_id"]
        new_id = str(uuid.uuid4())
        specs = {
            "principals": (
                "INSERT INTO principals (principal_id, organization_id, display_name, principal_type, role, "
                "active, created_at) VALUES (%s, %s, 'New Person', 'user', 'viewer', TRUE, now())",
                (new_id, org),
            ),
            "memberships": (
                "INSERT INTO memberships (membership_id, organization_id, principal_id, role, assigned_by, assigned_at) "
                "VALUES (%s, %s, %s, 'viewer', %s, now())",
                (new_id, org, principal, principal),
            ),
            "api_tokens": (
                "INSERT INTO api_tokens (token_id, organization_id, principal_id, label, secret_hash, created_at, "
                "expires_at) VALUES (%s, %s, %s, 'new', 'hash', now(), now() + interval '1 day')",
                (new_id, org, principal),
            ),
            "security_audit_events": (
                "INSERT INTO security_audit_events (event_id, request_id, organization_id, principal_id, token_id, "
                "action, resource_type, resource_id, outcome, occurred_at) "
                "VALUES (%s, %s, %s, %s, %s, 'test', 'test', 'test', 'succeeded', now())",
                (new_id, str(uuid.uuid4()), org, principal, str(uuid.uuid4())),
            ),
            "targets": (
                "INSERT INTO targets (target_id, organization_id, url, created_by, created_at) "
                "VALUES (%s, %s, %s, %s, now())",
                (new_id, org, f"https://{new_id}.example.com", principal),
            ),
            "target_verifications": (
                "INSERT INTO target_verifications (verification_id, target_id, organization_id, method, status, "
                "checked_at) VALUES (%s, %s, %s, 'dns', 'pending', now())",
                (new_id, fx["target_id"], org),
            ),
            "callback_registrations": (
                "INSERT INTO callback_registrations (token_value, organization_id, scan_id, target, "
                "authorization_id, candidate_fingerprint, created_at, expires_at) "
                "VALUES (%s, %s, 'scan-new', 'https://example.com', 'auth', 'fp', now(), now() + interval '1 day')",
                (f"cbnew-{new_id}", org),
            ),
            "scan_permits": (
                "INSERT INTO scan_permits (permit_id, organization_id, authorization_id, authorization_sha256, "
                "target, issued_by, issued_at, not_before, expires_at, permit_sha256, signing_key_id, document_json) "
                "VALUES (%s, %s, 'auth', %s, 'https://example.com', %s, now(), now(), now() + interval '1 day', "
                "%s, 'key', '{}')",
                (new_id, org, "e" * 64, principal, "f" * 64),
            ),
            "job_permits": (
                "INSERT INTO job_permits (job_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                (fx["spare_job_id"], fx["permit_id"], "g" * 64),
            ),
            "scan_jobs": (
                "INSERT INTO scan_jobs (job_id, organization_id, submitted_by, target, authorization_id, mode, "
                "state, submitted_at, updated_at) "
                "VALUES (%s, %s, %s, 'https://example.com', 'auth', 'passive', 'queued', now(), now())",
                (new_id, org, principal),
            ),
            "scan_schedules": (
                "INSERT INTO scan_schedules (schedule_id, organization_id, created_by, name, target, "
                "authorization_id, authorization_sha256, mode, interval_seconds, state, created_at, updated_at, "
                "next_run_at) VALUES (%s, %s, %s, 'new', 'https://example.com', 'auth', %s, 'passive', 3600, "
                "'active', now(), now(), now())",
                (new_id, org, principal, "h" * 64),
            ),
            "schedule_permits": (
                "INSERT INTO schedule_permits (schedule_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                (fx["spare_schedule_id"], fx["permit_id"], "i" * 64),
            ),
            "scan_records": (
                "INSERT INTO scan_records (scan_id, organization_id, target, authorization_id, mode, status, "
                "scanner_version, started_at) VALUES (%s, %s, 'https://example.com', 'auth', 'passive', "
                "'running', 'v1', now())",
                (new_id, org),
            ),
            "findings": (
                "INSERT INTO findings (finding_id, organization_id, fingerprint, check_id, severity, confidence, "
                "asset, endpoint, http_method, scanner_version, first_seen_at, last_seen_at) "
                "VALUES (%s, %s, %s, 'check', 'low', 'low', 'asset', '/', 'GET', 'v1', now(), now())",
                (new_id, org, f"fp-{new_id}"),
            ),
            "finding_events": (
                "INSERT INTO finding_events (event_id, finding_id, organization_id, previous_status, new_status, "
                "created_at) VALUES (%s, %s, %s, 'open', 'confirmed', now())",
                (new_id, fx["finding_id"], org),
            ),
            "reports": (
                "INSERT INTO reports (report_id, organization_id, report_ref, created_at) VALUES (%s, %s, %s, now())",
                (new_id, org, f"ref-{new_id}"),
            ),
            "authentication_contexts": (
                "INSERT INTO authentication_contexts (authentication_context_id, organization_id, target, "
                "authorization_id, identity_label, method, created_at, expires_at) "
                "VALUES (%s, %s, 'https://example.com', 'auth', 'label', 'method', now(), now() + interval '1 day')",
                (new_id, org),
            ),
            "authorization_comparison_plans": (
                "INSERT INTO authorization_comparison_plans (comparison_plan_id, organization_id, target, "
                "authorization_id, primary_context_id, secondary_context_id, permitted_active_check, "
                "allowed_http_methods, resource_scope, maximum_resources, maximum_comparisons, created_at, "
                "expires_at) VALUES (%s, %s, 'https://example.com', 'auth', %s, %s, 'check', ARRAY['GET'], '{}', "
                "10, 10, now(), now() + interval '1 day')",
                (new_id, org, str(uuid.uuid4()), str(uuid.uuid4())),
            ),
            "identity_tokens": (
                "INSERT INTO identity_tokens (token_id, principal_id, organization_id, purpose, secret_hash, "
                "created_at, expires_at) VALUES (%s, %s, %s, 'email_verification', 'hash', now(), "
                "now() + interval '1 day')",
                (new_id, principal, org),
            ),
            "browser_sessions": (
                "INSERT INTO browser_sessions (session_id, principal_id, organization_id, secret_hash, csrf_hash, "
                "assurance_level, issued_at, idle_expires_at, absolute_expires_at) "
                "VALUES (%s, %s, %s, 'hash', 'csrf', 'level', now(), now() + interval '1 hour', "
                "now() + interval '1 day')",
                (new_id, principal, org),
            ),
            "password_credentials": (
                "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at) "
                "VALUES (%s, 'argon2', 'hash', now(), now())",
                (fx["spare_principal_id"],),
            ),
            "technical_assertion_collections": (
                "INSERT INTO technical_assertion_collections (collection_id, organization_id, assertion_id, "
                "assertion_version, evidence_source, evidence_provenance, collection_status, raw_evidence, "
                "outcome, collected_by, collected_at, evaluated_at) "
                "VALUES (%s, %s, 'entra_conditional_access_policy_mode', 'v1', 'fixture', 'fixture:new', "
                "'succeeded', '{}', 'satisfied', %s, now(), now())",
                (new_id, org, principal),
            ),
        }
        return specs[table]

    def test_organizations_insert_self_tenant_registration_pattern(self) -> None:
        # organizations is a special case (Section 5 of the design
        # record): a brand-new row's own tenant identity IS the new
        # organization_id, so "allowed" means the caller's context is
        # set to the SAME fresh id it is about to insert (matching the
        # documented future repository-conversion pattern: generate
        # the UUID, set tenant context to it, then insert), not to a
        # pre-existing tenant.
        with self._connect(self._api_dsn) as connection:
            try:
                new_org = str(uuid.uuid4())
                self._set_tenant(connection, new_org)
                connection.execute(
                    "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
                    "VALUES (%s, 'New Org', %s, 'active', now())",
                    (new_org, f"neworg-{new_org}"),
                )
                seen = connection.execute(
                    "SELECT organization_id FROM organizations WHERE organization_id = %s", (new_org,)
                ).fetchone()
                self.assertIsNotNone(seen, "an insert whose tenant context matches its own new id must succeed")

                mismatched_org = str(uuid.uuid4())
                with self.assertRaises(Exception) as ctx:
                    connection.execute(
                        "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
                        "VALUES (%s, 'Denied Org', %s, 'active', now())",
                        (mismatched_org, f"denied-{mismatched_org}"),
                    )
                self.assertIn("row-level security", str(ctx.exception).lower())
            finally:
                connection.rollback()

    def test_ordinary_insert_matrix(self) -> None:
        pairs = [(role, table) for role, table in self.ORDINARY_INSERT_PAIRS if table != "organizations"]
        # 2026-09-15: +1 for ("api_tenant_data", "technical_assertion_collections"). 22 + 1 = 23.
        self.assertEqual(len(pairs), 23, f"{pairs}")
        tested = []
        for role, table in pairs:
            with self.subTest(role=role, table=table):
                with self._connect(self._dsn_for_role(role)) as connection:
                    try:
                        self._set_tenant(connection, self.ORG_A)
                        sql, params = self._insert_row_spec(table, self.FIXTURE["A"])
                        connection.execute(sql, params)
                    finally:
                        connection.rollback()

                with self._connect(self._dsn_for_role(role)) as connection:
                    try:
                        self._set_tenant(connection, self.ORG_A)
                        sql, params = self._insert_row_spec(table, self.FIXTURE["B"])
                        with self.assertRaises(Exception) as ctx:
                            connection.execute(sql, params)
                        self.assertIn(
                            "row-level security", str(ctx.exception).lower(),
                            f"{role}/{table}: inserting a row shaped for tenant B while context=A must be denied",
                        )
                    finally:
                        connection.rollback()
                tested.append((role, table))
        self.assertEqual(len(tested), 23)

    # -- Section 9: exhaustive ordinary UPDATE matrix ------------------------

    _UPDATE_PK = {
        "principals": "principal_id", "api_tokens": "token_id", "targets": "target_id",
        "target_verifications": "verification_id", "scan_permits": "permit_id", "scan_jobs": "job_id",
        "scan_schedules": "schedule_id", "scan_records": "scan_id", "findings": "finding_id",
        "authentication_contexts": "authentication_context_id",
        "authorization_comparison_plans": "comparison_plan_id",
        "identity_tokens": "token_id", "browser_sessions": "session_id",
        "password_credentials": "principal_id",
    }
    _UPDATE_FIXTURE_KEY = {
        "principals": "principal_id", "api_tokens": "token_id", "targets": "target_id",
        "target_verifications": "verification_id", "scan_permits": "permit_id", "scan_jobs": "job_id",
        "scan_schedules": "schedule_id", "scan_records": "scan_record_id", "findings": "finding_id",
        "authentication_contexts": "auth_context_id",
        "authorization_comparison_plans": "comparison_plan_id",
        "identity_tokens": "identity_token_id", "browser_sessions": "browser_session_id",
        "password_credentials": "principal_id",
    }
    _UPDATE_HARMLESS_SET = {
        "principals": "display_name = 'unchanged'",
        "api_tokens": "label = 'unchanged'",
        "targets": "label = 'unchanged'",
        "target_verifications": "evidence = 'unchanged'",
        "scan_permits": "signing_key_id = 'unchanged'",
        "scan_jobs": "error_message = 'unchanged'",
        "scan_schedules": "last_error_code = 'unchanged'",
        "scan_records": "report_ref = 'unchanged'",
        "findings": "confidence = 'low'",
        "authentication_contexts": "identity_label = 'unchanged'",
        "authorization_comparison_plans": "permitted_active_check = 'unchanged'",
        "identity_tokens": "used_at = NULL",
        "browser_sessions": "user_agent = 'unchanged'",
        "password_credentials": "password_hash = 'unchanged'",
    }
    # organization_id is a real column on these; password_credentials
    # has no organization_id at all (it is derived via principal_id),
    # so tenant-reassignment does not apply the same way -- reported
    # as NOT APPLICABLE rather than skipped silently.
    _DIRECT_UPDATE_TABLES = set(_UPDATE_PK) - {"password_credentials"}

    # P1-2 Phase-D correction (tenant_isolation_acl.sql): identity_tokens
    # and password_credentials originally had UPDATE (and, for
    # password_credentials, INSERT) granted to api_tenant_data WITHOUT
    # SELECT, which meant neither table's UPDATE could actually
    # execute -- PostgreSQL requires SELECT on any column an UPDATE's
    # WHERE clause reads (the same rule Phase E's own
    # recover_expired_leases already accounted for on scan_records),
    # confirmed empirically and independent of RLS entirely. The
    # correction granted narrow column SELECT (token_id, principal_id,
    # purpose, used_at on identity_tokens; principal_id on
    # password_credentials) sized to exactly what each table's real
    # production statements need, and this file's own
    # wg_api_identity_tokens_select / wg_api_password_credentials_select
    # policies are that grant's RLS-side counterpart. Both pairs are
    # now directly executable; this set stays empty as the place that
    # would record any future such gap.
    _UPDATE_NOT_DIRECTLY_EXECUTABLE: set[str] = set()

    def test_ordinary_update_matrix(self) -> None:
        self.assertEqual(len(self.ORDINARY_UPDATE_PAIRS), 15, f"{self.ORDINARY_UPDATE_PAIRS}")
        tested = []
        not_executable = []
        for role, table in self.ORDINARY_UPDATE_PAIRS:
            if table in self._UPDATE_NOT_DIRECTLY_EXECUTABLE:
                not_executable.append((role, table))
                continue
            pk = self._UPDATE_PK[table]
            fixture_key = self._UPDATE_FIXTURE_KEY[table]
            set_clause = self._UPDATE_HARMLESS_SET[table]
            with self.subTest(role=role, table=table, case="own_row_allowed"):
                with self._connect(self._dsn_for_role(role)) as connection:
                    try:
                        self._set_tenant(connection, self.ORG_A)
                        own_id = self.FIXTURE["A"][fixture_key]
                        result = connection.execute(
                            f"UPDATE {table} SET {set_clause} WHERE {pk} = %s", (own_id,)  # noqa: S608
                        )
                        self.assertEqual(result.rowcount, 1, f"{role}/{table}: updating the caller's own row must succeed")
                    finally:
                        connection.rollback()

            with self.subTest(role=role, table=table, case="other_tenant_row_denied"):
                with self._connect(self._dsn_for_role(role)) as connection:
                    try:
                        self._set_tenant(connection, self.ORG_A)
                        victim_id = self.FIXTURE["B"][fixture_key]
                        result = connection.execute(
                            f"UPDATE {table} SET {set_clause} WHERE {pk} = %s", (victim_id,)  # noqa: S608
                        )
                        self.assertEqual(
                            result.rowcount, 0, f"{role}/{table}: tenant A must not be able to UPDATE tenant B's row"
                        )
                    finally:
                        connection.rollback()

            if table in self._DIRECT_UPDATE_TABLES:
                with self.subTest(role=role, table=table, case="reassignment_denied"):
                    with self._connect(self._dsn_for_role(role)) as connection:
                        try:
                            self._set_tenant(connection, self.ORG_A)
                            own_id = self.FIXTURE["A"][fixture_key]
                            with self.assertRaises(Exception) as ctx:
                                connection.execute(
                                    f"UPDATE {table} SET organization_id = %s WHERE {pk} = %s",  # noqa: S608
                                    (self.ORG_B, own_id),
                                )
                            self.assertIn("row-level security", str(ctx.exception).lower())
                        finally:
                            connection.rollback()
            tested.append((role, table))
        self.assertEqual(len(tested), 15)
        self.assertEqual(set(not_executable), set(), "no ordinary UPDATE pair should remain blocked after the Phase-D correction")

    # -- P1-2 Phase-D correction reconciliation: the two new DML-
    # dependency SELECT policies, proven under FORCE RLS ---------------------

    def test_identity_tokens_dml_dependency_under_force_rls(self) -> None:
        # api_tenant_data's narrow column SELECT (token_id,
        # principal_id, purpose, used_at) exists so
        # consume_identity_token's post-resolution UPDATE and
        # invalidate_identity_tokens's UPDATE can execute at all --
        # wg_api_identity_tokens_select is that grant's RLS-side
        # counterpart. Proves both real production UPDATE shapes
        # succeed for tenant A's own row, a narrow SELECT restricted
        # to exactly the granted columns stays tenant-filtered, tenant
        # B's row is untouched and invisible while context=A (0 rows,
        # not an exception -- the ACL permits the statement, RLS just
        # filters it), no context fails closed, and secret_hash/
        # SELECT * remain denied regardless -- the new policy enables
        # the DML dependency without widening what column data is
        # actually readable.
        with self._connect(self._api_dsn) as connection:
            try:
                self._set_tenant(connection, self.ORG_A)
                result = connection.execute(
                    "UPDATE identity_tokens SET used_at = now() WHERE token_id = %s",
                    (self.FIXTURE["A"]["identity_token_id"],),
                )
                self.assertEqual(result.rowcount, 1, "tenant A's post-resolution UPDATE must succeed under the corrected ACL")
            finally:
                connection.rollback()

            try:
                self._set_tenant(connection, self.ORG_A)
                result = connection.execute(
                    "UPDATE identity_tokens SET used_at = now() "
                    "WHERE principal_id = %s AND purpose = %s AND used_at IS NULL",
                    (self.FIXTURE["A"]["principal_id"], "email_verification"),
                )
                self.assertEqual(result.rowcount, 1, "invalidate_identity_tokens's own predicate must succeed for tenant A")
            finally:
                connection.rollback()

            try:
                self._set_tenant(connection, self.ORG_A)
                visible = connection.execute(
                    "SELECT token_id, principal_id, purpose, used_at FROM identity_tokens WHERE token_id = %s",
                    (self.FIXTURE["A"]["identity_token_id"],),
                ).fetchone()
                self.assertIsNotNone(visible, "the narrow granted-column SELECT must see tenant A's own row")
                hidden = connection.execute(
                    "SELECT token_id, principal_id, purpose, used_at FROM identity_tokens WHERE token_id = %s",
                    (self.FIXTURE["B"]["identity_token_id"],),
                ).fetchone()
                self.assertIsNone(hidden, "the narrow granted-column SELECT must not see tenant B's row while context=A")
            finally:
                connection.rollback()

            try:
                self._set_tenant(connection, self.ORG_A)
                result = connection.execute(
                    "UPDATE identity_tokens SET used_at = now() WHERE token_id = %s",
                    (self.FIXTURE["B"]["identity_token_id"],),
                )
                self.assertEqual(result.rowcount, 0, "tenant A must not be able to update tenant B's identity_tokens row")
            finally:
                connection.rollback()

        with self._connect(self._api_dsn) as connection:
            try:
                result = connection.execute(
                    "UPDATE identity_tokens SET used_at = now() WHERE token_id = %s",
                    (self.FIXTURE["A"]["identity_token_id"],),
                )
                self.assertEqual(result.rowcount, 0, "no tenant context must fail closed, updating zero rows")
            finally:
                connection.rollback()

        import psycopg

        with self._connect(self._api_dsn) as connection:
            self._set_tenant(connection, self.ORG_A)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT secret_hash FROM identity_tokens LIMIT 1")
            connection.rollback()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT * FROM identity_tokens LIMIT 1")

    def test_password_credentials_dml_dependency_under_force_rls(self) -> None:
        # api_tenant_data's narrow column SELECT (principal_id) exists
        # so set_password_hash's two-statement write shape -- INSERT
        # ... ON CONFLICT (principal_id) DO NOTHING, then a conditional
        # UPDATE only if that inserted nothing -- can execute at all.
        # This is the ONLY write shape tested here: the old single-
        # statement ON CONFLICT DO UPDATE is not this role's write
        # path any more and would force SELECT on password_hash
        # itself, which this ACL never grants.
        # wg_api_password_credentials_select is that grant's RLS-side
        # counterpart, derived through principals since this table has
        # no organization_id of its own.
        import psycopg

        with self._connect(self._api_dsn) as connection:
            try:
                self._set_tenant(connection, self.ORG_A)
                cursor = connection.execute(
                    "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at) "
                    "VALUES (%s, 'argon2', 'fresh-hash', now(), now()) "
                    "ON CONFLICT (principal_id) DO NOTHING",
                    (self.FIXTURE["A"]["spare_principal_id"],),
                )
                self.assertEqual(cursor.rowcount, 1, "tenant A's fresh-credential INSERT must succeed under the corrected ACL")
            finally:
                connection.rollback()

            try:
                self._set_tenant(connection, self.ORG_A)
                cursor = connection.execute(
                    "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at) "
                    "VALUES (%s, 'argon2', 'ignored', now(), now()) "
                    "ON CONFLICT (principal_id) DO NOTHING",
                    (self.FIXTURE["A"]["principal_id"],),
                )
                self.assertEqual(cursor.rowcount, 0, "an existing credential's conflict-detect INSERT must apply nothing")
                cursor = connection.execute(
                    "UPDATE password_credentials SET algorithm = %s, password_hash = %s, updated_at = now() "
                    "WHERE principal_id = %s",
                    ("argon2", "updated-hash", self.FIXTURE["A"]["principal_id"]),
                )
                self.assertEqual(cursor.rowcount, 1, "the conditional UPDATE path must succeed for tenant A's own row")
            finally:
                connection.rollback()

            try:
                self._set_tenant(connection, self.ORG_A)
                visible = connection.execute(
                    "SELECT principal_id FROM password_credentials WHERE principal_id = %s",
                    (self.FIXTURE["A"]["principal_id"],),
                ).fetchone()
                self.assertIsNotNone(visible, "the narrow granted-column SELECT must see tenant A's own row")
                hidden = connection.execute(
                    "SELECT principal_id FROM password_credentials WHERE principal_id = %s",
                    (self.FIXTURE["B"]["principal_id"],),
                ).fetchone()
                self.assertIsNone(hidden, "the narrow granted-column SELECT must not see tenant B's row while context=A")
            finally:
                connection.rollback()

            try:
                self._set_tenant(connection, self.ORG_A)
                with self.assertRaises(Exception) as ctx:
                    connection.execute(
                        "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at) "
                        "VALUES (%s, 'argon2', 'hash', now(), now()) ON CONFLICT (principal_id) DO NOTHING",
                        (self.FIXTURE["B"]["spare_principal_id"],),
                    )
                self.assertIn(
                    "row-level security", str(ctx.exception).lower(),
                    "inserting a credential for tenant B's principal while context=A must be denied",
                )
            finally:
                connection.rollback()

            try:
                self._set_tenant(connection, self.ORG_A)
                cursor = connection.execute(
                    "UPDATE password_credentials SET password_hash = 'x', updated_at = now() WHERE principal_id = %s",
                    (self.FIXTURE["B"]["principal_id"],),
                )
                self.assertEqual(cursor.rowcount, 0, "tenant A must not be able to update tenant B's credential row")
            finally:
                connection.rollback()

        with self._connect(self._api_dsn) as connection:
            try:
                with self.assertRaises(Exception) as ctx:
                    connection.execute(
                        "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at) "
                        "VALUES (%s, 'argon2', 'hash', now(), now()) ON CONFLICT (principal_id) DO NOTHING",
                        (self.FIXTURE["A"]["spare_principal_id"],),
                    )
                self.assertIn(
                    "row-level security", str(ctx.exception).lower(), "no tenant context must fail closed on INSERT too"
                )
            finally:
                connection.rollback()

            try:
                cursor = connection.execute(
                    "UPDATE password_credentials SET password_hash = 'x', updated_at = now() WHERE principal_id = %s",
                    (self.FIXTURE["A"]["principal_id"],),
                )
                self.assertEqual(cursor.rowcount, 0, "no tenant context must fail closed on UPDATE, updating zero rows")
            finally:
                connection.rollback()

        with self._connect(self._api_dsn) as connection:
            self._set_tenant(connection, self.ORG_A)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT password_hash FROM password_credentials LIMIT 1")
            connection.rollback()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT * FROM password_credentials LIMIT 1")

    def test_password_credentials_reassignment_not_applicable(self) -> None:
        # Documented explicitly rather than silently skipped: unlike
        # every direct table, password_credentials has no
        # organization_id column to reassign -- its tenant ownership
        # is derived entirely through principal_id, which is both its
        # primary key and immutable in practice. No "reassignment"
        # sub-test applies here.
        self.assertNotIn("password_credentials", self._DIRECT_UPDATE_TABLES)

    # -- Section 10: DELETE remains N/A ---------------------------------------

    def test_delete_cross_tenant_not_applicable(self) -> None:
        self.assertEqual(
            self.ORDINARY_DELETE_PAIRS, [],
            "no ordinary role may hold DELETE on any RLS-managed (tenant-owned, non-global) table",
        )
        # Confirmed directly too: an attempted DELETE fails on ACL
        # (permission denied), not merely on RLS -- there is no grant
        # to even reach the policy layer.
        with self._connect(self._api_dsn) as connection:
            self._set_tenant(connection, self.ORG_A)
            with self.assertRaises(Exception) as ctx:
                connection.execute("DELETE FROM targets WHERE target_id = %s", (self.FIXTURE["A"]["target_id"],))
            self.assertIn("permission denied", str(ctx.exception).lower())

    # -- Section 6: representative cross-tenant primary-key lookup ----------

    def test_cross_tenant_primary_key_lookup_hidden_across_representative_tables(self) -> None:
        checks = [
            ("targets", "target_id", "target_id"),
            ("job_permits", "job_id", "job_id"),
            ("api_tokens", "token_id", "token_id"),
            ("scan_jobs", "job_id", "job_id"),
            ("scan_schedules", "schedule_id", "schedule_id"),
            ("findings", "finding_id", "finding_id"),
        ]
        with self._connect(self._api_dsn) as connection:
            self._set_tenant(connection, self.ORG_A)
            for table, pk_col, fixture_key in checks:
                victim_id = self.FIXTURE["B"][fixture_key]
                row = connection.execute(
                    f"SELECT 1 FROM {table} WHERE {pk_col} = %s", (victim_id,)  # noqa: S608
                ).fetchone()
                self.assertIsNone(row, f"tenant A must not see tenant B's {table} row by exact PK lookup")

    # -- Section 7: all five derived-tenant chains ---------------------------

    def test_derived_chain_callback_observations(self) -> None:
        with self._connect(self._worker_dsn) as connection:
            self._set_tenant(connection, self.ORG_A)
            visible = connection.execute(
                "SELECT observation_id FROM callback_observations WHERE observation_id = %s",
                (self.FIXTURE["A"]["callback_observation_id"],),
            ).fetchone()
            self.assertIsNotNone(visible, "tenant A must see its own derived callback_observations row")
            hidden = connection.execute(
                "SELECT observation_id FROM callback_observations WHERE observation_id = %s",
                (self.FIXTURE["B"]["callback_observation_id"],),
            ).fetchone()
            self.assertIsNone(hidden, "tenant A must not see tenant B's derived callback_observations row")
        # worker_tenant_data has no INSERT/UPDATE on callback_observations
        # (only callback_function_owner does, tested separately).

    def test_derived_chain_job_permits(self) -> None:
        with self._connect(self._api_dsn) as connection:
            try:
                self._set_tenant(connection, self.ORG_A)
                visible = connection.execute(
                    "SELECT job_id FROM job_permits WHERE job_id = %s", (self.FIXTURE["A"]["job_id"],)
                ).fetchone()
                self.assertIsNotNone(visible, "tenant A must see its own derived job_permits row")
                hidden = connection.execute(
                    "SELECT job_id FROM job_permits WHERE job_id = %s", (self.FIXTURE["B"]["job_id"],)
                ).fetchone()
                self.assertIsNone(hidden, "tenant A must not see tenant B's derived job_permits row")

                connection.execute(
                    "INSERT INTO job_permits (job_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                    (self.FIXTURE["A"]["spare_job_id"], self.FIXTURE["A"]["permit_id"], "j" * 64),
                )
                with self.assertRaises(Exception) as ctx:
                    connection.execute(
                        "INSERT INTO job_permits (job_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                        (self.FIXTURE["B"]["spare_job_id"], self.FIXTURE["A"]["permit_id"], "k" * 64),
                    )
                self.assertIn("row-level security", str(ctx.exception).lower())
            finally:
                connection.rollback()

    def test_derived_chain_schedule_permits(self) -> None:
        with self._connect(self._api_dsn) as connection:
            try:
                self._set_tenant(connection, self.ORG_A)
                visible = connection.execute(
                    "SELECT schedule_id FROM schedule_permits WHERE schedule_id = %s",
                    (self.FIXTURE["A"]["schedule_id"],),
                ).fetchone()
                self.assertIsNotNone(visible, "tenant A must see its own derived schedule_permits row")
                hidden = connection.execute(
                    "SELECT schedule_id FROM schedule_permits WHERE schedule_id = %s",
                    (self.FIXTURE["B"]["schedule_id"],),
                ).fetchone()
                self.assertIsNone(hidden, "tenant A must not see tenant B's derived schedule_permits row")

                connection.execute(
                    "INSERT INTO schedule_permits (schedule_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                    (self.FIXTURE["A"]["spare_schedule_id"], self.FIXTURE["A"]["permit_id"], "l" * 64),
                )
                with self.assertRaises(Exception) as ctx:
                    connection.execute(
                        "INSERT INTO schedule_permits (schedule_id, permit_id, permit_sha256) VALUES (%s, %s, %s)",
                        (self.FIXTURE["B"]["spare_schedule_id"], self.FIXTURE["A"]["permit_id"], "m" * 64),
                    )
                self.assertIn("row-level security", str(ctx.exception).lower())
            finally:
                connection.rollback()

    def test_derived_chain_job_safety_receipts(self) -> None:
        # api_tenant_data has SELECT only here (no INSERT/UPDATE);
        # worker_function_owner's INSERT is control-plane (true-policy,
        # tested separately under the worker control-function proof).
        with self._connect(self._api_dsn) as connection:
            self._set_tenant(connection, self.ORG_A)
            visible = connection.execute(
                "SELECT job_id FROM job_safety_receipts WHERE job_id = %s", (self.FIXTURE["A"]["job_id"],)
            ).fetchone()
            self.assertIsNotNone(visible, "tenant A must see its own derived job_safety_receipts row")
            hidden = connection.execute(
                "SELECT job_id FROM job_safety_receipts WHERE job_id = %s", (self.FIXTURE["B"]["job_id"],)
            ).fetchone()
            self.assertIsNone(hidden, "tenant A must not see tenant B's derived job_safety_receipts row")

    def test_derived_chain_password_credentials(self) -> None:
        # P1-2 Phase-D correction: api_tenant_data now holds narrow
        # column SELECT (principal_id), backed by this file's own
        # wg_api_password_credentials_select policy, so SELECT
        # visibility through the principals join IS applicable here --
        # unlike before the correction, when this table had no
        # ordinary-role SELECT of any kind and this test only covered
        # INSERT. UPDATE's own DML-dependency proof (both write-shape
        # statements, under FORCE RLS) lives in the dedicated
        # test_password_credentials_dml_dependency_under_force_rls;
        # this test stays focused on the derived-chain SELECT/INSERT
        # visibility pattern shared with the other four chains.
        with self._connect(self._api_dsn) as connection:
            self._set_tenant(connection, self.ORG_A)
            visible = connection.execute(
                "SELECT principal_id FROM password_credentials WHERE principal_id = %s",
                (self.FIXTURE["A"]["principal_id"],),
            ).fetchone()
            self.assertIsNotNone(visible, "tenant A must see its own derived password_credentials row")
            hidden = connection.execute(
                "SELECT principal_id FROM password_credentials WHERE principal_id = %s",
                (self.FIXTURE["B"]["principal_id"],),
            ).fetchone()
            self.assertIsNone(hidden, "tenant A must not see tenant B's derived password_credentials row")

        with self._connect(self._api_dsn) as connection:
            try:
                self._set_tenant(connection, self.ORG_A)
                connection.execute(
                    "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at) "
                    "VALUES (%s, 'argon2', 'hash', now(), now())",
                    (self.FIXTURE["A"]["spare_principal_id"],),
                )
                with self.assertRaises(Exception) as ctx:
                    connection.execute(
                        "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, "
                        "updated_at) VALUES (%s, 'argon2', 'hash', now(), now())",
                        (self.FIXTURE["B"]["spare_principal_id"],),
                    )
                self.assertIn("row-level security", str(ctx.exception).lower())
            finally:
                connection.rollback()

    # -- Section 2: crawl_checkpoints default-deny under future RLS ----------

    def test_crawl_checkpoints_default_deny_under_future_rls(self) -> None:
        # A test-only probe role holds SELECT (granted only inside this
        # disposable fixture, never in production) but there is
        # deliberately no policy for it on crawl_checkpoints. Under
        # FORCE RLS with zero applicable policy, PostgreSQL denies by
        # default regardless of tenant context -- proving future
        # enforcement semantics without inventing a production ACL,
        # a runtime role, or a policy that would only exist for this
        # test.
        with self._connect(self._checkpoint_probe_dsn) as connection:
            no_ctx = connection.execute("SELECT count(*) FROM crawl_checkpoints").fetchone()[0]
            self.assertEqual(no_ctx, 0, "no tenant context: default-deny must return zero rows")

        with self._connect(self._checkpoint_probe_dsn) as connection:
            self._set_tenant(connection, self.ORG_A)
            count_a = connection.execute("SELECT count(*) FROM crawl_checkpoints").fetchone()[0]
            self.assertEqual(count_a, 0, "tenant A context: default-deny must still return zero rows (no policy exists)")

        with self._connect(self._checkpoint_probe_dsn) as connection:
            self._set_tenant(connection, self.ORG_B)
            count_b = connection.execute("SELECT count(*) FROM crawl_checkpoints").fetchone()[0]
            self.assertEqual(count_b, 0, "tenant B context: default-deny must still return zero rows (no policy exists)")

    # -- Section 34: identity control functions under FORCE RLS --------------

    def test_identity_control_function_works_under_force_rls_then_ordinary_access_follows(self) -> None:
        with self._connect(self._api_dsn) as connection:
            direct = connection.execute("SELECT token_id FROM api_tokens").fetchall()
            self.assertEqual(direct, [], "no tenant context: ordinary role must see zero identity rows")

            resolved = connection.execute(
                "SELECT organization_id FROM webguard_control.resolve_api_token(%s)",
                (self.FIXTURE["A"]["token_id"],),
            ).fetchone()
            self.assertIsNotNone(resolved, "resolve_api_token must still work under FORCE RLS")
            self.assertEqual(str(resolved[0]), self.ORG_A)

            self._set_tenant(connection, self.ORG_A)
            own = connection.execute(
                "SELECT token_id FROM api_tokens WHERE token_id = %s", (self.FIXTURE["A"]["token_id"],)
            ).fetchone()
            self.assertIsNotNone(own)

    # -- Section 35: worker control functions under FORCE RLS -----------------

    def test_worker_control_function_works_under_force_rls_ordinary_access_stays_tenant_filtered(self) -> None:
        with self._connect(self._worker_dsn) as connection:
            org = connection.execute(
                "SELECT webguard_control.resolve_job_organization(%s)", (self.FIXTURE["A"]["job_id"],)
            ).fetchone()
            self.assertEqual(str(org[0]), self.ORG_A, "resolve_job_organization must still work under FORCE RLS")

            self._set_tenant(connection, self.ORG_A)
            rows = connection.execute("SELECT permit_id FROM scan_permits ORDER BY permit_id").fetchall()
            self.assertEqual(
                [str(r[0]) for r in rows], [self.FIXTURE["A"]["permit_id"]],
                "ordinary worker_tenant_data access must remain tenant-filtered even with FORCE RLS on",
            )

    # -- Section 36: scheduler control functions under FORCE RLS --------------

    def test_scheduler_control_function_works_cross_tenant_ordinary_access_stays_filtered(self) -> None:
        with self._connect(self._scheduler_dsn) as connection:
            due = connection.execute(
                "SELECT schedule_id FROM webguard_control.list_due_schedules(now(), 100)"
            ).fetchall()
            due_ids = {row[0] for row in due}
            self.assertIn(
                uuid.UUID(self.FIXTURE["A"]["schedule_id"]), due_ids,
                "scheduler owner function must see tenant A's schedule",
            )
            self.assertIn(
                uuid.UUID(self.FIXTURE["B"]["schedule_id"]), due_ids,
                "scheduler owner function must see tenant B's schedule too (cross-tenant by design)",
            )

            self._set_tenant(connection, self.ORG_A)
            rows = connection.execute("SELECT permit_id FROM scan_permits ORDER BY permit_id").fetchall()
            self.assertEqual(
                [str(r[0]) for r in rows], [self.FIXTURE["A"]["permit_id"]],
                "ordinary scheduler_tenant_data access must remain tenant-filtered even with FORCE RLS on",
            )

    # -- Section 37: callback owner policy surface, no runtime role ----------

    def test_callback_owner_policy_surface_is_exactly_its_acl_no_broader(self) -> None:
        import psycopg

        with psycopg.connect(self._db_dsn) as connection:
            connection.autocommit = True
            # SET ROLE itself is session-level (confirmed: it survives
            # a later BEGIN/ROLLBACK), so it is issued in autocommit
            # mode; the probe INSERT below is wrapped in its own
            # explicit transaction and rolled back so it does not leak
            # into the SELECT matrix's callback_observations row count.
            connection.execute("SET ROLE callback_function_owner")
            try:
                reg = connection.execute(
                    "SELECT token_value FROM callback_registrations WHERE token_value = %s",
                    (self.FIXTURE["A"]["callback_token"],),
                ).fetchone()
                self.assertIsNotNone(reg, "callback_function_owner must be able to SELECT callback_registrations")

                connection.execute("BEGIN")
                connection.execute(
                    "INSERT INTO callback_observations (observation_id, token_value, method, source_class, "
                    "observed_at) VALUES (%s, %s, 'GET', 'test', now())",
                    (str(uuid.uuid4()), self.FIXTURE["A"]["callback_token"]),
                )
                connection.execute("ROLLBACK")

                with self.assertRaises(Exception) as ctx:
                    connection.execute("SELECT job_id FROM scan_jobs LIMIT 1")
                self.assertIn("permission denied", str(ctx.exception).lower())
            finally:
                connection.execute("RESET ROLE")

    # -- Section 38: function-owner ACL envelope still wins over RLS ---------

    def test_function_owner_acl_envelope_still_wins_over_true_policy(self) -> None:
        import psycopg

        with psycopg.connect(self._db_dsn) as connection:
            connection.autocommit = True
            connection.execute("SET ROLE worker_function_owner")
            try:
                with self.assertRaises(Exception) as ctx:
                    connection.execute(
                        "INSERT INTO findings (finding_id, organization_id, fingerprint, check_id, severity, "
                        "confidence, asset, endpoint, http_method, scanner_version, first_seen_at, last_seen_at) "
                        "VALUES (%s, %s, 'fp', 'check', 'low', 'low', 'asset', '/', 'GET', 'v1', now(), now())",
                        (str(uuid.uuid4()), self.ORG_A),
                    )
                self.assertIn(
                    "permission denied", str(ctx.exception).lower(),
                    "worker_function_owner has no findings ACL at all; a true RLS policy elsewhere must not "
                    "change that -- ACL is checked first and must still deny this",
                )
            finally:
                connection.execute("RESET ROLE")


if __name__ == "__main__":
    unittest.main()
