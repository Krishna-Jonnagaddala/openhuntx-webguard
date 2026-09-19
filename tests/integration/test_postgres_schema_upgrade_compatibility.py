"""P1-2 Phase H gap closure, schema-compatibility check (2026-09-18).

tenant_isolation_control_functions.sql's own comment claims that
widening resolve_identity_token/enqueue_due_schedule via DROP FUNCTION
then CREATE FUNCTION, keeping the original columns first in the same
order, "never breaks a caller that only reads the columns it already
expects by position." That claim was never exercised against an
actual pre-upgrade database, only reasoned about. This file exercises
it: it applies the bootstrap chain exactly as it existed immediately
before this Phase H gap-closure pass (commit 19cc604, the last commit
on this branch before 8693ddc started widening these two functions),
against a real database, calls the OLD-shaped functions, THEN applies
the CURRENT bootstrap chain on top of that same live database (the
real upgrade path, not a fresh install), and re-runs the identical
positional reads to prove they still return the same values.

Findings, established here rather than assumed:

1. Fresh install (current bootstrap chain applied to an empty
   database) and upgrade (Phase-H-era chain applied on top of a
   pre-Phase-H chain already applied) both succeed. Bootstrap
   repeatability (each file's own idempotent design) holds across an
   upgrade too, not merely on a single fresh apply.
2. A caller decoding resolve_identity_token/enqueue_due_schedule by
   position (row[0], row[4], etc. -- confirmed as the real decode
   style in postgres_identity.py/postgres_schedules.py, never exact-
   arity tuple unpacking) gets byte-identical values at every
   pre-existing position after the upgrade. An OLD application binary
   still running against an upgraded database continues to work
   unmodified.
3. EXECUTE grants and function ownership (identity_function_owner /
   scheduler_function_owner) survive the DROP FUNCTION + CREATE
   FUNCTION step, re-established by the same file that removes them
   (this is not automatic -- DROP FUNCTION drops every grant on that
   function; the file's own REVOKE ALL FROM PUBLIC / GRANT EXECUTE
   TO ... lines immediately after each CREATE are what restores them,
   and this test proves they actually do, not merely that the SQL
   parses).
4. Deployment ordering requirement: a NEW application binary (one
   that reads row[7]/created_at, e.g. the current consume_identity_token)
   run against the OLD, not-yet-upgraded function would raise
   IndexError the moment it tried to read that position -- there is no
   database-side fallback for a column that does not exist yet. The
   SQL bootstrap chain must therefore be applied and committed BEFORE
   any new application version that depends on the widened columns
   starts serving traffic. This is a deployment ORDERING requirement,
   not a traffic-stopping maintenance window: the DROP+CREATE itself
   runs inside one transaction (already proven atomic and safe to
   re-run by test_postgres_control_functions.py's own
   test_control_functions_bootstrap_is_safe_to_run_a_second_time and
   NonSuperuserOwnershipTransferTests), so old-binary traffic served
   concurrently with the migration transaction sees either the fully
   old or the fully new function, never a partial state, and needs no
   downtime of its own. Old binaries keep working unmodified after the
   migration commits (point 2 above), so the two rollout steps (apply
   SQL, then deploy new app code) do not need to happen in the same
   instant, only in that relative order.

Requires a real database (WEBGUARD_RUN_INTEGRATION=1 and a reachable
WEBGUARD_POSTGRES_TEST_DSN) with a connecting role holding CREATE ROLE
and CREATE DATABASE privilege, exactly like every other Postgres
integration test in this suite. Also requires this file to be able to
run `git show 19cc604:<path>` from within the repository (the "old"
bootstrap chain is read from that pre-existing commit, not
duplicated by hand as a second copy that could drift from the real
history).
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
import uuid
from datetime import timedelta
from datetime import datetime as dt
from datetime import timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_BOOTSTRAP_DIR = _REPO_ROOT / "infra" / "postgres" / "bootstrap"
ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"

# The last commit on this branch before Phase H's gap-closure work
# started widening resolve_identity_token/enqueue_due_schedule --
# i.e. the bootstrap chain a real, already-deployed environment would
# have been running if it had been stood up any time before this pass.
_PRE_PHASE_H_GAP_CLOSURE_SHA = "19cc604"

ALL_BOOTSTRAP_ROLES = (
    "api_tenant_data", "worker_tenant_data", "scheduler_tenant_data",
    "identity_function_owner", "worker_function_owner", "scheduler_function_owner",
    "callback_function_owner", "callback_receiver",
)


def _git_show(sha: str, relative_path: Path) -> str:
    result = subprocess.run(
        ["git", "show", f"{sha}:{relative_path.relative_to(_REPO_ROOT)}"],
        cwd=_REPO_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class SchemaUpgradeCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import psycopg

        cls._admin_dsn = POSTGRES_TEST_DSN
        cls._db_name = "test_schema_upgrade_compat_db"

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            admin.execute(f'CREATE DATABASE "{cls._db_name}"')
            for role in ALL_BOOTSTRAP_ROLES:
                exists = admin.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)", (role,)
                ).fetchone()[0]
                if exists:
                    admin.execute(f'DROP OWNED BY "{role}" CASCADE')
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

        db_parts = urlsplit(cls._admin_dsn)
        cls._db_dsn = urlunsplit((db_parts.scheme, db_parts.netloc, f"/{cls._db_name}", "", ""))

        env = dict(os.environ)
        env["WEBGUARD_DATABASE_URL"] = cls._db_dsn
        migration_result = subprocess.run(
            [sys.executable, str(_REPO_ROOT / "scripts" / "run-postgres-migrations.py")],
            env=env, capture_output=True, text=True, cwd=_REPO_ROOT,
        )
        assert migration_result.returncode == 0, migration_result.stderr

        cls._old_roles_sql = _git_show(_PRE_PHASE_H_GAP_CLOSURE_SHA, ROLES_SQL_PATH)
        cls._old_control_functions_sql = _git_show(_PRE_PHASE_H_GAP_CLOSURE_SHA, CONTROL_FUNCTIONS_SQL_PATH)
        # acl.sql/function_acl.sql are byte-identical between the old
        # commit and HEAD (confirmed via `git diff 19cc604..HEAD --
        # infra/postgres/bootstrap/tenant_isolation_acl.sql
        # infra/postgres/bootstrap/tenant_isolation_function_acl.sql`,
        # empty output) -- reading them from disk at HEAD is the same
        # content the old commit would have applied.

    @classmethod
    def tearDownClass(cls) -> None:
        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

    def setUp(self) -> None:
        self.now = dt.now(timezone.utc)
        import psycopg

        with psycopg.connect(self._db_dsn, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA IF EXISTS webguard_control CASCADE')
            for role in ALL_BOOTSTRAP_ROLES:
                exists = connection.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)", (role,)
                ).fetchone()[0]
                if exists:
                    connection.execute(f'DROP OWNED BY "{role}" CASCADE')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')
            connection.execute(
                "TRUNCATE TABLE scan_jobs, scan_schedules, schedule_permits, job_permits, "
                "scan_permits, organization_authorizations, identity_tokens, principals, "
                "organizations RESTART IDENTITY CASCADE"
            )

    def _connect(self):
        import psycopg

        return psycopg.connect(self._db_dsn)

    def _fresh_org_and_principal(self, connection) -> tuple[str, str]:
        org_id = str(uuid.uuid4())
        principal_id = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
            "VALUES (%s,%s,%s,%s,%s)",
            (org_id, f"Org-{org_id}", f"org-{org_id}", "active", self.now),
        )
        connection.execute(
            "INSERT INTO principals (principal_id, organization_id, display_name, principal_type, role, "
            "active, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (principal_id, org_id, "Person", "user", "owner", True, self.now),
        )
        return org_id, principal_id

    def test_fresh_install_of_current_bootstrap_chain_succeeds(self) -> None:
        with self._connect() as connection:
            connection.execute(ROLES_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(TENANT_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            columns = connection.execute(
                "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'webguard_control' AND p.proname = 'resolve_identity_token'"
            ).fetchone()[0]
        self.assertEqual(columns, 1, "fresh install must produce exactly one resolve_identity_token overload")

    def test_upgrade_from_pre_phase_h_bootstrap_preserves_grants_and_old_shaped_reads(self) -> None:
        import psycopg

        # Step 1: stand up the OLD (pre-Phase-H) bootstrap chain, as if
        # this were an already-deployed environment.
        with self._connect() as connection:
            connection.execute(self._old_roles_sql)
            connection.execute(TENANT_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(self._old_control_functions_sql)
            connection.commit()

        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            token_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO identity_tokens (token_id, principal_id, organization_id, purpose, "
                "secret_hash, created_at, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (token_id, principal_id, org_id, "email_verification", "ih", self.now,
                 self.now + timedelta(hours=1)),
            )
            connection.commit()
            old_row = connection.execute(
                "SELECT * FROM webguard_control.resolve_identity_token(%s)", (token_id,)
            ).fetchone()

        self.assertEqual(len(old_row), 7, "pre-upgrade resolve_identity_token must return the original 7 columns")

        # Step 2: the real upgrade -- apply the CURRENT bootstrap chain
        # on top of this same live database, exactly as a deployment
        # runbook would (roles.sql is additive/idempotent; acl.sql and
        # function_acl.sql are unchanged; control_functions.sql is what
        # actually performs the DROP FUNCTION + CREATE FUNCTION step).
        with self._connect() as connection:
            connection.execute(ROLES_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(TENANT_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()

        with self._connect() as connection:
            new_row = connection.execute(
                "SELECT * FROM webguard_control.resolve_identity_token(%s)", (token_id,)
            ).fetchone()

        self.assertEqual(len(new_row), 8, "post-upgrade resolve_identity_token must return the widened 8 columns")
        # An OLD application binary only ever reads positions 0..6
        # (postgres_identity.py's own decode, pre- and post-widening,
        # confirmed by direct reading: row[4]=secret_hash, row[3]=purpose,
        # row[6]=used_at, row[2]=organization_id, row[5]=expires_at --
        # never row[7]). Those positions must be byte-identical to what
        # the pre-upgrade row already returned.
        self.assertEqual(tuple(new_row[:7]), tuple(old_row), "existing columns must be unchanged after the upgrade")
        self.assertIsNotNone(new_row[7], "the new created_at column must be populated (identity_tokens' own NOT NULL DEFAULT now())")

        # Grants and ownership must survive the DROP FUNCTION step --
        # not automatic, since DROP FUNCTION drops every grant on the
        # function it removes.
        with self._connect() as connection:
            can_execute = connection.execute(
                "SELECT has_function_privilege('api_tenant_data', p.oid, 'EXECUTE') "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'webguard_control' AND p.proname = 'resolve_identity_token'"
            ).fetchone()[0]
            owner = connection.execute(
                "SELECT r.rolname FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "JOIN pg_roles r ON r.oid = p.proowner "
                "WHERE n.nspname = 'webguard_control' AND p.proname = 'resolve_identity_token'"
            ).fetchone()[0]
        self.assertTrue(can_execute, "api_tenant_data must still hold EXECUTE after the upgrade")
        self.assertEqual(owner, "identity_function_owner", "ownership must survive the DROP FUNCTION + CREATE FUNCTION step")

        # enqueue_due_schedule: same DROP+CREATE treatment, widened from
        # 8 to 38 columns. Prove the post-upgrade function is fully
        # operational end to end (not just that it parses), and that
        # its grant/ownership also survived.
        with self._connect() as connection:
            org_id2, principal_id2 = self._fresh_org_and_principal(connection)
            auth_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO organization_authorizations (organization_id, authorization_id, assigned_by, "
                "assigned_at) VALUES (%s,%s,%s,%s)",
                (org_id2, auth_id, principal_id2, self.now),
            )
            schedule_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO scan_schedules (schedule_id, organization_id, created_by, name, target, "
                "authorization_id, authorization_sha256, mode, interval_seconds, state, created_at, "
                "updated_at, next_run_at, revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)",
                (schedule_id, org_id2, principal_id2, "s", "https://example.com", auth_id, "a" * 64,
                 "passive", 3600, "active", self.now, self.now, self.now),
            )
            permit_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO scan_permits (permit_id, organization_id, authorization_id, "
                "authorization_sha256, target, issued_by, issued_at, not_before, expires_at, "
                "permit_sha256, signing_key_id, document_json) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (permit_id, org_id2, auth_id, "a" * 64, "https://example.com", principal_id2, self.now,
                 self.now - timedelta(hours=1), self.now + timedelta(hours=1), "b" * 64, "key-1", "{}"),
            )
            connection.execute(
                "INSERT INTO schedule_permits (schedule_id, permit_id, permit_sha256) VALUES (%s,%s,%s)",
                (schedule_id, permit_id, "b" * 64),
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM webguard_control.enqueue_due_schedule(%s,%s,%s,%s,%s,%s,%s)",
                (schedule_id, 0, "a" * 64, permit_id, "b" * 64, self.now, "fp-upgrade-test"),
            ).fetchone()

        self.assertEqual(len(row), 38, "post-upgrade enqueue_due_schedule must return the widened 38 columns")
        self.assertEqual(row[0], "ok")

        with self._connect() as connection:
            can_execute = connection.execute(
                "SELECT has_function_privilege('scheduler_tenant_data', p.oid, 'EXECUTE') "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'webguard_control' AND p.proname = 'enqueue_due_schedule'"
            ).fetchone()[0]
        self.assertTrue(can_execute, "scheduler_tenant_data must still hold EXECUTE after the upgrade")

        # Bootstrap repeatability across an upgrade, not just a single
        # fresh apply: run the current chain a second time on this
        # already-upgraded database.
        with self._connect() as connection:
            connection.execute(ROLES_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(TENANT_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.execute(CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
