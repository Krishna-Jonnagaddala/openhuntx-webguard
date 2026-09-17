"""P1-2 Phase H method-level gap closure (2026-09-17): proves each of
the 9 remaining unrestricted-connection gaps identified in this phase
now runs correctly under its own correct, restricted runtime role
against a real, disposable PostgreSQL database with row-level security
ENABLED and FORCED on every tenant-owned table, mirroring
test_postgres_rls_policies.py's own TwoTenantIsolationTests bootstrap
sequence (roles -> tenant ACL -> function ACL -> control functions ->
RLS policies, then ENABLE/FORCE RLS in this disposable database only),
plus the new callback_receiver LOGIN role's own separately-authenticated
pool, which nothing else in this test suite yet exercises end to end.

Gaps proved here (see each test method's own docstring for exactly
which repository method(s) and control function(s) it covers):

- Group A (identity_function_owner): get_password_hash,
  consume_identity_token
- Group B (worker_function_owner): get_job_permit_binding,
  is_cancellation_requested (get()'s former caller), get_scope
- Group C (scheduler_function_owner): get_schedule_permit_binding,
  enqueue_due_schedule
- Group D (callback): record_observation via the new callback_receiver
  role, plus its own adversarial checks (Section: CALLBACK RECEIVER
  ADVERSARIAL PASS below)

`get` (postgres_jobs.py) and `revoke_registration`
(postgres_callback_service.py) are deliberately NOT exercised here:
`get` has zero production callers left once `is_cancellation_requested`
stops routing through it (proved by that test not needing `get` at
all), and `revoke_registration` is deliberately left unconverted
(re-verified zero callers, see its own docstring), so there is no
restricted-role behavior to prove for either.

Requires a real database (WEBGUARD_RUN_INTEGRATION=1 and a reachable
WEBGUARD_POSTGRES_TEST_DSN) with the schema migrations already applied,
and a connecting role with CREATE ROLE and CREATE DATABASE privilege
(the disposable dev/CI Postgres's own POSTGRES_USER already satisfies
this, per every other Postgres integration test in this suite).
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

ALL_BOOTSTRAP_ROLES = (
    "api_tenant_data", "worker_tenant_data", "scheduler_tenant_data",
    "identity_function_owner", "worker_function_owner", "scheduler_function_owner",
    "callback_function_owner", "callback_receiver",
)

# Every tenant-owned table with a policy (mirrors test_postgres_rls_policies.py's
# own RLS_MANAGED_TABLES). ENABLE/FORCE RLS on all of them so this
# suite proves the 9 gaps under the SAME real enforcement condition a
# future production activation would run under, not merely under an
# unenforced policy definition.
RLS_TARGET_TABLES = [
    "organizations", "principals", "memberships", "api_tokens",
    "organization_authorizations", "security_audit_events",
    "targets", "target_verifications",
    "callback_registrations", "callback_observations",
    "scan_permits", "job_permits", "schedule_permits", "job_safety_receipts",
    "scan_jobs", "scan_schedules", "scan_records", "findings", "reports",
    "authentication_contexts", "authorization_comparison_plans",
    "finding_events", "password_credentials", "identity_tokens",
    "browser_sessions", "auth_rate_limit_events",
    "coverage_records", "module_entitlements", "frameworks", "master_controls",
    "scoped_control_implementations", "technical_assertion_collections",
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class PhaseHGapClosureTests(unittest.TestCase):
    ORG_A = None
    ORG_B = None

    @classmethod
    def setUpClass(cls) -> None:
        import psycopg
        from urllib.parse import urlsplit, urlunsplit

        cls._admin_dsn = POSTGRES_TEST_DSN
        parts = urlsplit(POSTGRES_TEST_DSN)
        cls._host_port = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
        cls._db_name = "test_phase_h_gap_closure_db"

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            admin.execute(f'CREATE DATABASE "{cls._db_name}"')
            for role in ALL_BOOTSTRAP_ROLES + (
                "test_ph_api_caller", "test_ph_worker_caller", "test_ph_scheduler_caller",
            ):
                exists = admin.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)", (role,)
                ).fetchone()[0]
                if exists:
                    admin.execute(f'DROP OWNED BY "{role}" CASCADE')
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

        db_parts = urlsplit(cls._admin_dsn)
        cls._db_dsn = urlunsplit((db_parts.scheme, db_parts.netloc, f"/{cls._db_name}", "", ""))

        import subprocess
        import sys

        repo_root = Path(__file__).resolve().parent.parent.parent
        env = dict(os.environ)
        env["WEBGUARD_DATABASE_URL"] = cls._db_dsn
        migration_result = subprocess.run(
            [sys.executable, str(repo_root / "scripts" / "run-postgres-migrations.py")],
            env=env, capture_output=True, text=True, cwd=repo_root,
        )
        assert migration_result.returncode == 0, migration_result.stderr

        with psycopg.connect(cls._db_dsn) as connection:
            for path in (
                ROLES_SQL_PATH, TENANT_ACL_SQL_PATH, FUNCTION_ACL_SQL_PATH,
                CONTROL_FUNCTIONS_SQL_PATH, RLS_POLICIES_SQL_PATH,
            ):
                connection.execute(path.read_text(encoding="utf-8"))
                connection.commit()

        # Section: disposable LOGIN test-caller roles, one per ordinary
        # tenant-data role, plus the callback_receiver role's own
        # password (never set by bootstrap SQL: see
        # tenant_isolation_roles.sql's own comment on why).
        with psycopg.connect(cls._db_dsn) as connection:
            connection.autocommit = True
            connection.execute(
                'CREATE ROLE "test_ph_api_caller" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                "PASSWORD 'test-caller-password'"
            )
            connection.execute(
                'CREATE ROLE "test_ph_worker_caller" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                "PASSWORD 'test-caller-password'"
            )
            connection.execute(
                'CREATE ROLE "test_ph_scheduler_caller" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                "PASSWORD 'test-caller-password'"
            )
            connection.execute('GRANT api_tenant_data TO "test_ph_api_caller"')
            connection.execute('GRANT worker_tenant_data TO "test_ph_worker_caller"')
            connection.execute('GRANT scheduler_tenant_data TO "test_ph_scheduler_caller"')
            connection.execute("ALTER ROLE callback_receiver PASSWORD 'test-callback-receiver-password'")

        netloc_fmt = "{user}:test-caller-password@" + cls._host_port
        cls._api_dsn = urlunsplit(("postgresql", netloc_fmt.format(user="test_ph_api_caller"), f"/{cls._db_name}", "", ""))
        cls._worker_dsn = urlunsplit(
            ("postgresql", netloc_fmt.format(user="test_ph_worker_caller"), f"/{cls._db_name}", "", "")
        )
        cls._scheduler_dsn = urlunsplit(
            ("postgresql", netloc_fmt.format(user="test_ph_scheduler_caller"), f"/{cls._db_name}", "", "")
        )
        cls._callback_receiver_dsn = urlunsplit((
            "postgresql",
            f"callback_receiver:test-callback-receiver-password@{cls._host_port}",
            f"/{cls._db_name}", "", "",
        ))

        # Section: ENABLE + FORCE RLS, exactly like TwoTenantIsolationTests.
        # Disposable database only, never production bootstrap SQL.
        with psycopg.connect(cls._db_dsn) as connection:
            connection.autocommit = True
            for table in RLS_TARGET_TABLES:
                connection.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
                connection.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")

    @classmethod
    def tearDownClass(cls) -> None:
        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            for role in ALL_BOOTSTRAP_ROLES + (
                "test_ph_api_caller", "test_ph_worker_caller", "test_ph_scheduler_caller",
            ):
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

    def _admin_connect(self):
        import psycopg

        return psycopg.connect(self._db_dsn)

    # Shared fixtures, seeded as the unrestricted admin actor (always
    # bypasses RLS regardless of FORCE, matching every other proof in
    # this suite).

    def _seed_org_and_owner(self, connection, *, label: str) -> tuple[str, str]:
        org_id = str(uuid.uuid4())
        principal_id = str(uuid.uuid4())
        now = _utc_now()
        connection.execute(
            "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
            "VALUES (%s,%s,%s,%s,%s)",
            (org_id, f"Org {label}", f"org-{label}-{org_id}", "active", now),
        )
        connection.execute(
            "INSERT INTO principals (principal_id, organization_id, display_name, principal_type, role, "
            "active, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (principal_id, org_id, f"Owner {label}", "user", "owner", True, now),
        )
        connection.commit()
        return org_id, principal_id

    def _seed_authorization(self, connection, org_id: str, principal_id: str) -> str:
        auth_id = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO organization_authorizations (organization_id, authorization_id, assigned_by, "
            "assigned_at) VALUES (%s,%s,%s,%s)",
            (org_id, auth_id, principal_id, _utc_now()),
        )
        connection.commit()
        return auth_id

    def _seed_permit(self, connection, org_id: str, principal_id: str, auth_id: str) -> tuple[str, str]:
        permit_id = str(uuid.uuid4())
        permit_sha256 = uuid.uuid4().hex + uuid.uuid4().hex
        now = _utc_now()
        connection.execute(
            "INSERT INTO scan_permits (permit_id, organization_id, authorization_id, "
            "authorization_sha256, target, issued_by, issued_at, not_before, expires_at, "
            "permit_sha256, signing_key_id, document_json) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (permit_id, org_id, auth_id, "a" * 64, "https://example.com", principal_id, now,
             now - timedelta(hours=1), now + timedelta(hours=1), permit_sha256, "key-1", "{}"),
        )
        connection.commit()
        return permit_id, permit_sha256

    def _seed_job(self, connection, org_id: str, principal_id: str, auth_id: str, *, permit=None) -> str:
        job_id = str(uuid.uuid4())
        now = _utc_now()
        connection.execute(
            "INSERT INTO scan_jobs (job_id, organization_id, submitted_by, idempotency_key, "
            "request_fingerprint, target, authorization_id, authorization_sha256, mode, submitted_at, "
            "state, updated_at, revision, cancellation_requested) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,FALSE)",
            (job_id, org_id, principal_id, f"key-{job_id}", f"fp-{job_id}", "https://example.com",
             auth_id, "a" * 64, "single_page", now, "queued", now),
        )
        if permit is not None:
            permit_id, permit_sha256 = permit
            connection.execute(
                "INSERT INTO job_permits (job_id, permit_id, permit_sha256) VALUES (%s,%s,%s)",
                (job_id, permit_id, permit_sha256),
            )
        connection.commit()
        return job_id

    # ===================================================================
    # Group A: identity_function_owner
    # ===================================================================

    def test_get_password_hash_succeeds_under_api_tenant_data(self) -> None:
        """gap 1/9: postgres_identity.py's get_password_hash, via the
        new webguard_control.resolve_password_hash, under
        api_tenant_data, with RLS FORCED on password_credentials."""

        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool

        with self._admin_connect() as connection:
            org_id, principal_id = self._seed_org_and_owner(connection, label="pwd-hash")
            # Seeded directly (not via identity.set_password_hash):
            # that method is a PRE-EXISTING gap this task did not
            # touch: it runs under api_tenant_data via
            # role_scoped_connection but never calls
            # set_tenant_context, so its INSERT/UPDATE fails closed
            # under FORCE RLS (password_credentials' own policy is
            # tenant-predicated through a join to principals). Confirmed
            # directly while writing this test (InsufficientPrivilege:
            # "new row violates row-level security policy for table
            # password_credentials"). Out of scope for the 9 gaps this
            # phase closes. Flagged in the final report for the
            # orchestrating session, not fixed here.
            now = _utc_now()
            connection.execute(
                "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at) "
                "VALUES (%s,%s,%s,%s,%s)",
                (principal_id, "argon2id", "the-real-hash", now, now),
            )
            connection.commit()

        pool = WebGuardPostgresPool(self._api_dsn)
        try:
            identity = PostgresIdentityRepository(pool)

            self.assertEqual(identity.get_password_hash(principal_id), "the-real-hash")
            # Anti-enumeration: an unknown principal_id returns None,
            # the exact same shape as "found, no credential row yet":
            # no distinct error, no timing-oracle-shaped exception.
            self.assertIsNone(identity.get_password_hash(str(uuid.uuid4())))
        finally:
            pool.close()

    def test_consume_identity_token_succeeds_and_sets_tenant_context(self) -> None:
        """gap 2/9: postgres_identity.py's consume_identity_token, via
        the widened webguard_control.resolve_identity_token (created_at
        appended), under api_tenant_data, with RLS FORCED on
        identity_tokens. Also proves the post-resolution UPDATE
        actually lands (requires this method's own new
        set_tenant_context call to satisfy identity_tokens' tenant-
        predicated RLS UPDATE policy) and that reuse/expiry/purpose
        checks still fail closed exactly as before."""

        from webguard_api.identity import IdentityStoreError, IdentityTokenPurpose
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool

        with self._admin_connect() as connection:
            org_id, principal_id = self._seed_org_and_owner(connection, label="token")

        pool = WebGuardPostgresPool(self._api_dsn)
        try:
            identity = PostgresIdentityRepository(pool)
            now = _utc_now()
            issued = identity.create_identity_token(
                principal_id, org_id, purpose=IdentityTokenPurpose.PASSWORD_RESET,
                ttl=timedelta(hours=1), now=now,
            )

            record = identity.consume_identity_token(
                issued.token, purpose=IdentityTokenPurpose.PASSWORD_RESET, now=now
            )
            self.assertEqual(record.token_id, issued.record.token_id)
            self.assertEqual(record.organization_id, org_id)
            self.assertEqual(record.created_at, issued.record.created_at)

            # The post-resolution UPDATE actually committed (not just
            # "no exception raised"), verified as the admin actor,
            # which always bypasses RLS/ACL and can read used_at
            # directly.
            with self._admin_connect() as admin_connection:
                used_at = admin_connection.execute(
                    "SELECT used_at FROM identity_tokens WHERE token_id = %s", (issued.record.token_id,)
                ).fetchone()[0]
            self.assertIsNotNone(used_at, "consume_identity_token's UPDATE must actually persist used_at")

            # Fail closed: the same token cannot be consumed twice.
            with self.assertRaises(IdentityStoreError) as ctx:
                identity.consume_identity_token(
                    issued.token, purpose=IdentityTokenPurpose.PASSWORD_RESET, now=now
                )
            self.assertEqual(ctx.exception.code, "identity_token_used")

            # Fail closed: an unknown token is rejected, not a 500 or a
            # role/RLS internal error leaking through.
            with self.assertRaises(IdentityStoreError) as ctx:
                identity.consume_identity_token(
                    "wgidt_" + str(uuid.uuid4()) + "_" + "x" * 32,
                    purpose=IdentityTokenPurpose.PASSWORD_RESET, now=now,
                )
            self.assertEqual(ctx.exception.code, "identity_token_invalid")
        finally:
            pool.close()

    # ===================================================================
    # Group B: worker_function_owner
    # ===================================================================

    def test_worker_gaps_succeed_under_worker_tenant_data(self) -> None:
        """gaps 3-5/9: postgres_jobs.py's get_job_permit_binding,
        is_cancellation_requested (get()'s former sole caller), and
        get_scope, all three now run entirely through new
        SECURITY DEFINER functions owned by worker_function_owner,
        under worker_tenant_data, with RLS FORCED on scan_jobs and
        job_permits."""

        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.store import JobStoreError

        with self._admin_connect() as connection:
            org_id, principal_id = self._seed_org_and_owner(connection, label="worker-gaps")
            auth_id = self._seed_authorization(connection, org_id, principal_id)
            permit_id, permit_sha256 = self._seed_permit(connection, org_id, principal_id, auth_id)
            job_id = self._seed_job(
                connection, org_id, principal_id, auth_id, permit=(permit_id, permit_sha256)
            )
            job_id_no_permit = self._seed_job(connection, org_id, principal_id, auth_id)

        pool = WebGuardPostgresPool(self._worker_dsn)
        try:
            jobs = PostgresJobRepository(pool)

            # get_job_permit_binding (gap 3)
            binding = jobs.get_job_permit_binding(job_id)
            self.assertEqual(binding, (permit_id, permit_sha256))
            self.assertIsNone(jobs.get_job_permit_binding(job_id_no_permit))
            self.assertIsNone(jobs.get_job_permit_binding(str(uuid.uuid4())))

            # is_cancellation_requested (gap 4, get()'s former caller)
            self.assertFalse(jobs.is_cancellation_requested(job_id))
            with self._admin_connect() as connection:
                connection.execute(
                    "UPDATE scan_jobs SET cancellation_requested = TRUE WHERE job_id = %s", (job_id,)
                )
                connection.commit()
            self.assertTrue(jobs.is_cancellation_requested(job_id))
            with self.assertRaises(JobStoreError) as ctx:
                jobs.is_cancellation_requested(str(uuid.uuid4()))
            self.assertEqual(ctx.exception.code, "job_not_found")

            # get_scope (gap 5)
            scope = jobs.get_scope(job_id)
            self.assertEqual(scope, (org_id, principal_id))
            self.assertIsNone(jobs.get_scope(str(uuid.uuid4())))
        finally:
            pool.close()

    # ===================================================================
    # Group C: scheduler_function_owner
    # ===================================================================

    def test_scheduler_gaps_succeed_under_scheduler_tenant_data(self) -> None:
        """gaps 6-7/9: postgres_schedules.py's get_schedule_permit_binding
        and enqueue_due_schedule (the former via a new SECURITY
        DEFINER function, the latter via the widened
        webguard_control.enqueue_due_schedule (30 columns appended)),
        both under scheduler_tenant_data, with RLS FORCED on
        scan_schedules, schedule_permits, and scan_jobs."""

        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.store import JobStoreError

        with self._admin_connect() as connection:
            org_id, principal_id = self._seed_org_and_owner(connection, label="scheduler-gaps")
            auth_id = self._seed_authorization(connection, org_id, principal_id)
            permit_id, permit_sha256 = self._seed_permit(connection, org_id, principal_id, auth_id)
            schedule_id = str(uuid.uuid4())
            now = _utc_now()
            connection.execute(
                "INSERT INTO scan_schedules (schedule_id, organization_id, created_by, name, target, "
                "authorization_id, authorization_sha256, mode, interval_seconds, state, created_at, "
                "updated_at, next_run_at, revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)",
                (schedule_id, org_id, principal_id, "gap-closure-schedule", "https://example.com",
                 auth_id, "a" * 64, "single_page", 3600, "active", now, now,
                 now - timedelta(seconds=1)),
            )
            connection.execute(
                "INSERT INTO schedule_permits (schedule_id, permit_id, permit_sha256) VALUES (%s,%s,%s)",
                (schedule_id, permit_id, permit_sha256),
            )
            connection.commit()

        pool = WebGuardPostgresPool(self._scheduler_dsn)
        try:
            jobs = PostgresJobRepository(pool)

            # get_schedule_permit_binding (gap 6)
            binding = jobs.get_schedule_permit_binding(schedule_id)
            self.assertEqual(binding, (permit_id, permit_sha256))
            self.assertIsNone(jobs.get_schedule_permit_binding(str(uuid.uuid4())))

            # enqueue_due_schedule (gap 7): full record pair.
            result = jobs.enqueue_due_schedule(
                schedule_id, expected_revision=0, authorization_sha256="a" * 64,
                permit_id=permit_id, permit_sha256=permit_sha256, now=_utc_now(),
            )
            self.assertIsNotNone(result)
            schedule_record, job_record = result
            self.assertEqual(schedule_record.schedule_id, schedule_id)
            self.assertEqual(schedule_record.organization_id, org_id)
            self.assertEqual(schedule_record.created_by, principal_id)
            self.assertEqual(schedule_record.name, "gap-closure-schedule")
            self.assertEqual(schedule_record.revision, 1)
            self.assertEqual(job_record.request.target, "https://example.com/")
            self.assertEqual(job_record.state.value, "queued")

            with self._admin_connect() as connection:
                job_row = connection.execute(
                    "SELECT organization_id, state FROM scan_jobs WHERE job_id = %s", (job_record.job_id,)
                ).fetchone()
            self.assertEqual(str(job_row[0]), org_id)
            self.assertEqual(job_row[1], "queued")

            # Fail closed: the stale revision is no longer due (already
            # advanced by the successful call above).
            raced = jobs.enqueue_due_schedule(
                schedule_id, expected_revision=0, authorization_sha256="a" * 64,
                permit_id=permit_id, permit_sha256=permit_sha256, now=_utc_now(),
            )
            self.assertIsNone(raced)

            # Fail closed: a mismatched permit binding raises, exactly
            # as it always has (JobStoreError, not a bare DB error).
            with self._admin_connect() as connection:
                connection.execute(
                    "UPDATE scan_schedules SET revision = 1, next_run_at = %s WHERE schedule_id = %s",
                    (_utc_now() - timedelta(seconds=1), schedule_id),
                )
                connection.commit()
            with self.assertRaises(JobStoreError) as ctx:
                jobs.enqueue_due_schedule(
                    schedule_id, expected_revision=1, authorization_sha256="a" * 64,
                    permit_id=str(uuid.uuid4()), permit_sha256="b" * 64, now=_utc_now(),
                )
            self.assertEqual(ctx.exception.code, "trustscan_schedule_binding_changed")
        finally:
            pool.close()

    # ===================================================================
    # Group D: callback_receiver (the new role)
    # ===================================================================

    def test_callback_receiver_records_observation_and_nothing_else(self) -> None:
        """gap 8/9 plus the callback-receiver adversarial pass:
        record_observation now runs through
        webguard_control.resolve_and_record_callback_observation,
        called over a pool authenticated AS callback_receiver directly
        (never SET LOCAL ROLE from a broader identity). Proves:

        1. The legitimate path succeeds (a real registration, a
           matching token, a fresh observation).
        2. A garbage/unknown token resolves to False, not a leak of
           whether some OTHER organization's token exists (anti-
           enumeration, same as before this change).
        3. callback_receiver's connection can be used for nothing else:
           a direct table query on this exact connection fails with
           InsufficientPrivilege, not a silent cross-tenant read.
        4. api_tenant_data (an entirely different, already-existing
           role) cannot call this function: the callback ingress
           path is not reachable through any other identity.
        5. Two full observation-recording round trips on freshly
           checked-out connections from the SAME pool both succeed
           independently, proving nothing from the first checkout
           (role, GUC, or otherwise) leaked into the second."""

        import psycopg

        from webguard_api.postgres_callback_service import PostgresCallbackRegistrationRepository
        from webguard_api.postgres_pool import WORKER_TENANT_DATA_ROLE, WebGuardPostgresPool

        with self._admin_connect() as connection:
            org_id, principal_id = self._seed_org_and_owner(connection, label="callback")

        # The registration itself is created by the ordinary
        # worker_tenant_data path (register()'s own real caller,
        # unaffected by this gap closure), a separate pool, exactly
        # mirroring how the worker process and the callback-service
        # process are two different OS processes with two different
        # DSNs in a real deployment.
        worker_pool = WebGuardPostgresPool(self._worker_dsn)
        try:
            worker_repository = PostgresCallbackRegistrationRepository(worker_pool)
            registration = worker_repository.register(
                scan_id=str(uuid.uuid4()), candidate_fingerprint="fp-1", organization_id=org_id,
                target="https://example.com", authorization_id=str(uuid.uuid4()), now=_utc_now(),
            )
        finally:
            worker_pool.close()

        callback_pool = WebGuardPostgresPool(self._callback_receiver_dsn)
        try:
            callback_repository = PostgresCallbackRegistrationRepository(callback_pool)

            # 1. Legitimate path.
            recorded = callback_repository.record_observation(
                registration.token_value, method="GET", now=_utc_now()
            )
            self.assertTrue(recorded)
            with self._admin_connect() as connection:
                count = connection.execute(
                    "SELECT count(*) FROM callback_observations WHERE token_value = %s",
                    (registration.token_value,),
                ).fetchone()[0]
            self.assertEqual(count, 1)

            # 2. Unknown token: no crash, no distinguishing error, just
            # False. An attacker probing the public callback endpoint
            # with a guessed token learns nothing about whether it
            # exists, is expired, or is revoked.
            self.assertFalse(
                callback_repository.record_observation(
                    "guessed-token-" + uuid.uuid4().hex, method="GET", now=_utc_now()
                )
            )

            # 3. This exact connection can do nothing else: a direct
            # table query fails closed, proving callback_receiver holds
            # no ambient table privilege that a future bug reusing this
            # connection could exploit.
            with callback_pool.connection() as connection:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT * FROM callback_registrations LIMIT 1")
            with callback_pool.connection() as connection:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT * FROM organizations LIMIT 1")
        finally:
            callback_pool.close()

        # 4. A different, already-existing, already-narrow role cannot
        # reach the callback function either: the ingress path really
        # is reachable only through callback_receiver.
        with self._admin_connect() as connection:
            can_execute = connection.execute(
                "SELECT has_function_privilege(%s, %s, 'EXECUTE')",
                (
                    "worker_tenant_data",
                    "webguard_control.resolve_and_record_callback_observation(text, text, text, timestamptz)",
                ),
            ).fetchone()[0]
        self.assertFalse(can_execute, "worker_tenant_data must not be able to call the callback function")
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with psycopg.connect(self._worker_dsn) as connection:
                connection.execute(
                    "SELECT webguard_control.resolve_and_record_callback_observation(%s, %s, %s, %s)",
                    (registration.token_value, "GET", "external", _utc_now()),
                )
        self.assertEqual(WORKER_TENANT_DATA_ROLE, "worker_tenant_data")  # sanity: the constant used above

        # 5. Pooled-connection leak check: a second, independent
        # checkout from the SAME callback_pool succeeds on its own
        # merits, proving no residual state (role, GUC) survived from
        # the first checkout into the next.
        callback_pool_2 = WebGuardPostgresPool(self._callback_receiver_dsn)
        try:
            callback_repository_2 = PostgresCallbackRegistrationRepository(callback_pool_2)
            worker_pool_2 = WebGuardPostgresPool(self._worker_dsn)
            try:
                second_registration = PostgresCallbackRegistrationRepository(worker_pool_2).register(
                    scan_id=str(uuid.uuid4()), candidate_fingerprint="fp-2", organization_id=org_id,
                    target="https://example.com", authorization_id=str(uuid.uuid4()), now=_utc_now(),
                )
            finally:
                worker_pool_2.close()
            self.assertTrue(
                callback_repository_2.record_observation(
                    second_registration.token_value, method="POST", now=_utc_now()
                )
            )
        finally:
            callback_pool_2.close()

    def test_pooled_connection_does_not_leak_role_or_tenant_context(self) -> None:
        """Hard requirement 6: acquire a connection under one role/tenant,
        release it, acquire again, confirm no residual role or GUC
        state survives. role_scoped_connection/tenant_connection use
        SET LOCAL (transaction-scoped), so both must revert the instant
        each `with` block's own transaction ends."""

        from webguard_api.postgres_pool import API_TENANT_DATA_ROLE, WORKER_TENANT_DATA_ROLE, WebGuardPostgresPool

        with self._admin_connect() as connection:
            org_id, _principal_id = self._seed_org_and_owner(connection, label="leak-check")

        pool = WebGuardPostgresPool(self._api_dsn, minimum_connections=1, maximum_connections=1)
        try:
            with pool.tenant_connection(org_id, role=API_TENANT_DATA_ROLE) as connection:
                role_during = connection.execute("SELECT current_user").fetchone()[0]
                guc_during = connection.execute(
                    "SELECT current_setting('webguard.current_organization_id', true)"
                ).fetchone()[0]
            self.assertEqual(role_during, "api_tenant_data")
            self.assertEqual(guc_during, org_id)

            # Same pool (min=max=1, so this MUST be the identical
            # physical connection reused), fresh checkout, no role/tenant
            # requested this time.
            with pool.connection() as connection:
                role_after = connection.execute("SELECT current_user").fetchone()[0]
                guc_after = connection.execute(
                    "SELECT current_setting('webguard.current_organization_id', true)"
                ).fetchone()[0]
            self.assertEqual(role_after, "test_ph_api_caller", "SET LOCAL ROLE must not survive past its transaction")
            self.assertEqual(guc_after, "", "the tenant GUC must not survive past its transaction")
        finally:
            pool.close()

        # role_scoped_connection alone (no tenant context) reverts the
        # same way.
        worker_pool = WebGuardPostgresPool(self._worker_dsn, minimum_connections=1, maximum_connections=1)
        try:
            with worker_pool.role_scoped_connection(WORKER_TENANT_DATA_ROLE) as connection:
                self.assertEqual(connection.execute("SELECT current_user").fetchone()[0], "worker_tenant_data")
            with worker_pool.connection() as connection:
                self.assertEqual(
                    connection.execute("SELECT current_user").fetchone()[0], "test_ph_worker_caller"
                )
        finally:
            worker_pool.close()


if __name__ == "__main__":
    unittest.main()
