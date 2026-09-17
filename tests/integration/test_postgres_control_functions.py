"""Real-PostgreSQL proof of P1-2 Phase F's control functions
(docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md):
infra/postgres/bootstrap/tenant_isolation_control_functions.sql,
applied on top of Phase C's roles, Phase D's ordinary tenant-data
ACLs, and Phase E's function-owner ACLs.

No SECURITY DEFINER function created here is reachable from live
WebGuard runtime: no repository method calls any of them yet, no RLS
policy exists, no production LOGIN role exists. This phase proves the
functions exist, are owned by the right role, run inside exactly that
role's Phase-E ACL envelope (not the bootstrap admin's), cannot be
reached by PUBLIC or an unintended caller, resist a caller-controlled
search_path, and reproduce the current repository methods' observable
behavior (transaction boundary, CAS semantics, returned data,
not-found/error outcomes) as closely as a dormant function reasonably
can.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`) with the 12 schema migrations already
applied, and a connecting role with CREATE ROLE and GRANT privilege
(see test_postgres_tenant_role_bootstrap.py's own docstring for why
the official postgres Docker image's POSTGRES_USER already satisfies
this in this project's disposable dev/CI Postgres).
"""

from __future__ import annotations

import os
import threading
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

TENANT_DATA_ROLES = ["api_tenant_data", "worker_tenant_data", "scheduler_tenant_data"]
FUNCTION_OWNER_ROLES = [
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
]
ALL_BOOTSTRAP_ROLES = TENANT_DATA_ROLES + FUNCTION_OWNER_ROLES

# name -> (owner role, grantee role, identity-argument-signature)
EXPECTED_FUNCTIONS = {
    "resolve_api_token": ("identity_function_owner", "api_tenant_data", "p_token_id uuid"),
    "resolve_browser_session": ("identity_function_owner", "api_tenant_data", "p_session_id uuid"),
    "resolve_principal_by_email": ("identity_function_owner", "api_tenant_data", "p_email text"),
    "resolve_identity_token": ("identity_function_owner", "api_tenant_data", "p_token_id uuid"),
    "claim_next_job": (
        "worker_function_owner",
        "worker_tenant_data",
        "p_worker_id text, p_lease_seconds numeric, p_now timestamp with time zone",
    ),
    "recover_expired_leases": (
        "worker_function_owner",
        "worker_tenant_data",
        "p_now timestamp with time zone, p_maximum_attempts integer",
    ),
    "renew_lease": (
        "worker_function_owner",
        "worker_tenant_data",
        "p_job_id uuid, p_worker_id text, p_lease_token text, p_now timestamp with time zone, "
        "p_lease_seconds numeric",
    ),
    "resolve_job_organization": ("worker_function_owner", "worker_tenant_data", "p_job_id uuid"),
    "terminal_transition": (
        "worker_function_owner",
        "worker_tenant_data",
        "p_job_id uuid, p_state text, p_now timestamp with time zone, p_worker_id text, "
        "p_lease_token text, p_scan_id text, p_result_status text, p_report_ref text, "
        "p_audit_ref text, p_error_code text, p_error_message text, p_safety_receipt_ref text, "
        "p_safety_receipt_sha256 text",
    ),
    "list_due_schedules": (
        "scheduler_function_owner",
        "scheduler_tenant_data",
        "p_now timestamp with time zone, p_limit integer",
    ),
    "enqueue_due_schedule": (
        "scheduler_function_owner",
        "scheduler_tenant_data",
        "p_schedule_id uuid, p_expected_revision integer, p_authorization_sha256 text, "
        "p_permit_id uuid, p_permit_sha256 text, p_now timestamp with time zone, "
        "p_request_fingerprint text",
    ),
    "block_due_schedule": (
        "scheduler_function_owner",
        "scheduler_tenant_data",
        "p_schedule_id uuid, p_expected_revision integer, p_error_code text, "
        "p_now timestamp with time zone",
    ),
    # P1-2 Phase H gap closure, 2026-09-17: callback_function_owner
    # remains the privileged owner (not a caller-facing role), but the
    # deferred "future deployment phase that actually wires a LOGIN
    # identity to this path" (Section 9's own words) has arrived.
    # callback_receiver is that identity. See
    # test_callback_function_execute_grantee_is_exactly_callback_receiver
    # for the dedicated no-other-role-can-execute-it proof.
    "resolve_and_record_callback_observation": (
        "callback_function_owner",
        "callback_receiver",
        "p_token_value text, p_method text, p_source_class text, p_observed_at timestamp with time zone",
    ),
    # P1-2 Phase H gap closure, 2026-09-17: six new functions, none
    # of Phase F's original 13.
    "resolve_password_hash": ("identity_function_owner", "api_tenant_data", "p_principal_id uuid"),
    "resolve_job_scope": ("worker_function_owner", "worker_tenant_data", "p_job_id uuid"),
    "resolve_job_cancellation_requested": ("worker_function_owner", "worker_tenant_data", "p_job_id uuid"),
    "resolve_job_permit_binding": ("worker_function_owner", "worker_tenant_data", "p_job_id uuid"),
    "resolve_schedule_permit_binding": (
        "scheduler_function_owner", "scheduler_tenant_data", "p_schedule_id uuid",
    ),
    "resolve_schedule_request_shape": (
        "scheduler_function_owner", "scheduler_tenant_data", "p_schedule_id uuid",
    ),
}


def _utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ControlFunctionsFileStructureTests(unittest.TestCase):
    """Static, no-database proof that ownership arises from CREATE OR
    REPLACE FUNCTION running while CURRENT_USER is already the intended
    owner (SET ROLE), never from a separate ALTER FUNCTION ... OWNER TO
    statement. These read the file as text; no PostgreSQL connection is
    involved, so they run unconditionally."""

    def test_no_alter_function_owner_to_statements(self) -> None:
        sql = CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8")
        code_only = "\n".join(
            line for line in sql.splitlines() if not line.strip().startswith("--")
        )
        self.assertNotIn(
            "OWNER TO", code_only,
            "no CREATE OR REPLACE FUNCTION in this file may be followed by an "
            "ALTER FUNCTION ... OWNER TO -- ownership must come from CURRENT_USER "
            "already being the intended owner (via SET ROLE) at CREATE time",
        )

    def test_each_function_created_inside_its_owner_set_role_window(self) -> None:
        # Marker deliberately matches both "CREATE FUNCTION" and
        # "CREATE OR REPLACE FUNCTION": resolve_identity_token and
        # enqueue_due_schedule (P1-2 Phase H gap closure, 2026-09-17)
        # use DROP FUNCTION IF EXISTS + CREATE FUNCTION instead of
        # CREATE OR REPLACE, since PostgreSQL refuses to let CREATE OR
        # REPLACE FUNCTION widen an existing RETURNS TABLE (confirmed
        # directly against this project's own disposable Postgres 16).
        # Every other function here is still plain CREATE OR REPLACE
        # FUNCTION, and this marker matches either form identically.
        sql = CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8")
        for name, (expected_owner, _grantee, _args) in EXPECTED_FUNCTIONS.items():
            set_role_marker = f"SET ROLE {expected_owner};"
            create_marker = f"FUNCTION webguard_control.{name}("
            set_index = sql.index(set_role_marker)
            reset_index = sql.index("RESET ROLE;", set_index)
            create_index = sql.index(create_marker)
            self.assertTrue(
                set_index < create_index < reset_index,
                f"{name}'s CREATE [OR REPLACE] FUNCTION must fall between "
                f"'{set_role_marker}' and the 'RESET ROLE;' that closes its block, "
                f"so it is created while CURRENT_USER is {expected_owner}",
            )


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class ControlFunctionBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.roles_sql = ROLES_SQL_PATH.read_text(encoding="utf-8")
        cls.tenant_acl_sql = TENANT_ACL_SQL_PATH.read_text(encoding="utf-8")
        cls.function_acl_sql = FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8")
        cls.control_functions_sql = CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8")
        cls._apply_full_bootstrap()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._drop_bootstrap_roles()

    @classmethod
    def _connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def _drop_bootstrap_roles(cls) -> None:
        with cls._connect() as connection:
            connection.autocommit = True
            connection.execute("DROP SCHEMA IF EXISTS webguard_control CASCADE")
            for role in ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

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

    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        # claim_next_job/enqueue_due_schedule/etc. are deliberately
        # cross-tenant control-plane functions with no per-caller
        # scoping filter -- that is the point of them. A shared
        # database across test methods would let one test's leftover
        # row (e.g. a QUEUED job from another test) be the one a
        # different test's claim_next_job call actually claims. Start
        # every test from a clean slate on the tables these functions
        # touch, rather than fabricate artificial per-test scoping
        # these functions don't have.
        with self._connect() as connection:
            connection.execute(
                "TRUNCATE TABLE scan_jobs, scan_schedules, schedule_permits, job_permits, "
                "scan_permits, scan_records, job_safety_receipts, organization_authorizations, "
                "callback_registrations, callback_observations, api_tokens, browser_sessions, "
                "identity_tokens, password_credentials, principals, organizations "
                "RESTART IDENTITY CASCADE"
            )
            connection.commit()

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

    def _assign_authorization(self, connection, org_id: str, principal_id: str) -> str:
        auth_id = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO organization_authorizations (organization_id, authorization_id, assigned_by, "
            "assigned_at) VALUES (%s,%s,%s,%s)",
            (org_id, auth_id, principal_id, self.now),
        )
        return auth_id

    def _insert_queued_job(self, connection, org_id: str, principal_id: str, auth_id: str, key: str) -> str:
        job_id = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO scan_jobs (job_id, organization_id, submitted_by, idempotency_key, "
            "request_fingerprint, target, authorization_id, authorization_sha256, mode, submitted_at, "
            "state, updated_at, revision, cancellation_requested) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,FALSE)",
            (job_id, org_id, principal_id, key, f"fp-{key}", "https://example.com", auth_id, "a" * 64,
             "passive", self.now, "queued", self.now),
        )
        return job_id

    # -- Section 29: complete function inventory --------------------------

    def test_exactly_nineteen_functions_with_correct_metadata(self) -> None:
        # 13 from Phase F, plus 6 from P1-2 Phase H's method-level gap
        # closure (2026-09-17): resolve_password_hash, resolve_job_scope,
        # resolve_job_cancellation_requested, resolve_job_permit_binding,
        # resolve_schedule_permit_binding, resolve_schedule_request_shape.
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT p.proname, pg_get_function_identity_arguments(p.oid), p.prosecdef,
                       pg_get_userbyid(p.proowner), p.proconfig
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'webguard_control'
                """
            ).fetchall()

        self.assertEqual(len(rows), 19, f"expected exactly 19 functions, found {len(rows)}: {rows}")
        by_name = {name: (args, secdef, owner, config) for name, args, secdef, owner, config in rows}
        self.assertEqual(set(by_name), set(EXPECTED_FUNCTIONS), "unexpected function name set")

        for name, (owner, _grantee, expected_args) in EXPECTED_FUNCTIONS.items():
            args, secdef, actual_owner, config = by_name[name]
            self.assertEqual(args, expected_args, f"{name} argument signature mismatch")
            self.assertTrue(secdef, f"{name} must be SECURITY DEFINER")
            self.assertEqual(actual_owner, owner, f"{name} must be owned by {owner}")
            self.assertEqual(
                config, ["search_path=pg_catalog, pg_temp"], f"{name} must have a fixed search_path"
            )

    def test_webguard_control_schema_privileges(self) -> None:
        # has_schema_privilege has no literal 'PUBLIC' role-name form;
        # the established technique (Phase D's own test file) is a
        # freshly created, zero-explicit-grant probe role, whose only
        # privileges come from whatever the PUBLIC pseudo-role grants
        # by default.
        with self._connect() as connection:
            connection.autocommit = True
            connection.execute('DROP ROLE IF EXISTS "test_public_default_probe"')
            connection.execute('CREATE ROLE "test_public_default_probe" NOLOGIN')
            try:
                public_create = connection.execute(
                    "SELECT has_schema_privilege('test_public_default_probe', 'webguard_control', 'CREATE')"
                ).fetchone()[0]
                public_usage = connection.execute(
                    "SELECT has_schema_privilege('test_public_default_probe', 'webguard_control', 'USAGE')"
                ).fetchone()[0]
            finally:
                connection.execute('DROP ROLE IF EXISTS "test_public_default_probe"')
        self.assertFalse(public_create, "PUBLIC must not have CREATE on webguard_control")
        self.assertFalse(public_usage, "PUBLIC must not have USAGE on webguard_control")

    # -- Section 28: function owners cannot CREATE in webguard_control -----

    def test_function_owners_cannot_create_in_webguard_control(self) -> None:
        with self._connect() as connection:
            for role in FUNCTION_OWNER_ROLES:
                has_create = connection.execute(
                    "SELECT has_schema_privilege(%s, 'webguard_control', 'CREATE')", (role,)
                ).fetchone()[0]
                self.assertFalse(has_create, f"{role} must not have CREATE on webguard_control")

    # -- Section 27: PUBLIC EXECUTE revoked, intended grantees can execute --

    def test_public_execute_revoked_and_intended_grants_present(self) -> None:
        # has_function_privilege's function-signature argument takes
        # bare argument TYPES only (no parameter names), unlike
        # pg_get_function_identity_arguments's display form used
        # elsewhere in this file for readability.
        def bare_types(args: str) -> str:
            return ", ".join(segment.split(" ", 1)[1] for segment in args.split(", "))

        with self._connect() as connection:
            connection.autocommit = True
            connection.execute('DROP ROLE IF EXISTS "test_no_grant_probe"')
            connection.execute('CREATE ROLE "test_no_grant_probe" NOLOGIN')
            try:
                for name, (_owner, grantee, args) in EXPECTED_FUNCTIONS.items():
                    signature = f"webguard_control.{name}({bare_types(args)})"
                    no_grant = connection.execute(
                        "SELECT has_function_privilege('test_no_grant_probe', %s, 'EXECUTE')",
                        (signature,),
                    ).fetchone()[0]
                    self.assertFalse(no_grant, f"an ungranted role must not be able to EXECUTE {name}")

                    if grantee is None:
                        # resolve_and_record_callback_observation: no
                        # external Phase-F grantee, checked in its own
                        # dedicated test below.
                        continue

                    granted = connection.execute(
                        "SELECT has_function_privilege(%s, %s, 'EXECUTE')", (grantee, signature)
                    ).fetchone()[0]
                    self.assertTrue(granted, f"{grantee} must be able to EXECUTE {name}")
            finally:
                connection.execute('DROP ROLE IF EXISTS "test_no_grant_probe"')

    # -- Section 31: second run is stable -----------------------------------

    def test_control_functions_bootstrap_is_safe_to_run_a_second_time(self) -> None:
        with self._connect() as connection:
            before = connection.execute(
                """
                SELECT p.proname, pg_get_function_identity_arguments(p.oid), p.prosecdef,
                       pg_get_userbyid(p.proowner), p.proconfig, p.proacl::text
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'webguard_control' ORDER BY p.proname
                """
            ).fetchall()

        with self._connect() as connection:
            connection.execute(self.control_functions_sql)

        with self._connect() as connection:
            after = connection.execute(
                """
                SELECT p.proname, pg_get_function_identity_arguments(p.oid), p.prosecdef,
                       pg_get_userbyid(p.proowner), p.proconfig, p.proacl::text
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'webguard_control' ORDER BY p.proname
                """
            ).fetchall()

        self.assertEqual(before, after, "a second control-functions bootstrap run must change nothing")
        self.assertEqual(len(after), 19, "second run must not create duplicate overloads")

    # -- Section 26: search_path hijack resistance --------------------------

    def test_search_path_hijack_is_ineffective(self) -> None:
        with self._connect() as connection:
            connection.autocommit = True
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "hijack-test")

            connection.execute('DROP SCHEMA IF EXISTS attacker_schema CASCADE')
            connection.execute('CREATE SCHEMA attacker_schema')
            connection.execute(
                'CREATE TABLE attacker_schema.scan_jobs (job_id uuid PRIMARY KEY, organization_id uuid)'
            )
            fake_org_id = str(uuid.uuid4())
            connection.execute(
                'INSERT INTO attacker_schema.scan_jobs (job_id, organization_id) VALUES (%s, %s)',
                (job_id, fake_org_id),
            )
            connection.execute("SET search_path TO attacker_schema, public")
            try:
                result = connection.execute(
                    "SELECT webguard_control.resolve_job_organization(%s)", (job_id,)
                ).fetchone()[0]
            finally:
                connection.execute("RESET search_path")
                connection.execute('DROP SCHEMA attacker_schema CASCADE')

        self.assertEqual(
            str(result), org_id,
            "the function must resolve public.scan_jobs regardless of the caller's search_path, "
            "never the attacker-controlled table of the same unqualified name",
        )
        self.assertNotEqual(str(result), fake_org_id)

    # -- Section 25: SECURITY DEFINER executes within the owner's ACL -------
    # -- envelope, not as the bootstrap admin --------------------------------

    def test_security_definer_runs_within_owner_acl_not_as_bootstrap_admin(self) -> None:
        with self._connect() as connection:
            connection.autocommit = True
            connection.execute('DROP FUNCTION IF EXISTS webguard_control.test_only_probe_beyond_acl()')
            connection.execute(
                """
                CREATE FUNCTION webguard_control.test_only_probe_beyond_acl()
                    RETURNS void
                    LANGUAGE sql
                    SECURITY DEFINER
                    SET search_path = pg_catalog, pg_temp
                    AS $$
                    INSERT INTO public.findings (finding_id, organization_id, fingerprint, check_id,
                        severity, confidence, asset, endpoint, http_method, scanner_version, status,
                        first_seen_at, last_seen_at, references_list)
                    VALUES (gen_random_uuid(), gen_random_uuid(), 'x', 'y', 'low', 'high', 'a', 'b',
                        'GET', 'v1', 'open', now(), now(), '[]')
                $$
                """
            )
            connection.execute(
                "ALTER FUNCTION webguard_control.test_only_probe_beyond_acl() OWNER TO worker_function_owner"
            )
            connection.execute(
                "REVOKE ALL ON FUNCTION webguard_control.test_only_probe_beyond_acl() FROM PUBLIC"
            )
            connection.execute(
                "GRANT EXECUTE ON FUNCTION webguard_control.test_only_probe_beyond_acl() TO worker_tenant_data"
            )
            try:
                with self.assertRaises(Exception) as ctx:
                    connection.execute("SELECT webguard_control.test_only_probe_beyond_acl()")
                self.assertIn(
                    "permission denied", str(ctx.exception).lower(),
                    "a SECURITY DEFINER function must fail with permission denied when it attempts an "
                    "operation outside its owner's Phase-E ACL (findings INSERT is not granted to "
                    "worker_function_owner), proving it executes as that owner, not as the bootstrap admin",
                )
            finally:
                connection.execute('DROP FUNCTION IF EXISTS webguard_control.test_only_probe_beyond_acl()')

    def test_direct_table_access_matches_ordinary_role_privilege_honestly(self) -> None:
        """Section 24: RLS is not enabled, so a caller holding
        worker_tenant_data's own ordinary Phase-D grants can already
        read/write scan_records directly -- that is not a privilege
        this phase's functions grant or deny, and this test states
        that honestly rather than pretending the function boundary
        creates a denial that Phase D's own ACL doesn't already
        contradict."""

        with self._connect() as connection:
            has_select = connection.execute(
                "SELECT has_table_privilege('worker_tenant_data', 'scan_records', 'SELECT')"
            ).fetchone()[0]
        self.assertTrue(
            has_select,
            "worker_tenant_data already has ordinary SELECT on scan_records via Phase D; this phase "
            "does not and should not attempt to revoke it",
        )

    # -- Identity resolvers ---------------------------------------------------

    def test_resolve_api_token_matches_current_lookup_shape(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            token_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO api_tokens (token_id, organization_id, principal_id, label, secret_hash, "
                "created_at, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (token_id, org_id, principal_id, "t", "the-hash", self.now, self.now + timedelta(days=1)),
            )
            row = connection.execute(
                "SELECT * FROM webguard_control.resolve_api_token(%s)", (token_id,)
            ).fetchone()
            missing = connection.execute(
                "SELECT * FROM webguard_control.resolve_api_token(%s)", (str(uuid.uuid4()),)
            ).fetchall()

        self.assertIsNotNone(row)
        self.assertEqual(row[1], "the-hash")
        self.assertIsNone(row[2])  # token_revoked_at
        self.assertEqual(str(row[4]), principal_id)  # principal_id
        self.assertEqual(str(row[8]), org_id)  # organization_id
        self.assertEqual(row[10], "active")  # organization_status
        self.assertEqual(missing, [], "an unknown token_id must return zero rows")

    def test_resolve_api_token_returns_row_even_when_revoked_preserving_check_order(self) -> None:
        """Section 4: current authenticate_token() checks revoked_at/
        expires_at BEFORE resolving principal/organization. This
        resolver must still return the token's own fields when
        revoked, so a future caller can replicate that check order."""

        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            token_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO api_tokens (token_id, organization_id, principal_id, label, secret_hash, "
                "created_at, expires_at, revoked_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (token_id, org_id, principal_id, "t", "h", self.now, self.now + timedelta(days=1), self.now),
            )
            row = connection.execute(
                "SELECT * FROM webguard_control.resolve_api_token(%s)", (token_id,)
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertIsNotNone(row[2], "token_revoked_at must be populated")

    def test_resolve_browser_session_matches_current_lookup_shape(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            session_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO browser_sessions (session_id, principal_id, organization_id, secret_hash, "
                "csrf_hash, assurance_level, issued_at, idle_expires_at, absolute_expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (session_id, principal_id, org_id, "sh", "ch", "aal1", self.now,
                 self.now + timedelta(hours=1), self.now + timedelta(days=1)),
            )
            row = connection.execute(
                "SELECT * FROM webguard_control.resolve_browser_session(%s)", (session_id,)
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], "sh")
        self.assertEqual(row[2], "ch")
        self.assertEqual(str(row[7]), principal_id)

    def test_resolve_principal_by_email_matches_current_lookup_shape(self) -> None:
        with self._connect() as connection:
            org_id, _ = self._fresh_org_and_principal(connection)
            principal_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO principals (principal_id, organization_id, display_name, principal_type, "
                "role, active, created_at, email) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (principal_id, org_id, "Emailed", "user", "owner", True, self.now, "test@example.com"),
            )
            connection.execute(
                "INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, "
                "updated_at) VALUES (%s,%s,%s,%s,%s)",
                (principal_id, "argon2id", "pw-hash", self.now, self.now),
            )
            row = connection.execute(
                "SELECT * FROM webguard_control.resolve_principal_by_email(%s)", ("test@example.com",)
            ).fetchone()
            no_password_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO principals (principal_id, organization_id, display_name, principal_type, "
                "role, active, created_at, email) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (no_password_id, org_id, "NoPassword", "user", "owner", True, self.now, "nopw@example.com"),
            )
            row_no_password = connection.execute(
                "SELECT * FROM webguard_control.resolve_principal_by_email(%s)", ("nopw@example.com",)
            ).fetchone()
        self.assertEqual(str(row[0]), principal_id)
        self.assertEqual(row[4], "pw-hash")
        self.assertIsNone(row_no_password[4], "a principal without password_credentials must yield NULL")

    def test_resolve_identity_token_matches_current_lookup_shape(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            token_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO identity_tokens (token_id, principal_id, organization_id, purpose, "
                "secret_hash, created_at, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (token_id, principal_id, org_id, "email_verification", "ih", self.now,
                 self.now + timedelta(hours=1)),
            )
            row = connection.execute(
                "SELECT * FROM webguard_control.resolve_identity_token(%s)", (token_id,)
            ).fetchone()
        self.assertEqual(row[4], "ih")
        self.assertEqual(row[3], "email_verification")
        self.assertIsNone(row[6])  # used_at

    # -- Worker: claim_next_job concurrency (Section 14) --------------------

    def test_claim_next_job_two_concurrent_callers_claim_at_most_one_job(self) -> None:
        with self._connect() as connection:
            connection.autocommit = True
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "concurrency-test")

        results: list[tuple[str, list]] = []

        def claim(name: str) -> None:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                    (name, 30.0, self.now),
                ).fetchall()
                connection.commit()
                results.append((name, rows))

        threads = [threading.Thread(target=claim, args=(f"worker-{i}",)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        claimers = [(name, rows) for name, rows in results if rows]
        self.assertEqual(len(claimers), 1, f"exactly one caller must claim the job, got: {claimers}")
        claimed_row = claimers[0][1][0]
        self.assertEqual(str(claimed_row[0]), job_id)
        self.assertEqual(claimed_row[5], "running")
        self.assertEqual(claimed_row[19], claimers[0][0])  # worker_id

    def test_claim_next_job_respects_authorization_and_permit_predicate(self) -> None:
        """Preserves the exact claimable-row predicate: a job whose
        authorization is not assigned to its organization must never
        be claimed."""

        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            unassigned_auth_id = str(uuid.uuid4())
            job_id = self._insert_queued_job(
                connection, org_id, principal_id, unassigned_auth_id, "unassigned-auth"
            )
            connection.commit()
            rows = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("solo-worker", 30.0, self.now),
            ).fetchall()
            connection.commit()
            state = connection.execute("SELECT state FROM scan_jobs WHERE job_id = %s", (job_id,)).fetchone()[0]

        self.assertEqual(rows, [], "a job with an unassigned authorization must not be claimable")
        self.assertEqual(state, "queued", "the unclaimable job must remain untouched")

    # -- Worker: renew_lease CAS (Section 16) --------------------------------

    def test_renew_lease_ownership_and_token_are_enforced(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "renew-test")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("renew-worker", 30.0, self.now),
            ).fetchone()
            connection.commit()
            lease_token = claimed[20]

            ok = connection.execute(
                "SELECT * FROM webguard_control.renew_lease(%s, %s, %s, %s, %s::numeric)",
                (job_id, "renew-worker", lease_token, self.now + timedelta(seconds=5), 30.0),
            ).fetchone()
            connection.commit()
            self.assertEqual(ok[0], "ok")

            wrong_worker = connection.execute(
                "SELECT * FROM webguard_control.renew_lease(%s, %s, %s, %s, %s::numeric)",
                (job_id, "someone-else", lease_token, self.now, 30.0),
            ).fetchone()
            self.assertEqual(wrong_worker[0], "lease_lost")

            wrong_token = connection.execute(
                "SELECT * FROM webguard_control.renew_lease(%s, %s, %s, %s, %s::numeric)",
                (job_id, "renew-worker", str(uuid.uuid4()), self.now, 30.0),
            ).fetchone()
            self.assertEqual(wrong_token[0], "lease_lost")

            not_found = connection.execute(
                "SELECT * FROM webguard_control.renew_lease(%s, %s, %s, %s, %s::numeric)",
                (str(uuid.uuid4()), "x", str(uuid.uuid4()), self.now, 30.0),
            ).fetchone()
            self.assertEqual(not_found[0], "not_found")

    # -- Worker: resolve_job_organization (Section 17) -----------------------

    def test_resolve_job_organization_returns_only_organization_id(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "resolve-org-test")
            connection.commit()
            result = connection.execute(
                "SELECT webguard_control.resolve_job_organization(%s)", (job_id,)
            ).fetchone()[0]
            missing = connection.execute(
                "SELECT webguard_control.resolve_job_organization(%s)", (str(uuid.uuid4()),)
            ).fetchone()[0]
        self.assertEqual(str(result), org_id)
        self.assertIsNone(missing)

    # -- Worker: terminal_transition atomicity (Section 18) ------------------

    def test_terminal_transition_failed_reconciles_scan_records_atomically(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "terminal-failed")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("terminal-worker", 30.0, self.now),
            ).fetchone()
            connection.commit()
            worker_id, lease_token = claimed[19], claimed[20]

            scan_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO scan_records (scan_id, job_id, organization_id, target, authorization_id, "
                "mode, status, scanner_version, started_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (scan_id, job_id, org_id, "https://example.com", auth_id, "passive", "running", "t1",
                 self.now),
            )
            connection.commit()

            result = connection.execute(
                "SELECT * FROM webguard_control.terminal_transition(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (job_id, "failed", self.now + timedelta(seconds=10), worker_id, lease_token, None, None,
                 None, None, "boom", "it broke", None, None),
            ).fetchone()
            connection.commit()

            record = connection.execute(
                "SELECT status, completed_at FROM scan_records WHERE job_id = %s", (job_id,)
            ).fetchone()
            job_row = connection.execute(
                "SELECT state, worker_id, lease_token FROM scan_jobs WHERE job_id = %s", (job_id,)
            ).fetchone()

        self.assertEqual(result[0], "ok")
        self.assertEqual(result[6], "failed")
        self.assertEqual(record[0], "failed")
        self.assertIsNotNone(record[1])
        self.assertEqual(job_row[0], "failed")
        self.assertIsNone(job_row[1])
        self.assertIsNone(job_row[2])

    def test_terminal_transition_succeeded_does_not_touch_scan_records(self) -> None:
        """Reconfirms the SUCCEEDED-is-separate distinction (Section
        18): terminal_transition must not reconcile scan_records for a
        SUCCEEDED outcome, since current code's complete_scan() already
        does that in an earlier, separate transaction."""

        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "terminal-succeeded")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("succ-worker", 30.0, self.now),
            ).fetchone()
            connection.commit()
            worker_id, lease_token = claimed[19], claimed[20]

            scan_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO scan_records (scan_id, job_id, organization_id, target, authorization_id, "
                "mode, status, scanner_version, started_at, completed_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (scan_id, job_id, org_id, "https://example.com", auth_id, "passive", "succeeded", "t1",
                 self.now, self.now),
            )
            connection.commit()
            before = connection.execute(
                "SELECT status, completed_at FROM scan_records WHERE job_id = %s", (job_id,)
            ).fetchone()

            result = connection.execute(
                "SELECT * FROM webguard_control.terminal_transition(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (job_id, "succeeded", self.now + timedelta(seconds=10), worker_id, lease_token, scan_id,
                 "succeeded", "report-ref", "audit-ref", None, None, None, None),
            ).fetchone()
            connection.commit()
            after = connection.execute(
                "SELECT status, completed_at FROM scan_records WHERE job_id = %s", (job_id,)
            ).fetchone()

        self.assertEqual(result[0], "ok")
        self.assertEqual(result[6], "succeeded")
        self.assertEqual(before, after, "SUCCEEDED must not touch scan_records at all")

    def test_terminal_transition_wrong_lease_leaves_no_partial_write(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "terminal-badlease")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("real-worker", 30.0, self.now),
            ).fetchone()
            connection.commit()

            result = connection.execute(
                "SELECT * FROM webguard_control.terminal_transition(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (job_id, "failed", self.now, "wrong-worker", str(uuid.uuid4()), None, None, None, None,
                 "x", "y", None, None),
            ).fetchone()
            connection.commit()
            job_row = connection.execute(
                "SELECT state FROM scan_jobs WHERE job_id = %s", (job_id,)
            ).fetchone()

        self.assertEqual(result[0], "lease_lost")
        self.assertEqual(job_row[0], "running", "the job must remain untouched when the lease check fails")

    def test_terminal_transition_receipt_metadata_pairing_enforced(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "terminal-receipt")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("receipt-worker", 30.0, self.now),
            ).fetchone()
            connection.commit()
            worker_id, lease_token = claimed[19], claimed[20]

            result = connection.execute(
                "SELECT * FROM webguard_control.terminal_transition(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (job_id, "failed", self.now, worker_id, lease_token, None, None, None, None, "x", "y",
                 "some/ref", None),
            ).fetchone()
        self.assertEqual(result[0], "receipt_metadata_invalid")

    def test_terminal_transition_with_valid_receipt_inserts_it(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "terminal-receipt-ok")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("receipt-worker-2", 30.0, self.now),
            ).fetchone()
            connection.commit()
            worker_id, lease_token = claimed[19], claimed[20]

            result = connection.execute(
                "SELECT * FROM webguard_control.terminal_transition(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (job_id, "cancelled", self.now, worker_id, lease_token, None, None, None, None, None, None,
                 "receipts/x.json", "e" * 64),
            ).fetchone()
            connection.commit()
            receipt = connection.execute(
                "SELECT receipt_ref, receipt_sha256 FROM job_safety_receipts WHERE job_id = %s", (job_id,)
            ).fetchone()
        self.assertEqual(result[0], "ok")
        self.assertEqual(receipt, ("receipts/x.json", "e" * 64))

    # -- Worker: recover_expired_leases (Section 15) -------------------------

    def test_recover_expired_leases_requeues_cancels_and_fails_correctly(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)

            requeue_job = str(uuid.uuid4())
            cancel_job = str(uuid.uuid4())
            fail_job = str(uuid.uuid4())
            for job_id, cancellation_requested, attempt_count in (
                (requeue_job, False, 0),
                (cancel_job, True, 0),
                (fail_job, False, 5),
            ):
                connection.execute(
                    "INSERT INTO scan_jobs (job_id, organization_id, submitted_by, idempotency_key, "
                    "request_fingerprint, target, authorization_id, authorization_sha256, mode, "
                    "submitted_at, state, updated_at, revision, cancellation_requested, worker_id, "
                    "lease_token, lease_expires_at, attempt_count) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s,%s,%s,%s,%s)",
                    (job_id, org_id, principal_id, f"idem-{job_id}", f"fp-{job_id}", "https://example.com",
                     auth_id, "b" * 64, "passive", self.now, "running", self.now, cancellation_requested,
                     "stale-worker", str(uuid.uuid4()), self.now - timedelta(seconds=5), attempt_count),
                )
            connection.execute(
                "INSERT INTO scan_records (scan_id, job_id, organization_id, target, authorization_id, "
                "mode, status, scanner_version, started_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (str(uuid.uuid4()), cancel_job, org_id, "https://example.com", auth_id, "passive",
                 "running", "t1", self.now),
            )
            connection.execute(
                "INSERT INTO scan_records (scan_id, job_id, organization_id, target, authorization_id, "
                "mode, status, scanner_version, started_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (str(uuid.uuid4()), fail_job, org_id, "https://example.com", auth_id, "passive",
                 "running", "t1", self.now),
            )
            connection.commit()

            summary = connection.execute(
                "SELECT * FROM webguard_control.recover_expired_leases(%s, %s)", (self.now, 3)
            ).fetchone()
            connection.commit()

            states = {
                job_id: connection.execute(
                    "SELECT state FROM scan_jobs WHERE job_id = %s", (job_id,)
                ).fetchone()[0]
                for job_id in (requeue_job, cancel_job, fail_job)
            }
            record_statuses = {
                job_id: connection.execute(
                    "SELECT status FROM scan_records WHERE job_id = %s", (job_id,)
                ).fetchone()[0]
                for job_id in (cancel_job, fail_job)
            }

        self.assertEqual(summary, (1, 1, 1))
        self.assertEqual(states[requeue_job], "queued")
        self.assertEqual(states[cancel_job], "cancelled")
        self.assertEqual(states[fail_job], "failed")
        self.assertEqual(record_statuses[cancel_job], "cancelled")
        self.assertEqual(record_statuses[fail_job], "failed")

    # -- Scheduler (Sections 19-21) -------------------------------------------

    def _seed_schedule_with_permit(self, connection, org_id, principal_id, auth_id, name):
        schedule_id = str(uuid.uuid4())
        permit_id = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO scan_schedules (schedule_id, organization_id, created_by, name, target, "
            "authorization_id, authorization_sha256, mode, interval_seconds, state, created_at, "
            "updated_at, next_run_at, revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)",
            (schedule_id, org_id, principal_id, name, "https://example.com", auth_id, "c" * 64,
             "passive", 3600, "active", self.now, self.now, self.now - timedelta(seconds=1)),
        )
        connection.execute(
            "INSERT INTO scan_permits (permit_id, organization_id, authorization_id, "
            "authorization_sha256, target, issued_by, issued_at, not_before, expires_at, "
            "permit_sha256, signing_key_id, document_json) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (permit_id, org_id, auth_id, "c" * 64, "https://example.com", principal_id, self.now,
             self.now - timedelta(hours=1), self.now + timedelta(hours=1), "d" * 64, "key-1", "{}"),
        )
        connection.execute(
            "INSERT INTO schedule_permits (schedule_id, permit_id, permit_sha256) VALUES (%s,%s,%s)",
            (schedule_id, permit_id, "d" * 64),
        )
        return schedule_id, permit_id

    def test_list_due_schedules_eligibility_and_ordering(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            due_id, _ = self._seed_schedule_with_permit(connection, org_id, principal_id, auth_id, "due")
            connection.execute(
                "INSERT INTO scan_schedules (schedule_id, organization_id, created_by, name, target, "
                "authorization_id, authorization_sha256, mode, interval_seconds, state, created_at, "
                "updated_at, next_run_at, revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)",
                (str(uuid.uuid4()), org_id, principal_id, "not-due", "https://example.com", auth_id,
                 "c" * 64, "passive", 3600, "active", self.now, self.now,
                 self.now + timedelta(hours=1)),
            )
            connection.commit()
            due = connection.execute(
                "SELECT * FROM webguard_control.list_due_schedules(%s, %s)", (self.now, 10)
            ).fetchall()
        self.assertEqual(len(due), 1)
        self.assertEqual(str(due[0][0]), due_id)

    def test_enqueue_due_schedule_full_lifecycle_and_race_detection(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            schedule_id, permit_id = self._seed_schedule_with_permit(
                connection, org_id, principal_id, auth_id, "enqueue-test"
            )
            connection.commit()

            result = connection.execute(
                "SELECT * FROM webguard_control.enqueue_due_schedule(%s, %s, %s, %s, %s, %s, %s)",
                (schedule_id, 0, "c" * 64, permit_id, "d" * 64, self.now, "fp-enqueue-test"),
            ).fetchone()
            connection.commit()
            self.assertEqual(result[0], "ok")
            new_job_id = str(result[5])
            job_row = connection.execute(
                "SELECT state, organization_id FROM scan_jobs WHERE job_id = %s", (new_job_id,)
            ).fetchone()
            self.assertEqual(job_row[0], "queued")
            self.assertEqual(str(job_row[1]), org_id)
            permit_binding = connection.execute(
                "SELECT permit_id FROM job_permits WHERE job_id = %s", (new_job_id,)
            ).fetchone()
            self.assertEqual(str(permit_binding[0]), permit_id)

            raced = connection.execute(
                "SELECT * FROM webguard_control.enqueue_due_schedule(%s, %s, %s, %s, %s, %s, %s)",
                (schedule_id, 0, "c" * 64, permit_id, "d" * 64, self.now, "fp-enqueue-test"),
            ).fetchone()
            self.assertEqual(raced[0], "not_due", "the stale revision must no longer be due")

    def test_enqueue_due_schedule_binding_changed_and_permit_invalid(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            schedule_id, permit_id = self._seed_schedule_with_permit(
                connection, org_id, principal_id, auth_id, "binding-test"
            )
            connection.commit()

            wrong_permit = connection.execute(
                "SELECT * FROM webguard_control.enqueue_due_schedule(%s, %s, %s, %s, %s, %s, %s)",
                (schedule_id, 0, "c" * 64, str(uuid.uuid4()), "d" * 64, self.now, "fp-binding-test"),
            ).fetchone()
            self.assertEqual(wrong_permit[0], "binding_changed")

            org_id2, principal_id2 = self._fresh_org_and_principal(connection)
            auth_id2 = self._assign_authorization(connection, org_id2, principal_id2)
            schedule_id2, permit_id2 = self._seed_schedule_with_permit(
                connection, org_id2, principal_id2, auth_id2, "expired-permit-test"
            )
            connection.execute(
                "UPDATE scan_permits SET expires_at = %s WHERE permit_id = %s",
                (self.now - timedelta(minutes=1), permit_id2),
            )
            connection.commit()
            expired = connection.execute(
                "SELECT * FROM webguard_control.enqueue_due_schedule(%s, %s, %s, %s, %s, %s, %s)",
                (schedule_id2, 0, "c" * 64, permit_id2, "d" * 64, self.now, "fp-expired-test"),
            ).fetchone()
            self.assertEqual(expired[0], "permit_invalid")

    def test_block_due_schedule_cas_and_readback(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            schedule_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO scan_schedules (schedule_id, organization_id, created_by, name, target, "
                "authorization_id, authorization_sha256, mode, interval_seconds, state, created_at, "
                "updated_at, next_run_at, revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)",
                (schedule_id, org_id, principal_id, "block-test", "https://example.com", auth_id,
                 "c" * 64, "passive", 3600, "active", self.now, self.now,
                 self.now - timedelta(seconds=1)),
            )
            connection.commit()

            blocked = connection.execute(
                "SELECT * FROM webguard_control.block_due_schedule(%s, %s, %s, %s)",
                (schedule_id, 0, "authorization_not_assigned", self.now),
            ).fetchone()
            connection.commit()
            self.assertIsNotNone(blocked)
            self.assertEqual(blocked[9], "paused")
            self.assertEqual(blocked[16], "authorization_not_assigned")

            stale_cas = connection.execute(
                "SELECT * FROM webguard_control.block_due_schedule(%s, %s, %s, %s)",
                (schedule_id, 0, "x", self.now),
            ).fetchall()
            self.assertEqual(stale_cas, [], "a stale revision CAS must return zero rows")

    # -- Callback atomicity (Section 22-23) -----------------------------------

    def test_callback_observation_valid_expired_and_revoked(self) -> None:
        with self._connect() as connection:
            org_id, _ = self._fresh_org_and_principal(connection)

            valid_token = "cb-valid"
            connection.execute(
                "INSERT INTO callback_registrations (token_value, organization_id, scan_id, job_id, "
                "permit_id, target, authorization_id, candidate_fingerprint, created_at, expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (valid_token, org_id, "s", "j", "p", "https://example.com", "a" * 8, "f" * 64, self.now,
                 self.now + timedelta(hours=1)),
            )
            expired_token = "cb-expired"
            connection.execute(
                "INSERT INTO callback_registrations (token_value, organization_id, scan_id, job_id, "
                "permit_id, target, authorization_id, candidate_fingerprint, created_at, expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (expired_token, org_id, "s", "j", "p", "https://example.com", "a" * 8, "f" * 64,
                 self.now - timedelta(hours=2), self.now - timedelta(hours=1)),
            )
            revoked_token = "cb-revoked"
            connection.execute(
                "INSERT INTO callback_registrations (token_value, organization_id, scan_id, job_id, "
                "permit_id, target, authorization_id, candidate_fingerprint, created_at, expires_at, "
                "revoked_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (revoked_token, org_id, "s", "j", "p", "https://example.com", "a" * 8, "f" * 64, self.now,
                 self.now + timedelta(hours=1), self.now),
            )
            connection.commit()

            valid_result = connection.execute(
                "SELECT webguard_control.resolve_and_record_callback_observation(%s,%s,%s,%s)",
                (valid_token, "GET", "external", self.now),
            ).fetchone()[0]
            expired_result = connection.execute(
                "SELECT webguard_control.resolve_and_record_callback_observation(%s,%s,%s,%s)",
                (expired_token, "GET", "external", self.now),
            ).fetchone()[0]
            revoked_result = connection.execute(
                "SELECT webguard_control.resolve_and_record_callback_observation(%s,%s,%s,%s)",
                (revoked_token, "GET", "external", self.now),
            ).fetchone()[0]
            unknown_result = connection.execute(
                "SELECT webguard_control.resolve_and_record_callback_observation(%s,%s,%s,%s)",
                ("cb-unknown", "GET", "external", self.now),
            ).fetchone()[0]
            connection.commit()

            observation_count = connection.execute(
                "SELECT count(*) FROM callback_observations WHERE token_value = %s", (valid_token,)
            ).fetchone()[0]
            no_observation = connection.execute(
                "SELECT count(*) FROM callback_observations WHERE token_value IN (%s, %s, %s)",
                (expired_token, revoked_token, "cb-unknown"),
            ).fetchone()[0]

        self.assertTrue(valid_result)
        self.assertFalse(expired_result)
        self.assertFalse(revoked_result)
        self.assertFalse(unknown_result)
        self.assertEqual(observation_count, 1)
        self.assertEqual(no_observation, 0, "no observation may be recorded for an ineligible token")

    def test_callback_observation_uses_trusted_observed_at_not_its_own_clock(self) -> None:
        """Section 23: the function must persist the supplied
        observed_at exactly, never substitute now()/clock_timestamp()."""

        with self._connect() as connection:
            org_id, _ = self._fresh_org_and_principal(connection)
            token = "cb-trusted-time"
            trusted_time = self.now - timedelta(days=3)
            connection.execute(
                "INSERT INTO callback_registrations (token_value, organization_id, scan_id, job_id, "
                "permit_id, target, authorization_id, candidate_fingerprint, created_at, expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (token, org_id, "s", "j", "p", "https://example.com", "a" * 8, "f" * 64,
                 trusted_time - timedelta(hours=1), self.now + timedelta(days=1)),
            )
            connection.commit()
            result = connection.execute(
                "SELECT webguard_control.resolve_and_record_callback_observation(%s,%s,%s,%s)",
                (token, "GET", "external", trusted_time),
            ).fetchone()[0]
            connection.commit()
            observed_at = connection.execute(
                "SELECT observed_at FROM callback_observations WHERE token_value = %s", (token,)
            ).fetchone()[0]

        self.assertTrue(result)
        self.assertEqual(_utc(observed_at), _utc(trusted_time))

    # -- Section 1/9 correction: callback has NO external Phase-F ----------
    # -- EXECUTE grantee -----------------------------------------------------

    def test_callback_function_execute_grantee_is_exactly_callback_receiver(self) -> None:
        """callback_function_owner is the privileged SECURITY DEFINER
        owner, not a caller-facing capability role: unchanged. P1-2
        Phase H gap closure, 2026-09-17: callback_receiver is now the
        ONE role granted EXECUTE (Section 9's own deferred "future
        deployment phase" has arrived). Every other role, a fresh
        no-grant probe, and all three ordinary tenant-data roles, none
        of which should ever need this pre-authentication-only
        function, must still be unable to execute it."""

        signature = "webguard_control.resolve_and_record_callback_observation(text, text, text, timestamptz)"
        with self._connect() as connection:
            connection.autocommit = True
            connection.execute('DROP ROLE IF EXISTS "test_no_grant_probe_cb"')
            connection.execute('CREATE ROLE "test_no_grant_probe_cb" NOLOGIN')
            try:
                can_execute = connection.execute(
                    "SELECT has_function_privilege('callback_receiver', %s, 'EXECUTE')", (signature,)
                ).fetchone()[0]
                self.assertTrue(can_execute, "callback_receiver must be able to EXECUTE the callback function")

                for role in (
                    "test_no_grant_probe_cb",
                    "api_tenant_data",
                    "worker_tenant_data",
                    "scheduler_tenant_data",
                ):
                    can_execute = connection.execute(
                        "SELECT has_function_privilege(%s, %s, 'EXECUTE')", (role, signature)
                    ).fetchone()[0]
                    self.assertFalse(can_execute, f"{role} must not be able to EXECUTE the callback function")
            finally:
                connection.execute('DROP ROLE IF EXISTS "test_no_grant_probe_cb"')

    # -- Section 2 correction: webguard_control schema USAGE matrix --------

    def test_webguard_control_schema_usage_matrix(self) -> None:
        # Section 9: standing USAGE on webguard_control for all seven roles
        # (the three tenant-data roles and the four function-owner roles)
        # is now a load-bearing part of the owner-context bootstrap design,
        # not incidental: the REVOKE/GRANT EXECUTE statements each owner
        # block runs while impersonating its owner (SET ROLE) reference
        # their own function by schema-qualified name, which requires
        # USAGE on the schema to resolve, separately from the temporary
        # CREATE that lets the owner define the function in the first
        # place. CREATE must still read FALSE for all four function-owner
        # roles once bootstrap cleanup has run.
        with self._connect() as connection:
            connection.autocommit = True
            connection.execute('DROP ROLE IF EXISTS "test_unrelated_probe"')
            connection.execute('CREATE ROLE "test_unrelated_probe" NOLOGIN')
            try:
                for role, expected_usage, expected_create in [
                    ("api_tenant_data", True, False),
                    ("worker_tenant_data", True, False),
                    ("scheduler_tenant_data", True, False),
                    ("identity_function_owner", True, False),
                    ("worker_function_owner", True, False),
                    ("scheduler_function_owner", True, False),
                    ("callback_function_owner", True, False),
                    # P1-2 Phase H gap closure, 2026-09-17: callback_receiver
                    # needs USAGE to resolve resolve_and_record_callback_observation
                    # by its schema-qualified name; it is never granted
                    # CREATE (it holds exactly one privilege, EXECUTE on
                    # that one function).
                    ("callback_receiver", True, False),
                    ("test_unrelated_probe", False, False),
                ]:
                    usage = connection.execute(
                        "SELECT has_schema_privilege(%s, 'webguard_control', 'USAGE')", (role,)
                    ).fetchone()[0]
                    create = connection.execute(
                        "SELECT has_schema_privilege(%s, 'webguard_control', 'CREATE')", (role,)
                    ).fetchone()[0]
                    self.assertEqual(usage, expected_usage, f"{role} USAGE on webguard_control")
                    self.assertEqual(create, expected_create, f"{role} CREATE on webguard_control")
            finally:
                connection.execute('DROP ROLE IF EXISTS "test_unrelated_probe"')

    # -- Section 4 correction: request_fingerprint exact equivalence -------

    def test_enqueue_due_schedule_stores_supplied_fingerprint_unchanged(self) -> None:
        """The function must store p_request_fingerprint byte-for-byte,
        never compute or approximate it. Proven here by computing the
        REAL fingerprint via webguard_contracts.scan_jobs.ScanJobRequest
        (the exact current Python algorithm) for a given
        target/authorization_id/authorization_sha256/mode, then
        confirming the function's stored request_fingerprint column is
        an exact string match."""

        from webguard_contracts.scan_jobs import ScanJobMode, ScanJobRequest

        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            schedule_id, permit_id = self._seed_schedule_with_permit(
                connection, org_id, principal_id, auth_id, "fingerprint-test"
            )
            connection.commit()

            authorization_sha256 = "c" * 64
            request = ScanJobRequest(
                idempotency_key="fingerprint-equivalence-probe",
                target="https://example.com",
                authorization_id=auth_id,
                authorization_sha256=authorization_sha256,
                mode=ScanJobMode.SINGLE_PAGE,
                submitted_at=self.now,
            )
            expected_fingerprint = request.fingerprint

            result = connection.execute(
                "SELECT * FROM webguard_control.enqueue_due_schedule(%s, %s, %s, %s, %s, %s, %s)",
                (schedule_id, 0, authorization_sha256, permit_id, "d" * 64, self.now, expected_fingerprint),
            ).fetchone()
            connection.commit()
            self.assertEqual(result[0], "ok")
            new_job_id = str(result[5])

            stored_fingerprint = connection.execute(
                "SELECT request_fingerprint FROM scan_jobs WHERE job_id = %s", (new_job_id,)
            ).fetchone()[0]

        self.assertEqual(
            stored_fingerprint, expected_fingerprint,
            "the stored request_fingerprint must be byte-for-byte identical to Python's own "
            "ScanJobRequest.fingerprint, not a SQL-side approximation",
        )

    # -- Section 5 correction: blank worker_id is rejected ------------------

    def test_claim_next_job_rejects_blank_worker_id(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            self._insert_queued_job(connection, org_id, principal_id, auth_id, "blank-worker-test")
            connection.commit()
            for bad_worker_id in ("", "   ", None):
                with self.assertRaises(Exception) as ctx:
                    connection.execute(
                        "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                        (bad_worker_id, 30.0, self.now),
                    )
                connection.rollback()
                self.assertIn("job_worker_id_invalid", str(ctx.exception))

    def test_renew_lease_rejects_blank_worker_id(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "renew-blank-worker")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("legit-worker", 30.0, self.now),
            ).fetchone()
            connection.commit()
            lease_token = claimed[20]

            result = connection.execute(
                "SELECT * FROM webguard_control.renew_lease(%s, %s, %s, %s, %s::numeric)",
                (job_id, "  ", lease_token, self.now, 30.0),
            ).fetchone()
        self.assertEqual(result[0], "worker_id_invalid")

    def test_terminal_transition_rejects_blank_worker_id_when_lease_supplied(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "terminal-blank-worker")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("legit-worker-2", 30.0, self.now),
            ).fetchone()
            connection.commit()
            lease_token = claimed[20]

            result = connection.execute(
                "SELECT * FROM webguard_control.terminal_transition(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (job_id, "failed", self.now, "", lease_token, None, None, None, None, "x", "y", None, None),
            ).fetchone()
        self.assertEqual(result[0], "worker_id_invalid")

    # -- Section 5 correction: safety-receipt format validation -------------

    def test_terminal_transition_rejects_path_traversal_receipt_reference(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "receipt-traversal")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("receipt-worker-3", 30.0, self.now),
            ).fetchone()
            connection.commit()
            worker_id, lease_token = claimed[19], claimed[20]

            for bad_ref in ("/etc/passwd", "../../etc/passwd", "reports/../../etc/passwd", ""):
                result = connection.execute(
                    "SELECT * FROM webguard_control.terminal_transition"
                    "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (job_id, "failed", self.now, worker_id, lease_token, None, None, None, None,
                     None, None, bad_ref, "e" * 64),
                ).fetchone()
                self.assertEqual(result[0], "safety_receipt_reference_invalid", f"ref={bad_ref!r}")

    def test_terminal_transition_rejects_malformed_receipt_digest(self) -> None:
        with self._connect() as connection:
            org_id, principal_id = self._fresh_org_and_principal(connection)
            auth_id = self._assign_authorization(connection, org_id, principal_id)
            job_id = self._insert_queued_job(connection, org_id, principal_id, auth_id, "receipt-digest")
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM webguard_control.claim_next_job(%s, %s::numeric, %s)",
                ("receipt-worker-4", 30.0, self.now),
            ).fetchone()
            connection.commit()
            worker_id, lease_token = claimed[19], claimed[20]

            for bad_digest in ("short", "E" * 64, "g" * 64, "e" * 63):
                result = connection.execute(
                    "SELECT * FROM webguard_control.terminal_transition"
                    "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (job_id, "failed", self.now, worker_id, lease_token, None, None, None, None,
                     None, None, "reports/x.json", bad_digest),
                ).fetchone()
                self.assertEqual(result[0], "safety_receipt_digest_invalid", f"digest={bad_digest!r}")

    # -- Section 6 correction: callback result is a generic boolean, --------
    # -- never a distinguishing oracle ----------------------------------------

    def test_callback_result_is_a_plain_boolean_not_an_oracle(self) -> None:
        with self._connect() as connection:
            return_type = connection.execute(
                """
                SELECT pg_get_function_result(p.oid)
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'webguard_control'
                  AND p.proname = 'resolve_and_record_callback_observation'
                """
            ).fetchone()[0]
        self.assertEqual(
            return_type, "boolean",
            "the callback function must return a plain boolean, never a composite/table result "
            "that could expose a reason code distinguishing why a token was rejected",
        )


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class NonSuperuserOwnershipTransferTests(unittest.TestCase):
    """Section 3 correction: the accepted deployment model is a NON-
    SUPERUSER bootstrap actor (AWS RDS's own master user is
    NOSUPERUSER, the same reason Phase C/D/E never rely on
    BYPASSRLS). This proves the entire bootstrap chain -- schema
    migrations, roles, tenant ACL, function ACL, control functions --
    succeeds end to end when run by a disposable actor with exactly
    that attribute shape (NOSUPERUSER, CREATEROLE, CREATEDB, LOGIN),
    using ONLY the existing flat role graph (no Phase C change, no new
    bootstrap role)."""

    @classmethod
    def setUpClass(cls) -> None:
        import psycopg
        from urllib.parse import urlsplit, urlunsplit

        cls._admin_dsn = POSTGRES_TEST_DSN
        parts = urlsplit(POSTGRES_TEST_DSN)
        cls._host_port = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
        cls._actor_user = "test_rds_master_actor"
        cls._actor_password = "test-actor-password-1"
        cls._actor_db = "test_rds_sim_db"

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._actor_db}"')
            admin.execute(f'DROP ROLE IF EXISTS "{cls._actor_user}"')
            # Phase C's seven roles are cluster-wide, not per-database.
            # If another test class already created them (in a
            # different database on this same Postgres server), this
            # class's own CREATE ROLE below would be a silent no-op,
            # and this actor would never get PG16's automatic
            # admin-option grant on them. Start from a clean slate.
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')
            admin.execute(
                f'CREATE ROLE "{cls._actor_user}" LOGIN NOSUPERUSER CREATEROLE CREATEDB '
                f"PASSWORD '{cls._actor_password}'"
            )
            admin.execute(f'CREATE DATABASE "{cls._actor_db}" OWNER "{cls._actor_user}"')

        netloc = f"{cls._actor_user}:{cls._actor_password}@{cls._host_port}"
        cls._actor_dsn = urlunsplit(("postgresql", netloc, f"/{cls._actor_db}", "", ""))

    @classmethod
    def tearDownClass(cls) -> None:
        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            # Drop the database first so every privilege the seven
            # roles hold inside it goes away, then the roles themselves
            # can be dropped cleanly from the shared cluster, leaving
            # nothing for the next test class to collide with.
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._actor_db}"')
            admin.execute(f'DROP ROLE IF EXISTS "{cls._actor_user}"')
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

    @staticmethod
    def _capture_metadata(connection) -> dict:
        """Complete Phase-F metadata snapshot: signatures, owners,
        prosecdef, proconfig, EXECUTE ACL (proacl), for all functions
        in webguard_control, plus the schema's own ACL and the four
        function-owner roles' CREATE state on it."""

        functions = connection.execute(
            """
            SELECT p.proname, pg_get_function_identity_arguments(p.oid), p.prosecdef,
                   pg_get_userbyid(p.proowner), p.proconfig, p.proacl::text
            FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'webguard_control'
            ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)
            """
        ).fetchall()
        schema_acl = connection.execute(
            "SELECT nspacl::text FROM pg_namespace WHERE nspname = 'webguard_control'"
        ).fetchone()[0]
        owner_create = {
            role: connection.execute(
                "SELECT has_schema_privilege(%s, 'webguard_control', 'CREATE')", (role,)
            ).fetchone()[0]
            for role in FUNCTION_OWNER_ROLES
        }
        return {"functions": functions, "schema_acl": schema_acl, "owner_create": owner_create}

    def test_full_bootstrap_first_and_second_run_under_non_superuser_actor(self) -> None:
        import subprocess
        import sys

        import psycopg

        repo_root = Path(__file__).resolve().parent.parent.parent
        env = dict(os.environ)
        env["WEBGUARD_DATABASE_URL"] = self._actor_dsn
        migration_result = subprocess.run(
            [sys.executable, str(repo_root / "scripts" / "run-postgres-migrations.py")],
            env=env, capture_output=True, text=True, cwd=repo_root,
        )
        self.assertEqual(
            migration_result.returncode, 0,
            f"schema migrations must succeed under the non-superuser actor:\n{migration_result.stderr}",
        )

        with psycopg.connect(self._actor_dsn) as actor_connection:
            actor_connection.execute(ROLES_SQL_PATH.read_text(encoding="utf-8"))
            actor_connection.commit()
            actor_connection.execute(TENANT_ACL_SQL_PATH.read_text(encoding="utf-8"))
            actor_connection.commit()
            actor_connection.execute(FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8"))
            actor_connection.commit()

        # -- FIRST run -----------------------------------------------------
        control_functions_sql = CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8")
        with psycopg.connect(self._actor_dsn) as actor_connection:
            actor_connection.execute(control_functions_sql)
            actor_connection.commit()

        with psycopg.connect(self._actor_dsn) as actor_connection:
            before = self._capture_metadata(actor_connection)

        self.assertEqual(len(before["functions"]), 19, "expected exactly 19 functions after the first run")
        # row shape: (proname, args, prosecdef, owner, proconfig, proacl)
        owners_by_name = {row[0]: row[3] for row in before["functions"]}
        for name, (expected_owner, _grantee, _args) in EXPECTED_FUNCTIONS.items():
            self.assertEqual(
                owners_by_name[name], expected_owner,
                f"{name} must be owned by {expected_owner} under the non-superuser bootstrap actor",
            )
        for role in FUNCTION_OWNER_ROLES:
            self.assertFalse(
                before["owner_create"][role],
                f"{role} must not retain CREATE on webguard_control after the first run",
            )

        # -- SECOND run, same actor, no superuser intervention --------------
        with psycopg.connect(self._actor_dsn) as actor_connection:
            actor_connection.execute(control_functions_sql)
            actor_connection.commit()

        with psycopg.connect(self._actor_dsn) as actor_connection:
            after = self._capture_metadata(actor_connection)

        self.assertEqual(
            before, after,
            "a second control-functions bootstrap run by the SAME non-superuser actor must leave "
            "function metadata, schema ACL, and function-owner CREATE state byte-identical",
        )
        self.assertEqual(len(after["functions"]), 19, "second run must not create duplicate overloads")

        # -- Section 6/8/9 spot checks under the non-superuser actor --------
        with psycopg.connect(self._actor_dsn) as actor_connection:
            actor_connection.autocommit = True
            actor_connection.execute('DROP ROLE IF EXISTS "test_nonsuper_probe"')
            actor_connection.execute('CREATE ROLE "test_nonsuper_probe" NOLOGIN')
            try:
                for name, (_owner, grantee, args) in EXPECTED_FUNCTIONS.items():
                    bare = ", ".join(seg.split(" ", 1)[1] for seg in args.split(", "))
                    signature = f"webguard_control.{name}({bare})"
                    no_grant = actor_connection.execute(
                        "SELECT has_function_privilege('test_nonsuper_probe', %s, 'EXECUTE')", (signature,)
                    ).fetchone()[0]
                    self.assertFalse(no_grant, f"PUBLIC/ungranted must not EXECUTE {name}")
                    if grantee is not None:
                        granted = actor_connection.execute(
                            "SELECT has_function_privilege(%s, %s, 'EXECUTE')", (grantee, signature)
                        ).fetchone()[0]
                        self.assertTrue(granted, f"{grantee} must be able to EXECUTE {name}")

                for role, expected in [
                    ("api_tenant_data", True), ("worker_tenant_data", True),
                    ("scheduler_tenant_data", True), ("test_nonsuper_probe", False),
                ]:
                    usage = actor_connection.execute(
                        "SELECT has_schema_privilege(%s, 'webguard_control', 'USAGE')", (role,)
                    ).fetchone()[0]
                    self.assertEqual(usage, expected, f"{role} USAGE on webguard_control")
            finally:
                actor_connection.execute('DROP ROLE IF EXISTS "test_nonsuper_probe"')

        # -- Section 3: final role-membership state --------------------------
        # PG16 keeps admin/inherit/set as three independent options per
        # (role, member, grantor) row in pg_auth_members, not one row per
        # (role, member) pair. The auto-admin row Phase C's CREATE ROLE
        # conferred and the self-grant row this file's own ownership-
        # transfer mechanics created (function-owner roles only) have
        # different grantors, so both rows persist side by side. Do not
        # collapse them into a dict keyed only by role name -- a second
        # row for the same role silently overwrites the first that way,
        # which is exactly how the INHERIT leak this test now guards
        # against went unnoticed the first time through.
        with psycopg.connect(self._actor_dsn) as actor_connection:
            membership = actor_connection.execute(
                """
                SELECT r.rolname, m.grantor::regrole::text, m.admin_option, m.inherit_option, m.set_option
                FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                JOIN pg_roles g ON g.oid = m.member
                WHERE g.rolname = %s
                ORDER BY r.rolname, m.grantor
                """,
                (self._actor_user,),
            ).fetchall()

        rows_by_role: dict[str, list[tuple[str, bool, bool, bool]]] = {}
        for rolname, grantor, admin, inherit, set_opt in membership:
            rows_by_role.setdefault(rolname, []).append((grantor, admin, inherit, set_opt))

        self.assertEqual(
            set(rows_by_role), set(ALL_BOOTSTRAP_ROLES),
            "the bootstrap actor must hold at least one membership row for each of the seven "
            "Phase-C roles",
        )

        for role in TENANT_DATA_ROLES:
            self.assertEqual(
                len(rows_by_role[role]), 1,
                f"{role} was never touched by Phase F's ownership-transfer mechanics, so it must "
                f"still carry exactly the one auto-admin row Phase C's CREATE ROLE conferred, "
                f"got {rows_by_role[role]}",
            )
            self.assertEqual(
                rows_by_role[role][0][1:], (True, False, False),
                f"{role}: auto-admin row must be ADMIN=True/INHERIT=False/SET=False, "
                f"got {rows_by_role[role]}",
            )

        for role in FUNCTION_OWNER_ROLES:
            rows = rows_by_role[role]
            self.assertEqual(
                len(rows), 2,
                f"{role} must carry exactly two rows after Phase F: the original auto-admin row "
                f"and this file's own self-granted row, got {rows}",
            )
            auto_admin_rows = [row for row in rows if row[1] is True]
            self_grant_rows = [row for row in rows if row[1] is False]
            self.assertEqual(
                len(auto_admin_rows), 1,
                f"{role}: expected exactly one row with admin_option=True (the auto-admin row "
                f"PG16's CREATEROLE conferred), got {rows}",
            )
            self.assertEqual(
                auto_admin_rows[0][1:], (True, False, False),
                f"{role}: auto-admin row must be ADMIN=True/INHERIT=False/SET=False, got {rows}",
            )
            self.assertEqual(
                len(self_grant_rows), 1,
                f"{role}: expected exactly one self-granted row (admin_option=False), got {rows}",
            )
            self.assertEqual(
                self_grant_rows[0][1:], (False, False, False),
                f"{role}: self-granted row must be ADMIN=False/INHERIT=False/SET=False after "
                f"cleanup. INHERIT=True here would mean the bootstrap actor still standingly "
                f"inherits {role}'s privileges -- the exact leak the file's WITH INHERIT FALSE "
                f"grant (claimed before WITH SET TRUE) exists to prevent. Got {rows}",
            )

        # Effective (aggregate) capability is the security-relevant view: a
        # role has a capability if ANY membership row for that pair grants
        # it, so bool_or across every row is what actually matters, not a
        # single row read in isolation.
        with psycopg.connect(self._actor_dsn) as actor_connection:
            aggregate = actor_connection.execute(
                """
                SELECT r.rolname, bool_or(m.admin_option), bool_or(m.inherit_option), bool_or(m.set_option)
                FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                JOIN pg_roles g ON g.oid = m.member
                WHERE g.rolname = %s
                GROUP BY r.rolname
                """,
                (self._actor_user,),
            ).fetchall()
        aggregate_by_role = {row[0]: (row[1], row[2], row[3]) for row in aggregate}
        for role in ALL_BOOTSTRAP_ROLES:
            admin, inherit, set_opt = aggregate_by_role[role]
            self.assertTrue(admin, f"{role}: expected effective admin_option=True (PG16 CREATEROLE default)")
            self.assertFalse(
                inherit,
                f"{role}: bootstrap actor must not effectively inherit runtime/function-owner privileges",
            )
            self.assertFalse(
                set_opt,
                f"{role}: bootstrap actor must not effectively retain standing SET access after "
                "Phase F's own cleanup revoked it",
            )

        # The seven Phase-C roles remain mutually flat (none is a member of
        # another), and no runtime/capability role holds ADMIN OPTION on
        # another -- Phase F must not have introduced any such relationship.
        with psycopg.connect(self._actor_dsn) as actor_connection:
            cross_membership = actor_connection.execute(
                """
                SELECT count(*)
                FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                JOIN pg_roles g ON g.oid = m.member
                WHERE g.rolname = ANY(%s) AND r.rolname = ANY(%s)
                """,
                (ALL_BOOTSTRAP_ROLES, ALL_BOOTSTRAP_ROLES),
            ).fetchone()[0]
            self.assertEqual(cross_membership, 0, "the seven Phase-C roles must remain mutually flat")

            admin_on_another = actor_connection.execute(
                """
                SELECT r.rolname, g.rolname
                FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                JOIN pg_roles g ON g.oid = m.member
                WHERE m.admin_option = true
                  AND g.rolname != %s
                  AND r.rolname = ANY(%s)
                """,
                (self._actor_user, ALL_BOOTSTRAP_ROLES),
            ).fetchall()
            self.assertEqual(
                admin_on_another, [],
                "no runtime/capability role may hold ADMIN OPTION on another Phase-C role",
            )

        # No runtime role received ADMIN OPTION on anything, and every
        # function-owner role remains NOLOGIN, confirming Phase F
        # granted no new capability to any role other than the
        # temporary, already-reversed CREATE it gave itself above.
        with psycopg.connect(self._actor_dsn) as actor_connection:
            for role in FUNCTION_OWNER_ROLES:
                can_login = actor_connection.execute(
                    "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (role,)
                ).fetchone()[0]
                self.assertFalse(can_login, f"{role} must remain NOLOGIN")

        # -- Section 7: effective privilege test, not just catalog flags ----
        # Grant a harmless, disposable privilege to identity_function_owner
        # only, then prove the bootstrap actor cannot use it through
        # inheritance and cannot SET ROLE to it. This proves INHERIT=False
        # and SET=False are effective behavior, not only catalog metadata
        # that happens to read correctly.
        #
        # The probe schema must be created by the ADMIN connection, not the
        # actor: a schema's OWNER always has every privilege on it
        # unconditionally (has_schema_privilege returns true for the owner
        # regardless of INHERIT), so if the actor created and therefore
        # owned this schema, the CREATE check below would trivially pass
        # for a reason that has nothing to do with the INHERIT fix. It
        # must also land in the actor's OWN database (self._actor_db), not
        # whatever database self._admin_dsn (== POSTGRES_TEST_DSN) points
        # at by default -- those are two different databases.
        from urllib.parse import urlsplit as _urlsplit, urlunsplit as _urlunsplit

        admin_parts = _urlsplit(self._admin_dsn)
        admin_into_actor_db_dsn = _urlunsplit(
            (admin_parts.scheme, admin_parts.netloc, f"/{self._actor_db}", "", "")
        )
        with psycopg.connect(admin_into_actor_db_dsn) as admin_connection:
            admin_connection.autocommit = True
            admin_connection.execute("DROP SCHEMA IF EXISTS test_inherit_leak_probe")
            admin_connection.execute("CREATE SCHEMA test_inherit_leak_probe")
            admin_connection.execute(
                "GRANT CREATE ON SCHEMA test_inherit_leak_probe TO identity_function_owner"
            )
        try:
            with psycopg.connect(self._actor_dsn) as actor_connection:
                inherited = actor_connection.execute(
                    "SELECT has_schema_privilege(%s, 'test_inherit_leak_probe', 'CREATE')",
                    (self._actor_user,),
                ).fetchone()[0]
                self.assertFalse(
                    inherited,
                    "the bootstrap actor must not inherit identity_function_owner's CREATE "
                    "privilege on an unrelated schema",
                )

                with self.assertRaises(Exception) as ctx:
                    actor_connection.execute("CREATE TABLE test_inherit_leak_probe.leak_check (x int)")
                self.assertIn("permission denied", str(ctx.exception).lower())

            with psycopg.connect(self._actor_dsn) as actor_connection:
                with self.assertRaises(Exception) as ctx:
                    actor_connection.execute("SET ROLE identity_function_owner")
                self.assertIn("permission denied", str(ctx.exception).lower())
        finally:
            with psycopg.connect(admin_into_actor_db_dsn) as admin_connection:
                admin_connection.autocommit = True
                admin_connection.execute("DROP SCHEMA IF EXISTS test_inherit_leak_probe CASCADE")

    def test_candidate_fix_repairs_a_database_left_in_the_pre_fix_buggy_state(self) -> None:
        """Section 9: reproduces the exact leaked shape a database would be
        left in by the ORIGINAL (pre-fix) Phase-F file (self-grant row
        ADMIN=False/INHERIT=True/SET=False), on a disposable role, then
        proves the corrected WITH INHERIT FALSE / WITH SET TRUE / REVOKE
        SET OPTION FOR sequence converges it to the safe end state. This
        is what makes the fix a genuine repair for a database an earlier,
        un-patched Phase-F run already touched, not just a guard against
        the leak on a fresh bootstrap."""
        import psycopg

        with psycopg.connect(self._actor_dsn) as actor_connection:
            actor_connection.autocommit = True
            actor_connection.execute('DROP ROLE IF EXISTS "test_buggy_state_sim"')
            actor_connection.execute('CREATE ROLE "test_buggy_state_sim" NOLOGIN')
            try:
                # Reproduce the leak using the OLD (pre-fix) sequence: a
                # bare WITH SET TRUE grant, then REVOKE SET OPTION FOR.
                actor_connection.execute(
                    'GRANT "test_buggy_state_sim" TO CURRENT_USER WITH SET TRUE'
                )
                actor_connection.execute(
                    'REVOKE SET OPTION FOR "test_buggy_state_sim" FROM CURRENT_USER'
                )

                buggy_rows = actor_connection.execute(
                    """
                    SELECT m.grantor::regrole::text, m.admin_option, m.inherit_option, m.set_option
                    FROM pg_auth_members m
                    JOIN pg_roles r ON r.oid = m.roleid
                    JOIN pg_roles g ON g.oid = m.member
                    WHERE g.rolname = %s AND r.rolname = 'test_buggy_state_sim'
                    ORDER BY m.grantor
                    """,
                    (self._actor_user,),
                ).fetchall()
                self_grant_before = [row for row in buggy_rows if row[1] is False]
                self.assertEqual(
                    len(self_grant_before), 1,
                    f"setup must reproduce exactly one leaked self-grant row, got {buggy_rows}",
                )
                self.assertEqual(
                    self_grant_before[0][1:], (False, True, False),
                    f"setup must reproduce the exact pre-fix leaked shape "
                    f"(ADMIN=False/INHERIT=True/SET=False), got {buggy_rows}",
                )

                # Apply the corrected sequence.
                actor_connection.execute(
                    'GRANT "test_buggy_state_sim" TO CURRENT_USER WITH INHERIT FALSE'
                )
                actor_connection.execute(
                    'GRANT "test_buggy_state_sim" TO CURRENT_USER WITH SET TRUE'
                )
                actor_connection.execute(
                    'REVOKE SET OPTION FOR "test_buggy_state_sim" FROM CURRENT_USER'
                )

                repaired_rows = actor_connection.execute(
                    """
                    SELECT m.grantor::regrole::text, m.admin_option, m.inherit_option, m.set_option
                    FROM pg_auth_members m
                    JOIN pg_roles r ON r.oid = m.roleid
                    JOIN pg_roles g ON g.oid = m.member
                    WHERE g.rolname = %s AND r.rolname = 'test_buggy_state_sim'
                    ORDER BY m.grantor
                    """,
                    (self._actor_user,),
                ).fetchall()
                self_grant_after = [row for row in repaired_rows if row[1] is False]
                self.assertEqual(
                    len(self_grant_after), 1,
                    f"repair must not create a third membership row, got {repaired_rows}",
                )
                self.assertEqual(
                    self_grant_after[0][1:], (False, False, False),
                    f"repaired self-grant row must be ADMIN=False/INHERIT=False/SET=False, "
                    f"got {repaired_rows}",
                )

                admin, inherit, set_opt = actor_connection.execute(
                    """
                    SELECT bool_or(m.admin_option), bool_or(m.inherit_option), bool_or(m.set_option)
                    FROM pg_auth_members m
                    JOIN pg_roles r ON r.oid = m.roleid
                    JOIN pg_roles g ON g.oid = m.member
                    WHERE g.rolname = %s AND r.rolname = 'test_buggy_state_sim'
                    """,
                    (self._actor_user,),
                ).fetchone()
                self.assertTrue(admin, "effective admin_option must remain True after repair")
                self.assertFalse(inherit, "effective inherit_option must be False after repair")
                self.assertFalse(set_opt, "effective set_option must be False after repair")
            finally:
                actor_connection.execute('DROP ROLE IF EXISTS "test_buggy_state_sim"')


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class TemporaryPrivilegeFailureInjectionTests(unittest.TestCase):
    """Section 5: proves the temporary SET-option/CREATE-on-schema
    window this file's ownership-transfer mechanics claim can never be
    partially committed. Starts from a clean Phase A-E state (fresh
    non-superuser actor and database, migrations + roles + tenant ACL
    + function ACL applied normally), then executes a TEST-ONLY
    modified copy of tenant_isolation_control_functions.sql with a
    deliberately failing statement injected after the temporary SET
    option and CREATE grant have been claimed but before the file's
    own cleanup runs. The production SQL file itself is never
    modified; only an in-memory string built from it is."""

    @classmethod
    def setUpClass(cls) -> None:
        import psycopg
        from urllib.parse import urlsplit, urlunsplit

        cls._admin_dsn = POSTGRES_TEST_DSN
        parts = urlsplit(POSTGRES_TEST_DSN)
        cls._host_port = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
        cls._actor_user = "test_rds_failure_actor"
        cls._actor_password = "test-actor-password-2"
        cls._actor_db = "test_rds_failure_db"

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._actor_db}"')
            admin.execute(f'DROP ROLE IF EXISTS "{cls._actor_user}"')
            # Phase C's seven roles are cluster-wide, not per-database.
            # If another test class already created them (in a
            # different database on this same Postgres server), this
            # class's own CREATE ROLE below would be a silent no-op,
            # and this actor would never get PG16's automatic
            # admin-option grant on them. Start from a clean slate.
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')
            admin.execute(
                f'CREATE ROLE "{cls._actor_user}" LOGIN NOSUPERUSER CREATEROLE CREATEDB '
                f"PASSWORD '{cls._actor_password}'"
            )
            admin.execute(f'CREATE DATABASE "{cls._actor_db}" OWNER "{cls._actor_user}"')

        netloc = f"{cls._actor_user}:{cls._actor_password}@{cls._host_port}"
        cls._actor_dsn = urlunsplit(("postgresql", netloc, f"/{cls._actor_db}", "", ""))

    @classmethod
    def tearDownClass(cls) -> None:
        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            # Drop the database first so every privilege the seven
            # roles hold inside it goes away, then the roles themselves
            # can be dropped cleanly from the shared cluster, leaving
            # nothing for the next test class to collide with.
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._actor_db}"')
            admin.execute(f'DROP ROLE IF EXISTS "{cls._actor_user}"')
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

    def test_injected_failure_before_cleanup_rolls_back_everything(self) -> None:
        import subprocess
        import sys

        import psycopg

        repo_root = Path(__file__).resolve().parent.parent.parent
        env = dict(os.environ)
        env["WEBGUARD_DATABASE_URL"] = self._actor_dsn
        migration_result = subprocess.run(
            [sys.executable, str(repo_root / "scripts" / "run-postgres-migrations.py")],
            env=env, capture_output=True, text=True, cwd=repo_root,
        )
        self.assertEqual(migration_result.returncode, 0, migration_result.stderr)

        with psycopg.connect(self._actor_dsn) as actor_connection:
            actor_connection.execute(ROLES_SQL_PATH.read_text(encoding="utf-8"))
            actor_connection.commit()
            actor_connection.execute(TENANT_ACL_SQL_PATH.read_text(encoding="utf-8"))
            actor_connection.commit()
            actor_connection.execute(FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8"))
            actor_connection.commit()

        with psycopg.connect(self._actor_dsn) as actor_connection:
            pre_transaction_membership = actor_connection.execute(
                """
                SELECT r.rolname, m.grantor::regrole::text, m.admin_option, m.inherit_option, m.set_option
                FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                JOIN pg_roles g ON g.oid = m.member
                WHERE g.rolname = %s AND r.rolname = ANY(%s)
                ORDER BY r.rolname, m.grantor
                """,
                (self._actor_user, FUNCTION_OWNER_ROLES),
            ).fetchall()

        real_sql = CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8")
        # Injection point: immediately before the IDENTITY block's own
        # RESET ROLE (its first occurrence in the file) -- after SET ROLE
        # identity_function_owner and after all four of that block's
        # CREATE OR REPLACE FUNCTION statements have run, but before
        # RESET ROLE and that block's own CREATE/SET cleanup.
        set_role_index = real_sql.index("SET ROLE identity_function_owner;")
        marker = "RESET ROLE;"
        marker_index = real_sql.index(marker, set_role_index)
        self.assertGreater(
            marker_index, set_role_index,
            "the expected injection point (the IDENTITY block's own RESET ROLE, after its SET ROLE) "
            "was not found; the production file's structure may have changed",
        )
        injected_failure = "\nSELECT 1 / 0; -- TEST-ONLY injected failure, never written to production SQL\n"
        broken_sql = real_sql[:marker_index] + injected_failure + real_sql[marker_index:]

        with psycopg.connect(self._actor_dsn) as actor_connection:
            with self.assertRaises(Exception) as ctx:
                actor_connection.execute(broken_sql)
            self.assertIn("division by zero", str(ctx.exception).lower())
            actor_connection.rollback()

        with psycopg.connect(self._actor_dsn) as actor_connection:
            # Check schema existence FIRST: has_schema_privilege raises
            # InvalidSchemaName for a schema that does not exist at all
            # (rather than returning false), and since CREATE SCHEMA IF
            # NOT EXISTS webguard_control is itself inside the rolled-
            # back transaction, the schema must not exist after rollback.
            schema_exists = actor_connection.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'webguard_control')"
            ).fetchone()[0]
            self.assertFalse(
                schema_exists,
                "the webguard_control schema itself was created inside the same rolled-back "
                "transaction (this file's CREATE SCHEMA IF NOT EXISTS is now inside the BEGIN/COMMIT "
                "wrapper), so it must not exist either -- confirming no partial schema ACL broadening "
                "of any kind survived",
            )

            function_count = actor_connection.execute(
                """
                SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'webguard_control'
                """
            ).fetchone()[0]
            self.assertEqual(
                function_count, 0,
                "the injected failure happened after the IDENTITY block's four CREATE OR REPLACE "
                "FUNCTION statements had already run (worker/scheduler/callback never got a chance "
                "to run at all, since they come later in the file), so a correct rollback of the "
                "whole transaction leaves ZERO functions behind, not a partially-populated schema",
            )

            # Only meaningful if the schema somehow survived (it must not,
            # per the assertion above); has_schema_privilege would raise
            # otherwise. Defense in depth, not the primary check.
            if schema_exists:
                for role in FUNCTION_OWNER_ROLES:
                    has_create = actor_connection.execute(
                        "SELECT has_schema_privilege(%s, 'webguard_control', 'CREATE')", (role,)
                    ).fetchone()[0]
                    self.assertFalse(
                        has_create,
                        f"{role} must not retain CREATE on webguard_control after the injected failure "
                        "rolled back the whole transaction",
                    )

            post_rollback_membership = actor_connection.execute(
                """
                SELECT r.rolname, m.grantor::regrole::text, m.admin_option, m.inherit_option, m.set_option
                FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                JOIN pg_roles g ON g.oid = m.member
                WHERE g.rolname = %s AND r.rolname = ANY(%s)
                ORDER BY r.rolname, m.grantor
                """,
                (self._actor_user, FUNCTION_OWNER_ROLES),
            ).fetchall()
            self.assertEqual(
                post_rollback_membership, pre_transaction_membership,
                "the candidate fix's WITH INHERIT FALSE and WITH SET TRUE self-grants both ran "
                "inside this same failing transaction, so a correct rollback must restore membership "
                "state to exactly what it was before the transaction started, not merely clear the "
                "SET option on a row that still exists",
            )
            for role in FUNCTION_OWNER_ROLES:
                self_granted_rows = [
                    row for row in post_rollback_membership
                    if row[0] == role and row[1] == self._actor_user
                ]
                self.assertEqual(
                    self_granted_rows, [],
                    f"{role} must not carry a self-granted pg_auth_members row at all after the "
                    "injected failure rolled back the whole transaction -- both the WITH INHERIT "
                    "FALSE and WITH SET TRUE grants that created it ran inside this same transaction",
                )

            public_execute_count = actor_connection.execute(
                """
                SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'webguard_control'
                  AND has_function_privilege('public', p.oid, 'EXECUTE')
                """
            ).fetchone()[0]
            self.assertEqual(public_execute_count, 0, "no PUBLIC EXECUTE broadening may survive a rollback")


if __name__ == "__main__":
    unittest.main()
