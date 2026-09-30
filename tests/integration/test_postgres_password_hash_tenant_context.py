"""P1-2 Phase H follow-up (2026-09-18): set_password_hash's own tenant-
context gap, found while building test_postgres_phase_h_gap_closure.py
and flagged there as out of scope for that pass. This file closes it
and proves the fix through the real service layer, not by seeding
credentials directly.

Root cause: set_password_hash ran under role_scoped_connection
(API_TENANT_DATA_ROLE) with no organization_id and no tenant context
set at all. password_credentials' own INSERT/UPDATE RLS policies
(tenant_isolation_rls_policies.sql) are both predicated on
EXISTS(... principals ... organization_id = webguard_current_tenant()),
since the table carries no organization_id column of its own, so
with no tenant context set, every one of set_password_hash's five real
callers (register_account, login's rehash path, change_password,
confirm_password_reset, accept_invitation) would fail closed with
"new row violates row-level security policy" the moment RLS is
force-enabled anywhere real, not merely against the disposable database
this file builds.

The fix (postgres_identity.py, service.py): set_password_hash now takes
organization_id as a required parameter and uses tenant_connection
instead of role_scoped_connection. Every one of the five call sites
already had a server-resolved organization_id in scope before this fix
(the just-created Organization in register_account; the Principal
login already fetched by email; the authenticated AuthContext in
change_password; the IdentityTokenRecord consume_identity_token already
returned in confirm_password_reset/accept_invitation): none of them
needed a new, separately-trusted lookup to supply it.

This file proves that fix two ways:

1. Through the real service layer (WebGuardJobService, via
   webguard_production_harness.run_production_stack, the same real
   production component graph, real PostgreSQL, real mail transport
   the browser E2E suite and webguard_e2e_server.py already use),
   against a disposable database with the full 6-file bootstrap chain
   applied (including tenant_isolation_runtime_grant.sql, so "webguard"
   can actually SET LOCAL ROLE the way a real deployment's one pool
   does. test_postgres_phase_h_gap_closure.py's own bootstrap
   deliberately skips that file, since it authenticates test callers
   directly as each tenant-data role instead) and RLS ENABLED and
   FORCED on every tenant-owned table. Registration, login, password
   change, and password-reset/invitation-acceptance through legitimately
   issued tokens (read from the real mail transport's own sent-message
   list, never fabricated) all exercise set_password_hash through this
   exact path.
2. Directly against PostgresIdentityRepository, for the one property
   the service layer structurally cannot be made to violate (every
   service call site already derives organization_id from
   already-trusted data, so there is no service-level request that
   could ever supply a mismatched one): proving RLS itself, not just
   the Python call sites, rejects a mismatched organization_id. That is
   what makes this a genuine defense-in-depth property rather than a
   fact about today's five call sites alone.

Requires a real database (WEBGUARD_RUN_INTEGRATION=1 and a reachable
WEBGUARD_POSTGRES_TEST_DSN) with a connecting role holding CREATE ROLE
and CREATE DATABASE privilege, exactly like every other Postgres
integration test in this suite.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# webguard_production_harness.py is a plain sibling file in this
# directory, never pip-installed (unlike webguard_api/webguard_contracts,
# which CI's install-locked-dependencies.sh installs as real packages).
# `python -m unittest tests.integration.test_postgres_password_hash_tenant_context`
# from the repo root does not put this directory on sys.path, so the
# bare `from webguard_production_harness import ...` import inside
# _stack() below would fail in CI (though not in a local run that
# happens to already have this directory on PYTHONPATH). Mirrors the
# identical fix webguard_e2e_server.py's own header already uses for
# the same import.
sys.path.insert(0, str(Path(__file__).resolve().parent))

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"
RLS_POLICIES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_rls_policies.sql"
RUNTIME_GRANT_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_runtime_grant.sql"

ALL_BOOTSTRAP_ROLES = (
    "api_tenant_data", "worker_tenant_data", "scheduler_tenant_data",
    "identity_function_owner", "worker_function_owner", "scheduler_function_owner",
    "callback_function_owner", "callback_receiver",
)

# Same table list as test_postgres_phase_h_gap_closure.py / test_postgres_rls_policies.py.
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

_TOKEN_LINK_RE = re.compile(r"token=([A-Za-z0-9_.\-]+)")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _extract_token(body: str) -> str:
    match = _TOKEN_LINK_RE.search(body)
    assert match, f"no token found in mail body: {body!r}"
    return match.group(1)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class SetPasswordHashTenantContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import psycopg

        cls._admin_dsn = POSTGRES_TEST_DSN
        parts = urlsplit(POSTGRES_TEST_DSN)
        cls._host_port = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
        cls._db_name = "test_password_hash_tenant_context_db"

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

        import subprocess

        repo_root = Path(__file__).resolve().parent.parent.parent
        env = dict(os.environ)
        env["WEBGUARD_DATABASE_URL"] = cls._db_dsn
        migration_result = subprocess.run(
            [sys.executable, str(repo_root / "scripts" / "run-postgres-migrations.py")],
            env=env, capture_output=True, text=True, cwd=repo_root,
        )
        assert migration_result.returncode == 0, migration_result.stderr

        with psycopg.connect(cls._db_dsn) as connection:
            # Full six-file chain, including the runtime grant this
            # file's own module docstring explains is required here
            # (unlike test_postgres_phase_h_gap_closure.py's dedicated-
            # per-role-DSN approach): run_production_stack authenticates
            # as "webguard" and relies on SET LOCAL ROLE internally,
            # exactly like a real deployment's one pool does.
            for path in (
                ROLES_SQL_PATH, TENANT_ACL_SQL_PATH, FUNCTION_ACL_SQL_PATH,
                CONTROL_FUNCTIONS_SQL_PATH, RLS_POLICIES_SQL_PATH, RUNTIME_GRANT_SQL_PATH,
            ):
                connection.execute(path.read_text(encoding="utf-8"))
                connection.commit()

        with psycopg.connect(cls._db_dsn, autocommit=True) as connection:
            for table in RLS_TARGET_TABLES:
                connection.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
                connection.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")

    @classmethod
    def tearDownClass(cls) -> None:
        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

    # -- helpers ---------------------------------------------------------

    def _stack(self, **kwargs):
        from webguard_production_harness import run_production_stack

        return run_production_stack(self._db_dsn, **kwargs)

    def _sent_bodies_to(self, stack, email: str) -> list[str]:
        return [
            message.get("TextBody", "")
            for message in stack.mail_transport.sent
            if message.get("To") == email
        ]

    # -- legitimate flows, through the real service layer ---------------

    def test_registration_login_and_change_password_succeed_under_forced_rls(self) -> None:
        """gap: register_account's and change_password's own
        set_password_hash calls, under api_tenant_data, with
        password_credentials' RLS policies FORCED. Before the fix,
        register_account itself would have failed closed with "new row
        violates row-level security policy" the instant it tried to
        persist the owner's own password: there would be no account
        to log into at all."""

        with self._stack() as stack:
            service = stack.components.service
            email = f"owner-{uuid.uuid4().hex[:8]}@webguard-dev.invalid"
            context, _issued = service.register_account(
                {
                    "organization_name": f"Tenant Context Org {uuid.uuid4().hex[:6]}",
                    "display_name": "Register Flow Owner",
                    "email": email,
                    "password": "register-flow-password-123",
                },
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            self.assertEqual(context.principal_name, "Register Flow Owner")

            login_context, _login_issued = service.login(
                {"email": email, "password": "register-flow-password-123"},
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            self.assertEqual(login_context.principal_id, context.principal_id)

            service.change_password(
                login_context,
                {"current_password": "register-flow-password-123", "new_password": "register-flow-password-456"},
                request_id=str(uuid.uuid4()),
            )

            # The new password works; the old one no longer does. Both
            # routed through the same, now tenant-scoped, set_password_hash.
            relogin_context, _ = service.login(
                {"email": email, "password": "register-flow-password-456"},
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            self.assertEqual(relogin_context.principal_id, context.principal_id)
            with self.assertRaises(Exception):
                service.login(
                    {"email": email, "password": "register-flow-password-123"},
                    request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
                )

    def test_password_reset_via_legitimate_mail_sink_succeeds_under_forced_rls(self) -> None:
        """gap: confirm_password_reset's own set_password_hash call.
        Uses the actual token the real mail transport captured for this
        request, never a token constructed or seeded by this test."""

        with self._stack() as stack:
            service = stack.components.service
            email = f"reset-{uuid.uuid4().hex[:8]}@webguard-dev.invalid"
            service.register_account(
                {
                    "organization_name": f"Reset Flow Org {uuid.uuid4().hex[:6]}",
                    "display_name": "Reset Flow Owner",
                    "email": email,
                    "password": "reset-flow-password-123",
                },
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            service.request_password_reset(
                {"email": email}, request_id=str(uuid.uuid4()), ip_address="127.0.0.1",
            )
            bodies = self._sent_bodies_to(stack, email)
            reset_bodies = [b for b in bodies if "reset" in b.lower()]
            self.assertTrue(reset_bodies, f"no password-reset email captured for {email}: {bodies}")
            token = _extract_token(reset_bodies[-1])

            service.confirm_password_reset(
                {"token": token, "new_password": "reset-flow-password-456"},
                request_id=str(uuid.uuid4()), ip_address="127.0.0.1",
            )

            new_login, _ = service.login(
                {"email": email, "password": "reset-flow-password-456"},
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            self.assertIsNotNone(new_login.principal_id)

    def test_reused_password_reset_token_is_rejected(self) -> None:
        """Denial case: a password-reset token is single-use.
        consume_identity_token's own used_at check must still reject a
        replay after this fix, exactly as before it."""

        with self._stack() as stack:
            service = stack.components.service
            email = f"reset-reuse-{uuid.uuid4().hex[:8]}@webguard-dev.invalid"
            service.register_account(
                {
                    "organization_name": f"Reset Reuse Org {uuid.uuid4().hex[:6]}",
                    "display_name": "Reset Reuse Owner",
                    "email": email,
                    "password": "reset-reuse-password-123",
                },
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            service.request_password_reset(
                {"email": email}, request_id=str(uuid.uuid4()), ip_address="127.0.0.1",
            )
            token = _extract_token(self._sent_bodies_to(stack, email)[-1])

            service.confirm_password_reset(
                {"token": token, "new_password": "reset-reuse-password-456"},
                request_id=str(uuid.uuid4()), ip_address="127.0.0.1",
            )
            with self.assertRaises(Exception) as raised:
                service.confirm_password_reset(
                    {"token": token, "new_password": "reset-reuse-password-789"},
                    request_id=str(uuid.uuid4()), ip_address="127.0.0.1",
                )
            self.assertEqual(raised.exception.code, "identity_token_used")

    def test_invalid_password_reset_token_is_rejected(self) -> None:
        """Denial case: a well-formed but never-issued token must be
        rejected, not silently accepted or crashed on."""

        with self._stack() as stack:
            service = stack.components.service
            with self.assertRaises(Exception) as raised:
                service.confirm_password_reset(
                    {"token": f"wgi_{uuid.uuid4()}_not-a-real-secret", "new_password": "irrelevant-password-123"},
                    request_id=str(uuid.uuid4()), ip_address="127.0.0.1",
                )
            self.assertEqual(raised.exception.code, "identity_token_invalid")

    def test_invitation_accept_via_legitimate_mail_sink_succeeds_under_forced_rls(self) -> None:
        """gap: accept_invitation's own set_password_hash call, under a
        DIFFERENT principal than the one who requested it (the invited
        member, not the owner), proving the fix threads the invitee's
        own organization_id through correctly, not just the org's
        original owner's."""

        with self._stack() as stack:
            service = stack.components.service
            owner_email = f"invite-owner-{uuid.uuid4().hex[:8]}@webguard-dev.invalid"
            owner_context, _ = service.register_account(
                {
                    "organization_name": f"Invite Flow Org {uuid.uuid4().hex[:6]}",
                    "display_name": "Invite Flow Owner",
                    "email": owner_email,
                    "password": "invite-flow-owner-password-123",
                },
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            invitee_email = f"invite-member-{uuid.uuid4().hex[:8]}@webguard-dev.invalid"
            service.invite_team_member(
                owner_context,
                {"display_name": "Invited Member", "email": invitee_email, "role": "viewer"},
                request_id=str(uuid.uuid4()),
            )
            token = _extract_token(self._sent_bodies_to(stack, invitee_email)[-1])

            invitee_context, _ = service.accept_invitation(
                {"token": token, "password": "invite-flow-member-password-456"},
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            self.assertEqual(invitee_context.organization_id, owner_context.organization_id)
            self.assertNotEqual(invitee_context.principal_id, owner_context.principal_id)

            member_login, _ = service.login(
                {"email": invitee_email, "password": "invite-flow-member-password-456"},
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            self.assertEqual(member_login.principal_id, invitee_context.principal_id)

    def test_change_password_ignores_a_different_principal_id_in_the_request_body(self) -> None:
        """Denial case: change_password must only ever act on
        context.principal_id (the authenticated caller's own session),
        never on a caller-supplied identifier. A malicious or merely
        buggy client that stuffs another principal's id into the
        request body must not be able to change that other principal's
        password."""

        with self._stack() as stack:
            service = stack.components.service
            owner_email = f"victim-owner-{uuid.uuid4().hex[:8]}@webguard-dev.invalid"
            owner_context, _ = service.register_account(
                {
                    "organization_name": f"Injection Org {uuid.uuid4().hex[:6]}",
                    "display_name": "Victim Owner",
                    "email": owner_email,
                    "password": "victim-owner-password-123",
                },
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            attacker_email = f"attacker-{uuid.uuid4().hex[:8]}@webguard-dev.invalid"
            attacker_context, _ = service.register_account(
                {
                    "organization_name": f"Attacker Org {uuid.uuid4().hex[:6]}",
                    "display_name": "Attacker",
                    "email": attacker_email,
                    "password": "attacker-password-123",
                },
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )

            # attacker_context is a real, valid, authenticated session --
            # for its OWN principal. The body below names the victim's
            # principal_id, which change_password's signature never even
            # reads; the call can only ever act on context.principal_id.
            service.change_password(
                attacker_context,
                {
                    "current_password": "attacker-password-123",
                    "new_password": "attacker-password-456",
                    "principal_id": owner_context.principal_id,
                },
                request_id=str(uuid.uuid4()),
            )

            # The victim's own password is unchanged.
            victim_login, _ = service.login(
                {"email": owner_email, "password": "victim-owner-password-123"},
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            self.assertEqual(victim_login.principal_id, owner_context.principal_id)
            # The attacker's own password is the one that changed.
            attacker_login, _ = service.login(
                {"email": attacker_email, "password": "attacker-password-456"},
                request_id=str(uuid.uuid4()), user_agent=None, ip_address="127.0.0.1",
            )
            self.assertEqual(attacker_login.principal_id, attacker_context.principal_id)

    # -- repository-level defense-in-depth -------------------------------

    def test_set_password_hash_rejects_a_mismatched_organization_id_under_forced_rls(self) -> None:
        """No service-level request can ever reach set_password_hash
        with a caller-supplied organization_id that does not match the
        principal's own; every real call site derives it from
        already-trusted data (see this file's own module docstring).
        That makes this property untestable through the service layer
        by construction, which is exactly why it needs to be proven one
        level down: even if some future caller (a bug, a new code path)
        ever did pass the wrong organization_id, RLS itself, not
        application logic, must be the thing that rejects it, proving
        this is genuine defense in depth, not merely a fact about
        today's five call sites."""

        from webguard_contracts import OrganizationRole, PrincipalType
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool

        pool = WebGuardPostgresPool(self._db_dsn)
        try:
            identity = PostgresIdentityRepository(pool)
            now = _utc_now()
            org_a = identity.create_organization(f"Org A {uuid.uuid4().hex[:6]}", now=now)
            org_b = identity.create_organization(f"Org B {uuid.uuid4().hex[:6]}", now=now)
            principal_a = identity.create_principal(
                org_a.organization_id, "Principal A", principal_type=PrincipalType.USER,
                role=OrganizationRole.OWNER, now=now,
            )

            # Correct organization_id: succeeds.
            identity.set_password_hash(
                principal_a.principal_id, org_a.organization_id,
                algorithm="argon2id", password_hash="hash-for-org-a", now=now,
            )
            self.assertEqual(identity.get_password_hash(principal_a.principal_id), "hash-for-org-a")

            # Wrong organization_id for this principal: RLS's own WITH
            # CHECK on the UPDATE policy must reject this, not merely
            # decline to match a row. affected_rows == 0 (RLS silently
            # filters, the ordinary RLS failure mode) or a raised
            # exception are both acceptable "rejected" outcomes; a
            # successful, applied write is not.
            raised = None
            try:
                identity.set_password_hash(
                    principal_a.principal_id, org_b.organization_id,
                    algorithm="argon2id", password_hash="hash-for-org-b-mismatch", now=now,
                )
            except Exception as exc:  # noqa: BLE001 - either outcome below is acceptable
                raised = exc

            still_org_a_hash = identity.get_password_hash(principal_a.principal_id)
            self.assertEqual(
                still_org_a_hash, "hash-for-org-a",
                "a mismatched organization_id must never overwrite the real tenant's own credential, "
                f"whether or not it raised (raised={raised!r})",
            )
        finally:
            pool.close()
