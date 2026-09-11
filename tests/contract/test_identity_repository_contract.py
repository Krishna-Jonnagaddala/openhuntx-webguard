"""Contract tests for `IdentityRepository` (Slice 12 requirement 9):
the same test bodies run against the SQLite `IdentityStore` and the
PostgreSQL `PostgresIdentityRepository`, proving domain behavior is
independent of backend. The PostgreSQL cases require a real database
(`WEBGUARD_RUN_INTEGRATION=1` and a reachable `WEBGUARD_POSTGRES_TEST_DSN`)
and are skipped otherwise, matching this project's existing
integration-test gating convention.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from webguard_api.identity import IdentityStore, IdentityStoreError
from webguard_contracts import OrganizationRole, OrganizationStatus, PrincipalType

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
# No hardcoded default DSN -- see test_postgres_connection_pool.py's
# comment on this exact env-var pair for why WEBGUARD_RUN_INTEGRATION=1
# alone is not sufficient (it is already set by CI's Juice-Shop-only
# integration job, which runs no PostgreSQL service at all).
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)

# P1-2 Phase H: authenticate_token() now runs its pre-auth resolve
# step under api_tenant_data (see postgres_pool.py's
# role_scoped_connection and postgres_identity.py's authenticate_token),
# so this contract test's PostgreSQL side needs the same role/ACL/
# control-function/runtime-grant bootstrap test_postgres_control_functions.py
# applies for its own tests -- without it, SET LOCAL ROLE fails with
# "role \"api_tenant_data\" does not exist" the first time any test
# here calls authenticate_token. The SQLite side needs none of this;
# it never touches a database role at all.
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


class IdentityRepositoryContractMixin:
    """Subclasses provide `make_repository()`. Every test method here
    runs unmodified against whatever backend that returns."""

    def make_repository(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def test_create_and_get_organization_round_trips(self) -> None:
        repo = self.make_repository()
        org = repo.create_organization("Acme", now=NOW, organization_id=str(uuid4()))
        fetched = repo.get_organization(org.organization_id)
        self.assertEqual(fetched.organization_id, org.organization_id)
        self.assertEqual(fetched.name, "Acme")
        self.assertEqual(fetched.status, OrganizationStatus.ACTIVE)

    def test_duplicate_organization_id_conflicts(self) -> None:
        repo = self.make_repository()
        org_id = str(uuid4())
        repo.create_organization("Acme", now=NOW, organization_id=org_id)
        with self.assertRaises(IdentityStoreError) as caught:
            repo.create_organization("Acme Two", now=NOW, organization_id=org_id)
        self.assertEqual(caught.exception.code, "organization_conflict")

    def test_get_unknown_organization_not_found(self) -> None:
        repo = self.make_repository()
        with self.assertRaises(IdentityStoreError) as caught:
            repo.get_organization(str(uuid4()))
        self.assertEqual(caught.exception.code, "organization_not_found")

    def test_create_and_get_principal_round_trips(self) -> None:
        repo = self.make_repository()
        org = repo.create_organization("Acme", now=NOW, organization_id=str(uuid4()))
        principal = repo.create_principal(
            org.organization_id,
            "Alice",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=str(uuid4()),
        )
        fetched = repo.get_principal(principal.principal_id)
        self.assertEqual(fetched.display_name, "Alice")
        self.assertEqual(fetched.role, OrganizationRole.OWNER)
        self.assertTrue(fetched.active)

    def test_token_issue_authenticate_and_revoke_lifecycle(self) -> None:
        repo = self.make_repository()
        org = repo.create_organization("Acme", now=NOW, organization_id=str(uuid4()))
        principal = repo.create_principal(
            org.organization_id,
            "Alice",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=str(uuid4()),
        )
        issued = repo.create_token(principal.principal_id, label="ci", now=NOW)

        metadata, fetched_principal, fetched_org = repo.authenticate_token(
            issued.token, now=NOW + timedelta(minutes=1)
        )
        self.assertEqual(metadata.token_id, issued.metadata.token_id)
        self.assertEqual(fetched_principal.principal_id, principal.principal_id)
        self.assertEqual(fetched_org.organization_id, org.organization_id)

        revoked = repo.revoke_token(issued.metadata.token_id, now=NOW + timedelta(minutes=2))
        self.assertIsNotNone(revoked.revoked_at)

        with self.assertRaises(IdentityStoreError) as caught:
            repo.authenticate_token(issued.token, now=NOW + timedelta(minutes=3))
        self.assertEqual(caught.exception.code, "api_token_revoked")

    def test_get_principal_by_email_matches_and_returns_none_for_unknown(self) -> None:
        repo = self.make_repository()
        org = repo.create_organization("Acme", now=NOW, organization_id=str(uuid4()))
        principal = repo.create_principal(
            org.organization_id,
            "Alice",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=str(uuid4()),
            email="Alice@Example.com",
        )
        fetched = repo.get_principal_by_email("  alice@example.com  ")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.principal_id, principal.principal_id)
        self.assertEqual(fetched.organization_id, org.organization_id)
        self.assertEqual(fetched.email, "alice@example.com")

        self.assertIsNone(repo.get_principal_by_email("nobody@example.com"))

    def test_consume_identity_token_lifecycle(self) -> None:
        from webguard_api.identity import IdentityTokenPurpose

        repo = self.make_repository()
        org = repo.create_organization("Acme", now=NOW, organization_id=str(uuid4()))
        principal = repo.create_principal(
            org.organization_id,
            "Alice",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=str(uuid4()),
        )
        issued = repo.create_identity_token(
            principal.principal_id,
            org.organization_id,
            purpose=IdentityTokenPurpose.PASSWORD_RESET,
            ttl=timedelta(hours=1),
            now=NOW,
        )

        with self.assertRaises(IdentityStoreError) as caught:
            repo.consume_identity_token(
                issued.token, purpose=IdentityTokenPurpose.EMAIL_VERIFICATION, now=NOW
            )
        self.assertEqual(caught.exception.code, "identity_token_invalid")

        forged = issued.token[:-4] + "xxxx"
        with self.assertRaises(IdentityStoreError) as caught:
            repo.consume_identity_token(
                forged, purpose=IdentityTokenPurpose.PASSWORD_RESET, now=NOW
            )
        self.assertEqual(caught.exception.code, "identity_token_invalid")

        with self.assertRaises(IdentityStoreError) as caught:
            repo.consume_identity_token(
                issued.token,
                purpose=IdentityTokenPurpose.PASSWORD_RESET,
                now=NOW + timedelta(hours=2),
            )
        self.assertEqual(caught.exception.code, "identity_token_expired")

        record = repo.consume_identity_token(
            issued.token, purpose=IdentityTokenPurpose.PASSWORD_RESET, now=NOW + timedelta(minutes=5)
        )
        self.assertEqual(record.token_id, issued.record.token_id)
        self.assertEqual(record.principal_id, principal.principal_id)
        self.assertEqual(record.organization_id, org.organization_id)
        self.assertEqual(record.created_at, issued.record.created_at)
        self.assertIsNotNone(record.used_at)

        with self.assertRaises(IdentityStoreError) as caught:
            repo.consume_identity_token(
                issued.token, purpose=IdentityTokenPurpose.PASSWORD_RESET, now=NOW + timedelta(minutes=6)
            )
        self.assertEqual(caught.exception.code, "identity_token_used")

    def test_wrong_secret_is_rejected(self) -> None:
        repo = self.make_repository()
        org = repo.create_organization("Acme", now=NOW, organization_id=str(uuid4()))
        principal = repo.create_principal(
            org.organization_id,
            "Alice",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=str(uuid4()),
        )
        issued = repo.create_token(principal.principal_id, label="ci", now=NOW)
        forged = issued.token[:-4] + "xxxx"
        with self.assertRaises(IdentityStoreError) as caught:
            repo.authenticate_token(forged, now=NOW)
        self.assertEqual(caught.exception.code, "api_token_invalid")

    def test_authorization_assignment_is_tenant_scoped(self) -> None:
        repo = self.make_repository()
        org_a = repo.create_organization("Org A", now=NOW, organization_id=str(uuid4()))
        org_b = repo.create_organization("Org B", now=NOW, organization_id=str(uuid4()))
        owner_a = repo.create_principal(
            org_a.organization_id,
            "Owner A",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=str(uuid4()),
        )
        authorization_id = str(uuid4())
        repo.assign_authorization(
            org_a.organization_id, authorization_id, assigned_by=owner_a.principal_id, now=NOW
        )
        self.assertTrue(repo.authorization_is_assigned(org_a.organization_id, authorization_id))
        self.assertFalse(repo.authorization_is_assigned(org_b.organization_id, authorization_id))

    def test_cross_tenant_assignment_is_rejected(self) -> None:
        repo = self.make_repository()
        org_a = repo.create_organization("Org A", now=NOW, organization_id=str(uuid4()))
        org_b = repo.create_organization("Org B", now=NOW, organization_id=str(uuid4()))
        owner_b = repo.create_principal(
            org_b.organization_id,
            "Owner B",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=str(uuid4()),
        )
        with self.assertRaises(IdentityStoreError) as caught:
            repo.assign_authorization(
                org_a.organization_id, str(uuid4()), assigned_by=owner_b.principal_id, now=NOW
            )
        self.assertEqual(caught.exception.code, "cross_tenant_assignment_rejected")

    def test_audit_events_are_tenant_filtered_and_paginated(self) -> None:
        from webguard_contracts import AuditOutcome, SecurityAuditEvent

        repo = self.make_repository()
        org_a = repo.create_organization("Org A", now=NOW, organization_id=str(uuid4()))
        org_b = repo.create_organization("Org B", now=NOW, organization_id=str(uuid4()))
        owner_a = repo.create_principal(
            org_a.organization_id,
            "Owner A",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=str(uuid4()),
        )
        token = repo.create_token(owner_a.principal_id, label="ci", now=NOW)

        for offset in range(5):
            repo.record_audit_event(
                SecurityAuditEvent(
                    event_id=str(uuid4()),
                    request_id=str(uuid4()),
                    organization_id=org_a.organization_id,
                    principal_id=owner_a.principal_id,
                    token_id=token.metadata.token_id,
                    action="scan.submit",
                    resource_type="scan_job",
                    resource_id=str(uuid4()),
                    outcome=AuditOutcome.SUCCEEDED,
                    occurred_at=NOW + timedelta(seconds=offset),
                    detail_code=None,
                )
            )

        page_one, has_more = repo.list_audit_events_page(org_a.organization_id, limit=3)
        self.assertEqual(len(page_one), 3)
        self.assertTrue(has_more)

        after = (
            page_one[-1].occurred_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            page_one[-1].event_id,
        )
        page_two, has_more_two = repo.list_audit_events_page(
            org_a.organization_id, limit=3, after=after
        )
        self.assertEqual(len(page_two), 2)
        self.assertFalse(has_more_two)

        # Org B sees none of Org A's audit events.
        events_b, _ = repo.list_audit_events_page(org_b.organization_id, limit=10)
        self.assertEqual(events_b, ())


class SqliteIdentityRepositoryContractTests(IdentityRepositoryContractMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self._db_path = Path(self._tempdir.name) / "identity.db"
        self._db_path.touch()

    def make_repository(self) -> IdentityStore:
        return IdentityStore(self._db_path)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test.",
)
class PostgresIdentityRepositoryContractTests(IdentityRepositoryContractMixin, unittest.TestCase):
    @classmethod
    def _connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def setUpClass(cls) -> None:
        # Same file-per-connection sequencing test_postgres_control_functions.py's
        # own _apply_full_bootstrap uses -- each file gets its own
        # transaction, committed on that `with` block's clean exit,
        # before the next file (which may depend on the previous one
        # having actually committed) runs.
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
            connection.execute(
                "TRUNCATE organizations, principals, memberships, api_tokens, "
                "organization_authorizations, security_audit_events CASCADE"
            )

    def make_repository(self):
        from webguard_api.postgres_identity import PostgresIdentityRepository

        return PostgresIdentityRepository(self._pool)


if __name__ == "__main__":
    unittest.main()
