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
POSTGRES_TEST_DSN = os.environ.get(
    "WEBGUARD_POSTGRES_TEST_DSN",
    "postgresql://webguard:webguard_dev_only_not_for_production@127.0.0.1:5433/webguard",
)
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


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
    RUN_INTEGRATION, "Set WEBGUARD_RUN_INTEGRATION=1 to run this PostgreSQL contract test."
)
class PostgresIdentityRepositoryContractTests(IdentityRepositoryContractMixin, unittest.TestCase):
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
