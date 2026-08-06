from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import IdentityStore, IdentityStoreError, ScanJobStore
from webguard_contracts import AuditOutcome, OrganizationRole, PrincipalType, SecurityAuditEvent
from tests.unit.service_test_support import AUTH_ID, NOW, ORG_ID, OWNER_ID, OWNER_TOKEN_ID


class IdentityStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "jobs.sqlite3"
        ScanJobStore(self.database)
        self.store = IdentityStore(self.database)
        self.org = self.store.create_organization("InternStack", now=NOW, organization_id=ORG_ID)
        self.owner = self.store.create_principal(
            ORG_ID, "Krishna", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW, principal_id=OWNER_ID
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_requires_initialized_database(self):
        with self.assertRaises(IdentityStoreError):
            IdentityStore(Path(self.temp.name) / "missing.sqlite3")

    def test_duplicate_organization_name_is_rejected_case_insensitively(self):
        with self.assertRaises(IdentityStoreError):
            self.store.create_organization("internstack", now=NOW)

    def test_principal_belongs_to_organization(self):
        self.assertEqual(self.store.get_principal(OWNER_ID).organization_id, ORG_ID)

    def test_unknown_principal_is_controlled(self):
        with self.assertRaises(IdentityStoreError):
            self.store.get_principal("99999999-9999-4999-8999-999999999999")

    def test_create_token_returns_secret_once(self):
        issued = self.store.create_token(
            OWNER_ID, label="owner", now=NOW, token_id=OWNER_TOKEN_ID
        )
        self.assertTrue(issued.token.startswith(f"wgt_{OWNER_TOKEN_ID}_"))
        self.assertNotIn(issued.token, str(issued.metadata.to_dict()))

    def test_authenticate_updates_last_used(self):
        issued = self.store.create_token(OWNER_ID, label="owner", now=NOW)
        metadata, principal, organization = self.store.authenticate_token(
            issued.token, now=NOW + timedelta(seconds=1)
        )
        self.assertEqual(principal.principal_id, OWNER_ID)
        self.assertEqual(organization.organization_id, ORG_ID)
        self.assertEqual(metadata.last_used_at, NOW + timedelta(seconds=1))

    def test_wrong_secret_is_rejected(self):
        issued = self.store.create_token(OWNER_ID, label="owner", now=NOW)
        token = issued.token.rsplit("_", 1)[0] + "_wrong"
        with self.assertRaises(IdentityStoreError):
            self.store.authenticate_token(token, now=NOW)

    def test_expired_token_is_rejected(self):
        issued = self.store.create_token(OWNER_ID, label="owner", now=NOW, validity_days=1)
        with self.assertRaisesRegex(IdentityStoreError, "expired"):
            self.store.authenticate_token(issued.token, now=NOW + timedelta(days=1))

    def test_revoked_token_is_rejected(self):
        issued = self.store.create_token(OWNER_ID, label="owner", now=NOW)
        self.store.revoke_token(issued.metadata.token_id, now=NOW + timedelta(seconds=1))
        with self.assertRaisesRegex(IdentityStoreError, "revoked"):
            self.store.authenticate_token(issued.token, now=NOW + timedelta(seconds=2))

    def test_revoke_is_idempotent(self):
        issued = self.store.create_token(OWNER_ID, label="owner", now=NOW)
        first = self.store.revoke_token(issued.metadata.token_id, now=NOW)
        second = self.store.revoke_token(issued.metadata.token_id, now=NOW + timedelta(seconds=1))
        self.assertEqual(first.revoked_at, second.revoked_at)

    def test_token_validity_is_bounded(self):
        with self.assertRaises(IdentityStoreError):
            self.store.create_token(OWNER_ID, label="owner", now=NOW, validity_days=367)

    def test_authorization_assignment_is_tenant_scoped(self):
        self.store.assign_authorization(ORG_ID, AUTH_ID, assigned_by=OWNER_ID, now=NOW)
        self.assertTrue(self.store.authorization_is_assigned(ORG_ID, AUTH_ID))
        self.assertFalse(self.store.authorization_is_assigned(ORG_ID, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))

    def test_cross_tenant_assigner_is_rejected(self):
        other = self.store.create_organization("Other", now=NOW)
        with self.assertRaises(IdentityStoreError):
            self.store.assign_authorization(other.organization_id, AUTH_ID, assigned_by=OWNER_ID, now=NOW)

    def test_audit_event_round_trip(self):
        issued = self.store.create_token(OWNER_ID, label="owner", now=NOW)
        event = SecurityAuditEvent(
            event_id="66666666-6666-4666-8666-666666666666",
            request_id="77777777-7777-4777-8777-777777777777",
            organization_id=ORG_ID, principal_id=OWNER_ID, token_id=issued.metadata.token_id,
            action="jobs.submit", resource_type="scan_job", resource_id="pending",
            outcome=AuditOutcome.SUCCEEDED, occurred_at=NOW,
        )
        self.store.record_audit_event(event)
        self.assertEqual(self.store.list_audit_events(ORG_ID), (event,))

    def test_audit_list_limit_is_bounded(self):
        with self.assertRaises(IdentityStoreError):
            self.store.list_audit_events(ORG_ID, limit=0)

    def test_database_remains_private(self):
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
