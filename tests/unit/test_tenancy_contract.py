from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from webguard_contracts import (
    ApiTokenMetadata,
    AuditOutcome,
    Organization,
    OrganizationRole,
    OrganizationStatus,
    Principal,
    PrincipalType,
    SecurityAuditEvent,
    TenancyContractError,
)

NOW = datetime(2026, 8, 6, 21, 0, tzinfo=timezone.utc)
ORG = "11111111-1111-4111-8111-111111111111"
PRINCIPAL = "22222222-2222-4222-8222-222222222222"
TOKEN = "33333333-3333-4333-8333-333333333333"
REQUEST = "44444444-4444-4444-8444-444444444444"
EVENT = "55555555-5555-4555-8555-555555555555"


class TenancyContractTests(unittest.TestCase):
    def test_organization_is_canonical(self):
        value = Organization(ORG, " InternStack ", OrganizationStatus.ACTIVE, NOW)
        self.assertEqual(value.name, "InternStack")
        self.assertEqual(value.to_dict()["schema_version"], "1.0")

    def test_organization_rejects_noncanonical_uuid(self):
        with self.assertRaises(TenancyContractError):
            Organization("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "InternStack", OrganizationStatus.ACTIVE, NOW)

    def test_organization_rejects_blank_name(self):
        with self.assertRaises(TenancyContractError):
            Organization(ORG, " ", OrganizationStatus.ACTIVE, NOW)

    def test_principal_accepts_all_roles(self):
        for role in OrganizationRole:
            value = Principal(PRINCIPAL, ORG, "Krishna", PrincipalType.USER, role, True, NOW)
            self.assertEqual(value.role, role)

    def test_principal_rejects_non_boolean_active(self):
        with self.assertRaises(TenancyContractError):
            Principal(PRINCIPAL, ORG, "Krishna", PrincipalType.USER, OrganizationRole.OWNER, 1, NOW)

    def test_token_metadata_never_contains_secret(self):
        value = ApiTokenMetadata(TOKEN, ORG, PRINCIPAL, "Owner", NOW, NOW + timedelta(days=1))
        self.assertNotIn("secret", str(value.to_dict()).lower())

    def test_token_expiry_must_follow_creation(self):
        with self.assertRaises(TenancyContractError):
            ApiTokenMetadata(TOKEN, ORG, PRINCIPAL, "Owner", NOW, NOW)

    def test_token_optional_timestamps_are_utc(self):
        value = ApiTokenMetadata(
            TOKEN, ORG, PRINCIPAL, "Owner", NOW, NOW + timedelta(days=1),
            revoked_at=NOW + timedelta(hours=1), last_used_at=NOW + timedelta(minutes=1)
        )
        self.assertEqual(value.revoked_at.tzinfo, timezone.utc)

    def test_audit_event_is_canonical(self):
        event = SecurityAuditEvent(
            EVENT, REQUEST, ORG, PRINCIPAL, TOKEN, "jobs.submit", "scan_job",
            "pending", AuditOutcome.SUCCEEDED, NOW
        )
        self.assertEqual(event.to_dict()["action"], "jobs.submit")

    def test_audit_event_rejects_invalid_action(self):
        with self.assertRaises(TenancyContractError):
            SecurityAuditEvent(
                EVENT, REQUEST, ORG, PRINCIPAL, TOKEN, "Jobs Submit", "scan_job",
                "pending", AuditOutcome.SUCCEEDED, NOW
            )

    def test_audit_event_rejects_naive_time(self):
        with self.assertRaises(TenancyContractError):
            SecurityAuditEvent(
                EVENT, REQUEST, ORG, PRINCIPAL, TOKEN, "jobs.submit", "scan_job",
                "pending", AuditOutcome.SUCCEEDED, datetime(2026, 1, 1)
            )

    def test_control_characters_are_rejected(self):
        with self.assertRaises(TenancyContractError):
            Organization(ORG, "Intern\nStack", OrganizationStatus.ACTIVE, NOW)


if __name__ == "__main__":
    unittest.main()
