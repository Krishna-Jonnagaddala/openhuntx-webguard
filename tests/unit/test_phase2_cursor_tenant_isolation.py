from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    ApiServiceError,
    AuthContext,
    AuthorizationRepository,
    ScanJobStore,
    WebGuardJobService,
)
from webguard_api.pagination import PageRequest
from webguard_contracts import OrganizationRole, PrincipalType

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    TARGET,
    create_identity_fixture,
    create_trustscan_permit,
    write_authorization,
)


OTHER_ORG_ID = "88888888-8888-4888-8888-888888888888"
OTHER_PRINCIPAL_ID = "99999999-9999-4999-8999-999999999999"
OTHER_TOKEN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def job_body() -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
        }
    ).encode("utf-8")


def schedule_body(name: str) -> bytes:
    starts_at = (NOW + timedelta(hours=1)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")

    return json.dumps(
        {
            "name": name,
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
            "interval_seconds": 86400,
            "starts_at": starts_at,
        }
    ).encode("utf-8")


class Phase2CursorTenantIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)

        auth_dir = root / "authorizations"
        write_authorization(auth_dir)

        self.store = ScanJobStore(root / "jobs.sqlite3")

        self.identity, self.owner_a, _ = create_identity_fixture(
            self.store.path
        )

        self.permit_a = create_trustscan_permit(self.store)
        self.permit_a_id = self.permit_a.permit.claims.permit_id

        other_org = self.identity.create_organization(
            "Adversarial Tenant B",
            now=NOW,
            organization_id=OTHER_ORG_ID,
        )

        other_principal = self.identity.create_principal(
            OTHER_ORG_ID,
            "Tenant B Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OTHER_PRINCIPAL_ID,
        )

        other_token = self.identity.create_token(
            OTHER_PRINCIPAL_ID,
            label="tenant-b-owner",
            now=NOW,
            token_id=OTHER_TOKEN_ID,
        )

        self.owner_b = AuthContext(
            organization_id=OTHER_ORG_ID,
            organization_name=other_org.name,
            principal_id=OTHER_PRINCIPAL_ID,
            principal_name=other_principal.display_name,
            role=other_principal.role,
            token_id=other_token.metadata.token_id,
        )

        self.identity.assign_authorization(
            OTHER_ORG_ID,
            AUTH_ID,
            assigned_by=OTHER_PRINCIPAL_ID,
            now=NOW,
        )

        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

        # Create enough Tenant-A objects for every feed to issue a cursor.
        for index in range(2):
            self.service.submit(
                self.owner_a,
                job_body(),
                idempotency_key=f"phase2-cursor-job-{index}",
                permit_id=self.permit_a_id,
                request_id=f"11111111-1111-4111-8111-11111111111{index}",
            )

            self.service.create_schedule(
                self.owner_a,
                schedule_body(f"Phase 2 cursor schedule {index}"),
                permit_id=self.permit_a_id,
                request_id=f"22222222-2222-4222-8222-22222222222{index}",
            )

        # Ensure Tenant B has its own audit activity too.
        self.service.me(
            self.owner_b,
            request_id="33333333-3333-4333-8333-333333333331",
        )
        self.service.me(
            self.owner_b,
            request_id="33333333-3333-4333-8333-333333333332",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def capture(call) -> ApiServiceError:
        with unittest.TestCase().assertRaises(ApiServiceError) as caught:
            call()
        return caught.exception

    def assert_scope_mismatch(self, call) -> None:
        exc = self.capture(call)

        self.assertEqual(exc.status, 400)
        self.assertEqual(
            exc.code,
            "page_cursor_scope_mismatch",
        )

    def tenant_a_job_cursor(self) -> str:
        page = self.service.list_jobs(
            self.owner_a,
            PageRequest(limit=1),
            request_id="44444444-4444-4444-8444-444444444441",
        )

        cursor = page["page"]["next_cursor"]
        self.assertIsNotNone(cursor)
        return cursor

    def tenant_a_schedule_cursor(self) -> str:
        page = self.service.list_schedules(
            self.owner_a,
            PageRequest(limit=1),
            request_id="44444444-4444-4444-8444-444444444442",
        )

        cursor = page["page"]["next_cursor"]
        self.assertIsNotNone(cursor)
        return cursor

    def tenant_a_audit_cursor(self) -> str:
        page = self.service.audit_events(
            self.owner_a,
            PageRequest(limit=1),
            request_id="44444444-4444-4444-8444-444444444443",
        )

        cursor = page["page"]["next_cursor"]
        self.assertIsNotNone(cursor)
        return cursor

    def test_job_cursor_cannot_be_replayed_by_other_tenant(self) -> None:
        cursor = self.tenant_a_job_cursor()

        self.assert_scope_mismatch(
            lambda: self.service.list_jobs(
                self.owner_b,
                PageRequest(limit=1, cursor=cursor),
                request_id="55555555-5555-4555-8555-555555555551",
            )
        )

    def test_schedule_cursor_cannot_be_replayed_by_other_tenant(
        self,
    ) -> None:
        cursor = self.tenant_a_schedule_cursor()

        self.assert_scope_mismatch(
            lambda: self.service.list_schedules(
                self.owner_b,
                PageRequest(limit=1, cursor=cursor),
                request_id="55555555-5555-4555-8555-555555555552",
            )
        )

    def test_audit_cursor_cannot_be_replayed_by_other_tenant(self) -> None:
        cursor = self.tenant_a_audit_cursor()

        self.assert_scope_mismatch(
            lambda: self.service.audit_events(
                self.owner_b,
                PageRequest(limit=1, cursor=cursor),
                request_id="55555555-5555-4555-8555-555555555553",
            )
        )

    def test_audit_cursor_cannot_cross_resource_boundary(self) -> None:
        cursor = self.tenant_a_audit_cursor()

        exc = self.capture(
            lambda: self.service.list_jobs(
                self.owner_a,
                PageRequest(limit=1, cursor=cursor),
                request_id="66666666-6666-4666-8666-666666666661",
            )
        )

        self.assertEqual(exc.status, 400)
        self.assertEqual(
            exc.code,
            "page_cursor_resource_mismatch",
        )

    def test_audit_cursor_cannot_be_reused_with_different_filters(
        self,
    ) -> None:
        cursor = self.tenant_a_audit_cursor()

        exc = self.capture(
            lambda: self.service.audit_events(
                self.owner_a,
                PageRequest(
                    limit=1,
                    cursor=cursor,
                    filters=(("outcome", "succeeded"),),
                ),
                request_id="66666666-6666-4666-8666-666666666662",
            )
        )

        self.assertEqual(exc.status, 400)
        self.assertEqual(
            exc.code,
            "page_cursor_filter_mismatch",
        )

    def test_tampered_audit_cursor_is_rejected(self) -> None:
        cursor = self.tenant_a_audit_cursor()

        payload, signature = cursor.split(".", 1)

        replacement = "A" if signature[0] != "A" else "B"
        tampered = payload + "." + replacement + signature[1:]

        exc = self.capture(
            lambda: self.service.audit_events(
                self.owner_a,
                PageRequest(limit=1, cursor=tampered),
                request_id="66666666-6666-4666-8666-666666666663",
            )
        )

        self.assertEqual(exc.status, 400)
        self.assertEqual(
            exc.code,
            "page_cursor_signature_invalid",
        )

    def test_tenant_b_audit_feed_contains_only_tenant_b_events(
        self,
    ) -> None:
        payload = self.service.audit_events(
            self.owner_b,
            PageRequest(limit=100),
            request_id="77777777-7777-4777-8777-777777777777",
        )

        self.assertTrue(payload["events"])

        for event in payload["events"]:
            self.assertEqual(
                event["organization_id"],
                OTHER_ORG_ID,
                msg="Tenant B audit feed exposed another organization",
            )


if __name__ == "__main__":
    unittest.main()
