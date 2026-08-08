from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from webguard_api import (
    ApiServiceError,
    AuthContext,
    AuthorizationRepository,
    ScanJobStore,
    WebGuardJobService,
)
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    create_identity_fixture,
    create_trustscan_permit,
    write_authorization,
)


OTHER_ORG_ID = "88888888-8888-4888-8888-888888888888"
OTHER_PRINCIPAL_ID = "99999999-9999-4999-8999-999999999999"
OTHER_TOKEN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

UNKNOWN_JOB_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def body() -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
        }
    ).encode("utf-8")


def store_request(key: str) -> ScanJobRequest:
    return ScanJobRequest(
        idempotency_key=key,
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256="a" * 64,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


class Phase2CrossTenantJobIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)

        auth_dir = root / "authorizations"
        write_authorization(auth_dir)

        self.store = ScanJobStore(root / "jobs.sqlite3")

        self.identity, self.owner_a, _ = create_identity_fixture(
            self.store.path
        )

        permit = create_trustscan_permit(self.store)
        self.permit_id = permit.permit.claims.permit_id

        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

        other_org = self.identity.create_organization(
            "Adversarial Tenant B",
            now=NOW,
            organization_id=OTHER_ORG_ID,
        )

        other_principal = self.identity.create_principal(
            other_org.organization_id,
            "Tenant B Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OTHER_PRINCIPAL_ID,
        )

        other_token = self.identity.create_token(
            other_principal.principal_id,
            label="tenant-b-owner",
            now=NOW,
            token_id=OTHER_TOKEN_ID,
        )

        self.owner_b = AuthContext(
            organization_id=other_org.organization_id,
            organization_name=other_org.name,
            principal_id=other_principal.principal_id,
            principal_name=other_principal.display_name,
            role=other_principal.role,
            token_id=other_token.metadata.token_id,
        )

        # Tenant B is independently and legitimately assigned the same
        # test authorization. This lets the attack reach the idempotency
        # boundary instead of being stopped earlier by authorization scope.
        self.identity.assign_authorization(
            OTHER_ORG_ID,
            AUTH_ID,
            assigned_by=OTHER_PRINCIPAL_ID,
            now=NOW,
        )

        self.permit_b = create_trustscan_permit(
            self.store,
            organization_id=OTHER_ORG_ID,
            issued_by=OTHER_PRINCIPAL_ID,
        )
        self.permit_b_id = self.permit_b.permit.claims.permit_id

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def submit_a(self):
        return self.service.submit(
            self.owner_a,
            body(),
            idempotency_key="phase2-tenant-a-job",
            permit_id=self.permit_id,
            request_id="11111111-1111-4111-8111-111111111111",
        )

    @staticmethod
    def error_projection(exc: ApiServiceError) -> tuple:
        return (
            exc.status,
            getattr(exc, "code", None),
            getattr(exc, "message", str(exc)),
        )

    def invoke_and_capture(self, method_name: str, job_id: str) -> tuple:
        method = getattr(self.service, method_name)

        with self.assertRaises(ApiServiceError) as caught:
            method(
                self.owner_b,
                job_id,
                request_id="22222222-2222-4222-8222-222222222222",
            )

        return self.error_projection(caught.exception)

    def test_known_cross_tenant_job_matches_unknown_job_for_get_cancel_and_result(
        self,
    ) -> None:
        document, created = self.submit_a()
        self.assertTrue(created)

        victim_job_id = document["job_id"]

        for method_name in ("get", "cancel", "result"):
            with self.subTest(method=method_name):
                known_other_tenant = self.invoke_and_capture(
                    method_name,
                    victim_job_id,
                )

                genuinely_unknown = self.invoke_and_capture(
                    method_name,
                    UNKNOWN_JOB_ID,
                )

                self.assertEqual(
                    known_other_tenant,
                    genuinely_unknown,
                    msg=(
                        f"{method_name} leaks whether a job exists "
                        "in another organization"
                    ),
                )

                self.assertEqual(known_other_tenant[0], 404)
                self.assertEqual(
                    known_other_tenant[1],
                    "job_not_found",
                )

        # Cross-tenant cancellation attempts must not alter Tenant A's job.
        victim = self.store.get(victim_job_id)
        self.assertEqual(victim.state.value, "queued")

    def test_same_client_idempotency_key_is_tenant_scoped_at_service_boundary(
        self,
    ) -> None:
        shared_key = "phase2-shared-idempotency-key"

        tenant_a, created_a = self.service.submit(
            self.owner_a,
            body(),
            idempotency_key=shared_key,
            permit_id=self.permit_id,
            request_id="33333333-3333-4333-8333-333333333333",
        )

        tenant_b, created_b = self.service.submit(
            self.owner_b,
            body(),
            idempotency_key=shared_key,
            permit_id=self.permit_b_id,
            request_id="44444444-4444-4444-8444-444444444444",
        )

        self.assertTrue(created_a)
        self.assertTrue(created_b)

        self.assertNotEqual(
            tenant_a["job_id"],
            tenant_b["job_id"],
            msg="Different organizations received the same job",
        )

        self.assertEqual(
            tenant_a["organization_id"],
            self.owner_a.organization_id,
        )
        self.assertEqual(
            tenant_b["organization_id"],
            self.owner_b.organization_id,
        )

        stored_a = self.store.get(tenant_a["job_id"])
        stored_b = self.store.get(tenant_b["job_id"])

        # The raw client key must not be the globally unique DB value.
        self.assertNotEqual(
            stored_a.request.idempotency_key,
            shared_key,
        )
        self.assertNotEqual(
            stored_b.request.idempotency_key,
            shared_key,
        )

        # Tenant scoping must produce different internal keys.
        self.assertNotEqual(
            stored_a.request.idempotency_key,
            stored_b.request.idempotency_key,
        )
        self.assertTrue(
            stored_a.request.idempotency_key.startswith("tenant-")
        )
        self.assertTrue(
            stored_b.request.idempotency_key.startswith("tenant-")
        )

        # Replaying the same client key inside Tenant A must still be
        # idempotent and return Tenant A's original job.
        replay_a, replay_created = self.service.submit(
            self.owner_a,
            body(),
            idempotency_key=shared_key,
            permit_id=self.permit_id,
            request_id="55555555-5555-4555-8555-555555555555",
        )

        self.assertFalse(replay_created)
        self.assertEqual(
            replay_a["job_id"],
            tenant_a["job_id"],
        )



if __name__ == "__main__":
    unittest.main()
