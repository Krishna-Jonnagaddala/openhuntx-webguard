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
from webguard_contracts import OrganizationRole, PrincipalType

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    create_identity_fixture,
    create_trustscan_permit,
    write_authorization,
)


OTHER_ORG_ID = "88888888-8888-4888-8888-888888888888"
OTHER_PRINCIPAL_ID = "99999999-9999-4999-8999-999999999999"
OTHER_TOKEN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

UNKNOWN_PERMIT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def submission() -> bytes:
    from tests.unit.service_test_support import TARGET

    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
        }
    ).encode("utf-8")


class Phase2CrossTenantPermitIsolationTests(unittest.TestCase):
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

        # Tenant B is legitimately assigned the same test authorization.
        # This ensures foreign-permit tests reach the permit boundary.
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

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def projection(exc: ApiServiceError) -> tuple:
        return (
            exc.status,
            getattr(exc, "code", None),
            getattr(exc, "message", str(exc)),
        )

    def invoke_permit_action(
        self,
        action: str,
        permit_id: str,
    ) -> tuple:
        method = getattr(self.service, action)

        with self.assertRaises(ApiServiceError) as caught:
            method(
                self.owner_b,
                permit_id,
                request_id="11111111-1111-4111-8111-111111111111",
            )

        return self.projection(caught.exception)

    def test_foreign_permit_read_matches_unknown_permit(self) -> None:
        foreign = self.invoke_permit_action(
            "get_permit",
            self.permit_a_id,
        )
        unknown = self.invoke_permit_action(
            "get_permit",
            UNKNOWN_PERMIT_ID,
        )

        self.assertEqual(
            foreign,
            unknown,
            msg="Permit read reveals whether another tenant's permit exists",
        )
        self.assertEqual(foreign[0], 404)
        self.assertEqual(
            foreign[1],
            "trustscan_permit_not_found",
        )

    def test_foreign_permit_revoke_matches_unknown_and_does_not_mutate(self) -> None:
        foreign = self.invoke_permit_action(
            "revoke_permit",
            self.permit_a_id,
        )
        unknown = self.invoke_permit_action(
            "revoke_permit",
            UNKNOWN_PERMIT_ID,
        )

        self.assertEqual(
            foreign,
            unknown,
            msg="Permit revocation reveals whether another tenant's permit exists",
        )
        self.assertEqual(foreign[0], 404)
        self.assertEqual(
            foreign[1],
            "trustscan_permit_not_found",
        )

        # Tenant B's failed revocation attempt must not modify Tenant A's permit.
        persisted = self.store.get_scan_permit(self.permit_a_id)
        self.assertIsNone(persisted.revoked_at)
        self.assertIsNone(persisted.revoked_by)

    def submit_b_with_permit(self, permit_id: str) -> tuple:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.submit(
                self.owner_b,
                submission(),
                idempotency_key="phase2-cross-tenant-permit",
                permit_id=permit_id,
                request_id="22222222-2222-4222-8222-222222222222",
            )

        return self.projection(caught.exception)

    def test_foreign_permit_cannot_authorize_job_and_matches_unknown(self) -> None:
        foreign = self.submit_b_with_permit(self.permit_a_id)
        unknown = self.submit_b_with_permit(UNKNOWN_PERMIT_ID)

        self.assertEqual(
            foreign,
            unknown,
            msg=(
                "Job submission reveals whether another tenant's "
                "TrustScan permit exists"
            ),
        )

        self.assertEqual(foreign[0], 404)
        self.assertEqual(
            foreign[1],
            "trustscan_permit_not_found",
        )

        # No Tenant-B job should have been created.
        connection = self.store._connect()
        try:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM scan_jobs AS jobs
                JOIN job_scopes AS scope
                  ON scope.job_id = jobs.job_id
                WHERE scope.organization_id = ?
                """,
                (OTHER_ORG_ID,),
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
