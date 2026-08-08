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

UNKNOWN_PERMIT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def schedule_body() -> bytes:
    starts_at = (NOW + timedelta(hours=1)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")

    return json.dumps(
        {
            "name": "Phase 2 tenant isolation schedule",
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
            "interval_seconds": 86400,
            "starts_at": starts_at,
        }
    ).encode("utf-8")


class Phase2SchedulePermitIsolationTests(unittest.TestCase):
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

        # Both tenants are legitimately assigned the test authorization.
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

    def create_b_with_permit(self, permit_id: str) -> tuple:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.create_schedule(
                self.owner_b,
                schedule_body(),
                permit_id=permit_id,
                request_id="11111111-1111-4111-8111-111111111111",
            )

        return self.projection(caught.exception)

    def schedule_count(self, organization_id: str) -> int:
        connection = self.store._connect()
        try:
            return connection.execute(
                """
                SELECT COUNT(*)
                FROM scan_schedules
                WHERE organization_id = ?
                """,
                (organization_id,),
            ).fetchone()[0]
        finally:
            connection.close()

    def test_foreign_permit_schedule_creation_matches_unknown_permit(
        self,
    ) -> None:
        foreign = self.create_b_with_permit(self.permit_a_id)
        unknown = self.create_b_with_permit(UNKNOWN_PERMIT_ID)

        self.assertEqual(
            foreign,
            unknown,
            msg=(
                "Schedule creation reveals whether another tenant's "
                "TrustScan permit exists"
            ),
        )

        self.assertEqual(foreign[0], 404)
        self.assertEqual(
            foreign[1],
            "trustscan_permit_not_found",
        )

        self.assertEqual(
            self.schedule_count(OTHER_ORG_ID),
            0,
            msg="Foreign permit attempt persisted a Tenant-B schedule",
        )

    def test_revoked_permit_cannot_create_schedule(self) -> None:
        self.service.revoke_permit(
            self.owner_a,
            self.permit_a_id,
            request_id="22222222-2222-4222-8222-222222222222",
        )

        before = self.schedule_count(self.owner_a.organization_id)

        with self.assertRaises(ApiServiceError) as caught:
            self.service.create_schedule(
                self.owner_a,
                schedule_body(),
                permit_id=self.permit_a_id,
                request_id="33333333-3333-4333-8333-333333333333",
            )

        after = self.schedule_count(self.owner_a.organization_id)

        self.assertEqual(
            before,
            after,
            msg="A schedule was persisted using a revoked TrustScan permit",
        )

        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_revoked",
        )


if __name__ == "__main__":
    unittest.main()
