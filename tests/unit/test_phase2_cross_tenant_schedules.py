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

UNKNOWN_SCHEDULE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


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


class Phase2CrossTenantScheduleIsolationTests(unittest.TestCase):
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

        self.schedule_a = self.service.create_schedule(
            self.owner_a,
            schedule_body(),
            permit_id=self.permit_a_id,
            request_id="11111111-1111-4111-8111-111111111111",
        )

        self.schedule_a_id = self.schedule_a["schedule_id"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def projection(exc: ApiServiceError) -> tuple:
        return (
            exc.status,
            getattr(exc, "code", None),
            getattr(exc, "message", str(exc)),
        )

    def invoke(
        self,
        method_name: str,
        schedule_id: str,
    ) -> tuple:
        method = getattr(self.service, method_name)

        with self.assertRaises(ApiServiceError) as caught:
            method(
                self.owner_b,
                schedule_id,
                request_id="22222222-2222-4222-8222-222222222222",
            )

        return self.projection(caught.exception)

    def test_foreign_schedule_get_matches_unknown(self) -> None:
        foreign = self.invoke(
            "get_schedule",
            self.schedule_a_id,
        )
        unknown = self.invoke(
            "get_schedule",
            UNKNOWN_SCHEDULE_ID,
        )

        self.assertEqual(
            foreign,
            unknown,
            msg="Schedule GET reveals existence across organizations",
        )
        self.assertEqual(foreign[0], 404)
        self.assertEqual(foreign[1], "schedule_not_found")

    def test_foreign_schedule_pause_matches_unknown_and_does_not_mutate(
        self,
    ) -> None:
        before = self.store.get_schedule_scoped(
            self.schedule_a_id,
            self.owner_a.organization_id,
        )

        foreign = self.invoke(
            "pause_schedule",
            self.schedule_a_id,
        )
        unknown = self.invoke(
            "pause_schedule",
            UNKNOWN_SCHEDULE_ID,
        )

        after = self.store.get_schedule_scoped(
            self.schedule_a_id,
            self.owner_a.organization_id,
        )

        self.assertEqual(
            foreign,
            unknown,
            msg="Schedule PAUSE reveals existence across organizations",
        )
        self.assertEqual(foreign[0], 404)
        self.assertEqual(foreign[1], "schedule_not_found")

        self.assertEqual(
            after,
            before,
            msg="Foreign pause attempt mutated Tenant A's schedule",
        )

    def test_foreign_schedule_resume_matches_unknown_and_does_not_mutate(
        self,
    ) -> None:
        before = self.store.get_schedule_scoped(
            self.schedule_a_id,
            self.owner_a.organization_id,
        )

        foreign = self.invoke(
            "resume_schedule",
            self.schedule_a_id,
        )
        unknown = self.invoke(
            "resume_schedule",
            UNKNOWN_SCHEDULE_ID,
        )

        after = self.store.get_schedule_scoped(
            self.schedule_a_id,
            self.owner_a.organization_id,
        )

        self.assertEqual(
            foreign,
            unknown,
            msg="Schedule RESUME reveals existence across organizations",
        )
        self.assertEqual(foreign[0], 404)
        self.assertEqual(foreign[1], "schedule_not_found")

        self.assertEqual(
            after,
            before,
            msg="Foreign resume attempt mutated Tenant A's schedule",
        )

    def test_tenant_b_schedule_list_does_not_contain_tenant_a_schedule(
        self,
    ) -> None:
        payload = self.service.list_schedules(
            self.owner_b,
            request_id="33333333-3333-4333-8333-333333333333",
        )

        schedule_ids = {
            item["schedule_id"]
            for item in payload["schedules"]
        }

        self.assertNotIn(
            self.schedule_a_id,
            schedule_ids,
            msg="Tenant B list exposed Tenant A's schedule",
        )

        for item in payload["schedules"]:
            self.assertEqual(
                item["organization_id"],
                OTHER_ORG_ID,
            )


if __name__ == "__main__":
    unittest.main()
