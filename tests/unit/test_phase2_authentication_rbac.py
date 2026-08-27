from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from webguard_api import (
    ApiTokenAuthenticator,
    AuthorizationRepository,
    ScanJobStore,
    WebGuardJobService,
)
from webguard_api.auth import (
    ApiPermission,
    AuthenticationError,
)
from webguard_contracts import (
    OrganizationRole,
    OrganizationStatus,
)

from tests.unit.service_test_support import (
    NOW,
    create_identity_fixture,
    write_authorization,
)


ANALYST_ID = "88888888-8888-4888-8888-888888888888"
ANALYST_TOKEN_ID = "99999999-9999-4999-8999-999999999999"

VIEWER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
VIEWER_TOKEN_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


class Phase2AuthenticationAndRbacTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)

        auth_dir = root / "authorizations"
        write_authorization(auth_dir)

        self.store = ScanJobStore(root / "jobs.sqlite3")

        self.identity, self.owner, self.owner_token = (
            create_identity_fixture(self.store.path)
        )

        _, self.analyst, self.analyst_token = (
            create_identity_fixture(
                self.store.path,
                role=OrganizationRole.ANALYST,
                principal_id=ANALYST_ID,
                token_id=ANALYST_TOKEN_ID,
            )
        )

        _, self.viewer, self.viewer_token = (
            create_identity_fixture(
                self.store.path,
                role=OrganizationRole.VIEWER,
                principal_id=VIEWER_ID,
                token_id=VIEWER_TOKEN_ID,
            )
        )

        self.authenticator = ApiTokenAuthenticator(self.identity)

        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def authenticate(self, token: str, *, now=NOW):
        return self.authenticator.authenticate(
            [f"Bearer {token}"],
            now=now,
        )

    def assert_auth_failure(
        self,
        headers: list[str],
        expected_code: str | None = None,
        *,
        now=NOW,
    ) -> AuthenticationError:
        with self.assertRaises(AuthenticationError) as caught:
            self.authenticator.authenticate(
                headers,
                now=now,
            )

        self.assertEqual(caught.exception.status, 401)

        if expected_code is not None:
            self.assertEqual(
                caught.exception.code,
                expected_code,
            )

        return caught.exception

    def test_authorization_header_parser_rejects_ambiguous_forms(
        self,
    ) -> None:
        cases = (
            [],
            [
                f"Bearer {self.owner_token}",
                f"Bearer {self.owner_token}",
            ],
            ["Basic credentials"],
            ["Bearer"],
            ["Bearer "],
            [f"Bearer  {self.owner_token}"],
            [f"Bearer {self.owner_token} "],
            [f"Bearer\t{self.owner_token}"],
        )

        for headers in cases:
            with self.subTest(headers_count=len(headers)):
                self.assert_auth_failure(headers)

    def test_bearer_scheme_is_case_insensitive_but_token_is_preserved(
        self,
    ) -> None:
        context = self.authenticator.authenticate(
            [f"bEaReR {self.owner_token}"],
            now=NOW,
        )

        self.assertEqual(
            context.principal_id,
            self.owner.principal_id,
        )
        self.assertEqual(
            context.organization_id,
            self.owner.organization_id,
        )

    def test_malformed_token_is_controlled_authentication_failure(
        self,
    ) -> None:
        exc = self.assert_auth_failure(
            ["Bearer definitely-not-a-webguard-token"]
        )

        self.assertTrue(exc.code)
        self.assertNotEqual(exc.code, "permission_denied")

    def test_revoked_token_cannot_authenticate(self) -> None:
        issued = self.identity.create_token(
            self.owner.principal_id,
            label="phase2-revoked",
            now=NOW,
            token_id=str(uuid4()),
        )

        self.identity.revoke_token(
            issued.metadata.token_id,
            now=NOW,
        )

        self.assert_auth_failure(
            [f"Bearer {issued.token}"],
            "api_token_revoked",
            now=NOW,
        )

    def test_expired_token_cannot_authenticate(self) -> None:
        issued = self.identity.create_token(
            self.owner.principal_id,
            label="phase2-expired",
            now=NOW,
            validity_days=1,
            token_id=str(uuid4()),
        )

        self.assert_auth_failure(
            [f"Bearer {issued.token}"],
            "api_token_expired",
            now=NOW + timedelta(days=1),
        )

    def test_disabled_principal_token_cannot_authenticate(self) -> None:
        connection = sqlite3.connect(self.store.path)

        try:
            connection.execute(
                """
                UPDATE principals
                SET active = 0
                WHERE principal_id = ?
                """,
                (self.owner.principal_id,),
            )
            connection.commit()
        finally:
            connection.close()

        self.assert_auth_failure(
            [f"Bearer {self.owner_token}"],
            "principal_disabled",
        )

    def test_disabled_organization_token_cannot_authenticate(
        self,
    ) -> None:
        disabled = next(
            status
            for status in OrganizationStatus
            if status is not OrganizationStatus.ACTIVE
        )

        connection = sqlite3.connect(self.store.path)

        try:
            connection.execute(
                """
                UPDATE organizations
                SET status = ?
                WHERE organization_id = ?
                """,
                (
                    disabled.value,
                    self.owner.organization_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

        self.assert_auth_failure(
            [f"Bearer {self.owner_token}"],
            "organization_disabled",
        )

    def test_authenticated_role_is_derived_from_persisted_principal(
        self,
    ) -> None:
        owner = self.authenticate(self.owner_token)
        analyst = self.authenticate(self.analyst_token)
        viewer = self.authenticate(self.viewer_token)

        self.assertEqual(
            owner.role,
            OrganizationRole.OWNER,
        )
        self.assertEqual(
            analyst.role,
            OrganizationRole.ANALYST,
        )
        self.assertEqual(
            viewer.role,
            OrganizationRole.VIEWER,
        )

    def test_analyst_has_only_intended_permissions(self) -> None:
        allowed = {
            ApiPermission.JOB_SUBMIT,
            ApiPermission.JOB_READ,
            ApiPermission.JOB_CANCEL,
            ApiPermission.SCHEDULE_CREATE,
            ApiPermission.SCHEDULE_READ,
            ApiPermission.SCHEDULE_UPDATE,
            ApiPermission.PERMIT_READ,
        }

        for permission in ApiPermission:
            with self.subTest(permission=permission.value):
                self.assertEqual(
                    self.analyst.permits(permission),
                    permission in allowed,
                )

    def test_viewer_has_only_read_permissions(self) -> None:
        allowed = {
            ApiPermission.JOB_READ,
            ApiPermission.SCHEDULE_READ,
            ApiPermission.PERMIT_READ,
        }

        for permission in ApiPermission:
            with self.subTest(permission=permission.value):
                self.assertEqual(
                    self.viewer.permits(permission),
                    permission in allowed,
                )

    def test_owner_and_administrator_permission_sets_are_complete(
        self,
    ) -> None:
        for permission in ApiPermission:
            self.assertTrue(
                self.owner.permits(permission),
                permission.value,
            )

        _, administrator, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            token_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        )

        for permission in ApiPermission:
            if permission is ApiPermission.PERMIT_ISSUE_ACTIVE:
                # Deliberately reserved to the organization owner -- see
                # test_only_owner_may_issue_active_capability_permits.
                continue
            self.assertTrue(
                administrator.permits(permission),
                permission.value,
            )
        self.assertFalse(
            administrator.permits(ApiPermission.PERMIT_ISSUE_ACTIVE)
        )

    def test_analyst_cannot_invoke_privileged_service_operations(
        self,
    ) -> None:
        operations = (
            lambda: self.service.issue_permit(
                self.analyst,
                b"{}",
                request_id="11111111-1111-4111-8111-111111111111",
            ),
            lambda: self.service.revoke_permit(
                self.analyst,
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                request_id="22222222-2222-4222-8222-222222222222",
            ),
            lambda: self.service.audit_events(
                self.analyst,
                request_id="33333333-3333-4333-8333-333333333333",
            ),
        )

        for operation in operations:
            with self.subTest():
                with self.assertRaises(
                    Exception
                ) as caught:
                    operation()

                self.assertEqual(
                    getattr(caught.exception, "status", None),
                    403,
                )
                self.assertEqual(
                    getattr(caught.exception, "code", None),
                    "permission_denied",
                )


if __name__ == "__main__":
    unittest.main()
