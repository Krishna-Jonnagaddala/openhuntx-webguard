"""Slice 11 stabilization audit: a genuine cross-tenant authorization
test was missing. Every existing cross-tenant test file
(`test_phase2_cross_tenant_jobs.py`, `test_phase2_cross_tenant_permits.py`,
`test_phase2_cross_tenant_schedules.py`) deliberately assigns the SAME
authorization ID to both tenants, specifically to reach a later
boundary (idempotency, permit ownership) rather than being stopped by
authorization scope itself. This file tests the authorization-scope
boundary directly: organization A has a real authorization genuinely
assigned; organization B does not; B's attempt to issue a permit or
submit a job against that exact, real authorization ID must fail
closed with the same "not found" signal an unknown authorization ID
would produce -- never leaking that the authorization exists at all,
and never granting access merely because the authorization ID itself
is valid and real.
"""

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
    TARGET,
    create_identity_fixture,
    write_authorization,
)

OTHER_ORG_ID = "c1c1c1c1-c1c1-4c1c-8c1c-c1c1c1c1c1c1"
OTHER_PRINCIPAL_ID = "c2c2c2c2-c2c2-4c2c-8c2c-c2c2c2c2c2c2"
OTHER_TOKEN_ID = "c3c3c3c3-c3c3-4c3c-8c3c-c3c3c3c3c3c3"


class CrossTenantAuthorizationScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)

        self.store = ScanJobStore(root / "jobs.sqlite3")
        # Tenant A: genuinely, correctly assigned AUTH_ID.
        self.identity, self.owner_a, _ = create_identity_fixture(self.store.path)

        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

        # Tenant B: a real, independent organization that is NEVER
        # assigned AUTH_ID -- the authorization is real and exists on
        # disk (both tenants share the same AuthorizationRepository),
        # but only tenant A has been granted it.
        other_org = self.identity.create_organization(
            "Adversarial Tenant B (unassigned)", now=NOW, organization_id=OTHER_ORG_ID
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

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _permit_body(self) -> bytes:
        from datetime import timedelta

        return json.dumps(
            {
                "target": TARGET,
                "authorization_id": AUTH_ID,
                "confirm_authorization": AUTH_ID,
                "permitted_modes": ["single_page"],
                "allowed_http_methods": ["GET", "HEAD"],
                "not_before": NOW.isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
                "expires_at": (NOW + timedelta(days=1))
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
                "maximum_request_attempts": 15,
                "maximum_requests_per_second": 1.0,
                "maximum_concurrency": 1,
                "active_checks": [],
                "authentication_context_id": None,
                "authorization_comparison_plan_id": None,
            }
        ).encode("utf-8")

    def test_tenant_a_can_use_its_own_genuinely_assigned_authorization(self) -> None:
        # Sanity precondition: the real authorization does work for the
        # tenant it was actually assigned to.
        issued = self.service.issue_permit(
            self.owner_a, self._permit_body(), request_id="d1d1d1d1-d1d1-4d1d-8d1d-d1d1d1d1d1d1"
        )
        self.assertIn("permit", issued)

    def test_unassigned_tenant_cannot_issue_a_permit_against_a_real_authorization(
        self,
    ) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                self.owner_b, self._permit_body(), request_id="d2d2d2d2-d2d2-4d2d-8d2d-d2d2d2d2d2d2"
            )
        # Must fail exactly like an authorization ID that doesn't exist
        # at all -- never a distinct "forbidden" signal that would
        # confirm the authorization is real but belongs to someone else.
        self.assertEqual(caught.exception.code, "authorization_not_found")
        self.assertEqual(caught.exception.status, 404)

    def test_unassigned_tenant_gets_the_identical_error_for_a_genuinely_unknown_id(
        self,
    ) -> None:
        # Confirms the "not found" response for the real-but-unassigned
        # authorization is indistinguishable from a genuinely unknown
        # one -- the existence of AUTH_ID is never leaked to tenant B.
        body = json.loads(self._permit_body())
        body["authorization_id"] = "00000000-0000-4000-8000-000000000000"
        body["confirm_authorization"] = "00000000-0000-4000-8000-000000000000"
        with self.assertRaises(ApiServiceError) as caught_unknown:
            self.service.issue_permit(
                self.owner_b, json.dumps(body).encode("utf-8"), request_id="d3d3d3d3-d3d3-4d3d-8d3d-d3d3d3d3d3d3"
            )
        with self.assertRaises(ApiServiceError) as caught_real:
            self.service.issue_permit(
                self.owner_b, self._permit_body(), request_id="d4d4d4d4-d4d4-4d4d-8d4d-d4d4d4d4d4d4"
            )
        self.assertEqual(caught_unknown.exception.code, caught_real.exception.code)
        self.assertEqual(
            caught_unknown.exception.status, caught_real.exception.status
        )


if __name__ == "__main__":
    unittest.main()
