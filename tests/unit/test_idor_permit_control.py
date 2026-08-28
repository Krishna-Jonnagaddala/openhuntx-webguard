"""Service-layer tests for authorization-comparison (IDOR/BOLA) permit
control (Slice 8): registering/revoking an AuthorizationComparisonPlan,
RBAC (owner-only), the two-distinct-identities requirement, binding
validation (wrong org/target, expired, revoked), the
authorization_comparison_check_not_requested rule, and the TrustScan
permit's authorization_comparison_plan_id claim -- including that
tampering with it invalidates the signature exactly like tampering with
any other claim.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace as dataclasses_replace
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    ApiServiceError,
    AuthenticationMethod,
    AuthorizationRepository,
    ScanJobStore,
    TrustScanPermitError,
    WebGuardJobService,
)
from webguard_scanner import AuthenticationMaterial
from webguard_contracts import (
    OrganizationRole,
    SignedTrustScanPermit,
    load_signed_trustscan_permit_json,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    VIEWER_ID,
    VIEWER_TOKEN_ID,
    create_identity_fixture,
    write_authorization,
)

REQUEST_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
ADMIN_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
ADMIN_TOKEN_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"

_RESOURCE_SCOPE = [
    {
        "resource_type": "order",
        "method": "GET",
        "primary_endpoint": "https://example.com/api/orders/A-001",
        "secondary_endpoint": "https://example.com/api/orders/B-001",
        "identifier_location": "path",
        "identifier_name": "id",
        "expected_access": "private_to_owner",
    }
]


def permit_body(**changes) -> bytes:
    values = {
        "target": TARGET,
        "authorization_id": AUTH_ID,
        "confirm_authorization": AUTH_ID,
        "permitted_modes": ["crawl", "single_page"],
        "allowed_http_methods": ["GET", "HEAD"],
        "not_before": NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=7))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "maximum_request_attempts": 15,
        "maximum_requests_per_second": 1.0,
        "maximum_concurrency": 1,
        "active_checks": [],
        "authentication_context_id": None,
        "authorization_comparison_plan_id": None,
    }
    values.update(changes)
    return json.dumps(values).encode("utf-8")


class AuthorizationComparisonPermitControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        self.store = ScanJobStore(root / "jobs.sqlite3")
        self.identity, self.owner, _ = create_identity_fixture(self.store.path)
        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    # -- helpers ------------------------------------------------------

    def register_context(self, label: str, context=None, **overrides):
        body = {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "identity_label": label,
            "method": "bearer_token",
            "expires_at": (NOW + timedelta(days=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "bearer_token": f"test-bearer-token-{label}",
        }
        body.update(overrides)
        return self.service.register_authentication_context(
            self.owner if context is None else context,
            body,
            request_id=REQUEST_ID,
        )

    def register_two_identities(self):
        primary = self.register_context("user-a")
        secondary = self.register_context("user-b")
        return primary, secondary

    def register_plan(self, context=None, **overrides):
        primary, secondary = self.register_two_identities()
        body = {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "primary_context_id": primary["authentication_context_id"],
            "secondary_context_id": secondary["authentication_context_id"],
            "resource_scope": _RESOURCE_SCOPE,
            "expires_at": (NOW + timedelta(days=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        }
        body.update(overrides)
        return self.service.register_authorization_comparison_plan(
            self.owner if context is None else context,
            body,
            request_id=REQUEST_ID,
        )

    # -- registration ---------------------------------------------------

    def test_owner_can_register_comparison_plan(self) -> None:
        record = self.register_plan()
        self.assertIn("comparison_plan_id", record)
        self.assertEqual(record["permitted_active_check"], "active.authorization.idor")
        self.assertEqual(record["status"], "active")
        # No secret material of either identity ever appears.
        dumped = json.dumps(record)
        self.assertNotIn("test-bearer-token-user-a", dumped)
        self.assertNotIn("test-bearer-token-user-b", dumped)

    def test_administrator_cannot_register_comparison_plan(self) -> None:
        _, administrator, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id=ADMIN_ID,
            token_id=ADMIN_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.register_plan(context=administrator)
        self.assertEqual(caught.exception.code, "permission_denied")

    def test_viewer_cannot_register_comparison_plan(self) -> None:
        _, viewer, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.VIEWER,
            principal_id=VIEWER_ID,
            token_id=VIEWER_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.register_plan(context=viewer)
        self.assertEqual(caught.exception.code, "permission_denied")

    def test_one_identity_only_cannot_register_a_plan(self) -> None:
        # Requirement: at least two DISTINCT, explicitly registered
        # authentication contexts. Reusing the same context ID for
        # both primary and secondary must fail closed at the service
        # layer, not merely at the repository layer.
        primary = self.register_context("user-a")
        with self.assertRaises(ApiServiceError) as caught:
            self.register_plan(
                primary_context_id=primary["authentication_context_id"],
                secondary_context_id=primary["authentication_context_id"],
            )
        self.assertEqual(
            caught.exception.code, "authorization_comparison_identities_not_distinct"
        )

    def test_context_from_different_organization_is_rejected(self) -> None:
        primary, secondary = self.register_two_identities()
        # Directly create a context bound to a different organization --
        # bypassing the register endpoint (which always binds to the
        # caller's own org) so the binding check itself is exercised.
        foreign = self.service.authentication_contexts.create(
            organization_id="99999999-9999-4999-8999-999999999999",
            target=TARGET,
            authorization_id=AUTH_ID,
            identity_label="user-c",
            method=AuthenticationMethod.BEARER_TOKEN,
            secret=AuthenticationMaterial(bearer_token="foreign-org-token"),
            expires_at=NOW + timedelta(days=1),
            now=NOW,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.register_plan(
                primary_context_id=foreign.authentication_context_id,
                secondary_context_id=secondary["authentication_context_id"],
            )
        self.assertEqual(
            caught.exception.code, "authentication_context_organization_mismatch"
        )

    def test_context_for_different_target_is_rejected(self) -> None:
        primary, secondary = self.register_two_identities()
        wrong_target = self.service.authentication_contexts.create(
            organization_id=ORG_ID,
            target="https://different.example/",
            authorization_id=AUTH_ID,
            identity_label="user-c",
            method=AuthenticationMethod.BEARER_TOKEN,
            secret=AuthenticationMaterial(bearer_token="wrong-target-token"),
            expires_at=NOW + timedelta(days=1),
            now=NOW,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.register_plan(
                primary_context_id=wrong_target.authentication_context_id,
                secondary_context_id=secondary["authentication_context_id"],
            )
        self.assertEqual(caught.exception.code, "authentication_context_target_mismatch")

    def test_expired_context_is_rejected(self) -> None:
        primary = self.register_context(
            "user-a",
            expires_at=(NOW + timedelta(seconds=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        )
        secondary = self.register_context("user-b")
        later_service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(
                Path(self.temporary.name) / "authorizations"
            ),
            identity=self.identity,
            clock=lambda: NOW + timedelta(seconds=2),
            authentication_contexts=self.service.authentication_contexts,
        )
        with self.assertRaises(ApiServiceError) as caught:
            later_service.register_authorization_comparison_plan(
                self.owner,
                {
                    "target": TARGET,
                    "authorization_id": AUTH_ID,
                    "primary_context_id": primary["authentication_context_id"],
                    "secondary_context_id": secondary["authentication_context_id"],
                    "resource_scope": _RESOURCE_SCOPE,
                    "expires_at": (NOW + timedelta(days=1))
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                },
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "authentication_context_expired")

    def test_revoked_context_is_rejected(self) -> None:
        primary, secondary = self.register_two_identities()
        self.service.revoke_authentication_context(
            self.owner, primary["authentication_context_id"], request_id=REQUEST_ID
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.register_plan(
                primary_context_id=primary["authentication_context_id"],
                secondary_context_id=secondary["authentication_context_id"],
            )
        self.assertEqual(caught.exception.code, "authentication_context_revoked")

    # -- permit binding ----------------------------------------------------

    def test_permit_can_bind_a_valid_comparison_plan(self) -> None:
        record = self.register_plan()
        issued = self.service.issue_permit(
            self.owner,
            permit_body(
                active_checks=["active.authorization.idor"],
                authorization_comparison_plan_id=record["comparison_plan_id"],
            ),
            request_id=REQUEST_ID,
        )
        self.assertEqual(
            issued["permit"]["claims"]["authorization_comparison_plan_id"],
            record["comparison_plan_id"],
        )

    def test_administrator_cannot_issue_permit_with_comparison_plan(self) -> None:
        record = self.register_plan()
        _, administrator, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id=ADMIN_ID,
            token_id=ADMIN_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                administrator,
                permit_body(
                    active_checks=["active.authorization.idor"],
                    authorization_comparison_plan_id=record["comparison_plan_id"],
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "permission_denied")

    def test_permit_rejects_unknown_comparison_plan(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                self.owner,
                permit_body(
                    active_checks=["active.authorization.idor"],
                    authorization_comparison_plan_id="ffffffff-ffff-4fff-8fff-ffffffffffff",
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(
            caught.exception.code, "authorization_comparison_plan_not_found"
        )

    def test_permit_rejects_revoked_comparison_plan(self) -> None:
        record = self.register_plan()
        self.service.revoke_authorization_comparison_plan(
            self.owner, record["comparison_plan_id"], request_id=REQUEST_ID
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                self.owner,
                permit_body(
                    active_checks=["active.authorization.idor"],
                    authorization_comparison_plan_id=record["comparison_plan_id"],
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "authorization_comparison_plan_revoked")

    def test_idor_not_in_active_checks_is_rejected(self) -> None:
        # A permit may reference the comparison plan only if it also
        # explicitly authorizes the detector the plan exists to run --
        # referencing the plan alone must never be sufficient.
        record = self.register_plan()
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                self.owner,
                permit_body(
                    active_checks=[],
                    authorization_comparison_plan_id=record["comparison_plan_id"],
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(
            caught.exception.code, "authorization_comparison_check_not_requested"
        )

    def test_xss_only_active_checks_cannot_carry_a_comparison_plan(self) -> None:
        record = self.register_plan()
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                self.owner,
                permit_body(
                    active_checks=["active.xss.reflected"],
                    authorization_comparison_plan_id=record["comparison_plan_id"],
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(
            caught.exception.code, "authorization_comparison_check_not_requested"
        )

    def test_sqli_only_active_checks_cannot_carry_a_comparison_plan(self) -> None:
        record = self.register_plan()
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                self.owner,
                permit_body(
                    active_checks=["active.sqli.error"],
                    authorization_comparison_plan_id=record["comparison_plan_id"],
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(
            caught.exception.code, "authorization_comparison_check_not_requested"
        )

    def test_tampering_with_signed_comparison_plan_id_fails_verification(self) -> None:
        record = self.register_plan()
        issued = self.service.issue_permit(
            self.owner,
            permit_body(
                active_checks=["active.authorization.idor"],
                authorization_comparison_plan_id=record["comparison_plan_id"],
            ),
            request_id=REQUEST_ID,
        )
        original = load_signed_trustscan_permit_json(json.dumps(issued["permit"]))
        tampered_claims = dataclasses_replace(
            original.claims, authorization_comparison_plan_id=None
        )
        tampered = SignedTrustScanPermit(
            claims=tampered_claims,
            signing_key_id=original.signing_key_id,
            signature=original.signature,
        )
        with self.assertRaises(TrustScanPermitError) as caught:
            self.service.trustscan_signer.verify(tampered)
        self.assertEqual(caught.exception.code, "trustscan_permit_signature_invalid")

    def test_permit_without_comparison_plan_id_is_unaffected(self) -> None:
        issued = self.service.issue_permit(
            self.owner, permit_body(), request_id=REQUEST_ID
        )
        self.assertIsNone(
            issued["permit"]["claims"]["authorization_comparison_plan_id"]
        )

    # -- secrets absent from errors and audit --------------------------

    def test_secrets_never_appear_in_service_errors(self) -> None:
        primary, secondary = self.register_two_identities()
        self.service.revoke_authentication_context(
            self.owner, primary["authentication_context_id"], request_id=REQUEST_ID
        )
        try:
            self.register_plan(
                primary_context_id=primary["authentication_context_id"],
                secondary_context_id=secondary["authentication_context_id"],
            )
            self.fail("expected ApiServiceError")
        except ApiServiceError as exc:
            self.assertNotIn("test-bearer-token-user-a", exc.message)
            self.assertNotIn("test-bearer-token-user-b", exc.message)


if __name__ == "__main__":
    unittest.main()
