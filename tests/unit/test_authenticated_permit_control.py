"""Service-layer tests for authenticated-scanning permit control (Slice 7):
registering/revoking an AuthenticationContext, RBAC (owner-only), binding
validation (wrong org/target/authorization, expired, revoked), and the
TrustScan permit's authentication_context_id claim.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from dataclasses import replace as dataclasses_replace

from webguard_api import (
    ApiServiceError,
    AuthorizationRepository,
    ScanJobStore,
    TrustScanPermitError,
    WebGuardJobService,
)
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

REQUEST_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ADMIN_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
ADMIN_TOKEN_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


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


class AuthenticatedPermitControlTests(unittest.TestCase):
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

    def register(self, context=None, **overrides):
        body = {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "identity_label": "user-a",
            "method": "bearer_token",
            "expires_at": (NOW + timedelta(days=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "bearer_token": "test-bearer-token-value",
        }
        body.update(overrides)
        return self.service.register_authentication_context(
            self.owner if context is None else context,
            body,
            request_id=REQUEST_ID,
        )

    # -- registration ---------------------------------------------------

    def test_owner_can_register_bearer_token_context(self) -> None:
        result = self.register()
        self.assertIn("authentication_context_id", result)
        self.assertEqual(result["identity_label"], "user-a")
        self.assertEqual(result["method"], "bearer_token")
        self.assertEqual(result["status"], "active")
        # The secret must never be echoed back.
        self.assertNotIn("test-bearer-token-value", json.dumps(result))
        self.assertNotIn("bearer_token", result)

    def test_administrator_cannot_register_authentication_context(self) -> None:
        _, administrator, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id=ADMIN_ID,
            token_id=ADMIN_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.register(context=administrator)
        self.assertEqual(caught.exception.code, "permission_denied")

    def test_viewer_cannot_register_authentication_context(self) -> None:
        _, viewer, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.VIEWER,
            principal_id=VIEWER_ID,
            token_id=VIEWER_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.register(context=viewer)
        self.assertEqual(caught.exception.code, "permission_denied")

    def test_wrong_authorization_id_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.register(authorization_id="00000000-0000-4000-8000-000000000000")
        self.assertEqual(caught.exception.code, "authorization_not_found")

    def test_target_mismatch_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.register(target="https://different.example/")
        self.assertEqual(caught.exception.code, "authorization_target_mismatch")

    def test_unknown_method_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.register(method="oauth_automation")
        self.assertEqual(caught.exception.code, "authentication_context_method_invalid")

    def test_missing_field_is_rejected(self) -> None:
        body = {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "method": "bearer_token",
            "expires_at": (NOW + timedelta(days=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        }
        with self.assertRaises(ApiServiceError) as caught:
            self.service.register_authentication_context(
                self.owner, body, request_id=REQUEST_ID
            )
        self.assertEqual(caught.exception.code, "authentication_context_field_missing")

    def test_oversized_token_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.register(bearer_token="a" * 100_000)
        self.assertEqual(
            caught.exception.code, "authentication_bearer_token_too_large"
        )

    # -- revocation -------------------------------------------------------

    def test_owner_can_revoke_registered_context(self) -> None:
        record = self.register()
        revoked = self.service.revoke_authentication_context(
            self.owner, record["authentication_context_id"], request_id=REQUEST_ID
        )
        self.assertEqual(revoked["status"], "revoked")

    def test_administrator_cannot_revoke_authentication_context(self) -> None:
        record = self.register()
        _, administrator, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id=ADMIN_ID,
            token_id=ADMIN_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.service.revoke_authentication_context(
                administrator,
                record["authentication_context_id"],
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "permission_denied")

    def test_revoke_unknown_context_is_404(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.revoke_authentication_context(
                self.owner, "nonexistent-id", request_id=REQUEST_ID
            )
        self.assertEqual(caught.exception.status, 404)

    # -- permit binding ----------------------------------------------------

    def test_permit_can_bind_a_valid_authentication_context(self) -> None:
        record = self.register()
        issued = self.service.issue_permit(
            self.owner,
            permit_body(
                authentication_context_id=record["authentication_context_id"]
            ),
            request_id=REQUEST_ID,
        )
        self.assertEqual(
            issued["permit"]["claims"]["authentication_context_id"],
            record["authentication_context_id"],
        )

    def test_administrator_cannot_issue_permit_with_authentication_context(
        self,
    ) -> None:
        record = self.register()
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
                    authentication_context_id=record["authentication_context_id"]
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "permission_denied")

    def test_permit_rejects_unknown_authentication_context(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                self.owner,
                permit_body(
                    authentication_context_id="ffffffff-ffff-4fff-8fff-ffffffffffff"
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(
            caught.exception.code, "authentication_context_not_found"
        )

    def test_permit_rejects_revoked_authentication_context(self) -> None:
        record = self.register()
        self.service.revoke_authentication_context(
            self.owner, record["authentication_context_id"], request_id=REQUEST_ID
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.service.issue_permit(
                self.owner,
                permit_body(
                    authentication_context_id=record["authentication_context_id"]
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "authentication_context_revoked")

    def test_permit_rejects_expired_authentication_context(self) -> None:
        record = self.register(
            expires_at=(NOW + timedelta(seconds=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
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
            later_service.issue_permit(
                self.owner,
                permit_body(
                    authentication_context_id=record["authentication_context_id"],
                    not_before=(NOW + timedelta(seconds=2))
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                ),
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "authentication_context_expired")

    def test_tampering_with_signed_authentication_context_id_fails_verification(
        self,
    ) -> None:
        record = self.register()
        issued = self.service.issue_permit(
            self.owner,
            permit_body(
                authentication_context_id=record["authentication_context_id"]
            ),
            request_id=REQUEST_ID,
        )
        original = load_signed_trustscan_permit_json(json.dumps(issued["permit"]))
        # An attacker who could rebind a signed permit's
        # authentication_context_id to a *different* context (without
        # re-signing) would smuggle authenticated-scanning capability
        # onto a context nobody explicitly authorized this permit to
        # use. Tampering with this claim must invalidate the signature
        # exactly like tampering with any other claim already does.
        tampered_claims = dataclasses_replace(
            original.claims, authentication_context_id=None
        )
        tampered = SignedTrustScanPermit(
            claims=tampered_claims,
            signing_key_id=original.signing_key_id,
            signature=original.signature,
        )
        with self.assertRaises(TrustScanPermitError) as caught:
            self.service.trustscan_signer.verify(tampered)
        self.assertEqual(caught.exception.code, "trustscan_permit_signature_invalid")

    def test_permit_without_authentication_context_id_is_unaffected(self) -> None:
        issued = self.service.issue_permit(
            self.owner, permit_body(), request_id=REQUEST_ID
        )
        self.assertIsNone(
            issued["permit"]["claims"]["authentication_context_id"]
        )


class _ReferenceOnlyAuthenticationContexts:
    """Minimal double for a production-shaped repository: no
    ``get_secret`` at all (forcing ``register_authentication_context``'s
    ``secret_reference_id`` branch, the same test service
    ``PostgresAuthenticationContextRepository`` takes in production),
    and a ``create`` matching that branch's exact call shape."""

    def __init__(self) -> None:
        self.created_with_reference: str | None = None

    def create(self, *, organization_id, target, authorization_id, identity_label, method, secret_reference_id, expires_at, now):
        from webguard_api.authentication_contexts import AuthenticationContextRecord
        from uuid import uuid4

        self.created_with_reference = secret_reference_id
        return AuthenticationContextRecord(
            authentication_context_id=str(uuid4()),
            organization_id=organization_id,
            target=target,
            authorization_id=authorization_id,
            identity_label=identity_label,
            method=method,
            created_at=now,
            expires_at=expires_at,
        )


class SecretReferenceTenantScopingTests(unittest.TestCase):
    """M22/P1-13: secret_reference_id must be scoped to the caller's
    own organization, matching the identical tenant-prefixed
    convention object storage already enforces for report/artifact
    keys, so org A cannot name org B's own Secrets Manager entry and
    have it silently accepted."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.owner, _ = create_identity_fixture(store.path)
        self.contexts = _ReferenceOnlyAuthenticationContexts()
        self.service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
            authentication_contexts=self.contexts,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _register(self, secret_reference_id: str):
        body = {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "identity_label": "user-a",
            "method": "bearer_token",
            "expires_at": (NOW + timedelta(days=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "secret_reference_id": secret_reference_id,
        }
        return self.service.register_authentication_context(
            self.owner, body, request_id=REQUEST_ID
        )

    def test_own_organization_prefixed_reference_is_accepted(self) -> None:
        reference = f"organizations/{self.owner.organization_id}/bearer-secret"
        self._register(reference)
        self.assertEqual(self.contexts.created_with_reference, reference)

    def test_unprefixed_reference_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self._register("bearer-secret")
        self.assertEqual(
            caught.exception.code, "authentication_context_secret_reference_not_tenant_scoped"
        )
        self.assertIsNone(self.contexts.created_with_reference)

    def test_a_different_organizations_prefix_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self._register("organizations/99999999-9999-4999-8999-999999999999/bearer-secret")
        self.assertEqual(
            caught.exception.code, "authentication_context_secret_reference_not_tenant_scoped"
        )
        self.assertIsNone(self.contexts.created_with_reference)

    def test_own_organization_id_as_a_bare_substring_not_a_real_prefix_is_rejected(self) -> None:
        # Guards against a naive "organization_id in reference" check:
        # this must require the exact "organizations/<id>/" prefix, not
        # merely contain the ID somewhere in the string.
        with self.assertRaises(ApiServiceError) as caught:
            self._register(f"other-team-note-mentions-{self.owner.organization_id}-somewhere")
        self.assertEqual(
            caught.exception.code, "authentication_context_secret_reference_not_tenant_scoped"
        )


if __name__ == "__main__":
    unittest.main()
