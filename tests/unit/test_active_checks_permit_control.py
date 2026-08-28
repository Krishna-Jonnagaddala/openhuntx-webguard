"""Service-layer tests for the active_checks TrustScan permit control
surface: RBAC, validation, canonicalization, tampering, and audit.

CLI-level and true end-to-end coverage live in separate files
(test_active_checks_cli.py, tests/integration/test_active_checks_e2e_lab.py)
so each file stays focused on one layer.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace as dataclasses_replace
from pathlib import Path

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
    TrustScanPermitLoadError,
    load_signed_trustscan_permit_json,
    load_trustscan_permit_submission_json,
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

REQUEST_ID = "77777777-7777-4777-8777-777777777777"
ADMIN_ID = "88888888-8888-4888-8888-888888888888"
ADMIN_TOKEN_ID = "99999999-9999-4999-8999-999999999999"


def permit_body(**changes) -> bytes:
    from datetime import timedelta

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


class ActiveChecksPermitControlTests(unittest.TestCase):
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

    def issue(self, context=None, payload=None):
        return self.service.issue_permit(
            self.owner if context is None else context,
            permit_body() if payload is None else payload,
            request_id=REQUEST_ID,
        )

    # -- 1/2: omitted / empty active_checks means passive-only --------

    def test_missing_active_checks_key_is_rejected_not_defaulted(self) -> None:
        """The wire submission is strict (no implicit optional fields --
        Slice 2 behaviour, reconfirmed here). An operator can never
        accidentally omit the field and get an unreviewed default; the
        CLI always sends an explicit [] (see test_active_checks_cli.py)."""

        raw = json.loads(permit_body())
        del raw["active_checks"]
        with self.assertRaises(TrustScanPermitLoadError) as caught:
            load_trustscan_permit_submission_json(json.dumps(raw).encode())
        self.assertEqual(caught.exception.code, "trustscan_permit_field_missing")

    def test_empty_active_checks_list_issues_passive_only_permit(self) -> None:
        issued = self.issue(payload=permit_body(active_checks=[]))
        self.assertEqual(issued["permit"]["claims"]["active_checks"], [])

    # -- 3: valid registered detector may be requested by the owner ---

    def test_owner_may_request_the_registered_xss_detector(self) -> None:
        issued = self.issue(
            payload=permit_body(active_checks=["active.xss.reflected"])
        )
        self.assertEqual(
            issued["permit"]["claims"]["active_checks"],
            ["active.xss.reflected"],
        )

    # -- 4: unknown detector ID fails closed ---------------------------

    def test_unknown_detector_id_fails_closed(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.issue(
                payload=permit_body(
                    active_checks=["active.ssrf.callback"]
                )
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_active_checks_unknown",
        )

    # -- 5: duplicate detector IDs are rejected, not silently deduped -

    def test_duplicate_detector_ids_are_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.issue(
                payload=permit_body(
                    active_checks=[
                        "active.xss.reflected",
                        "active.xss.reflected",
                    ]
                )
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_active_checks_non_canonical",
        )

    # -- 6: unauthorized role cannot issue active-capability permits --

    def test_administrator_cannot_issue_active_capability_permit(self) -> None:
        _, administrator, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id=ADMIN_ID,
            token_id=ADMIN_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.issue(
                context=administrator,
                payload=permit_body(active_checks=["active.xss.reflected"]),
            )
        self.assertEqual(caught.exception.status, 403)

    def test_administrator_may_still_issue_a_passive_only_permit(self) -> None:
        _, administrator, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id=ADMIN_ID,
            token_id=ADMIN_TOKEN_ID,
        )
        issued = self.issue(context=administrator, payload=permit_body())
        self.assertEqual(issued["permit"]["claims"]["active_checks"], [])

    def test_viewer_cannot_issue_any_permit_active_or_passive(self) -> None:
        _, viewer, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.VIEWER,
            principal_id=VIEWER_ID,
            token_id=VIEWER_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.issue(
                context=viewer,
                payload=permit_body(active_checks=["active.xss.reflected"]),
            )
        self.assertEqual(caught.exception.status, 403)

    # -- 7: cross-tenant request fails ---------------------------------

    def test_cross_tenant_permit_use_fails(self) -> None:
        issued = self.issue(
            payload=permit_body(active_checks=["active.xss.reflected"])
        )
        permit_id = issued["permit"]["claims"]["permit_id"]
        other_org_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        other_identity, other_owner, _ = create_identity_fixture(
            self.store.path,
            principal_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            token_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )
        # create_identity_fixture always attaches to the shared ORG_ID
        # fixture; force a genuinely different organization instead.
        other_org = self.identity.create_organization(
            "Other Tenant", now=NOW, organization_id=other_org_id
        )
        other_owner = dataclasses_replace(
            other_owner,
            organization_id=other_org.organization_id,
            organization_name=other_org.name,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.service.get_permit(
                other_owner, permit_id, request_id=REQUEST_ID
            )
        self.assertIn(caught.exception.status, (403, 404))

    # -- 8: wrong target/authorization fails ---------------------------

    def test_target_not_matching_authorization_fails(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.issue(
                payload=permit_body(
                    target="https://not-example.com/",
                    active_checks=["active.xss.reflected"],
                )
            )
        self.assertEqual(
            caught.exception.code, "authorization_target_mismatch"
        )

    # -- 9: tampering with signed active_checks invalidates the permit -

    def test_tampering_with_signed_active_checks_fails_verification(self) -> None:
        issued = self.issue(
            payload=permit_body(active_checks=["active.xss.reflected"])
        )
        original = load_signed_trustscan_permit_json(
            json.dumps(issued["permit"])
        )
        tampered_claims = dataclasses_replace(
            original.claims, active_checks=()
        )
        tampered = SignedTrustScanPermit(
            claims=tampered_claims,
            signing_key_id=original.signing_key_id,
            signature=original.signature,
        )
        with self.assertRaises(TrustScanPermitError) as caught:
            self.service.trustscan_signer.verify(tampered)
        self.assertEqual(
            caught.exception.code, "trustscan_permit_signature_invalid"
        )

    # -- 12: audit events record the decision, never secrets -----------

    def test_active_permit_issuance_is_audited_without_secrets(self) -> None:
        issued = self.issue(
            payload=permit_body(active_checks=["active.xss.reflected"])
        )
        events = list(
            self.identity.list_audit_events(self.owner.organization_id)
        )
        issue_events = [e for e in events if e.action == "permits.issue"]
        self.assertTrue(issue_events)
        matching = [
            e
            for e in issue_events
            if e.detail_code
            and "active" in e.detail_code
            and "xss" in e.detail_code
        ]
        self.assertTrue(
            matching,
            f"expected an active-checks detail_code, got: "
            f"{[e.detail_code for e in issue_events]}",
        )
        for event in events:
            serialized = json.dumps(
                {
                    "action": event.action,
                    "detail_code": event.detail_code,
                    "resource_id": event.resource_id,
                }
            )
            self.assertNotIn("signature", serialized)
            self.assertNotIn(TARGET, serialized)

    def test_denied_active_permit_request_is_audited(self) -> None:
        # An administrator has ordinary PERMIT_ISSUE but not the stricter
        # PERMIT_ISSUE_ACTIVE, so the denial is specifically for the
        # active-checks gate, not basic issuance -- unlike a viewer, who
        # is denied before active_checks is even inspected.
        _, administrator, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id=ADMIN_ID,
            token_id=ADMIN_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError):
            self.issue(
                context=administrator,
                payload=permit_body(active_checks=["active.xss.reflected"]),
            )
        events = list(
            self.identity.list_audit_events(administrator.organization_id)
        )
        denied = [
            e
            for e in events
            if e.action == "permits.issue_active"
            and e.outcome.value == "denied"
        ]
        self.assertTrue(denied)


if __name__ == "__main__":
    unittest.main()
