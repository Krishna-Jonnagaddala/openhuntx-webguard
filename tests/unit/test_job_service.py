from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import ApiServiceError, AuthorizationRepository, ScanJobStore, WebGuardJobService
from webguard_contracts import OrganizationRole, ScanStatus

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    TARGET,
    VIEWER_ID,
    VIEWER_TOKEN_ID,
    create_identity_fixture,
    write_authorization,
)


def body(**changes) -> bytes:
    values = {
        "target": TARGET,
        "authorization_id": AUTH_ID,
        "confirm_authorization": AUTH_ID,
        "mode": "crawl",
    }
    values.update(changes)
    return json.dumps(values).encode("utf-8")


class WebGuardJobServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        self.store = ScanJobStore(root / "jobs.sqlite3")
        self.identity, self.context, _ = create_identity_fixture(self.store.path)
        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def submit(self, payload=None, key="internstack-20260806"):
        return self.service.submit(
            self.context,
            body() if payload is None else payload,
            idempotency_key=key,
            request_id="66666666-6666-4666-8666-666666666666",
        )

    def test_submit_returns_queued_job(self) -> None:
        document, created = self.submit()
        self.assertTrue(created)
        self.assertEqual(document["state"], "queued")
        self.assertEqual(document["organization_id"], ORG_ID)
        self.assertEqual(document["request"]["authorization_id"], AUTH_ID)
        self.assertNotIn("confirm_authorization", json.dumps(document))

    def test_idempotent_submit_returns_same_job(self) -> None:
        first, created = self.submit()
        self.assertTrue(created)
        second, created = self.submit()
        self.assertFalse(created)
        self.assertEqual(second["job_id"], first["job_id"])

    def test_idempotency_conflict_is_http_409(self) -> None:
        self.submit()
        with self.assertRaises(ApiServiceError) as caught:
            self.submit(body(mode="single_page"))
        self.assertEqual(caught.exception.status, 409)

    def test_invalid_body_is_http_400(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.submit(b"{}")
        self.assertEqual(caught.exception.status, 400)

    def test_target_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(ApiServiceError, "does not match"):
            self.submit(body(target="https://www.internstack.in/"))

    def test_invalid_idempotency_key_is_http_400(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.submit(key="short")
        self.assertEqual(caught.exception.status, 400)

    def test_get_unknown_job_is_http_404(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.get(
                self.context,
                "b6a39765-16c6-42b4-91f0-998bf07f1912",
                request_id="66666666-6666-4666-8666-666666666666",
            )
        self.assertEqual(caught.exception.status, 404)

    def test_cancel_queued_job(self) -> None:
        document, _ = self.submit()
        cancelled = self.service.cancel(
            self.context,
            document["job_id"],
            request_id="66666666-6666-4666-8666-666666666666",
        )
        self.assertEqual(cancelled["state"], "cancelled")

    def test_result_is_not_ready_for_queued_job(self) -> None:
        document, _ = self.submit()
        with self.assertRaises(ApiServiceError) as caught:
            self.service.result(
                self.context,
                document["job_id"],
                request_id="66666666-6666-4666-8666-666666666666",
            )
        self.assertEqual(caught.exception.status, 409)

    def test_result_returns_refs_not_report_body(self) -> None:
        document, _ = self.submit()
        job_id = document["job_id"]
        self.store.claim_next(now=NOW)
        self.store.finish_result(
            job_id,
            scan_id="b6a39765-16c6-42b4-91f0-998bf07f1912",
            result_status=ScanStatus.COMPLETED,
            report_ref=f"organizations/{ORG_ID}/jobs/{job_id}/report.json",
            audit_ref=f"organizations/{ORG_ID}/jobs/{job_id}/authorization-audit.json",
            now=NOW + timedelta(seconds=1),
        )
        result = self.service.result(
            self.context,
            job_id,
            request_id="66666666-6666-4666-8666-666666666666",
        )
        self.assertEqual(result["state"], "completed")
        self.assertNotIn("findings", result)
        self.assertNotIn("authorization", result)

    def test_viewer_cannot_submit(self) -> None:
        _, viewer, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.VIEWER,
            principal_id=VIEWER_ID,
            token_id=VIEWER_TOKEN_ID,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.service.submit(
                viewer,
                body(),
                idempotency_key="viewer-submit-1",
                request_id="77777777-7777-4777-8777-777777777777",
            )
        self.assertEqual(caught.exception.status, 403)

    def test_cross_tenant_job_is_hidden(self) -> None:
        document, _ = self.submit()
        from webguard_api import AuthContext
        from webguard_contracts import OrganizationRole, PrincipalType
        other_org = self.identity.create_organization(
            "Other Tenant",
            now=NOW,
            organization_id="88888888-8888-4888-8888-888888888888",
        )
        other_principal = self.identity.create_principal(
            other_org.organization_id,
            "Other Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id="99999999-9999-4999-8999-999999999999",
        )
        other_token = self.identity.create_token(
            other_principal.principal_id,
            label="other-owner",
            now=NOW,
            token_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        other = AuthContext(
            organization_id=other_org.organization_id,
            organization_name=other_org.name,
            principal_id=other_principal.principal_id,
            principal_name=other_principal.display_name,
            role=other_principal.role,
            token_id=other_token.metadata.token_id,
        )
        with self.assertRaises(ApiServiceError) as caught:
            self.service.get(
                other,
                document["job_id"],
                request_id="99999999-9999-4999-8999-999999999999",
            )
        self.assertEqual(caught.exception.status, 404)

    def test_successful_submit_is_audited(self) -> None:
        document, _ = self.submit()
        events = self.identity.list_audit_events(ORG_ID)
        self.assertTrue(any(event.action == "jobs.submit" for event in events))
        self.assertTrue(any(event.resource_id == document["job_id"] for event in events))


if __name__ == "__main__":
    unittest.main()
