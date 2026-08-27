from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import ApiServiceError, AuthorizationRepository, ScanJobStore, WebGuardJobService
from webguard_contracts import OrganizationRole

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    TARGET,
    VIEWER_ID,
    VIEWER_TOKEN_ID,
    create_identity_fixture,
    write_authorization,
)

REQUEST_ID = "66666666-6666-4666-8666-666666666666"


def timestamp(value) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def permit_body(**changes) -> bytes:
    values = {
        "target": TARGET,
        "authorization_id": AUTH_ID,
        "confirm_authorization": AUTH_ID,
        "permitted_modes": ["crawl", "single_page"],
        "allowed_http_methods": ["GET", "HEAD"],
        "not_before": timestamp(NOW),
        "expires_at": timestamp(NOW + timedelta(days=7)),
        "maximum_request_attempts": 15,
        "maximum_requests_per_second": 1.0,
        "maximum_concurrency": 1,
        "active_checks": [],
        "authentication_context_id": None,
    }
    values.update(changes)
    return json.dumps(values).encode("utf-8")


def job_body(mode="crawl") -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": mode,
        }
    ).encode("utf-8")


class TrustScanPermitServiceTests(unittest.TestCase):
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

    def issue(self, context=None, payload=None):
        return self.service.issue_permit(
            self.context if context is None else context,
            permit_body() if payload is None else payload,
            request_id=REQUEST_ID,
        )

    def test_owner_issues_reads_and_revokes_permit(self) -> None:
        issued = self.issue()
        self.assertEqual(issued["state"], "active")
        permit_id = issued["permit"]["claims"]["permit_id"]
        self.assertEqual(issued["permit"]["signature"]["algorithm"], "Ed25519")
        fetched = self.service.get_permit(
            self.context,
            permit_id,
            request_id=REQUEST_ID,
        )
        self.assertEqual(fetched["permit"], issued["permit"])
        revoked = self.service.revoke_permit(
            self.context,
            permit_id,
            request_id=REQUEST_ID,
        )
        self.assertEqual(revoked["state"], "revoked")
        self.assertIsNotNone(revoked["revoked_at"])

    def test_viewer_can_read_but_cannot_issue_or_revoke(self) -> None:
        issued = self.issue()
        permit_id = issued["permit"]["claims"]["permit_id"]
        _, viewer, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.VIEWER,
            principal_id=VIEWER_ID,
            token_id=VIEWER_TOKEN_ID,
        )
        fetched = self.service.get_permit(viewer, permit_id, request_id=REQUEST_ID)
        self.assertEqual(fetched["permit"]["claims"]["permit_id"], permit_id)
        with self.assertRaises(ApiServiceError) as issue_error:
            self.issue(context=viewer)
        self.assertEqual(issue_error.exception.status, 403)
        with self.assertRaises(ApiServiceError) as revoke_error:
            self.service.revoke_permit(viewer, permit_id, request_id=REQUEST_ID)
        self.assertEqual(revoke_error.exception.status, 403)

    def test_permit_cannot_exceed_authorization_request_budget(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.issue(payload=permit_body(maximum_request_attempts=16))
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_request_budget_too_high",
        )

    def test_permit_cannot_exceed_authorization_rate(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.issue(payload=permit_body(maximum_requests_per_second=2.0))
        self.assertEqual(caught.exception.code, "trustscan_permit_rate_too_high")

    def test_revoked_permit_cannot_submit_job(self) -> None:
        issued = self.issue()
        permit_id = issued["permit"]["claims"]["permit_id"]
        self.service.revoke_permit(self.context, permit_id, request_id=REQUEST_ID)
        with self.assertRaises(ApiServiceError) as caught:
            self.service.submit(
                self.context,
                job_body(),
                idempotency_key="revoked-permit-job",
                permit_id=permit_id,
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_revoked")
        self.assertEqual(caught.exception.status, 403)

    def test_mode_not_listed_in_permit_is_denied(self) -> None:
        issued = self.issue(
            payload=permit_body(permitted_modes=["single_page"])
        )
        permit_id = issued["permit"]["claims"]["permit_id"]
        with self.assertRaises(ApiServiceError) as caught:
            self.service.submit(
                self.context,
                job_body("crawl"),
                idempotency_key="mode-not-permitted",
                permit_id=permit_id,
                request_id=REQUEST_ID,
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_mode_not_allowed")
        self.assertEqual(caught.exception.status, 403)

    def test_job_response_contains_only_permit_identity_not_private_key(self) -> None:
        issued = self.issue()
        permit_id = issued["permit"]["claims"]["permit_id"]
        job, created = self.service.submit(
            self.context,
            job_body(),
            idempotency_key="permit-public-binding",
            permit_id=permit_id,
            request_id=REQUEST_ID,
        )
        self.assertTrue(created)
        self.assertEqual(job["trustscan_permit"]["permit_id"], permit_id)
        serialized = json.dumps(job)
        self.assertNotIn("public_key", serialized)
        self.assertNotIn("private_key", serialized)

    def test_permit_actions_are_audited(self) -> None:
        issued = self.issue()
        permit_id = issued["permit"]["claims"]["permit_id"]
        self.service.get_permit(self.context, permit_id, request_id=REQUEST_ID)
        self.service.revoke_permit(self.context, permit_id, request_id=REQUEST_ID)
        actions = {event.action for event in self.identity.list_audit_events(self.context.organization_id)}
        self.assertTrue({"permits.issue", "permits.read", "permits.revoke"}.issubset(actions))


if __name__ == "__main__":
    unittest.main()
