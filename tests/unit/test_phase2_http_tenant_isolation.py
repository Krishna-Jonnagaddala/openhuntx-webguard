from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from webguard_api import (
    ApiTokenAuthenticator,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    ScanJobStore,
    WebGuardJobService,
    create_server,
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
OTHER_PERMIT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

UNKNOWN_JOB_ID = "77777777-7777-4777-8777-777777777777"
UNKNOWN_PERMIT_ID = "66666666-6666-4666-8666-666666666666"
UNKNOWN_SCHEDULE_ID = "55555555-5555-4555-8555-555555555555"


def job_submission() -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
        }
    ).encode("utf-8")


def schedule_submission(
    *,
    name: str,
    offset_hours: int = 1,
) -> bytes:
    starts_at = (
        NOW + timedelta(hours=offset_hours)
    ).isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )

    return json.dumps(
        {
            "name": name,
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
            "interval_seconds": 86400,
            "starts_at": starts_at,
        }
    ).encode("utf-8")


class Phase2HttpTenantIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)

        auth_dir = root / "authorizations"
        write_authorization(auth_dir)

        self.store = ScanJobStore(root / "jobs.sqlite3")

        self.identity, self.a_context, self.a_token = (
            create_identity_fixture(self.store.path)
        )

        self.a_permit = create_trustscan_permit(self.store)
        self.a_permit_id = (
            self.a_permit.permit.claims.permit_id
        )

        other_org = self.identity.create_organization(
            "Phase 2 Tenant B",
            now=NOW,
            organization_id=OTHER_ORG_ID,
        )

        other_principal = self.identity.create_principal(
            other_org.organization_id,
            "Phase 2 Tenant B Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OTHER_PRINCIPAL_ID,
        )

        issued = self.identity.create_token(
            other_principal.principal_id,
            label="phase2-tenant-b",
            now=NOW,
            token_id=OTHER_TOKEN_ID,
        )

        self.b_token = issued.token

        self.identity.assign_authorization(
            OTHER_ORG_ID,
            AUTH_ID,
            assigned_by=OTHER_PRINCIPAL_ID,
            now=NOW,
        )

        self.b_permit = create_trustscan_permit(
            self.store,
            organization_id=OTHER_ORG_ID,
            issued_by=OTHER_PRINCIPAL_ID,
            permit_id=OTHER_PERMIT_ID,
        )
        self.b_permit_id = (
            self.b_permit.permit.claims.permit_id
        )

        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

        self.server = create_server(
            "127.0.0.1",
            0,
            self.service,
            authenticator=ApiTokenAuthenticator(self.identity),
            rate_limiter=FixedWindowRateLimiter(
                requests=500,
                window_seconds=60,
            ),
            maximum_request_bytes=2048,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
        )

        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], dict]:
        effective = dict(headers or {})
        effective["Authorization"] = f"Bearer {token}"

        if body is not None:
            effective.setdefault(
                "Content-Type",
                "application/json",
            )

        connection = http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=3,
        )

        try:
            connection.request(
                method,
                path,
                body=body,
                headers=effective,
            )

            response = connection.getresponse()

            payload = json.loads(
                response.read()
            )

            return (
                response.status,
                dict(response.getheaders()),
                payload,
            )
        finally:
            connection.close()

    @staticmethod
    def error_signature(
        response: tuple[int, dict[str, str], dict],
    ) -> tuple[int, str, str]:
        status, _, payload = response

        return (
            status,
            payload["error"]["code"],
            payload["error"]["message"],
        )

    def create_job(
        self,
        *,
        token: str,
        permit_id: str,
        key: str,
    ) -> dict:
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            token=token,
            body=job_submission(),
            headers={
                "Idempotency-Key": key,
                "TrustScan-Permit": permit_id,
            },
        )

        self.assertEqual(status, 201)

        return payload

    def create_schedule(
        self,
        *,
        token: str,
        permit_id: str,
        name: str,
        offset_hours: int = 1,
    ) -> dict:
        status, _, payload = self.request(
            "POST",
            "/v1/schedules",
            token=token,
            body=schedule_submission(
                name=name,
                offset_hours=offset_hours,
            ),
            headers={
                "TrustScan-Permit": permit_id,
            },
        )

        self.assertEqual(status, 201)

        return payload

    def test_foreign_job_get_matches_unknown_job(self) -> None:
        job = self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key="phase2-http-job-get-a",
        )

        foreign = self.request(
            "GET",
            f"/v1/jobs/{job['job_id']}",
            token=self.b_token,
        )

        unknown = self.request(
            "GET",
            f"/v1/jobs/{UNKNOWN_JOB_ID}",
            token=self.b_token,
        )

        self.assertEqual(
            self.error_signature(foreign),
            self.error_signature(unknown),
        )
        self.assertEqual(
            self.error_signature(foreign)[:2],
            (404, "job_not_found"),
        )

    def test_foreign_job_result_matches_unknown_job(self) -> None:
        job = self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key="phase2-http-job-result-a",
        )

        foreign = self.request(
            "GET",
            f"/v1/jobs/{job['job_id']}/result",
            token=self.b_token,
        )

        unknown = self.request(
            "GET",
            f"/v1/jobs/{UNKNOWN_JOB_ID}/result",
            token=self.b_token,
        )

        self.assertEqual(
            self.error_signature(foreign),
            self.error_signature(unknown),
        )
        self.assertEqual(
            self.error_signature(foreign)[:2],
            (404, "job_not_found"),
        )

    def test_foreign_job_cancel_matches_unknown_and_does_not_mutate(
        self,
    ) -> None:
        job = self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key="phase2-http-job-cancel-a",
        )

        foreign = self.request(
            "POST",
            f"/v1/jobs/{job['job_id']}/cancel",
            token=self.b_token,
        )

        unknown = self.request(
            "POST",
            f"/v1/jobs/{UNKNOWN_JOB_ID}/cancel",
            token=self.b_token,
        )

        self.assertEqual(
            self.error_signature(foreign),
            self.error_signature(unknown),
        )
        self.assertEqual(
            self.error_signature(foreign)[:2],
            (404, "job_not_found"),
        )

        status, _, victim = self.request(
            "GET",
            f"/v1/jobs/{job['job_id']}",
            token=self.a_token,
        )

        self.assertEqual(status, 200)
        self.assertEqual(victim["state"], "queued")

    def test_foreign_permit_get_matches_unknown_permit(self) -> None:
        foreign = self.request(
            "GET",
            f"/v1/permits/{self.a_permit_id}",
            token=self.b_token,
        )

        unknown = self.request(
            "GET",
            f"/v1/permits/{UNKNOWN_PERMIT_ID}",
            token=self.b_token,
        )

        self.assertEqual(
            self.error_signature(foreign),
            self.error_signature(unknown),
        )
        self.assertEqual(
            self.error_signature(foreign)[:2],
            (404, "trustscan_permit_not_found"),
        )

    def test_foreign_permit_revoke_matches_unknown_and_does_not_mutate(
        self,
    ) -> None:
        foreign = self.request(
            "POST",
            f"/v1/permits/{self.a_permit_id}/revoke",
            token=self.b_token,
        )

        unknown = self.request(
            "POST",
            f"/v1/permits/{UNKNOWN_PERMIT_ID}/revoke",
            token=self.b_token,
        )

        self.assertEqual(
            self.error_signature(foreign),
            self.error_signature(unknown),
        )
        self.assertEqual(
            self.error_signature(foreign)[:2],
            (404, "trustscan_permit_not_found"),
        )

        status, _, permit = self.request(
            "GET",
            f"/v1/permits/{self.a_permit_id}",
            token=self.a_token,
        )

        self.assertEqual(status, 200)
        self.assertNotEqual(permit["state"], "revoked")
        self.assertIsNone(permit["revoked_at"])

    def test_foreign_schedule_get_matches_unknown_schedule(
        self,
    ) -> None:
        schedule = self.create_schedule(
            token=self.a_token,
            permit_id=self.a_permit_id,
            name="Phase2 HTTP A schedule get",
        )

        foreign = self.request(
            "GET",
            f"/v1/schedules/{schedule['schedule_id']}",
            token=self.b_token,
        )

        unknown = self.request(
            "GET",
            f"/v1/schedules/{UNKNOWN_SCHEDULE_ID}",
            token=self.b_token,
        )

        self.assertEqual(
            self.error_signature(foreign),
            self.error_signature(unknown),
        )
        self.assertEqual(
            self.error_signature(foreign)[:2],
            (404, "schedule_not_found"),
        )

    def test_foreign_schedule_pause_matches_unknown_and_does_not_mutate(
        self,
    ) -> None:
        schedule = self.create_schedule(
            token=self.a_token,
            permit_id=self.a_permit_id,
            name="Phase2 HTTP A schedule pause",
        )

        foreign = self.request(
            "POST",
            f"/v1/schedules/{schedule['schedule_id']}/pause",
            token=self.b_token,
        )

        unknown = self.request(
            "POST",
            f"/v1/schedules/{UNKNOWN_SCHEDULE_ID}/pause",
            token=self.b_token,
        )

        self.assertEqual(
            self.error_signature(foreign),
            self.error_signature(unknown),
        )
        self.assertEqual(
            self.error_signature(foreign)[:2],
            (404, "schedule_not_found"),
        )

        status, _, victim = self.request(
            "GET",
            f"/v1/schedules/{schedule['schedule_id']}",
            token=self.a_token,
        )

        self.assertEqual(status, 200)
        self.assertEqual(victim["state"], "active")

    def test_foreign_schedule_resume_matches_unknown_and_does_not_mutate(
        self,
    ) -> None:
        schedule = self.create_schedule(
            token=self.a_token,
            permit_id=self.a_permit_id,
            name="Phase2 HTTP A schedule resume",
        )

        foreign = self.request(
            "POST",
            f"/v1/schedules/{schedule['schedule_id']}/resume",
            token=self.b_token,
        )

        unknown = self.request(
            "POST",
            f"/v1/schedules/{UNKNOWN_SCHEDULE_ID}/resume",
            token=self.b_token,
        )

        self.assertEqual(
            self.error_signature(foreign),
            self.error_signature(unknown),
        )
        self.assertEqual(
            self.error_signature(foreign)[:2],
            (404, "schedule_not_found"),
        )

        status, _, victim = self.request(
            "GET",
            f"/v1/schedules/{schedule['schedule_id']}",
            token=self.a_token,
        )

        self.assertEqual(status, 200)
        self.assertEqual(victim["state"], "active")

    def test_job_cursor_cannot_cross_http_tenant_boundary(
        self,
    ) -> None:
        self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key="phase2-http-cursor-job-a1",
        )
        self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key="phase2-http-cursor-job-a2",
        )

        status, _, page = self.request(
            "GET",
            "/v1/jobs?limit=1",
            token=self.a_token,
        )

        self.assertEqual(status, 200)

        cursor = page["page"]["next_cursor"]
        self.assertIsNotNone(cursor)

        status, _, payload = self.request(
            "GET",
            f"/v1/jobs?limit=1&cursor={quote(cursor, safe='')}",
            token=self.b_token,
        )

        self.assertEqual(status, 400)
        self.assertEqual(
            payload["error"]["code"],
            "page_cursor_scope_mismatch",
        )

    def test_schedule_cursor_cannot_cross_http_tenant_boundary(
        self,
    ) -> None:
        self.create_schedule(
            token=self.a_token,
            permit_id=self.a_permit_id,
            name="Phase2 cursor A1",
            offset_hours=1,
        )
        self.create_schedule(
            token=self.a_token,
            permit_id=self.a_permit_id,
            name="Phase2 cursor A2",
            offset_hours=2,
        )

        status, _, page = self.request(
            "GET",
            "/v1/schedules?limit=1",
            token=self.a_token,
        )

        self.assertEqual(status, 200)

        cursor = page["page"]["next_cursor"]
        self.assertIsNotNone(cursor)

        status, _, payload = self.request(
            "GET",
            f"/v1/schedules?limit=1&cursor={quote(cursor, safe='')}",
            token=self.b_token,
        )

        self.assertEqual(status, 400)
        self.assertEqual(
            payload["error"]["code"],
            "page_cursor_scope_mismatch",
        )

    def test_audit_cursor_cannot_cross_http_tenant_boundary(
        self,
    ) -> None:
        self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key="phase2-http-audit-a1",
        )
        self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key="phase2-http-audit-a2",
        )

        status, _, page = self.request(
            "GET",
            "/v1/audit-events?limit=1",
            token=self.a_token,
        )

        self.assertEqual(status, 200)

        cursor = page["page"]["next_cursor"]
        self.assertIsNotNone(cursor)

        status, _, payload = self.request(
            "GET",
            f"/v1/audit-events?limit=1&cursor={quote(cursor, safe='')}",
            token=self.b_token,
        )

        self.assertEqual(status, 400)
        self.assertEqual(
            payload["error"]["code"],
            "page_cursor_scope_mismatch",
        )

    def test_same_http_idempotency_key_is_tenant_scoped(
        self,
    ) -> None:
        key = "phase2-http-shared-idempotency"

        a_job = self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key=key,
        )

        b_job = self.create_job(
            token=self.b_token,
            permit_id=self.b_permit_id,
            key=key,
        )

        self.assertNotEqual(
            a_job["job_id"],
            b_job["job_id"],
        )

        self.assertEqual(
            a_job["organization_id"],
            self.a_context.organization_id,
        )
        self.assertEqual(
            b_job["organization_id"],
            OTHER_ORG_ID,
        )

    def test_http_lists_do_not_leak_foreign_objects(
        self,
    ) -> None:
        a_job = self.create_job(
            token=self.a_token,
            permit_id=self.a_permit_id,
            key="phase2-http-list-a-job",
        )

        b_job = self.create_job(
            token=self.b_token,
            permit_id=self.b_permit_id,
            key="phase2-http-list-b-job",
        )

        a_schedule = self.create_schedule(
            token=self.a_token,
            permit_id=self.a_permit_id,
            name="Phase2 HTTP list A",
        )

        b_schedule = self.create_schedule(
            token=self.b_token,
            permit_id=self.b_permit_id,
            name="Phase2 HTTP list B",
        )

        status, _, jobs = self.request(
            "GET",
            "/v1/jobs?limit=100",
            token=self.b_token,
        )

        self.assertEqual(status, 200)

        job_ids = {
            item["job_id"]
            for item in jobs["jobs"]
        }

        self.assertIn(b_job["job_id"], job_ids)
        self.assertNotIn(a_job["job_id"], job_ids)

        status, _, schedules = self.request(
            "GET",
            "/v1/schedules?limit=100",
            token=self.b_token,
        )

        self.assertEqual(status, 200)

        schedule_ids = {
            item["schedule_id"]
            for item in schedules["schedules"]
        }

        self.assertIn(
            b_schedule["schedule_id"],
            schedule_ids,
        )
        self.assertNotIn(
            a_schedule["schedule_id"],
            schedule_ids,
        )

        status, _, audit = self.request(
            "GET",
            "/v1/audit-events?limit=100",
            token=self.b_token,
        )

        self.assertEqual(status, 200)
        self.assertTrue(audit["events"])

        for event in audit["events"]:
            self.assertEqual(
                event["organization_id"],
                OTHER_ORG_ID,
            )


if __name__ == "__main__":
    unittest.main()
