from __future__ import annotations

import http.client
import json
import tempfile
from datetime import timedelta
import threading
import unittest
from pathlib import Path

from webguard_api import (
    ApiTokenAuthenticator,
    ApiTransportError,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    ScanJobStore,
    WebGuardJobService,
    create_server,
)
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


def submission() -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
        }
    ).encode("utf-8")


def schedule_submission() -> bytes:
    starts_at = (NOW + timedelta(hours=1)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    return json.dumps(
        {
            "name": "Daily passive crawl",
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
            "interval_seconds": 86400,
            "starts_at": starts_at,
        }
    ).encode("utf-8")


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.context, self.token = create_identity_fixture(store.path)
        _, self.viewer_context, self.viewer_token = create_identity_fixture(
            store.path,
            role=OrganizationRole.VIEWER,
            principal_id=VIEWER_ID,
            token_id=VIEWER_TOKEN_ID,
        )
        service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
        )
        self.server = create_server(
            "127.0.0.1",
            0,
            service,
            authenticator=ApiTokenAuthenticator(identity),
            rate_limiter=FixedWindowRateLimiter(requests=100, window_seconds=60),
            maximum_request_bytes=1024,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method, path, body=None, headers=None, *, token="owner"):
        effective = dict(headers or {})
        if token == "owner":
            effective.setdefault("Authorization", f"Bearer {self.token}")
        elif token == "viewer":
            effective.setdefault("Authorization", f"Bearer {self.viewer_token}")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, body=body, headers=effective)
        response = connection.getresponse()
        payload = response.read()
        response_headers = dict(response.getheaders())
        status = response.status
        connection.close()
        return status, response_headers, json.loads(payload)

    def test_create_server_rejects_public_binding(self) -> None:
        with self.assertRaisesRegex(ApiTransportError, "loopback"):
            create_server(
                "0.0.0.0",
                0,
                None,
                authenticator=None,
                rate_limiter=None,
                maximum_request_bytes=1024,
            )

    def test_health_endpoint_is_public(self) -> None:
        status, headers, payload = self.request("GET", "/healthz", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("X-Request-ID", headers)

    def test_missing_bearer_token_is_401(self) -> None:
        status, headers, payload = self.request("GET", "/v1/me", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "authorization_header_required")
        self.assertIn("Bearer", headers["WWW-Authenticate"])

    def test_me_returns_scoped_identity(self) -> None:
        status, _, payload = self.request("GET", "/v1/me")
        self.assertEqual(status, 200)
        self.assertEqual(payload["organization_id"], self.context.organization_id)
        self.assertEqual(payload["role"], "owner")

    def test_submit_get_and_cancel_job(self) -> None:
        body = submission()
        status, headers, created = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-1",
            },
        )
        self.assertEqual(status, 201)
        self.assertIn("RateLimit-Remaining", headers)
        job_id = created["job_id"]
        status, _, fetched = self.request("GET", f"/v1/jobs/{job_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["job_id"], job_id)
        status, _, cancelled = self.request(
            "POST",
            f"/v1/jobs/{job_id}/cancel",
            body=b"",
            headers={"Content-Length": "0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(cancelled["state"], "cancelled")

    def test_viewer_cannot_submit(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "viewer-http-1",
            },
            token="viewer",
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "permission_denied")

    def test_idempotent_replay_returns_200(self) -> None:
        body = submission()
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Idempotency-Key": "internstack-http-2",
        }
        first = self.request("POST", "/v1/jobs", body=body, headers=headers)
        second = self.request("POST", "/v1/jobs", body=body, headers=headers)
        self.assertEqual(first[0], 201)
        self.assertEqual(second[0], 200)
        self.assertEqual(first[2]["job_id"], second[2]["job_id"])

    def test_result_not_ready_is_409(self) -> None:
        body = submission()
        status, _, created = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-3",
            },
        )
        self.assertEqual(status, 201)
        status, _, payload = self.request("GET", f"/v1/jobs/{created['job_id']}/result")
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "job_result_not_ready")

    def test_missing_idempotency_key_is_400(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "idempotency_key_required")

    def test_invalid_content_type_is_415(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "text/plain",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-4",
            },
        )
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "content_type_invalid")

    def test_oversized_body_is_413(self) -> None:
        body = b"x" * 1025
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-5",
            },
        )
        self.assertEqual(status, 413)
        self.assertEqual(payload["error"]["code"], "request_body_too_large")

    def test_query_string_is_rejected(self) -> None:
        status, _, payload = self.request("GET", "/healthz?verbose=1", token=None)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "request_query_not_allowed")

    def test_job_list_is_paginated_with_opaque_cursor(self) -> None:
        created_ids = []
        for index in range(3):
            body = submission()
            status, _, created = self.request(
                "POST",
                "/v1/jobs",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Idempotency-Key": f"pagination-http-{index}",
                },
            )
            self.assertEqual(status, 201)
            created_ids.append(created["job_id"])
        status, _, first = self.request("GET", "/v1/jobs?limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(len(first["jobs"]), 2)
        cursor = first["page"]["next_cursor"]
        self.assertIsInstance(cursor, str)
        self.assertNotIn(self.context.organization_id, cursor)
        status, _, second = self.request(
            "GET", f"/v1/jobs?limit=2&cursor={cursor}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(second["jobs"]), 1)
        self.assertIsNone(second["page"]["next_cursor"])
        returned = [item["job_id"] for item in first["jobs"] + second["jobs"]]
        self.assertEqual(set(returned), set(created_ids))
        self.assertEqual(len(returned), len(set(returned)))

    def test_job_list_filters_are_bound_to_cursor(self) -> None:
        body = submission()
        for index in range(2):
            self.request(
                "POST",
                "/v1/jobs",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Idempotency-Key": f"filter-http-{index}",
                },
            )
        status, _, first = self.request(
            "GET", "/v1/jobs?limit=1&state=queued&mode=crawl"
        )
        self.assertEqual(status, 200)
        cursor = first["page"]["next_cursor"]
        status, _, payload = self.request(
            "GET", f"/v1/jobs?limit=1&state=running&mode=crawl&cursor={cursor}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "page_cursor_filter_mismatch")

    def test_tampered_cursor_is_rejected(self) -> None:
        body = submission()
        for index in range(2):
            self.request(
                "POST",
                "/v1/jobs",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Idempotency-Key": f"tamper-http-{index}",
                },
            )
        _, _, first = self.request("GET", "/v1/jobs?limit=1")
        cursor = first["page"]["next_cursor"]
        payload_segment, signature_segment = cursor.split(".", 1)
        replacement = "A" if signature_segment[0] != "A" else "B"
        tampered = (
            f"{payload_segment}.{replacement}{signature_segment[1:]}"
        )
        status, _, payload = self.request(
            "GET", f"/v1/jobs?limit=1&cursor={tampered}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "page_cursor_signature_invalid")

    def test_list_query_validation_rejects_duplicate_unknown_and_invalid_values(self) -> None:
        cases = (
            ("/v1/jobs?limit=1&limit=2", "page_query_parameter_duplicate"),
            ("/v1/jobs?unknown=1", "page_query_parameter_unknown"),
            ("/v1/jobs?limit=101", "page_limit_invalid"),
            ("/v1/jobs?state=other", "page_filter_invalid"),
        )
        for path, code in cases:
            with self.subTest(path=path):
                status, _, payload = self.request("GET", path)
                self.assertEqual(status, 400)
                self.assertEqual(payload["error"]["code"], code)

    def test_unknown_route_is_404(self) -> None:
        status, _, payload = self.request("GET", "/v1/unknown")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "route_not_found")

    def test_unsupported_method_is_405(self) -> None:
        status, _, payload = self.request("PUT", "/v1/jobs")
        self.assertEqual(status, 405)
        self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_submission_response_does_not_echo_secrets(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-6",
            },
        )
        self.assertEqual(status, 201)
        serialized = json.dumps(payload)
        self.assertNotIn("confirm_authorization", serialized)
        self.assertNotIn(self.token, serialized)

    def test_owner_can_read_audit_events(self) -> None:
        self.request("GET", "/v1/me")
        status, _, payload = self.request("GET", "/v1/audit-events")
        self.assertEqual(status, 200)
        self.assertTrue(payload["events"])

    def test_schedule_create_list_pause_and_resume(self) -> None:
        body = schedule_submission()
        status, _, created = self.request(
            "POST",
            "/v1/schedules",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        self.assertEqual(status, 201)
        schedule_id = created["schedule_id"]
        status, _, listing = self.request("GET", "/v1/schedules")
        self.assertEqual(status, 200)
        self.assertEqual(listing["schedules"][0]["schedule_id"], schedule_id)
        status, _, fetched = self.request("GET", f"/v1/schedules/{schedule_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["schedule_id"], schedule_id)
        status, _, paused = self.request(
            "POST",
            f"/v1/schedules/{schedule_id}/pause",
            body=b"",
            headers={"Content-Length": "0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(paused["state"], "paused")
        status, _, resumed = self.request(
            "POST",
            f"/v1/schedules/{schedule_id}/resume",
            body=b"",
            headers={"Content-Length": "0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(resumed["state"], "active")

    def test_viewer_can_list_schedules_but_cannot_create(self) -> None:
        body = schedule_submission()
        status, _, payload = self.request(
            "POST",
            "/v1/schedules",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            token="viewer",
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "permission_denied")
        status, _, listing = self.request("GET", "/v1/schedules", token="viewer")
        self.assertEqual(status, 200)
        self.assertEqual(listing["schedules"], [])
        self.assertEqual(listing["page"]["limit"], 50)
        self.assertIsNone(listing["page"]["next_cursor"])

    def test_schedule_state_body_is_rejected(self) -> None:
        body = schedule_submission()
        status, _, created = self.request(
            "POST",
            "/v1/schedules",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        self.assertEqual(status, 201)
        status, _, payload = self.request(
            "POST",
            f"/v1/schedules/{created['schedule_id']}/pause",
            body=b"x",
            headers={"Content-Length": "1"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "schedule_body_not_allowed")

    def test_viewer_cannot_read_audit_events(self) -> None:
        status, _, payload = self.request("GET", "/v1/audit-events", token="viewer")
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "permission_denied")


if __name__ == "__main__":
    unittest.main()
