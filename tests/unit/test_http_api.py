from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from webguard_api import (
    ApiTransportError,
    AuthorizationRepository,
    ScanJobStore,
    WebGuardJobService,
    create_server,
)

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET, write_authorization


def submission() -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
        }
    ).encode("utf-8")


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            clock=lambda: NOW,
        )
        self.server = create_server(
            "127.0.0.1",
            0,
            service,
            maximum_request_bytes=1024,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, dict(response.getheaders()), json.loads(payload)


    def test_create_server_rejects_public_binding(self) -> None:
        with self.assertRaisesRegex(ApiTransportError, "loopback"):
            create_server(
                "0.0.0.0",
                0,
                self.server.RequestHandlerClass.service if False else None,
                maximum_request_bytes=1024,
            )

    def test_health_endpoint(self) -> None:
        status, headers, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_submit_get_and_cancel_job(self) -> None:
        body = submission()
        status, _, created = self.request(
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
        status, _, payload = self.request(
            "GET",
            f"/v1/jobs/{created['job_id']}/result",
        )
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "job_result_not_ready")

    def test_missing_idempotency_key_is_400(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
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
        status, _, payload = self.request("GET", "/healthz?verbose=1")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "request_target_invalid")

    def test_unknown_route_is_404(self) -> None:
        status, _, payload = self.request("GET", "/v1/unknown")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "route_not_found")

    def test_unsupported_method_is_405(self) -> None:
        status, _, payload = self.request("PUT", "/v1/jobs")
        self.assertEqual(status, 405)
        self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_submission_response_does_not_echo_confirmation(self) -> None:
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
        self.assertNotIn("confirmation", serialized)


if __name__ == "__main__":
    unittest.main()
