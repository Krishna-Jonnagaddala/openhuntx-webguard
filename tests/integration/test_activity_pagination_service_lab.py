from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from webguard_api import (
    ApiTokenAuthenticator,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    ScanJobStore,
    WebGuardJobService,
    create_server,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    TARGET,
    create_identity_fixture,
    write_authorization,
)

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


@unittest.skipUnless(
    RUN_INTEGRATION,
    "Set WEBGUARD_RUN_INTEGRATION=1 to run service integration tests.",
)
class ActivityPaginationServiceIntegrationTests(unittest.TestCase):
    def test_authenticated_job_feed_pages_without_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir = root / "authorizations"
            write_authorization(auth_dir)
            store = ScanJobStore(root / "jobs.sqlite3")
            identity, context, token = create_identity_fixture(store.path)
            service = WebGuardJobService(
                store=store,
                authorizations=AuthorizationRepository(auth_dir),
                identity=identity,
                clock=lambda: NOW,
            )
            server = create_server(
                "127.0.0.1",
                0,
                service,
                authenticator=ApiTokenAuthenticator(identity),
                rate_limiter=FixedWindowRateLimiter(requests=100, window_seconds=60),
                maximum_request_bytes=4096,
                clock=lambda: NOW,
                epoch_clock=lambda: 1000.0,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]

            def request(method: str, path: str, *, body: bytes | None = None, headers=None):
                effective = {"Authorization": f"Bearer {token}", **(headers or {})}
                connection = http.client.HTTPConnection(host, port, timeout=3)
                connection.request(method, path, body=body, headers=effective)
                response = connection.getresponse()
                payload = json.loads(response.read())
                status = response.status
                connection.close()
                return status, payload

            try:
                created_ids = []
                body = json.dumps(
                    {
                        "target": TARGET,
                        "authorization_id": AUTH_ID,
                        "confirm_authorization": AUTH_ID,
                        "mode": "crawl",
                    }
                ).encode("utf-8")
                for index in range(3):
                    status, created = request(
                        "POST",
                        "/v1/jobs",
                        body=body,
                        headers={
                            "Content-Type": "application/json",
                            "Content-Length": str(len(body)),
                            "Idempotency-Key": f"activity-integration-{index}",
                        },
                    )
                    self.assertEqual(status, 201)
                    self.assertEqual(created["organization_id"], context.organization_id)
                    created_ids.append(created["job_id"])

                status, first = request("GET", "/v1/jobs?limit=2")
                self.assertEqual(status, 200)
                self.assertEqual(len(first["jobs"]), 2)
                cursor = first["page"]["next_cursor"]
                self.assertIsInstance(cursor, str)

                status, second = request(
                    "GET", f"/v1/jobs?limit=2&cursor={cursor}"
                )
                self.assertEqual(status, 200)
                self.assertEqual(len(second["jobs"]), 1)
                self.assertIsNone(second["page"]["next_cursor"])

                returned = [
                    item["job_id"]
                    for item in first["jobs"] + second["jobs"]
                ]
                self.assertEqual(set(returned), set(created_ids))
                self.assertEqual(len(returned), len(set(returned)))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
