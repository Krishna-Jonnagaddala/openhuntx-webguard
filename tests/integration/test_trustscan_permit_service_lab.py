from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import unittest
from datetime import timedelta
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


def timestamp(value) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


@unittest.skipUnless(
    RUN_INTEGRATION,
    "Set WEBGUARD_RUN_INTEGRATION=1 to run service integration tests.",
)
class TrustScanPermitServiceIntegrationTests(unittest.TestCase):
    def test_issue_bind_revoke_and_fail_closed(self) -> None:
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
                permit_body = json.dumps(
                    {
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
                        "authorization_comparison_plan_id": None,
                        "missing_authentication_endpoints": [],
                    }
                ).encode("utf-8")
                status, issued = request(
                    "POST",
                    "/v1/permits",
                    body=permit_body,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(permit_body)),
                    },
                )
                self.assertEqual(status, 201)
                permit_id = issued["permit"]["claims"]["permit_id"]
                self.assertEqual(issued["state"], "active")

                job_body = json.dumps(
                    {
                        "target": TARGET,
                        "authorization_id": AUTH_ID,
                        "confirm_authorization": AUTH_ID,
                        "mode": "crawl",
                    }
                ).encode("utf-8")
                status, created = request(
                    "POST",
                    "/v1/jobs",
                    body=job_body,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(job_body)),
                        "Idempotency-Key": "trustscan-service-integration-1",
                        "TrustScan-Permit": permit_id,
                    },
                )
                self.assertEqual(status, 201)
                self.assertEqual(
                    created["trustscan_permit"]["permit_id"],
                    permit_id,
                )
                self.assertEqual(created["organization_id"], context.organization_id)

                status, revoked = request(
                    "POST",
                    f"/v1/permits/{permit_id}/revoke",
                    body=b"",
                    headers={"Content-Length": "0"},
                )
                self.assertEqual(status, 200)
                self.assertEqual(revoked["state"], "revoked")

                status, denied = request(
                    "POST",
                    "/v1/jobs",
                    body=job_body,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(job_body)),
                        "Idempotency-Key": "trustscan-service-integration-2",
                        "TrustScan-Permit": permit_id,
                    },
                )
                self.assertEqual(status, 403)
                self.assertEqual(denied["error"]["code"], "trustscan_permit_revoked")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
