"""P1-B1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
call-site proofs that the HTTP API emits request_completed/
request_failed/readiness_failed with correct fields, health-probe
traffic excluded from request_completed, and readiness_failed
edge-triggered rather than emitted on every failing probe. Reuses
test_http_api.py's own real-server, real-socket fixture pattern.
"""

from __future__ import annotations

import http.client
import io
import json
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
from webguard_api.structured_logging import configure_structured_logging

from tests.unit.service_test_support import NOW, create_identity_fixture, write_authorization


def _lines(buf: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def _events(buf: io.StringIO, name: str) -> list[dict]:
    return [line for line in _lines(buf) if line.get("event") == name]


class HttpApiStructuredEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.context, self.token = create_identity_fixture(store.path)
        self.service = WebGuardJobService(
            store=store, authorizations=AuthorizationRepository(auth_dir), identity=identity, clock=lambda: NOW,
        )
        self.server = create_server(
            "127.0.0.1", 0, self.service,
            authenticator=ApiTokenAuthenticator(identity),
            rate_limiter=FixedWindowRateLimiter(requests=100, window_seconds=60),
            maximum_request_bytes=1024, clock=lambda: NOW, epoch_clock=lambda: 1000.0,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]
        self.addCleanup(self._teardown_server)
        self.buf = io.StringIO()
        configure_structured_logging(service="api", stream=self.buf)

    def _teardown_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _get(self, path: str, headers=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=3)
        try:
            conn.request("GET", path, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_request_completed_on_a_normal_4xx_outcome(self) -> None:
        status, _ = self._get("/v1/unknown-route", headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(status, 404)
        completed = _events(self.buf, "request_completed")
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["status_code"], 404)
        self.assertEqual(completed[0]["http_method"], "GET")
        self.assertIn("request_id", completed[0])
        self.assertIn("duration_ms", completed[0])
        self.assertEqual(_events(self.buf, "request_failed"), [], "an ordinary 4xx is not an operational failure")

    def test_request_completed_on_success(self) -> None:
        status, _ = self._get("/v1/auth/session", headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(status, 200)
        completed = _events(self.buf, "request_completed")
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["status_code"], 200)

    def test_healthz_and_ready_success_are_excluded_from_request_completed(self) -> None:
        self._get("/healthz")
        self._get("/health")
        self._get("/ready")
        self.assertEqual(_events(self.buf, "request_completed"), [])
        self.assertEqual(_events(self.buf, "request_failed"), [])

    def test_readiness_failed_is_edge_triggered_not_per_probe(self) -> None:
        state = {"ready": True}
        self.service.readiness = lambda: (state["ready"], "dependency_unavailable" if not state["ready"] else "ready")

        state["ready"] = False
        for _ in range(5):
            status, _ = self._get("/ready")
            self.assertEqual(status, 503)

        failed = _events(self.buf, "readiness_failed")
        self.assertEqual(len(failed), 1, "must be exactly one event across 5 consecutive failing probes")
        self.assertEqual(failed[0]["reason_code"], "dependency_unavailable")

        state["ready"] = True
        status, _ = self._get("/ready")
        self.assertEqual(status, 200)

        state["ready"] = False
        status, _ = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(
            len(_events(self.buf, "readiness_failed")), 2,
            "a NEW outage episode after recovery must produce a second event",
        )


if __name__ == "__main__":
    unittest.main()
