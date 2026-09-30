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


def _matching(buf: io.StringIO, name: str, *, request_id: str) -> list[dict]:
    return [event for event in _events(buf, name) if event.get("request_id") == request_id]


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
        # Test-only override, set before serve_forever() ever accepts a
        # connection: create_server() sets daemon_threads=True for the
        # real production server, but socketserver.ThreadingMixIn's own
        # _Threads.append() silently refuses to track a thread whose
        # .daemon is True (see socketserver.py), so server_close() never
        # joins a daemon handler thread -- confirmed by reading that
        # source and empirically (a daemon handler thread deliberately
        # blocked mid-request; server_close() still returned in 0.000s
        # while it was still running). ThreadingMixIn.process_request()
        # reads self.daemon_threads fresh for every new connection, so
        # overriding the instance attribute here, before this server's
        # thread starts accepting connections, is sufficient: every
        # handler thread this server ever spawns is non-daemon, tracked,
        # and therefore actually joined by server_close() below. This
        # touches only this test's own server instance, not create_server()
        # or production server construction.
        self.server.daemon_threads = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]
        self.addCleanup(self._teardown_server)
        self.buf = io.StringIO()
        configure_structured_logging(service="api", stream=self.buf)

    def _shutdown_server(self) -> None:
        """Stops the accept loop, then closes the server. Because
        setUp() overrode this server instance to daemon_threads=False,
        server_close()'s block_on_close join (ThreadingMixIn's own
        _Threads.join(), stdlib default, not overridden) now actually
        covers every per-request handler thread this server spawned.
        Calling this after making a request and before reading the log
        buffer proves that request's handler -- including its
        post-response log_event() call -- has already finished, so an
        exactly-once check afterward is a true "exactly one,
        permanently" claim rather than "exactly one, so far."
        Idempotent: shutdown/close/join are all no-ops on a server
        that is already stopped, so calling this mid-test and again
        from the addCleanup teardown is safe.
        """
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _teardown_server(self) -> None:
        self._shutdown_server()

    def _get(self, path: str, headers=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=3)
        try:
            conn.request("GET", path, headers=headers or {})
            response = conn.getresponse()
            body = response.read()
            return response.status, body, response.getheader("X-Request-ID")
        finally:
            conn.close()

    def test_request_completed_on_a_normal_4xx_outcome(self) -> None:
        status, _, request_id = self._get(
            "/v1/unknown-route", headers={"Authorization": f"Bearer {self.token}"}
        )
        self.assertEqual(status, 404)
        self.assertIsNotNone(request_id)
        self._shutdown_server()
        completed = _matching(self.buf, "request_completed", request_id=request_id)
        self.assertEqual(len(completed), 1, "exactly one request_completed event for this request_id")
        self.assertEqual(completed[0]["status_code"], 404)
        self.assertEqual(completed[0]["http_method"], "GET")
        self.assertIn("request_id", completed[0])
        self.assertIn("duration_ms", completed[0])
        self.assertEqual(_events(self.buf, "request_failed"), [], "an ordinary 4xx is not an operational failure")

    def test_request_completed_on_success(self) -> None:
        status, _, request_id = self._get(
            "/v1/auth/session", headers={"Authorization": f"Bearer {self.token}"}
        )
        self.assertEqual(status, 200)
        self.assertIsNotNone(request_id)
        self._shutdown_server()
        completed = _matching(self.buf, "request_completed", request_id=request_id)
        self.assertEqual(len(completed), 1, "exactly one request_completed event for this request_id")
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
            status, _, _ = self._get("/ready")
            self.assertEqual(status, 503)

        failed = _events(self.buf, "readiness_failed")
        self.assertEqual(len(failed), 1, "must be exactly one event across 5 consecutive failing probes")
        self.assertEqual(failed[0]["reason_code"], "dependency_unavailable")

        state["ready"] = True
        status, _, _ = self._get("/ready")
        self.assertEqual(status, 200)

        state["ready"] = False
        status, _, _ = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(
            len(_events(self.buf, "readiness_failed")), 2,
            "a NEW outage episode after recovery must produce a second event",
        )


if __name__ == "__main__":
    unittest.main()
