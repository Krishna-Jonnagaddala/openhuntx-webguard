"""P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md): the
key P1-4 proof -- combined `webguard-api serve`'s single `/ready` must
reflect embedded worker/scheduler health, not just "did the HTTP
listener answer." Exercises `create_server`'s `additional_readiness_checks`
composition directly (the exact mechanism `cli.py::_serve_command`
wires up), reusing test_http_api_structured_events.py's own real-
server fixture pattern. `/healthz` is deliberately untouched by this
composition -- proven here to stay green throughout, exactly matching
liveness != readiness.
"""

from __future__ import annotations

import http.client
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

from tests.unit.service_test_support import NOW, create_identity_fixture, write_authorization


class ComposedServeReadinessTests(unittest.TestCase):
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
        self.identity = identity

    def _start(self, additional_readiness_checks=()) -> None:
        self.server = create_server(
            "127.0.0.1", 0, self.service,
            authenticator=ApiTokenAuthenticator(self.identity),
            rate_limiter=FixedWindowRateLimiter(requests=100, window_seconds=60),
            maximum_request_bytes=1024, clock=lambda: NOW, epoch_clock=lambda: 1000.0,
            additional_readiness_checks=additional_readiness_checks,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]
        self.addCleanup(self._teardown)

    def _teardown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _get(self, path: str):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=3)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_all_healthy_reports_ready(self) -> None:
        self._start([lambda: (True, "ready"), lambda: (True, "ready")])
        status, body = self._get("/ready")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ready")

    def test_worker_progress_stalled_reports_that_specific_reason(self) -> None:
        self._start(
            [
                lambda: (False, "worker_progress_stalled"),
                lambda: (False, "worker_dependency_unavailable"),
                lambda: (False, "scheduler_progress_stalled"),
                lambda: (False, "scheduler_dependency_unavailable"),
            ]
        )
        status, body = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["reason"], "worker_progress_stalled")

    def test_worker_dependency_unavailable_when_progress_healthy(self) -> None:
        self._start(
            [
                lambda: (True, "ready"),
                lambda: (False, "worker_dependency_unavailable"),
                lambda: (False, "scheduler_progress_stalled"),
                lambda: (False, "scheduler_dependency_unavailable"),
            ]
        )
        status, body = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["reason"], "worker_dependency_unavailable")

    def test_scheduler_progress_stalled_when_worker_healthy(self) -> None:
        self._start(
            [
                lambda: (True, "ready"),
                lambda: (True, "ready"),
                lambda: (False, "scheduler_progress_stalled"),
                lambda: (False, "scheduler_dependency_unavailable"),
            ]
        )
        status, body = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["reason"], "scheduler_progress_stalled")

    def test_scheduler_dependency_unavailable_when_everything_else_healthy(self) -> None:
        self._start(
            [
                lambda: (True, "ready"),
                lambda: (True, "ready"),
                lambda: (True, "ready"),
                lambda: (False, "scheduler_dependency_unavailable"),
            ]
        )
        status, body = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["reason"], "scheduler_dependency_unavailable")

    def test_precedence_worker_checked_before_scheduler(self) -> None:
        # Both worker and scheduler are unhealthy -- the deterministic
        # precedence (API -> worker progress -> worker dependency ->
        # scheduler progress -> scheduler dependency) must report the
        # worker's reason, never the scheduler's, and never both.
        self._start(
            [
                lambda: (False, "worker_progress_stalled"),
                lambda: (True, "ready"),
                lambda: (False, "scheduler_progress_stalled"),
                lambda: (True, "ready"),
            ]
        )
        status, body = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["reason"], "worker_progress_stalled")

    def test_no_extra_checks_matches_pre_p1_b2_behavior_exactly(self) -> None:
        # A standalone API-only process (no worker/scheduler embedded)
        # -- the default empty tuple -- must behave byte-for-byte as
        # it did before P1-B2.
        self._start()
        status, body = self._get("/ready")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ready", "reason": "ready"})

    def test_healthz_stays_green_even_while_ready_fails(self) -> None:
        # The key P1-4 proof: the worker loop having stopped making
        # progress must not be masked by "the HTTP server answered."
        # /healthz is a separate, simpler check -- untouched by
        # additional_readiness_checks entirely -- and must keep
        # answering 200 throughout.
        self._start([lambda: (False, "worker_progress_stalled")])
        status, _ = self._get("/healthz")
        self.assertEqual(status, 200)
        status, body = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["reason"], "worker_progress_stalled")
        # And /healthz right after, proving the failing /ready probe
        # didn't somehow affect it.
        status, _ = self._get("/healthz")
        self.assertEqual(status, 200)

    def test_extra_checks_never_run_when_api_dependency_itself_is_down(self) -> None:
        calls: list[str] = []

        def worker_check():
            calls.append("worker")
            return True, "ready"

        service = self.service
        service.readiness_check = lambda: (_ for _ in ()).throw(RuntimeError("db down"))  # type: ignore[method-assign]
        self._start([worker_check])
        status, body = self._get("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["reason"], "dependency_unavailable")
        self.assertEqual(calls, [], "worker/scheduler checks must not run once the API's own dependency already failed")


if __name__ == "__main__":
    unittest.main()
