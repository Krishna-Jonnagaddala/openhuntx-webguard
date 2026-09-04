"""P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
core tests for `webguard_api.health_server` -- the shared internal
`/healthz`+`/ready` listener reused by worker/scheduler/callback-
service/signing-service. Proves the fixed response schema, the
failure-safety model (a callback that raises never crashes the
listener or leaks a traceback), edge-triggered readiness_failed/
_recovered logging, and that nothing sensitive-shaped can appear in a
response body regardless of what a callback's exception message
contains.
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
import urllib.request

from webguard_api.health_server import HealthServer, validate_health_port, validate_stale_seconds
from webguard_api.structured_logging import configure_structured_logging


def _get(url: str) -> tuple[int, dict, dict]:
    try:
        response = urllib.request.urlopen(url, timeout=3)
        body = json.loads(response.read())
        return response.status, dict(response.getheaders()), body
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read())
        return exc.code, dict(exc.headers.items()), body


def _post(url: str) -> int:
    request = urllib.request.Request(url, method="POST", data=b"")
    try:
        urllib.request.urlopen(request, timeout=3)
        raise AssertionError("POST should have been rejected")
    except urllib.error.HTTPError as exc:
        return exc.code


class HealthServerCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.buf = io.StringIO()
        configure_structured_logging(service="worker", stream=self.buf)
        self.ready_state = {"ready": True}
        self.alive_state = {"alive": True}
        self.server = HealthServer(
            service="worker",
            liveness_check=lambda: (self.alive_state["alive"], "worker_progress_stalled"),
            readiness_check=lambda: (self.ready_state["ready"], "worker_dependency_unavailable"),
            port=0,
        )
        self.server.start()
        self.addCleanup(self.server.stop)

    def test_healthz_healthy(self) -> None:
        status, headers, body = _get(self.server.base_url + "healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("Content-Length"), str(len(b'{"status":"ok"}')))

    def test_healthz_unhealthy(self) -> None:
        self.alive_state["alive"] = False
        status, _, body = _get(self.server.base_url + "healthz")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"status": "not_ready", "reason": "worker_progress_stalled"})

    def test_ready_healthy(self) -> None:
        status, _, body = _get(self.server.base_url + "ready")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_ready_dependency_failure(self) -> None:
        self.ready_state["ready"] = False
        status, _, body = _get(self.server.base_url + "ready")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"status": "not_ready", "reason": "worker_dependency_unavailable"})

    def test_unknown_path_fixed_404(self) -> None:
        status, _, body = _get(self.server.base_url + "some/other/path")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"status": "not_found"})

    def test_post_fixed_rejection(self) -> None:
        status = _post(self.server.base_url + "ready")
        self.assertEqual(status, 405)

    def test_content_length_correct_for_not_ready_body(self) -> None:
        self.ready_state["ready"] = False
        status, headers, body = _get(self.server.base_url + "ready")
        expected = json.dumps(body, separators=(",", ":")).encode("ascii")
        # Compare byte length, not the exact serialization (key order
        # is fixed in this module, but this assertion should not be
        # sensitive to it).
        self.assertEqual(int(headers["Content-Length"]), len(expected))

    def test_query_parameters_ignored_not_echoed(self) -> None:
        status, _, body = _get(self.server.base_url + "healthz?foo=bar&baz=qux")
        self.assertEqual(status, 200)
        self.assertNotIn("foo", json.dumps(body))

    def test_repeated_start_stop_is_safe(self) -> None:
        server = HealthServer(
            service="worker", liveness_check=lambda: (True, "ready"), readiness_check=lambda: (True, "ready"), port=0,
        )
        server.start()
        status, _, _ = _get(server.base_url + "healthz")
        self.assertEqual(status, 200)
        server.stop()
        # A second stop() must not raise.
        server.stop()

    def test_host_override_rejected(self) -> None:
        with self.assertRaises(ValueError):
            HealthServer(
                service="worker", liveness_check=lambda: (True, "ready"), readiness_check=lambda: (True, "ready"),
                port=0, host="0.0.0.0",
            )


class HealthServerFailureSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.buf = io.StringIO()
        configure_structured_logging(service="worker", stream=self.buf)

    def test_readiness_callback_exception_returns_fixed_health_check_failed(self) -> None:
        def raising_check() -> tuple[bool, str]:
            raise RuntimeError("boom: password=hunter2 at /etc/webguard/secret.conf")

        server = HealthServer(
            service="worker", liveness_check=lambda: (True, "ready"), readiness_check=raising_check, port=0,
        )
        server.start()
        self.addCleanup(server.stop)

        status, _, body = _get(server.base_url + "ready")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"status": "not_ready", "reason": "health_check_failed"})
        self.assertNotIn("boom", json.dumps(body))
        self.assertNotIn("hunter2", json.dumps(body))
        self.assertNotIn("/etc/webguard", json.dumps(body))

    def test_liveness_callback_exception_does_not_crash_listener(self) -> None:
        def raising_check() -> tuple[bool, str]:
            raise RuntimeError("unexpected")

        server = HealthServer(
            service="worker", liveness_check=raising_check, readiness_check=lambda: (True, "ready"), port=0,
        )
        server.start()
        self.addCleanup(server.stop)

        status, _, body = _get(server.base_url + "healthz")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"status": "not_ready", "reason": "health_check_failed"})
        # The listener must still answer normally afterward -- one bad
        # probe must not have crashed the server thread.
        status, _, body = _get(server.base_url + "healthz")
        self.assertEqual(status, 503)

    def test_readiness_exception_logs_only_safe_exception_metadata(self) -> None:
        def raising_check() -> tuple[bool, str]:
            raise ValueError("sensitive: user@example.com token=abc123")

        server = HealthServer(
            service="worker", liveness_check=lambda: (True, "ready"), readiness_check=raising_check, port=0,
        )
        server.start()
        self.addCleanup(server.stop)

        _get(server.base_url + "ready")
        logged = self.buf.getvalue()
        self.assertNotIn("sensitive", logged)
        self.assertNotIn("abc123", logged)
        parsed = json.loads(logged.splitlines()[0])
        self.assertEqual(parsed["event"], "readiness_failed")
        self.assertEqual(parsed["reason_code"], "health_check_failed")
        self.assertEqual(parsed["exception_type"], "ValueError")


class ReadinessTransitionLoggingTests(unittest.TestCase):
    """P1-B2 Section 4: edge-triggered readiness_failed/readiness_recovered
    -- one event per transition, not one per probe for as long as the
    same state continues."""

    def setUp(self) -> None:
        self.buf = io.StringIO()
        configure_structured_logging(service="worker", stream=self.buf)
        self.ready_state = {"ready": True}
        self.server = HealthServer(
            service="worker",
            liveness_check=lambda: (True, "ready"),
            readiness_check=lambda: (self.ready_state["ready"], "worker_dependency_unavailable"),
            port=0,
        )
        self.server.start()
        self.addCleanup(self.server.stop)

    def _events(self) -> list[str]:
        return [json.loads(line)["event"] for line in self.buf.getvalue().splitlines() if line]

    def test_edge_triggered_failed_then_recovered_then_failed_again(self) -> None:
        _get(self.server.base_url + "ready")  # healthy -> healthy: no event
        self.assertEqual(self._events(), [])

        self.ready_state["ready"] = False
        for _ in range(5):
            _get(self.server.base_url + "ready")
        # Five consecutive failing probes during one continuous outage
        # -> exactly one readiness_failed, not five.
        self.assertEqual(self._events(), ["readiness_failed"])

        self.ready_state["ready"] = True
        for _ in range(3):
            _get(self.server.base_url + "ready")
        # Recovery, then continued healthy probes -> exactly one
        # readiness_recovered.
        self.assertEqual(self._events(), ["readiness_failed", "readiness_recovered"])

        self.ready_state["ready"] = False
        _get(self.server.base_url + "ready")
        self.assertEqual(
            self._events(), ["readiness_failed", "readiness_recovered", "readiness_failed"]
        )

    def test_readiness_failed_event_carries_only_safe_fields(self) -> None:
        self.ready_state["ready"] = False
        _get(self.server.base_url + "ready")
        parsed = json.loads(self.buf.getvalue().splitlines()[0])
        self.assertEqual(set(parsed) - {"timestamp", "level", "service", "event"}, {"reason_code"})
        self.assertEqual(parsed["reason_code"], "worker_dependency_unavailable")


class RedactionProofTests(unittest.TestCase):
    """P1-B2 Section 25/26: health response bodies must never contain
    anything sensitive, regardless of what a reason/exception carries."""

    def setUp(self) -> None:
        self.buf = io.StringIO()
        configure_structured_logging(service="callback-service", stream=self.buf)

    def test_marked_secrets_never_appear_in_response_body(self) -> None:
        fake_dsn = "postgresql://webguard:fake-not-a-real-password-000@10.0.0.5:5432/webguard"
        fake_token = "tok_" + "z" * 40
        fake_pin = "0000-FAKE-CLOUDHSM-PIN"

        def leaking_check() -> tuple[bool, str]:
            raise RuntimeError(f"connect failed: dsn={fake_dsn} token={fake_token} pin={fake_pin}")

        server = HealthServer(
            service="callback-service", liveness_check=lambda: (True, "ready"), readiness_check=leaking_check, port=0,
        )
        server.start()
        self.addCleanup(server.stop)

        status, _, body = _get(server.base_url + "ready")
        self.assertEqual(status, 503)
        dumped = json.dumps(body)
        for secret in (fake_dsn, fake_token, fake_pin, "10.0.0.5", "5432"):
            self.assertNotIn(secret, dumped)
        self.assertEqual(body, {"status": "not_ready", "reason": "health_check_failed"})


class PortAndStaleSecondsValidationTests(unittest.TestCase):
    def test_valid_port_accepted(self) -> None:
        self.assertEqual(validate_health_port("8768", env_var_name="X"), 8768)

    def test_port_zero_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_health_port("0", env_var_name="X")

    def test_port_negative_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_health_port("-1", env_var_name="X")

    def test_port_too_large_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_health_port("65536", env_var_name="X")

    def test_port_non_numeric_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_health_port("not-a-port", env_var_name="X")

    def test_valid_stale_seconds_accepted(self) -> None:
        self.assertEqual(validate_stale_seconds("5.5", env_var_name="X"), 5.5)

    def test_stale_seconds_zero_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_stale_seconds("0", env_var_name="X")

    def test_stale_seconds_negative_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_stale_seconds("-5", env_var_name="X")

    def test_stale_seconds_nan_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_stale_seconds("nan", env_var_name="X")

    def test_stale_seconds_infinity_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_stale_seconds("inf", env_var_name="X")

    def test_stale_seconds_absurdly_large_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_stale_seconds("999999999", env_var_name="X")


if __name__ == "__main__":
    unittest.main()
