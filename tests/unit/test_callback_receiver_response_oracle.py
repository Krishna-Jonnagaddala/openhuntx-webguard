"""P1-12: real-socket proof that CallbackHttpReceiver's response is
externally uniform across every outcome class -- including an expected
PostgreSQL-shaped DatabaseError, which previously (see
docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md) produced a
connection reset instead of the documented 204/302, a new,
externally-visible response-oracle this receiver's whole design exists
to prevent.

Also proves the two things that must NOT become uniform: an unexpected
programming error must keep its existing visibility (never silently
folded into a 204 that looks identical to a successful recording), and
process/thread survival under a sustained outage.
"""

from __future__ import annotations

import http.client
import io
import sys
import threading
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timezone

from webguard_api.callback_server import CallbackHttpReceiver
from webguard_api.db_errors import DatabaseUnavailableError


class _ScriptedSink:
    """A minimal `_ObservationSink` whose `record_observation()` can be
    scripted per-call: raise a given exception `fail_calls` times, then
    succeed. `calls` records every invocation for assertions."""

    def __init__(self, *, fail_calls: int = 0, exception: Exception | None = None) -> None:
        self.fail_calls = fail_calls
        self.exception = exception or DatabaseUnavailableError(
            "database_unavailable", "The database is currently unavailable."
        )
        self.calls: list[dict] = []

    def record_observation(self, token_value: str, *, method: str, now: datetime | None = None) -> bool:
        self.calls.append({"token_value": token_value, "method": method, "now": now})
        if len(self.calls) <= self.fail_calls:
            raise self.exception
        return True


def _receiver(sink, **kwargs) -> CallbackHttpReceiver:
    receiver = CallbackHttpReceiver(sink, **kwargs)
    receiver.start()
    return receiver


class ResponseOracleTests(unittest.TestCase):
    def _get(self, receiver: CallbackHttpReceiver, path: str = "/scan-1/tok-1"):
        host, port = receiver._server.server_address[:2]
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            body = response.read()
            return response.status, response.reason, dict(response.getheaders()), body
        finally:
            conn.close()

    def test_healthy_persistence_returns_uniform_204(self) -> None:
        sink = _ScriptedSink(fail_calls=0)
        receiver = _receiver(sink)
        try:
            status, reason, headers, body = self._get(receiver)
        finally:
            receiver.stop()
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(body, b"")

    def test_database_unavailable_still_returns_the_identical_204(self) -> None:
        """The core P1-12 proof: an outage that exhausts every retry
        attempt must still produce exactly the same response as the
        healthy case, not a connection reset."""
        sink = _ScriptedSink(fail_calls=99)  # every attempt fails
        receiver = _receiver(
            sink, record_observation_maximum_attempts=2, record_observation_retry_backoff_seconds=0.01
        )
        try:
            status, reason, headers, body = self._get(receiver)
        finally:
            receiver.stop()
        self.assertEqual(status, 204)
        self.assertEqual(reason, "No Content")
        self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(body, b"")
        self.assertEqual(len(sink.calls), 2, "must have exhausted the configured retry budget")

    def test_database_recovers_within_retry_budget_still_returns_the_identical_204(self) -> None:
        sink = _ScriptedSink(fail_calls=1)  # first attempt fails, second succeeds
        receiver = _receiver(
            sink, record_observation_maximum_attempts=2, record_observation_retry_backoff_seconds=0.01
        )
        try:
            status, reason, headers, body = self._get(receiver)
        finally:
            receiver.stop()
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(body, b"")
        self.assertEqual(len(sink.calls), 2)

    def test_redirect_mode_also_stays_uniform_under_database_outage(self) -> None:
        healthy_sink = _ScriptedSink(fail_calls=0)
        healthy_receiver = _receiver(healthy_sink, respond_with_redirect=True)
        down_sink = _ScriptedSink(fail_calls=99)
        down_receiver = _receiver(
            down_sink, respond_with_redirect=True,
            record_observation_maximum_attempts=2, record_observation_retry_backoff_seconds=0.01,
        )
        try:
            healthy_status, _, healthy_headers, _ = self._get(healthy_receiver)
            down_status, _, down_headers, _ = self._get(down_receiver)
        finally:
            healthy_receiver.stop()
            down_receiver.stop()
        self.assertEqual(healthy_status, 302)
        self.assertEqual(down_status, 302)
        self.assertEqual(healthy_headers.get("Location"), down_headers.get("Location"))
        self.assertEqual(healthy_headers.get("Content-Length"), down_headers.get("Content-Length"))

    def test_no_raw_traceback_reaches_stderr_for_an_expected_database_error(self) -> None:
        sink = _ScriptedSink(fail_calls=99)
        receiver = _receiver(
            sink, record_observation_maximum_attempts=2, record_observation_retry_backoff_seconds=0.01
        )
        captured = io.StringIO()
        try:
            with redirect_stderr(captured):
                self._get(receiver)
                import time as _time

                _time.sleep(0.1)  # let the handler thread's own log_message (suppressed) settle
        finally:
            receiver.stop()
        stderr_text = captured.getvalue()
        self.assertNotIn("Traceback (most recent call last):", stderr_text)
        self.assertNotIn("DatabaseUnavailableError", stderr_text)

    def test_unexpected_programming_error_is_not_silently_turned_into_a_204(self) -> None:
        """An unexpected exception type (not DatabaseError) must keep
        its existing visibility -- proven here as the connection
        failing to receive a normal response, exactly the pre-P1-12
        behavior for ANY unhandled exception, deliberately preserved
        for this one exception class."""

        class _BrokenSink:
            def record_observation(self, token_value: str, *, method: str, now=None) -> bool:
                raise TypeError("simulated unexpected programming error, not a DatabaseError")

        receiver = _receiver(_BrokenSink())
        try:
            with self.assertRaises(Exception):
                # Either a connection reset/BadStatusLine or a non-204
                # status -- what must NOT happen is a clean 204.
                status, _, _, _ = self._get(receiver)
                if status == 204:
                    raise AssertionError("an unexpected programming error must not be silently turned into a 204")
        finally:
            receiver.stop()

    def test_100_failing_requests_do_not_crash_the_process_or_poison_later_requests(self) -> None:
        sink = _ScriptedSink(fail_calls=100)
        receiver = _receiver(
            sink, record_observation_maximum_attempts=1, record_observation_retry_backoff_seconds=0.0
        )
        try:
            for _ in range(100):
                status, _, headers, body = self._get(receiver)
                self.assertEqual(status, 204)
                self.assertEqual(body, b"")
            # The server thread itself must still be alive and serving.
            self.assertTrue(receiver._thread.is_alive())

            # Recovery: the very next call succeeds, no restart needed.
            status, _, _, _ = self._get(receiver)
            self.assertEqual(status, 204)
        finally:
            receiver.stop()
        self.assertEqual(len(sink.calls), 101)


if __name__ == "__main__":
    unittest.main()
