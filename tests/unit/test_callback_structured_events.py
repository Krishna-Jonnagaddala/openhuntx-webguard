"""P1-B1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
call-site proofs that CallbackHttpReceiver's bounded persistence retry
emits the required structured events, with no raw token value and no
extra database lookup performed merely to enrich them.
"""

from __future__ import annotations

import http.client
import io
import json
import unittest

from webguard_api.callback_server import CallbackHttpReceiver
from webguard_api.db_errors import DatabaseUnavailableError
from webguard_api.structured_logging import configure_structured_logging


def _lines(buf: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def _events(buf: io.StringIO, name: str) -> list[dict]:
    return [line for line in _lines(buf) if line.get("event") == name]


class _ScriptedSink:
    def __init__(self, *, fail_calls: int) -> None:
        self.fail_calls = fail_calls
        self.calls = 0

    def record_observation(self, token_value: str, *, method: str, now=None) -> bool:
        self.calls += 1
        if self.calls <= self.fail_calls:
            raise DatabaseUnavailableError("database_unavailable", "simulated outage")
        return True


class CallbackStructuredEventTests(unittest.TestCase):
    def _get(self, receiver: CallbackHttpReceiver, token: str = "SUPER-SECRET-TOKEN-VALUE"):
        host, port = receiver._server.server_address[:2]
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request("GET", f"/scan-1/{token}")
            conn.getresponse().read()
        finally:
            conn.close()
        return token

    def test_retry_then_recovered(self) -> None:
        buf = io.StringIO()
        configure_structured_logging(service="callback-service", stream=buf)
        sink = _ScriptedSink(fail_calls=1)
        receiver = CallbackHttpReceiver(
            sink, record_observation_maximum_attempts=2, record_observation_retry_backoff_seconds=0.001,
        )
        receiver.start()
        try:
            token = self._get(receiver)
        finally:
            receiver.stop()

        retries = _events(buf, "callback_observation_persistence_retry")
        self.assertEqual(len(retries), 1)
        self.assertEqual(retries[0]["attempt"], 1)

        recovered = _events(buf, "callback_observation_persistence_recovered")
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["attempt"], 2)

        # No raw token value anywhere in the output, and no extra
        # database lookup was performed -- the fake sink's only method
        # is record_observation() itself, called exactly `maximum_attempts`
        # times, never anything else.
        self.assertNotIn(token, buf.getvalue())
        self.assertEqual(sink.calls, 2)

    def test_exhausted_has_fixed_error_code_and_attempt_count(self) -> None:
        buf = io.StringIO()
        configure_structured_logging(service="callback-service", stream=buf)
        sink = _ScriptedSink(fail_calls=99)
        receiver = CallbackHttpReceiver(
            sink, record_observation_maximum_attempts=2, record_observation_retry_backoff_seconds=0.001,
        )
        receiver.start()
        try:
            token = self._get(receiver)
        finally:
            receiver.stop()

        exhausted = _events(buf, "callback_observation_persistence_exhausted")
        self.assertEqual(len(exhausted), 1)
        self.assertEqual(exhausted[0]["attempt"], 2)
        self.assertEqual(exhausted[0]["error_code"], "callback_observation_persistence_unavailable")
        self.assertEqual(exhausted[0]["level"], "error")
        self.assertNotIn(token, buf.getvalue())

    def test_no_events_on_clean_first_attempt_success(self) -> None:
        buf = io.StringIO()
        configure_structured_logging(service="callback-service", stream=buf)
        sink = _ScriptedSink(fail_calls=0)
        receiver = CallbackHttpReceiver(sink)
        receiver.start()
        try:
            self._get(receiver)
        finally:
            receiver.stop()

        self.assertEqual(_events(buf, "callback_observation_persistence_retry"), [])
        self.assertEqual(_events(buf, "callback_observation_persistence_recovered"), [])
        self.assertEqual(_events(buf, "callback_observation_persistence_exhausted"), [])


if __name__ == "__main__":
    unittest.main()
