"""Live (real-socket) validation of the SSRF-callback detector against
a purpose-built, deliberately vulnerable local fixture -- not Juice
Shop, not a public site.

The fixture exposes exactly the five routes requirement 13 calls for,
each accepting a ``url`` GET parameter:

- ``/fetch-vulnerable``  -- genuinely vulnerable: the server actually
  performs a real, blocking outbound HTTP request to the supplied URL
  (via the Python standard library, not WebGuard's own client) before
  responding. This is the only route that should ever produce a
  CONFIRMED finding.
- ``/fetch-safe``        -- accepts the URL but never performs any
  outbound request at all.
- ``/reflect-only``      -- echoes the URL value back in the response
  body, never fetches it. Directly exercises the false-positive
  control this slice explicitly requires: reflection is not evidence.
- ``/validation-error``  -- always returns HTTP 400 (simulating an
  application that validates and rejects the URL) without ever
  fetching anything.
- ``/generic-500``       -- always returns HTTP 500 regardless of
  input, with no fetch of any kind.

The real callback receiver (``webguard_api.callback_server.CallbackHttpReceiver``)
and the real, unmodified `InMemoryCallbackBroker` (the same class the
API-layer `CallbackRepository` wraps for multi-tenant use) are used
directly -- the only thing "fixture" about this test is the target
application being probed and the fact that the vulnerable route's
outbound fetch is itself performed with Python's standard library
rather than a browser. Both the probe (WebGuard -> fixture) and the
confirmation (fixture -> WebGuard's own callback receiver) are real
network round trips over real sockets.
"""

from __future__ import annotations

import os
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    ContentType,
    RequestTemplate,
    SsrfDetectionOutcome,
    ValidatedTarget,
    run_ssrf_callback_detector,
)
from webguard_scanner.callback_broker import CallbackPolicy, InMemoryCallbackBroker

from webguard_api.callback_server import CallbackHttpReceiver


def _integration_enabled() -> bool:
    return os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


class _SsrfFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        url = query.get("url", [""])[0]

        if parsed.path == "/fetch-vulnerable":
            if url:
                try:
                    # Genuinely vulnerable: the server itself fetches
                    # whatever URL the client supplied, synchronously,
                    # before responding -- a real outbound request, not
                    # a simulation of one.
                    urllib.request.urlopen(url, timeout=3)
                except Exception:
                    pass
            self._respond(200, b"fetched")
            return

        if parsed.path == "/fetch-safe":
            self._respond(200, b"accepted, not fetched")
            return

        if parsed.path == "/reflect-only":
            self._respond(200, f"you gave me: {url}".encode())
            return

        if parsed.path == "/validation-error":
            self._respond(400, b"invalid url")
            return

        if parsed.path == "/generic-500":
            self._respond(500, b"internal error")
            return

        if parsed.path == "/":
            body = (
                b"<html><body>"
                b'<form method="GET" action="/fetch-vulnerable">'
                b'<input name="url" value="https://example.com/default.png"></form>'
                b'<form method="GET" action="/fetch-safe">'
                b'<input name="url" value="https://example.com/default.png"></form>'
                b'<form method="GET" action="/reflect-only">'
                b'<input name="url" value="https://example.com/default.png"></form>'
                b'<form method="GET" action="/validation-error">'
                b'<input name="url" value="https://example.com/default.png"></form>'
                b'<form method="GET" action="/generic-500">'
                b'<input name="url" value="https://example.com/default.png"></form>'
                b"</body></html>"
            )
            self._respond(200, body, content_type="text/html; charset=utf-8")
            return

        self._respond(404, b"not found")

    def _respond(self, status: int, body: bytes, *, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _template(endpoint: str, *, parameter: str = "url") -> RequestTemplate:
    return RequestTemplate(
        endpoint=endpoint,
        method="GET",
        content_type=ContentType.NONE,
        parameter=parameter,
        query_parameters=((parameter, "https://example.com/default.png"),),
        source_candidate_id=endpoint,
    )


@unittest.skipUnless(
    _integration_enabled(), "Set WEBGUARD_RUN_INTEGRATION=1 to run network integration tests."
)
class SsrfCallbackDetectorLiveFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _SsrfFixtureHandler)
        cls.fixture_thread = threading.Thread(
            target=cls.fixture_server.serve_forever, daemon=True
        )
        cls.fixture_thread.start()
        cls.fixture_port = cls.fixture_server.server_address[1]
        cls.fixture_base = f"http://127.0.0.1:{cls.fixture_port}"

        cls.broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:0/")
        cls.receiver = CallbackHttpReceiver(cls.broker)
        cls.receiver.start()
        cls.broker.set_base_url(cls.receiver.base_url)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()
        cls.fixture_thread.join(timeout=5)
        cls.receiver.stop()

    def _target(self) -> ValidatedTarget:
        return ValidatedTarget(
            original_url=self.fixture_base + "/",
            normalised_url=self.fixture_base + "/",
            scheme="http",
            hostname="127.0.0.1",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def test_only_the_actual_fetch_produces_a_confirmed_finding(self) -> None:
        candidates = (
            _template(f"{self.fixture_base}/fetch-vulnerable"),
            _template(f"{self.fixture_base}/fetch-safe"),
            _template(f"{self.fixture_base}/reflect-only"),
            _template(f"{self.fixture_base}/validation-error"),
            _template(f"{self.fixture_base}/generic-500"),
        )
        result = run_ssrf_callback_detector(
            self._target(),
            candidates,
            ActiveDetectionContext(scan_id="ssrf-live-scan"),
            callback_broker=self.broker,
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
            callback_policy=CallbackPolicy(
                maximum_wait_seconds=2.0, grace_seconds=1.0, poll_interval_seconds=0.05
            ),
        )

        outcomes = {
            record.candidate_endpoint: record.outcome for record in result.records
        }
        self.assertEqual(
            outcomes[f"{self.fixture_base}/fetch-vulnerable"],
            SsrfDetectionOutcome.CONFIRMED,
        )
        self.assertEqual(
            outcomes[f"{self.fixture_base}/fetch-safe"],
            SsrfDetectionOutcome.NOT_VULNERABLE,
        )
        self.assertEqual(
            outcomes[f"{self.fixture_base}/reflect-only"],
            SsrfDetectionOutcome.NOT_VULNERABLE,
        )
        self.assertEqual(
            outcomes[f"{self.fixture_base}/validation-error"],
            SsrfDetectionOutcome.NOT_VULNERABLE,
        )
        self.assertEqual(
            outcomes[f"{self.fixture_base}/generic-500"],
            SsrfDetectionOutcome.NOT_VULNERABLE,
        )

        confirmed = [
            f for f in result.findings if f.identity.path == "/fetch-vulnerable"
        ]
        self.assertEqual(len(confirmed), 1)
        cwe_values = [i.value for i in confirmed[0].identifiers if i.namespace == "CWE"]
        self.assertEqual(cwe_values, ["CWE-918"])
        self.assertEqual(len(result.findings), 1)


if __name__ == "__main__":
    unittest.main()
