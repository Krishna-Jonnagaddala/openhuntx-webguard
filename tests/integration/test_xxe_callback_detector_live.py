"""Live (real-socket) validation of the XXE-callback detector (CWE-611)
against a purpose-built, deliberately vulnerable local fixture, not a
public target.

Python's own standard library does not resolve external entities by
default: both xml.sax and xml.etree sit on top of pyexpat, and pyexpat
never fetches a SYSTEM identifier unless the caller explicitly wires up
an ExternalEntityRefHandler. That default is the reason this detector
has to rely on an out-of-band callback at all (see the module docstring
on xxe_callback_detector.py), and it is also why the fixture below
cannot just "parse some XML" to be vulnerable; it has to go out of its
way to opt into the unsafe behavior, the same way a real vulnerable
application would.

The fixture exposes two POST routes, each running the identical posted
body through xml.parsers.expat directly:

- ``/vulnerable`` sets ``parser.ExternalEntityRefHandler`` to a handler
  written for this test, which receives the entity's SYSTEM identifier
  (the callback URL WebGuard issued) and performs a real, blocking
  ``urllib.request.urlopen`` call to it before letting expat continue.
  This is the same kind of "deliberately vulnerable route" the SSRF
  live test already uses for its own ``/fetch-vulnerable`` route: real
  standard-library code doing the unsafe thing on purpose, not a
  canned response standing in for it.
- ``/safe`` parses the same raw body with a parser that never gets an
  ExternalEntityRefHandler at all, which is Python's actual
  secure-by-default behavior, not a mock of it. Whatever the posted
  document declares, expat silently skips the external reference and
  no outbound request happens.

Both routes respond 200 regardless of what parsing did, because the
detector never reads the response body for classification: only
whether the real ``CallbackHttpReceiver``, backed by the real
``InMemoryCallbackBroker`` (the same classes the SSRF live test uses),
actually observes an inbound callback decides the outcome. So the full
chain, probe reaches the fixture, the fixture's own parser makes a real
outbound fetch, that fetch lands at WebGuard's own receiver, runs over
real sockets end to end.
"""

from __future__ import annotations

import os
import threading
import unittest
import urllib.request
import xml.parsers.expat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    ContentType,
    FetchPolicy,
    RequestTemplate,
    ValidatedTarget,
    XxeDetectionOutcome,
    run_xxe_callback_detector,
)
from webguard_scanner.callback_broker import CallbackPolicy, InMemoryCallbackBroker

from webguard_api.callback_server import CallbackHttpReceiver


def _integration_enabled() -> bool:
    return os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


def _external_entity_ref_handler(context, base, system_id, public_id):
    """Genuinely resolves an external entity: fetches whatever URL the
    posted document's SYSTEM identifier names, for real, over a real
    socket, before returning. Any failure (connection refused, timeout,
    a non-200 status) is swallowed, exactly as a real vulnerable
    application's own error handling would swallow it, since the point
    of the attack is the outbound request itself, not its response.

    Returning 1 tells expat parsing may continue; there is nothing in
    the entity's expansion this test needs, since the detector only
    classifies on whether the callback arrived, never on the response
    body of either route.
    """

    if system_id:
        try:
            with urllib.request.urlopen(system_id, timeout=3):
                pass
        except Exception:
            pass
    return 1


class _XxeFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""

        if self.path == "/vulnerable":
            parser = xml.parsers.expat.ParserCreate()
            # The vulnerable line: an application choosing to resolve
            # external entities instead of leaving this unset.
            parser.ExternalEntityRefHandler = _external_entity_ref_handler
            self._parse_ignoring_errors(parser, body)
            self._respond(200, b"processed")
            return

        if self.path == "/safe":
            # No ExternalEntityRefHandler assigned at all, so pyexpat's
            # real default applies: the SYSTEM identifier is never
            # looked at, let alone fetched, no matter what is posted.
            parser = xml.parsers.expat.ParserCreate()
            self._parse_ignoring_errors(parser, body)
            self._respond(200, b"processed")
            return

        self._respond(404, b"not found")

    @staticmethod
    def _parse_ignoring_errors(parser, body: bytes) -> None:
        try:
            parser.Parse(body, True)
        except xml.parsers.expat.ExpatError:
            # Neither route's job is to validate the document; a parse
            # error just means whatever happened during parsing (or
            # didn't) already happened, which is all this test checks.
            pass

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _template(endpoint: str) -> RequestTemplate:
    # A POST form candidate, the shape select_xxe_candidates actually
    # accepts (ContentType.FORM_URLENCODED or JSON, never NONE). The
    # detector discards this body and content type entirely and sends
    # its own crafted application/xml document instead, so the field
    # values here only need to exist, not to matter.
    return RequestTemplate(
        endpoint=endpoint,
        method="POST",
        content_type=ContentType.FORM_URLENCODED,
        parameter="comment",
        form_parameters=(("comment", "placeholder"),),
        source_candidate_id=endpoint,
    )


@unittest.skipUnless(
    _integration_enabled(), "Set WEBGUARD_RUN_INTEGRATION=1 to run network integration tests."
)
class XxeCallbackDetectorLiveFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _XxeFixtureHandler)
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

    def _policy(self) -> ActiveDetectionPolicy:
        # FetchPolicy defaults to GET/HEAD only; the probe here is
        # POST, matching the candidate templates above.
        return ActiveDetectionPolicy(
            minimum_delay_seconds=0.0,
            fetch_policy=FetchPolicy(allowed_methods=frozenset({"POST"})),
        )

    def test_only_the_actual_external_entity_fetch_produces_a_confirmed_finding(
        self,
    ) -> None:
        candidates = (
            _template(f"{self.fixture_base}/vulnerable"),
            _template(f"{self.fixture_base}/safe"),
        )
        result = run_xxe_callback_detector(
            self._target(),
            candidates,
            ActiveDetectionContext(scan_id="xxe-live-scan"),
            callback_broker=self.broker,
            policy=self._policy(),
            callback_policy=CallbackPolicy(
                maximum_wait_seconds=2.0, grace_seconds=1.0, poll_interval_seconds=0.05
            ),
        )

        outcomes = {
            record.candidate_endpoint: record.outcome for record in result.records
        }
        self.assertEqual(
            outcomes[f"{self.fixture_base}/vulnerable"], XxeDetectionOutcome.CONFIRMED
        )
        self.assertEqual(
            outcomes[f"{self.fixture_base}/safe"], XxeDetectionOutcome.NOT_VULNERABLE
        )

        confirmed = [f for f in result.findings if f.identity.path == "/vulnerable"]
        self.assertEqual(len(confirmed), 1)
        cwe_values = [i.value for i in confirmed[0].identifiers if i.namespace == "CWE"]
        self.assertEqual(cwe_values, ["CWE-611"])
        self.assertIsNone(confirmed[0].identity.parameter)
        self.assertEqual(len(result.findings), 1)


if __name__ == "__main__":
    unittest.main()
