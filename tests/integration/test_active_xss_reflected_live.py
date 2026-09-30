"""Live (real-socket) validation of the reflected-XSS detector.

This does NOT test against OWASP Juice Shop. Investigation against the
pinned Juice Shop v20.1.1 lab target (search API, REST endpoints, 404
handler, change-password, captcha, redirect challenge) found no raw
server-side HTML reflection point: this Juice Shop version is an Angular
SPA where the documented XSS challenge is DOM-based (the payload is
rendered client-side via Angular after the page loads), not reflected by
the server in its raw HTTP response. WebGuard does not execute
JavaScript, so that class of finding is out of reach for this detector by
design -- this is an honest scope limitation, not a bug, and is recorded
in docs/audit/active-detection-phase1-xss.md rather than worked around
here.

This test instead validates the detector against a minimal, purpose-built
HTTP server that deliberately reflects a query parameter, run over a real
loopback socket (not a mocked connection) to exercise the actual network
path: real TCP connect, real HTTP parsing, real chunked/content-length
handling. It complements, and must not be confused with, the mocked
classification-logic tests in tests/unit/test_active_xss_reflected.py.
"""

from __future__ import annotations

import html
import os
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    DetectionCandidate,
    DetectionOutcome,
    ValidatedTarget,
    run_reflected_xss_detector,
)


def _integration_enabled() -> bool:
    return os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


class _ReflectionFixtureHandler(BaseHTTPRequestHandler):
    """Deliberately vulnerable/safe test fixture, never exposed beyond
    loopback. Reflects ?q= unescaped at /reflect, HTML-encoded at /safe,
    and not at all at /noecho."""

    def log_message(self, *args) -> None:  # noqa: D401 - silence test noise
        return None

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query)
        value = params.get("q", [""])[0]

        if parsed.path == "/reflect":
            body = f"<html><body>{value}</body></html>".encode()
        elif parsed.path == "/safe":
            body = f"<html><body>{html.escape(value)}</body></html>".encode()
        else:
            body = b"<html><body>no parameter used here</body></html>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(
    _integration_enabled(),
    "Set WEBGUARD_RUN_INTEGRATION=1 to run live network integration tests.",
)
class ReflectedXssLiveFixtureTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: Thread

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _ReflectionFixtureHandler
        )
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _target(self) -> ValidatedTarget:
        base = f"http://127.0.0.1:{self.port}/"
        return ValidatedTarget(
            original_url=base,
            normalised_url=base,
            scheme="http",
            hostname="127.0.0.1",
            port=self.port,
            resolved_addresses=("127.0.0.1",),
        )

    def _context(self) -> ActiveDetectionContext:
        return ActiveDetectionContext(scan_id="live-fixture-scan")

    def test_confirmed_reflection_over_a_real_socket(self) -> None:
        candidate = DetectionCandidate(
            url=f"http://127.0.0.1:{self.port}/reflect",
            parameter="q",
        )
        result = run_reflected_xss_detector(
            self._target(),
            (candidate,),
            self._context(),
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.records[0].outcome, DetectionOutcome.CONFIRMED
        )
        self.assertEqual(
            [i.value for i in result.findings[0].identifiers], ["CWE-79"]
        )

    def test_safely_encoded_reflection_over_a_real_socket(self) -> None:
        candidate = DetectionCandidate(
            url=f"http://127.0.0.1:{self.port}/safe",
            parameter="q",
        )
        result = run_reflected_xss_detector(
            self._target(),
            (candidate,),
            self._context(),
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )
        self.assertEqual(
            result.records[0].outcome, DetectionOutcome.INFORMATIONAL
        )
        self.assertEqual(result.findings[0].identifiers, ())

    def test_no_parameter_used_produces_no_finding_over_a_real_socket(
        self,
    ) -> None:
        candidate = DetectionCandidate(
            url=f"http://127.0.0.1:{self.port}/noecho",
            parameter="q",
        )
        result = run_reflected_xss_detector(
            self._target(),
            (candidate,),
            self._context(),
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, DetectionOutcome.INCONCLUSIVE
        )

    def test_off_origin_candidate_is_still_rejected_over_a_real_setup(
        self,
    ) -> None:
        from webguard_scanner import ActiveDetectionError

        candidate = DetectionCandidate(
            url="http://attacker.example/reflect",
            parameter="q",
        )
        with self.assertRaises(ActiveDetectionError):
            run_reflected_xss_detector(
                self._target(),
                (candidate,),
                self._context(),
            )


if __name__ == "__main__":
    unittest.main()
