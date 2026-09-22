"""Live (real-socket) validation of the active open-redirect detector
(CWE-601) against a purpose-built, deliberately vulnerable local fixture.

Unlike the SQLi and path-traversal live fixtures, this detector sends no
baseline request: the evidence is a structural match between a fresh
per-probe marker host and the Location header a real 3xx response
carries, so there is nothing for a second request to compare against.
Each test below issues exactly one live diagnostic request per candidate.

The fixture is a real HTTP server (ThreadingHTTPServer on 127.0.0.1,
an ephemeral port) with three routes:

- /vulnerable?next=  always answers 302 with the client-supplied value
  copied straight into the Location header. No allowlist, no host
  check: whatever the client sends comes back as the redirect target,
  which is exactly what makes an open redirect exploitable.
- /safe?next=  always answers 302 with Location set to "/", the
  fixture's own root path. The next value is read off the query string
  but never touches the response; this is a real fixed-destination
  defense, not a stand-in string.
- /safe-echoes-in-body?next=  always answers 200 with an ordinary HTML
  page. The raw next value is rendered as plain text next to a link
  that points at a fixed, unrelated path. Nothing in the response is a
  redirect at all, so this route exists purely to prove the detector's
  CONFIRMED verdict depends on a real 3xx status and a real Location
  header, not on the marker host appearing anywhere in the bytes that
  come back.

The detector's own classify function treats every CONFIRMED case the
same way, there is no PROBABLE tier for this check (see the module
docstring: the evidence is structural, either the Location header
resolves to the probe's own marker host or it does not), so the single
successful diagnostic against /vulnerable is expected to land on
CONFIRMED directly.
"""

from __future__ import annotations

import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    DetectionCandidate,
    OpenRedirectOutcome,
    ValidatedTarget,
    run_open_redirect_detector,
)


def _integration_enabled() -> bool:
    return os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


class _OpenRedirectFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def _redirect(self, location: str, status: int = 302) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query).get("next", [""])[0]

        if parsed.path == "/vulnerable":
            # A real, unconditional open redirect: the raw client value
            # becomes the Location header with no validation of any kind.
            self._redirect(value)
            return

        if parsed.path == "/safe":
            # A real fixed-destination redirect. next is parsed above but
            # never referenced again; the client lands on "/" no matter
            # what it asked for.
            self._redirect("/")
            return

        if parsed.path == "/safe-echoes-in-body":
            body = (
                "<html><body>"
                "<p>Leaving the site? <a href=\"/exit\">continue here</a>.</p>"
                f"<p>You requested: {value}</p>"
                "</body></html>"
            ).encode()
            self._respond(body)
            return

        self._respond(b"<html>not found</html>", status=404)


@unittest.skipUnless(
    _integration_enabled(),
    "Set WEBGUARD_RUN_INTEGRATION=1 to run live network integration tests.",
)
class OpenRedirectDetectorLiveFixtureTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _OpenRedirectFixtureHandler
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
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
        return ActiveDetectionContext(scan_id="live-open-redirect-fixture-scan")

    def _run(self, path: str):
        candidate = DetectionCandidate(
            url=f"http://127.0.0.1:{self.port}{path}",
            parameter="next",
            original_value="/home",
        )
        return run_open_redirect_detector(
            self._target(),
            (candidate,),
            self._context(),
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )

    def test_vulnerable_endpoint_is_confirmed(self) -> None:
        result = self._run("/vulnerable")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.CONFIRMED
        )
        self.assertEqual(
            [i.value for i in result.findings[0].identifiers], ["CWE-601"]
        )

    def test_fixed_destination_safe_endpoint_produces_no_finding(self) -> None:
        result = self._run("/safe")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.NOT_VULNERABLE
        )

    def test_marker_in_response_body_alone_produces_no_finding(self) -> None:
        # The marker host appears in the page text, but the response is a
        # plain 200 with no Location header at all. If this ever came back
        # CONFIRMED it would mean the detector is reading the body instead
        # of the status and header it claims to check.
        result = self._run("/safe-echoes-in-body")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.NOT_VULNERABLE
        )


if __name__ == "__main__":
    unittest.main()
