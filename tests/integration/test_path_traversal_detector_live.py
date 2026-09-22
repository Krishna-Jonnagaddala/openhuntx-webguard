"""Live (real-socket) validation of the active path-traversal detector
against a purpose-built, deliberately vulnerable local fixture, mirroring
test_sqli_error_detector_live.py's shape.

The fixture serves files from a real temporary directory on disk, created
fresh in setUpClass and torn down in tearDownClass:

- /vulnerable?file=: joins the raw parameter onto the base directory
  with os.path.join and opens whatever that produces, with no
  sanitisation. os.path.join does not collapse ".." segments itself, so
  when the parameter is the six-level traversal payload
  (../../../../../../etc/passwd), the eventual open() call genuinely
  walks up past the temp directory and reads the real /etc/passwd that
  already exists on the machine running this test. Nothing about the
  path is faked: the vulnerability is that os.path.join plus open()
  never checks where the resulting path actually lands.
- /safe?file=: resolves the requested path with os.path.realpath and
  refuses to open anything whose resolved path is not the base directory
  itself or something under it. This is the standard fix, canonicalise
  then check containment, not a fixed string standing in for one.
- /broken?file=: always 404, with no filesystem access at all. This is
  the negative control, a 404 that has nothing to do with a file read.

Both routes' baseline case reads a real file (baseline.txt) that this
fixture writes into the temp directory itself, so the baseline response
is also a genuine file read, not a canned 200.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    DetectionCandidate,
    PathTraversalOutcome,
    ValidatedTarget,
    run_path_traversal_detector,
)


def _integration_enabled() -> bool:
    return os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


def _resolve_within_base(base_dir: str, requested: str) -> str | None:
    """Real containment check: canonicalise the candidate path and
    accept it only if it is the base directory itself or genuinely
    inside it. Returns the resolved path, or None if it escapes."""

    candidate = os.path.join(base_dir, requested)
    real_base = os.path.realpath(base_dir)
    real_candidate = os.path.realpath(candidate)
    if real_candidate == real_base or real_candidate.startswith(
        real_base + os.sep
    ):
        return real_candidate
    return None


class _PathTraversalFixtureHandler(BaseHTTPRequestHandler):
    base_dir: str = ""

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def _respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query).get("file", [""])[0]

        if parsed.path == "/vulnerable":
            # No sanitisation: whatever os.path.join produces from the
            # raw parameter is handed straight to open(). A traversal
            # payload walks out of base_dir exactly the way it would on
            # a real unfixed file-download endpoint.
            target_path = os.path.join(self.base_dir, value)
            try:
                with open(target_path, "rb") as handle:
                    content = handle.read()
                self._respond(content, status=200)
            except OSError:
                self._respond(b"not found", status=404)
            return

        if parsed.path == "/safe":
            resolved = _resolve_within_base(self.base_dir, value)
            if resolved is None:
                self._respond(b"not found", status=404)
                return
            try:
                with open(resolved, "rb") as handle:
                    content = handle.read()
                self._respond(content, status=200)
            except OSError:
                self._respond(b"not found", status=404)
            return

        if parsed.path == "/broken":
            # Generic 404 with no filesystem access whatsoever,
            # regardless of the parameter value.
            self._respond(b"not found", status=404)
            return

        self._respond(b"not found", status=404)


@unittest.skipUnless(
    _integration_enabled(),
    "Set WEBGUARD_RUN_INTEGRATION=1 to run live network integration tests.",
)
class PathTraversalDetectorLiveFixtureTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread
    base_dir: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.base_dir = tempfile.mkdtemp(prefix="webguard-pathtraversal-")
        # One real, intended file the vulnerable and safe routes are
        # actually meant to serve.
        with open(os.path.join(cls.base_dir, "baseline.txt"), "w") as handle:
            handle.write("this is the harmless intended file\n")

        handler = type(
            "_BoundHandler", (_PathTraversalFixtureHandler,), {"base_dir": cls.base_dir}
        )
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        shutil.rmtree(cls.base_dir, ignore_errors=True)

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
        return ActiveDetectionContext(scan_id="live-pathtraversal-fixture-scan")

    def _run(self, path: str):
        candidate = DetectionCandidate(
            url=f"http://127.0.0.1:{self.port}{path}",
            parameter="file",
            original_value="baseline.txt",
        )
        return run_path_traversal_detector(
            self._target(),
            (candidate,),
            self._context(),
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )

    def test_vulnerable_endpoint_reads_real_etc_passwd(self) -> None:
        # Independently confirm, outside the detector, that the fixture
        # itself is genuinely vulnerable: reading through it with the
        # traversal payload really does return this machine's own
        # /etc/passwd content, byte for byte.
        target_path = os.path.join(self.base_dir, "../../../../../../etc/passwd")
        with open(target_path, "rb") as handle:
            fixture_read = handle.read()
        with open("/etc/passwd", "rb") as handle:
            real_read = handle.read()
        self.assertEqual(fixture_read, real_read)

    def test_vulnerable_endpoint_is_confirmed_or_probable(self) -> None:
        result = self._run("/vulnerable")
        self.assertEqual(len(result.findings), 1)
        self.assertIn(
            result.records[0].outcome,
            (PathTraversalOutcome.CONFIRMED, PathTraversalOutcome.PROBABLE),
        )
        self.assertEqual(
            [i.value for i in result.findings[0].identifiers], ["CWE-22"]
        )

    def test_safe_endpoint_produces_no_finding(self) -> None:
        result = self._run("/safe")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, PathTraversalOutcome.INCONCLUSIVE
        )

    def test_safe_endpoint_never_leaks_etc_passwd_content(self) -> None:
        # Belt-and-suspenders check on the safe route directly (not
        # through the detector): the traversal payload must come back
        # as a 404 body, never as /etc/passwd's own content.
        result = self._run("/safe")
        diagnostic_url = result.records[0].diagnostic_url
        parsed = urlsplit(diagnostic_url)
        value = parse_qs(parsed.query).get("file", [""])[0]
        self.assertEqual(value, "../../../../../../etc/passwd")
        resolved = _resolve_within_base(self.base_dir, value)
        self.assertIsNone(resolved)

    def test_generic_404_endpoint_produces_no_finding(self) -> None:
        result = self._run("/broken")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, PathTraversalOutcome.INCONCLUSIVE
        )


if __name__ == "__main__":
    unittest.main()
