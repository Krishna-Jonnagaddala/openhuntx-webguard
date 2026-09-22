"""Live (real-socket) validation of the OS command injection detector
against a purpose-built, deliberately vulnerable local fixture -- not
Juice Shop, not a public site.

The fixture is a plain http.server behind a real TCP socket on
127.0.0.1, with three routes that each do something genuinely different
with the parameter value, not a canned string standing in for one:

- /vulnerable?cmd=  -- actually shells out. It runs
  ``subprocess.run(f"echo {value}", shell=True, ...)`` with the raw,
  unsanitized parameter value interpolated straight into the command
  line. A real POSIX shell (bash or sh, whichever ``/bin/sh`` on this
  machine resolves to) parses that line, so a semicolon in ``value``
  really does end the ``echo`` command and start a new one. This is run
  once at import time below (see the module-level self-check) to prove
  it holds on the machine actually running this test, not just assumed.

- /safe?cmd=  -- also shells out to the same real ``echo`` binary, but
  through ``subprocess.run(["echo", value], shell=False, ...)``. With no
  shell in the middle, ``value`` is handed to ``/bin/echo`` as a single
  argv element; a semicolon or ``#`` inside it is just a character in
  that one argument, never syntax. This is a correct fix, not a stub:
  it still executes a real subprocess, it just removes the shell that
  makes injection possible.

- /reflects-input?cmd=  -- executes nothing. It builds an
  ``Invalid input: <value>`` string and sends it back. This is the
  specific false-positive shape ``_classify`` in
  command_injection_detector.py exists to rule out: the marker shows up
  in the body only because the whole raw payload, semicolon and ``#``
  and all, got reflected back untouched, not because anything ran it.

Route naming matches the routes the task asked for; where they'd
collide with the SQLi fixture's own /vulnerable and /safe (a separate,
unrelated server on its own port in that other test file), that's fine,
each test class runs its own ``ThreadingHTTPServer`` on an ephemeral
port.
"""

from __future__ import annotations

import os
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    CommandInjectionOutcome,
    DetectionCandidate,
    ValidatedTarget,
    run_command_injection_detector,
)


def _integration_enabled() -> bool:
    return os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


def _self_check_shell_behaviour() -> None:
    """Prove, on this machine, that a real shell splits the diagnostic
    payload the way the detector's docstring assumes: ``;`` ends the
    ``echo`` command and ``#`` comments out the rest, so real execution
    leaves the marker in stdout without the literal payload text, while
    a shell=False argv call leaves the whole payload intact as one
    argument. If either assumption is false here (an unusual shell, a
    locked-down ``/bin/sh``), fail loudly at import time instead of
    letting the live tests fail confusingly later."""

    marker = "wgcmdiselfcheck0001"
    value = f"1; echo {marker} #"

    shell_result = subprocess.run(
        f"echo {value}", shell=True, capture_output=True, timeout=5
    )
    shell_out = shell_result.stdout.decode("utf-8", errors="replace")
    if marker not in shell_out or value in shell_out:
        raise AssertionError(
            "Shell self-check failed: expected the real shell to strip "
            f"the payload syntax and print only the marker, got {shell_out!r}"
        )

    argv_result = subprocess.run(
        ["echo", value], capture_output=True, timeout=5
    )
    argv_out = argv_result.stdout.decode("utf-8", errors="replace")
    if value not in argv_out:
        raise AssertionError(
            "Argv self-check failed: expected the whole payload back as "
            f"one literal argument, got {argv_out!r}"
        )


if _integration_enabled():
    _self_check_shell_behaviour()


class _CmdiFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def _respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query).get("cmd", [""])[0]

        if parsed.path == "/vulnerable":
            # Genuinely vulnerable: the raw value is interpolated into a
            # shell command line and a real shell parses it.
            try:
                result = subprocess.run(
                    f"echo {value}", shell=True, capture_output=True, timeout=5
                )
                self._respond(
                    f"<html>{result.stdout.decode('utf-8', errors='replace')}</html>".encode()
                )
            except subprocess.SubprocessError as exc:
                self._respond(f"<html>error: {exc}</html>".encode(), status=500)
            return

        if parsed.path == "/safe":
            # A real fix: same subprocess call, but as an argv list with
            # shell=False, so nothing ever parses shell syntax in value.
            try:
                result = subprocess.run(
                    ["echo", value], capture_output=True, timeout=5
                )
                self._respond(
                    f"<html>{result.stdout.decode('utf-8', errors='replace')}</html>".encode()
                )
            except subprocess.SubprocessError as exc:
                self._respond(f"<html>error: {exc}</html>".encode(), status=500)
            return

        if parsed.path == "/reflects-input":
            # No subprocess at all: the raw value is echoed straight
            # into an error message, the classic reflection false
            # positive this detector's _classify guards against.
            self._respond(
                f"<html>Invalid input: {value}</html>".encode(), status=400
            )
            return

        self._respond(b"<html>not found</html>", status=404)


@unittest.skipUnless(
    _integration_enabled(),
    "Set WEBGUARD_RUN_INTEGRATION=1 to run live network integration tests.",
)
class CommandInjectionDetectorLiveFixtureTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _CmdiFixtureHandler)
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
        return ActiveDetectionContext(scan_id="live-cmdi-fixture-scan")

    def _run(self, path: str):
        candidate = DetectionCandidate(
            url=f"http://127.0.0.1:{self.port}{path}",
            parameter="cmd",
            original_value="1",
        )
        return run_command_injection_detector(
            self._target(),
            (candidate,),
            self._context(),
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )

    def test_vulnerable_endpoint_is_confirmed(self) -> None:
        result = self._run("/vulnerable")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.records[0].outcome, CommandInjectionOutcome.CONFIRMED
        )
        self.assertEqual(
            [i.value for i in result.findings[0].identifiers], ["CWE-78"]
        )
        self.assertEqual(result.findings[0].identity.path, "/vulnerable")

    def test_argv_safe_endpoint_produces_no_finding(self) -> None:
        result = self._run("/safe")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, CommandInjectionOutcome.INCONCLUSIVE
        )

    def test_reflected_input_produces_no_finding_despite_marker_text(
        self,
    ) -> None:
        # The marker string is genuinely present in this response body
        # (the whole payload was echoed back untouched), yet the
        # detector must not confirm: this is the exact real-execution-
        # vs-reflection distinction _classify exists to make.
        result = self._run("/reflects-input")
        record = result.records[0]
        self.assertIn(record.marker, self._fetch_body("/reflects-input", record))
        self.assertEqual(result.findings, ())
        self.assertEqual(record.outcome, CommandInjectionOutcome.INCONCLUSIVE)

    def _fetch_body(self, path: str, record) -> str:
        import urllib.error
        import urllib.request

        # /reflects-input answers with HTTP 400, which urlopen raises as
        # HTTPError rather than returning; the error object still has
        # the response body via .read(), same as a normal response would.
        try:
            with urllib.request.urlopen(record.diagnostic_url, timeout=5) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.read().decode("utf-8", errors="replace")

    def test_all_three_endpoints_in_one_run_only_flag_the_vulnerable_one(
        self,
    ) -> None:
        candidates = tuple(
            DetectionCandidate(
                url=f"http://127.0.0.1:{self.port}{path}",
                parameter="cmd",
                original_value="1",
            )
            for path in ("/vulnerable", "/safe", "/reflects-input")
        )
        result = run_command_injection_detector(
            self._target(),
            candidates,
            self._context(),
            policy=ActiveDetectionPolicy(
                minimum_delay_seconds=0.0, maximum_probe_requests=10
            ),
        )
        self.assertEqual(len(result.findings), 1)
        flagged_paths = {
            urlsplit(f.identity.path).path for f in result.findings
        }
        self.assertEqual(flagged_paths, {"/vulnerable"})


if __name__ == "__main__":
    unittest.main()
