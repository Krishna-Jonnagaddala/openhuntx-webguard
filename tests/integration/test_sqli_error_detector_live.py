"""Live (real-socket) validation of the error-based SQLi detector against
a purpose-built, deliberately vulnerable local fixture -- not Juice Shop,
not a public site.

The fixture runs a real in-memory SQLite database behind four HTTP
endpoints with known, distinct behaviour:

- /vulnerable?id=  -- string-concatenates the raw parameter into SQL
  (genuinely vulnerable; a bare apostrophe breaks the query).
- /safe?id=        -- uses a parameterised query (?, tuple binding); a
  bare apostrophe is just a literal string value, never breaks syntax.
- /broken?id=      -- always returns a generic HTTP 500 with no SQL
  involvement at all, regardless of input.
- /about?id=       -- always returns the same normal 200 page whose
  static copy happens to mention a database-error-shaped phrase
  ("SQLite3.OperationalError handling"), identically for every input.

The detector must fire (CONFIRMED) only on /vulnerable, and produce no
finding on the other three -- this is the core false-positive-resistance
claim of this slice, exercised over real sockets and a real SQLite
engine, not mocked.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    DetectionCandidate,
    SqliDetectionOutcome,
    ValidatedTarget,
    run_sqli_error_detector,
)


def _integration_enabled() -> bool:
    return os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


def _connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE products (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO products VALUES (1, 'Widget')")
    conn.commit()
    return conn


class _SqliFixtureHandler(BaseHTTPRequestHandler):
    db = _connection()
    _lock = threading.Lock()

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
        value = parse_qs(parsed.query).get("id", [""])[0]

        if parsed.path == "/vulnerable":
            query = f"SELECT id, name FROM products WHERE id = {value}"
            try:
                with self._lock:
                    rows = self.db.execute(query).fetchall()
                self._respond(
                    f"<html>Results: {len(rows)}</html>".encode()
                )
            except sqlite3.Error as exc:
                self._respond(
                    f"<html>Database error: {exc}</html>".encode(),
                    status=500,
                )
            return

        if parsed.path == "/safe":
            try:
                with self._lock:
                    rows = self.db.execute(
                        "SELECT id, name FROM products WHERE id = ?",
                        (value,),
                    ).fetchall()
                self._respond(
                    f"<html>Results: {len(rows)}</html>".encode()
                )
            except sqlite3.Error as exc:
                self._respond(
                    f"<html>Database error: {exc}</html>".encode(),
                    status=500,
                )
            return

        if parsed.path == "/broken":
            self._respond(b"<html>Internal Server Error</html>", status=500)
            return

        if parsed.path == "/about":
            self._respond(
                b"<html>Powered by our SQLite3.OperationalError "
                b"handling framework, est. 2020.</html>"
            )
            return

        self._respond(b"<html>not found</html>", status=404)


@unittest.skipUnless(
    _integration_enabled(),
    "Set WEBGUARD_RUN_INTEGRATION=1 to run live network integration tests.",
)
class SqliErrorDetectorLiveFixtureTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _SqliFixtureHandler)
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
        return ActiveDetectionContext(scan_id="live-sqli-fixture-scan")

    def _run(self, path: str):
        candidate = DetectionCandidate(
            url=f"http://127.0.0.1:{self.port}{path}",
            parameter="id",
            original_value="1",
        )
        return run_sqli_error_detector(
            self._target(),
            (candidate,),
            self._context(),
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )

    def test_vulnerable_endpoint_is_confirmed(self) -> None:
        result = self._run("/vulnerable")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.CONFIRMED
        )
        self.assertEqual(
            [i.value for i in result.findings[0].identifiers], ["CWE-89"]
        )

    def test_parameterised_safe_endpoint_produces_no_finding(self) -> None:
        result = self._run("/safe")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_generic_500_endpoint_produces_no_finding(self) -> None:
        result = self._run("/broken")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_database_looking_static_text_produces_no_finding(self) -> None:
        result = self._run("/about")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_all_four_endpoints_in_one_run_only_flag_the_vulnerable_one(
        self,
    ) -> None:
        candidates = tuple(
            DetectionCandidate(
                url=f"http://127.0.0.1:{self.port}{path}",
                parameter="id",
                original_value="1",
            )
            for path in ("/vulnerable", "/safe", "/broken", "/about")
        )
        result = run_sqli_error_detector(
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
