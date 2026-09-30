"""Live (real-socket) validation of the error-based SQLi detector against
a purpose-built, deliberately vulnerable local fixture -- not Juice Shop,
not a public site.

The fixture runs a real in-memory SQLite database behind HTTP endpoints
with known, distinct behaviour, across all three transports the detector
now supports (Slice 6):

- /vulnerable?id=            (GET query)      -- string-concatenates the
  raw parameter into SQL (genuinely vulnerable; a bare apostrophe breaks
  the query).
- /vulnerable-post-form      (POST form)      -- same vulnerability, id
  submitted as a form field.
- /vulnerable-json           (POST JSON)      -- same vulnerability, id
  submitted as a JSON body field.
- /safe?id=, /safe-post-form, /safe-json      -- each uses a
  parameterised query (?, tuple binding); a bare apostrophe is just a
  literal string value, never breaks syntax, across all three transports.
- /broken?id=  -- always returns a generic HTTP 500 with no SQL
  involvement at all, regardless of input.
- /about?id=   -- always returns the same normal 200 page whose static
  copy happens to mention a database-error-shaped phrase
  ("SQLite3.OperationalError handling"), identically for every input.

The detector must fire (CONFIRMED) only on the three /vulnerable*
endpoints, and produce no finding on any of the safe/control endpoints --
this is the core false-positive-resistance claim of this slice, exercised
over real sockets and a real SQLite engine, not mocked, now proven across
GET, POST-form, and JSON transports identically.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    ContentType,
    DetectionCandidate,
    FetchPolicy,
    RequestTemplate,
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

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b""
        content_type = self.headers.get("Content-Type", "")

        if "application/json" in content_type:
            try:
                document = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                document = {}
            value = str(document.get("id", ""))
        else:
            value = parse_qs(raw_body.decode()).get("id", [""])[0]

        if parsed.path in ("/vulnerable-post-form", "/vulnerable-json"):
            query = f"SELECT id, name FROM products WHERE id = {value}"
            try:
                with self._lock:
                    rows = self.db.execute(query).fetchall()
                self._respond(f"<html>Results: {len(rows)}</html>".encode())
            except sqlite3.Error as exc:
                self._respond(
                    f"<html>Database error: {exc}</html>".encode(), status=500
                )
            return

        if parsed.path in ("/safe-post-form", "/safe-json"):
            try:
                with self._lock:
                    rows = self.db.execute(
                        "SELECT id, name FROM products WHERE id = ?", (value,)
                    ).fetchall()
                self._respond(f"<html>Results: {len(rows)}</html>".encode())
            except sqlite3.Error as exc:
                self._respond(
                    f"<html>Database error: {exc}</html>".encode(), status=500
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

    def _post_policy(self) -> ActiveDetectionPolicy:
        return ActiveDetectionPolicy(
            minimum_delay_seconds=0.0,
            fetch_policy=FetchPolicy(
                allowed_methods=frozenset({"GET", "HEAD", "POST"})
            ),
        )

    def _run_post_form(self, path: str):
        template = RequestTemplate(
            endpoint=f"http://127.0.0.1:{self.port}{path}",
            method="POST",
            content_type=ContentType.FORM_URLENCODED,
            parameter="id",
            form_parameters=(("id", "1"),),
        )
        return run_sqli_error_detector(
            self._target(),
            (template,),
            self._context(),
            policy=self._post_policy(),
        )

    def _run_json(self, path: str):
        template = RequestTemplate(
            endpoint=f"http://127.0.0.1:{self.port}{path}",
            method="POST",
            content_type=ContentType.JSON,
            parameter="id",
            json_body=json.dumps({"id": "1"}),
        )
        return run_sqli_error_detector(
            self._target(),
            (template,),
            self._context(),
            policy=self._post_policy(),
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

    def test_vulnerable_post_form_endpoint_is_confirmed_over_real_socket(
        self,
    ) -> None:
        result = self._run_post_form("/vulnerable-post-form")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.CONFIRMED
        )
        self.assertEqual(result.findings[0].identity.method, "POST")

    def test_safe_post_form_endpoint_produces_no_finding_over_real_socket(
        self,
    ) -> None:
        result = self._run_post_form("/safe-post-form")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_vulnerable_json_endpoint_is_confirmed_over_real_socket(self) -> None:
        result = self._run_json("/vulnerable-json")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.CONFIRMED
        )
        self.assertEqual(result.findings[0].identity.method, "POST")

    def test_safe_json_endpoint_produces_no_finding_over_real_socket(self) -> None:
        result = self._run_json("/safe-json")
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
