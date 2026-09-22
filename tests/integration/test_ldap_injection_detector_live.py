"""Live validation of the active error-based LDAP injection detector
(CWE-90) against a purpose-built, deliberately vulnerable local fixture.

``docs/audit/active-detection-phase15-ldap-injection.md`` records that no
real, directory-backed fixture existed for this detector: only the mocked
connection in ``tests/unit/test_ldap_injection_detector.py``. This file
closes that gap without a real LDAP server or a real TCP LDAP port.

The fixture uses ``ldap3`` (pure Python, installed dev-only into this
project's venv for this test; not added to any requirements lock file)
with the ``MOCK_SYNC`` client strategy: a real ``ldap3.Connection`` object
backed by an in-memory fake directory with one entry, reached over the
HTTP fixture's real TCP socket, not a real LDAP wire connection.
``MOCK_SYNC`` only fakes the network transport. It does not touch
ldap3's own filter compiler, which parses every search filter string
client-side before any request would reach a real or mocked directory.
Confirmed empirically before writing this fixture: a throwaway script
built a ``MOCK_SYNC`` connection, called ``.search()`` with the filter
``"(uid=1))"`` (one closing parenthesis too many), and it raised a real
``ldap3.core.exceptions.LDAPInvalidFilterError`` from ldap3's own filter
parser, the same exception this detector's own signature list already
carries. The connection stayed usable for later searches afterward, so
one shared connection across requests is safe.

Two HTTP endpoints exercise the same directory connection with different
filter-construction code:

- ``/vulnerable?uid=``: builds the search filter by interpolating the raw
  client-supplied value straight into ``f"(uid={value})"``. The
  detector's diagnostic value is the baseline plus one appended ``)``
  (see ``ldap_injection_detector.py``'s own module docstring for why it
  appends rather than replaces), so for baseline ``"1"`` the diagnostic
  filter string becomes ``"(uid=1))"``, an unbalanced filter that
  ldap3's compiler genuinely rejects. The handler catches the resulting
  ``LDAPException`` and renders the exception's real, fully-qualified
  class name and message in the response body, the same way a plain
  Python app's own error page or traceback dump would, then returns
  HTTP 500. This is a real filter-string parse failure, not a canned
  string standing in for one.
- ``/safe?uid=``: escapes the value first with ldap3's own
  ``escape_filter_chars`` (the library's real RFC 4515 escaping helper)
  before building the same filter template. The appended ``)`` becomes
  the literal three-character escape sequence ``\\29``, so the filter
  stays syntactically balanced and the search returns normally, with no
  exception, for the same diagnostic value the vulnerable route breaks
  on.

Both routes share one fixture directory entry (``uid=1``) so a baseline
lookup on either route genuinely finds a match before the diagnostic
probe is sent.
"""

from __future__ import annotations

import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars

    _LDAP3_AVAILABLE = True
except ImportError:
    _LDAP3_AVAILABLE = False

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    DetectionCandidate,
    LdapInjectionOutcome,
    ValidatedTarget,
    run_ldap_injection_detector,
)

_SEARCH_BASE = "dc=example,dc=com"


def _integration_enabled() -> bool:
    return os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


def _build_mock_connection():
    """Builds a real ``ldap3.Connection`` on the ``MOCK_SYNC`` strategy
    with one directory entry (``uid=1``). Only ever called from
    ``setUpClass`` on the skip-gated test below, so ``ldap3`` is always
    importable by the time this runs even though the name is not bound
    at module level when the package is missing."""

    server = ldap3.Server("webguard-fixture-mock")
    connection = ldap3.Connection(
        server,
        user="cn=fixture,dc=example,dc=com",
        password="not-a-real-secret",
        client_strategy=ldap3.MOCK_SYNC,
    )
    connection.strategy.add_entry(
        "uid=1,ou=people,dc=example,dc=com",
        {"objectClass": ["person"], "uid": ["1"], "cn": ["Fixture User"]},
    )
    connection.bind()
    return connection


class _LdapFixtureHandler(BaseHTTPRequestHandler):
    """Real HTTP handler in front of a real (mocked-transport) ldap3
    connection. ``ldap_connection`` is set once, on the class, by
    ``setUpClass`` before the server starts serving; nothing here
    references ``ldap3`` at class-definition time, so this class can be
    defined even when ``ldap3`` is not installed.

    Named ``ldap_connection``, not ``connection``: ``BaseHTTPRequestHandler``
    already owns ``self.connection`` (it is the raw request socket, set
    by ``socketserver.StreamRequestHandler.setup()``), and that instance
    attribute would shadow a same-named class attribute silently."""

    ldap_connection = None
    _lock = threading.Lock()

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def _respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _search_and_respond(self, search_filter: str) -> None:
        try:
            with self._lock:
                found = self.ldap_connection.search(
                    _SEARCH_BASE, search_filter, attributes=["cn"]
                )
                count = len(self.ldap_connection.entries) if found else 0
            self._respond(f"<html>Results: {count}</html>".encode())
        except LDAPException as exc:
            # Rendered the way a minimal app's own error page or
            # traceback would: the real exception's fully-qualified
            # class name plus its real message, nothing invented.
            qualified = f"{type(exc).__module__}.{type(exc).__qualname__}"
            self._respond(
                f"<html>{qualified}: {exc}</html>".encode(), status=500
            )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query).get("uid", [""])[0]

        if parsed.path == "/vulnerable":
            # No escaping at all: the raw value is concatenated
            # straight into the filter template.
            self._search_and_respond(f"(uid={value})")
            return

        if parsed.path == "/safe":
            # ldap3's own real escaping helper, applied before the
            # value ever reaches the filter template.
            self._search_and_respond(f"(uid={escape_filter_chars(value)})")
            return

        if parsed.path == "/broken":
            self._respond(b"<html>Internal Server Error</html>", status=500)
            return

        self._respond(b"<html>not found</html>", status=404)


@unittest.skipUnless(
    _LDAP3_AVAILABLE and _integration_enabled(),
    "Set WEBGUARD_RUN_INTEGRATION=1 and pip install ldap3 to run this "
    "live LDAP-injection fixture test.",
)
class LdapInjectionDetectorLiveFixtureTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread

    @classmethod
    def setUpClass(cls) -> None:
        _LdapFixtureHandler.ldap_connection = _build_mock_connection()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LdapFixtureHandler)
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
        return ActiveDetectionContext(scan_id="live-ldapi-fixture-scan")

    def _run(self, path: str):
        candidate = DetectionCandidate(
            url=f"http://127.0.0.1:{self.port}{path}",
            parameter="uid",
            original_value="1",
        )
        return run_ldap_injection_detector(
            self._target(),
            (candidate,),
            self._context(),
            policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )

    def test_vulnerable_endpoint_is_confirmed_with_cwe90(self) -> None:
        result = self._run("/vulnerable")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            [i.value for i in result.findings[0].identifiers], ["CWE-90"]
        )
        # The real ldap3 filter-compiler exception is the signature this
        # detector's own list carries specifically for this case.
        self.assertEqual(
            result.records[0].matched_signature,
            "ldap3.core.exceptions.ldapinvalidfiltererror",
        )
        self.assertIn(
            result.records[0].outcome,
            (LdapInjectionOutcome.CONFIRMED, LdapInjectionOutcome.PROBABLE),
        )

    def test_escaped_safe_endpoint_produces_no_finding(self) -> None:
        result = self._run("/safe")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, LdapInjectionOutcome.INCONCLUSIVE
        )

    def test_generic_500_endpoint_produces_no_finding(self) -> None:
        # False-positive control: a 500 with no LDAP involvement at all
        # must not be mistaken for a directory error.
        result = self._run("/broken")
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, LdapInjectionOutcome.INCONCLUSIVE
        )

    def test_all_three_endpoints_in_one_run_only_flag_the_vulnerable_one(
        self,
    ) -> None:
        candidates = tuple(
            DetectionCandidate(
                url=f"http://127.0.0.1:{self.port}{path}",
                parameter="uid",
                original_value="1",
            )
            for path in ("/vulnerable", "/safe", "/broken")
        )
        result = run_ldap_injection_detector(
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
