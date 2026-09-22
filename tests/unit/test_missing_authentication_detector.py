"""Unit tests for the active missing-authentication (CWE-306) detector.

Covers: the CONFIRMED tier (exact fingerprint match *and* marker
present -- both signals, not either alone); PROBABLE for a bare exact
match with no marker configured (the false-positive control this
detector has no second identity to provide for free); PROBABLE for a
marker match on non-identical content (the CSRF-token/timestamp false-
negative case); NOT_VULNERABLE for a denied probe and for a redirect-
to-login probe (status short-circuited before any body is ever
fingerprinted); INCONCLUSIVE when the authenticated baseline itself
fails; per-endpoint ERROR isolation (one bad endpoint never discards
another endpoint's result); anonymous-probe identity isolation
(no Authorization header ever reaches the probe); evidence
sanitization; and budget/cancellation enforcement.
"""

from __future__ import annotations

import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import urlsplit

from webguard_contracts import MissingAuthenticationEndpoint
from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    AuthenticationMaterial,
    MissingAuthenticationOutcome,
    ValidatedTarget,
    run_missing_authentication_detector,
)


def _target(url: str = "http://example.com/") -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme="http",
        hostname="example.com",
        port=80,
        resolved_addresses=("93.184.216.34",),
    )


def _context() -> ActiveDetectionContext:
    return ActiveDetectionContext(scan_id="missing-auth-scan-1")


def _policy(maximum_probe_requests: int = 25) -> ActiveDetectionPolicy:
    return ActiveDetectionPolicy(maximum_probe_requests=maximum_probe_requests)


def _endpoint(path: str = "/admin/dashboard", owner_marker: str = "") -> MissingAuthenticationEndpoint:
    return MissingAuthenticationEndpoint(
        endpoint=f"http://example.com{path}", owner_marker=owner_marker
    )


_OWNER_TOKEN = "token-for-owner"


def _material(token: str = _OWNER_TOKEN) -> AuthenticationMaterial:
    return AuthenticationMaterial(bearer_token=token)


class _FakeResponse:
    def __init__(
        self, body: bytes = b"", status: int = 200, extra_headers=()
    ) -> None:
        self.status = status
        self.reason = "OK"
        self._body = body
        self._position = 0
        self._extra_headers = tuple(extra_headers)
        self.msg = Message()
        self.msg.add_header("Content-Length", str(len(body)))

    def getheaders(self):
        return [
            ("Content-Length", str(len(self._body))),
            *self._extra_headers,
        ]

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = len(self._body) - self._position
        chunk = self._body[self._position : self._position + amount]
        self._position += len(chunk)
        return chunk


class _IdentityAwareConnection:
    """A fake connection whose response depends on both the requested
    path and the bearer token actually sent (``None`` for an anonymous
    request), so tests can prove anonymous-probe isolation and
    classification precisely.

    ``responder(path, bearer_token) -> (status, body, extra_headers)``
    """

    def __init__(self, responder) -> None:
        self.responder = responder
        self.sock = None
        self._context = None
        self._path = ""
        self._bearer_token = None
        self.requested: list[tuple[str, str | None]] = []

    def putrequest(self, method, path, **kwargs) -> None:
        self._path = path
        self._bearer_token = None

    def putheader(self, name, value) -> None:
        if name == "Authorization" and value.startswith("Bearer "):
            self._bearer_token = value[len("Bearer ") :]

    def endheaders(self, message_body=None) -> None:
        self.requested.append((urlsplit(self._path).path, self._bearer_token))

    def getresponse(self):
        status, body, extra_headers = self.responder(
            urlsplit(self._path).path, self._bearer_token
        )
        return _FakeResponse(body, status=status, extra_headers=extra_headers)

    def close(self) -> None:
        pass


def _respond(status: int, body: bytes = b"", extra_headers=()):
    return status, body, extra_headers


class ConfirmedDetectionTests(unittest.TestCase):
    def test_confirmed_when_exact_match_and_marker_both_present(self) -> None:
        body = b'{"role":"admin","secret_marker":"leaked-content"}'

        def responder(path, token):
            if path == "/admin/dashboard":
                # Identical content regardless of who (or nobody) asks.
                return _respond(200, body)
            return _respond(404, b"not found")

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint(owner_marker="secret_marker")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {MissingAuthenticationOutcome.CONFIRMED})
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        cwe_values = [i.value for i in finding.identifiers if i.namespace == "CWE"]
        self.assertEqual(cwe_values, ["CWE-306"])


class ProbableTests(unittest.TestCase):
    def test_bare_exact_match_without_marker_is_probable_not_confirmed(self) -> None:
        """The BLOCKING false-positive control this detector needs since
        it has no second identity's own baseline to rule out 'this
        endpoint returns the same thing to everyone' -- a bare fingerprint
        match with no marker configured must never reach CONFIRMED."""

        body = b"<html>Dashboard</html>"

        def responder(path, token):
            return _respond(200, body)

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint(owner_marker="")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {MissingAuthenticationOutcome.PROBABLE})
        self.assertEqual(len(result.findings), 1)
        self.assertIn("probable", result.findings[0].source_rule_id.lower())

    def test_marker_match_without_exact_fingerprint_is_probable(self) -> None:
        """The false-negative control for per-request dynamic content
        (a CSRF token, nonce, or timestamp) that would otherwise make
        the authenticated and anonymous bodies differ byte-for-byte even
        though the same protected data leaked."""

        counter = {"n": 0}

        def responder(path, token):
            counter["n"] += 1
            return _respond(
                200,
                f'{{"secret_marker":"leaked","csrf":"{counter["n"]}"}}'.encode(),
            )

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint(owner_marker="secret_marker")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {MissingAuthenticationOutcome.PROBABLE})
        self.assertTrue(result.findings)


class NotVulnerableTests(unittest.TestCase):
    def test_anonymous_probe_denied_is_not_vulnerable(self) -> None:
        def responder(path, token):
            if token == _OWNER_TOKEN:
                return _respond(200, b"protected content")
            return _respond(403, b"denied")

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        self.assertEqual(result.findings, ())
        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {MissingAuthenticationOutcome.NOT_VULNERABLE})

    def test_anonymous_probe_redirected_to_login_is_not_vulnerable_not_error(
        self,
    ) -> None:
        """A 3xx to a login page is exactly what correct gating looks
        like -- must classify NOT_VULNERABLE, never ERROR, and must
        never fingerprint the redirect's own (unrelated) body."""

        def responder(path, token):
            if token == _OWNER_TOKEN:
                return _respond(200, b"protected content")
            return _respond(
                302, b"", extra_headers=(("Location", "/login"),)
            )

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        self.assertEqual(result.findings, ())
        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {MissingAuthenticationOutcome.NOT_VULNERABLE})
        self.assertEqual(result.probe_errors, ())

    def test_anonymous_200_with_unrelated_content_is_not_vulnerable(self) -> None:
        """A generic public response (e.g. a shared SPA shell) that
        happens to also return 200 must never be treated as a leak on
        its own -- neither the exact-match nor the marker signal fires."""

        def responder(path, token):
            if token == _OWNER_TOKEN:
                return _respond(200, b'{"role":"admin","secret_marker":"leak"}')
            return _respond(200, b"<html>Please sign in via the app shell</html>")

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint(owner_marker="secret_marker")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        self.assertEqual(result.findings, ())
        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {MissingAuthenticationOutcome.NOT_VULNERABLE})


class BaselineFailureTests(unittest.TestCase):
    def test_failed_baseline_is_inconclusive_not_vulnerable(self) -> None:
        def responder(path, token):
            # The authenticated baseline itself is denied (session
            # expired) -- nothing legitimate to compare the anonymous
            # probe against.
            return _respond(401, b"unauthenticated")

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        self.assertEqual(result.findings, ())
        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {MissingAuthenticationOutcome.INCONCLUSIVE})


class PerEndpointIsolationTests(unittest.TestCase):
    def test_one_bad_endpoint_does_not_discard_another_endpoints_result(self) -> None:
        """A malformed or off-origin endpoint among several must be
        isolated to its own ERROR outcome, never abort the whole batch
        -- the gap the pre-implementation verification flagged in
        IDOR's own executor wrapper, deliberately not repeated here."""

        def responder(path, token):
            if path == "/good" and token == _OWNER_TOKEN:
                return _respond(200, b"secret_marker leaked")
            if path == "/good":
                return _respond(200, b"secret_marker leaked")
            return _respond(404, b"not found")

        connection = _IdentityAwareConnection(responder)
        good = _endpoint("/good", owner_marker="secret_marker")
        off_origin = MissingAuthenticationEndpoint(
            endpoint="http://not-example.com/other", owner_marker=""
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (off_origin, good),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        outcome_by_endpoint = {r.endpoint: r.outcome for r in result.records}
        self.assertEqual(
            outcome_by_endpoint["http://not-example.com/other"],
            MissingAuthenticationOutcome.ERROR,
        )
        self.assertEqual(
            outcome_by_endpoint["http://example.com/good"],
            MissingAuthenticationOutcome.CONFIRMED,
        )
        self.assertEqual(len(result.findings), 1)


class AnonymousProbeIsolationTests(unittest.TestCase):
    def test_anonymous_probe_never_carries_a_bearer_token(self) -> None:
        sent_tokens: list[str | None] = []

        def responder(path, token):
            sent_tokens.append(token)
            if token == _OWNER_TOKEN:
                return _respond(200, b"protected")
            return _respond(403, b"denied")

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        # Exactly two requests: the authenticated baseline (real token)
        # and the anonymous probe (no token at all).
        self.assertEqual(sent_tokens, [_OWNER_TOKEN, None])


class EvidenceSanitizationTests(unittest.TestCase):
    def test_finding_evidence_never_contains_marker_or_bearer_token(self) -> None:
        body = b'{"ssn":"123-45-6789","secret_marker":"leak"}'

        def responder(path, token):
            return _respond(200, body)

        connection = _IdentityAwareConnection(responder)
        endpoint = _endpoint(owner_marker="secret_marker")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
            )

        self.assertTrue(result.findings)
        evidence_text = " ".join(
            e.summary for finding in result.findings for e in finding.evidence
        )
        self.assertNotIn(_OWNER_TOKEN, evidence_text)
        self.assertNotIn("123-45-6789", evidence_text)
        self.assertNotIn("secret_marker", evidence_text)
        self.assertNotIn("{", evidence_text)


class BudgetAndCancellationTests(unittest.TestCase):
    def test_budget_exceeded_raises_before_any_request(self) -> None:
        connection = _IdentityAwareConnection(lambda p, t: _respond(200, b"ok"))
        endpoint = _endpoint()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            with self.assertRaises(ActiveDetectionError) as caught:
                run_missing_authentication_detector(
                    _target(),
                    (endpoint,),
                    _context(),
                    authentication_material=_material(),
                    policy=_policy(maximum_probe_requests=1),
                )
        self.assertEqual(caught.exception.code, "candidate_budget_exceeded")
        self.assertEqual(connection.requested, [])

    def test_cancellation_before_first_endpoint_probes_nothing(self) -> None:
        connection = _IdentityAwareConnection(lambda p, t: _respond(200, b"ok"))
        endpoint = _endpoint()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_missing_authentication_detector(
                _target(),
                (endpoint,),
                _context(),
                authentication_material=_material(),
                policy=_policy(),
                cancellation_check=lambda: True,
            )
        self.assertTrue(result.cancelled)
        self.assertEqual(result.records, ())
        self.assertEqual(connection.requested, [])


if __name__ == "__main__":
    unittest.main()
