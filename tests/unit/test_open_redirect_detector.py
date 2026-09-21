"""Unit tests for the active open-redirect detector.

Covers the classification logic (status-code scope, Location-header
resolution via urlsplit, the userinfo-trick and safe-query-string-echo
false-positive controls, duplicate-Location-header handling, malformed
Location values), and the same-origin/budget/cancellation safety
boundaries already proven for the other value-substitution detectors,
against a fake connection so no network access is required.
"""

from __future__ import annotations

import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    DetectionCandidate,
    OpenRedirectOutcome,
    ValidatedTarget,
    run_open_redirect_detector,
)


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


class _ScriptedConnection:
    """A fake HTTP connection whose response is chosen by a caller-
    supplied function of the requested parameter value."""

    def __init__(self, responder) -> None:
        self.responder = responder
        self.closed = False
        self.sock = None
        self._context = None
        self.requested_paths: list[str] = []

    def putrequest(self, method, path, **kwargs) -> None:
        self.requested_paths.append(path)
        self._path = path

    def putheader(self, name, value) -> None:
        return None

    def endheaders(self, message_body=None, *, encode_chunked=False) -> None:
        return None

    def getresponse(self):
        parsed = urlsplit(self._path)
        value = parse_qs(parsed.query).get("next", [""])[0]
        return self.responder(value)

    def close(self) -> None:
        self.closed = True


def _target(url: str = "http://example.com/") -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme="http",
        hostname="example.com",
        port=80,
        resolved_addresses=("93.184.216.34",),
    )


def _candidate(url: str = "http://example.com/go") -> DetectionCandidate:
    return DetectionCandidate(url=url, parameter="next")


def _context() -> ActiveDetectionContext:
    return ActiveDetectionContext(
        scan_id="scan-1",
        authorization_id="auth-1",
        permit_id="permit-1",
        permit_fingerprint="fp-1",
    )


def _run(connection, candidates=None, policy=None, **kwargs):
    with patch(
        "webguard_scanner.safe_http._make_connection",
        return_value=connection,
    ):
        return run_open_redirect_detector(
            _target(),
            candidates or (_candidate(),),
            _context(),
            policy=policy or ActiveDetectionPolicy(minimum_delay_seconds=0.0),
            **kwargs,
        )


def _redirect_to(value: str, *, location: str, status: int = 302) -> _FakeResponse:
    return _FakeResponse(b"", status=status, extra_headers=(("Location", location),))


class OpenRedirectClassificationTests(unittest.TestCase):
    def test_genuine_redirect_to_injected_host_is_confirmed(self) -> None:
        def responder(value):
            return _redirect_to(value, location=value)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.confidence.value, "confirmed")
        self.assertEqual([i.value for i in finding.identifiers], ["CWE-601"])
        self.assertEqual(result.records[0].outcome, OpenRedirectOutcome.CONFIRMED)

    def test_each_browser_auto_followed_status_is_confirmed(self) -> None:
        for status in (301, 302, 303, 307, 308):
            def responder(value, status=status):
                return _redirect_to(value, location=value, status=status)

            result = _run(_ScriptedConnection(responder))
            self.assertEqual(
                result.records[0].outcome,
                OpenRedirectOutcome.CONFIRMED,
                f"status {status} should confirm",
            )

    def test_status_300_305_306_are_not_vulnerable_even_with_matching_location(
        self,
    ) -> None:
        for status in (300, 305, 306):
            def responder(value, status=status):
                return _redirect_to(value, location=value, status=status)

            result = _run(_ScriptedConnection(responder))
            self.assertEqual(
                result.records[0].outcome,
                OpenRedirectOutcome.NOT_VULNERABLE,
                f"status {status} should not confirm",
            )

    def test_relative_location_is_not_vulnerable(self) -> None:
        def responder(value):
            return _redirect_to(value, location="/home")

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.NOT_VULNERABLE
        )

    def test_no_location_header_on_a_3xx_is_not_vulnerable(self) -> None:
        def responder(value):
            return _FakeResponse(b"", status=302)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.NOT_VULNERABLE
        )

    def test_generic_200_response_is_not_vulnerable(self) -> None:
        def responder(value):
            return _FakeResponse(b"<html>ok</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.NOT_VULNERABLE
        )

    def test_userinfo_prefix_trick_resolves_to_the_real_host_and_confirms(
        self,
    ) -> None:
        # https://target.example.com@<marker>.invalid/ must resolve to
        # <marker>.invalid (the real destination), not be fooled into
        # thinking "target.example.com" is the host because it appears
        # first in the string.
        def responder(value):
            parsed = urlsplit(value)
            tricked = f"https://target.example.com@{parsed.hostname}/"
            return _redirect_to(value, location=tricked)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.records[0].outcome, OpenRedirectOutcome.CONFIRMED)

    def test_safe_app_redirects_to_itself_echoing_payload_in_query_string(
        self,
    ) -> None:
        # The app redirects to its own domain, merely echoing the
        # injected value back as a query parameter for its own use (a
        # "you are leaving this site" interstitial). A substring match
        # would wrongly flag this; resolving the actual redirect host
        # must not.
        def responder(value):
            safe_location = f"https://example.com/leaving?to={value}"
            return _redirect_to(value, location=safe_location)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.NOT_VULNERABLE
        )

    def test_protocol_relative_location_confirms(self) -> None:
        def responder(value):
            host = urlsplit(value).hostname
            return _redirect_to(value, location=f"//{host}/path")

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.records[0].outcome, OpenRedirectOutcome.CONFIRMED)

    def test_trailing_dot_fqdn_location_still_confirms(self) -> None:
        def responder(value):
            host = urlsplit(value).hostname
            return _redirect_to(value, location=f"https://{host}./")

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.records[0].outcome, OpenRedirectOutcome.CONFIRMED)

    def test_case_variation_in_location_still_confirms(self) -> None:
        def responder(value):
            host = urlsplit(value).hostname
            return _redirect_to(value, location=f"HTTPS://{host.upper()}/")

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.records[0].outcome, OpenRedirectOutcome.CONFIRMED)

    def test_duplicate_location_headers_is_not_vulnerable(self) -> None:
        # An ambiguous response (e.g. a proxy layer adding its own
        # Location on top of the origin's own) must never be resolved
        # by silently picking whichever header came first.
        def responder(value):
            return _FakeResponse(
                b"",
                status=302,
                extra_headers=(
                    ("Location", "https://safe.example.com/"),
                    ("Location", value),
                ),
            )

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.NOT_VULNERABLE
        )

    def test_malformed_ipv6_location_does_not_crash_and_is_not_vulnerable(
        self,
    ) -> None:
        def responder(value):
            return _redirect_to(value, location="http://[::1/broken")

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, OpenRedirectOutcome.NOT_VULNERABLE
        )

    def test_marker_is_unique_per_candidate(self) -> None:
        seen_hosts = []

        def responder(value):
            return _FakeResponse(b"<html>ok</html>", status=200)

        candidates = (
            _candidate(url="http://example.com/a"),
            _candidate(url="http://example.com/b"),
        )
        connection = _ScriptedConnection(responder)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_open_redirect_detector(
                _target(),
                candidates,
                _context(),
                policy=ActiveDetectionPolicy(
                    minimum_delay_seconds=0.0, maximum_probe_requests=25
                ),
            )
        for record in result.records:
            seen_hosts.append(record.expected_host)
        self.assertEqual(len(seen_hosts), len(set(seen_hosts)))

    def test_finding_evidence_never_contains_the_probe_host(self) -> None:
        def responder(value):
            return _redirect_to(value, location=value)

        result = _run(_ScriptedConnection(responder))
        evidence_text = result.findings[0].evidence[0].summary
        self.assertNotIn(".invalid", evidence_text)


class OpenRedirectSafetyBoundaryTests(unittest.TestCase):
    def test_off_origin_candidate_is_rejected_fail_closed(self) -> None:
        with self.assertRaises(ActiveDetectionError) as context:
            run_open_redirect_detector(
                _target(),
                (_candidate(url="http://attacker.example/go"),),
                _context(),
            )
        self.assertEqual(context.exception.code, "candidate_origin_mismatch")

    def test_probe_budget_accounts_for_one_request_per_candidate(self) -> None:
        def responder(value):
            return _FakeResponse(b"<html>ok</html>", status=200)

        candidates = tuple(
            _candidate(url=f"http://example.com/p{i}") for i in range(6)
        )
        connection = _ScriptedConnection(responder)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(ActiveDetectionError) as context:
                run_open_redirect_detector(
                    _target(),
                    candidates,
                    _context(),
                    # 6 candidates x 1 request = 6, budget only allows 5.
                    policy=ActiveDetectionPolicy(maximum_probe_requests=5),
                )
        self.assertEqual(context.exception.code, "candidate_budget_exceeded")
        self.assertEqual(connection.requested_paths, [])

    def test_connection_failure_is_recorded_as_probe_error(self) -> None:
        class _FailingConnection(_ScriptedConnection):
            def getresponse(self):
                raise ConnectionResetError("connection reset by peer")

        result = _run(_FailingConnection(lambda v: None))
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records, ())
        self.assertTrue(result.probe_errors)

    def test_cancellation_before_first_candidate_probes_nothing(self) -> None:
        connection = _ScriptedConnection(
            lambda value: _FakeResponse(b"<html>ok</html>", status=200)
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_open_redirect_detector(
                _target(),
                (_candidate(),),
                _context(),
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
                cancellation_check=lambda: True,
            )
        self.assertTrue(result.cancelled)
        self.assertEqual(result.records, ())
        self.assertEqual(connection.requested_paths, [])

    def test_before_and_after_request_hooks_invoked_once_per_candidate(
        self,
    ) -> None:
        connection = _ScriptedConnection(
            lambda value: _FakeResponse(b"<html>ok</html>", status=200)
        )
        before_calls = []
        after_calls = []
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            run_open_redirect_detector(
                _target(),
                (_candidate(),),
                _context(),
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
                before_request=lambda t, m: before_calls.append((t, m)),
                after_request=lambda t, m, r, e: after_calls.append((t, m, r, e)),
            )
        self.assertEqual(len(before_calls), 1)
        self.assertEqual(len(after_calls), 1)

    def test_non_get_candidate_is_rejected(self) -> None:
        with self.assertRaises(ActiveDetectionError):
            DetectionCandidate(
                url="http://example.com/go",
                parameter="next",
                method="POST",
            )


if __name__ == "__main__":
    unittest.main()
