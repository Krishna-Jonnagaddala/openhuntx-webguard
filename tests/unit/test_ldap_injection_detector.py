"""Unit tests for the active error-based LDAP injection detector.

Covers the classification logic (baseline vs. diagnostic comparison,
directory-error-signature matching, append-not-replace payload
construction), false-positive resistance, and the same-origin/budget/
cancellation safety boundaries already proven for the SQL-injection
detector, against a fake connection so no network access is required.
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
    LdapInjectionOutcome,
    ValidatedTarget,
    run_ldap_injection_detector,
)


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.status = status
        self.reason = "OK"
        self._body = body
        self._position = 0
        self.msg = Message()
        self.msg.add_header("Content-Length", str(len(body)))

    def getheaders(self):
        return [("Content-Length", str(len(self._body)))]

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = len(self._body) - self._position
        chunk = self._body[self._position : self._position + amount]
        self._position += len(chunk)
        return chunk


class _ScriptedConnection:
    """A fake HTTP connection whose response is chosen by a caller-
    supplied function of the requested parameter value, simulating a
    server with known baseline/diagnostic behaviour."""

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

    def endheaders(self) -> None:
        return None

    def getresponse(self):
        parsed = urlsplit(self._path)
        value = parse_qs(parsed.query).get("uid", [""])[0]
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


def _candidate(url: str = "http://example.com/directory") -> DetectionCandidate:
    return DetectionCandidate(url=url, parameter="uid")


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
        return run_ldap_injection_detector(
            _target(),
            candidates or (_candidate(),),
            _context(),
            policy=policy or ActiveDetectionPolicy(minimum_delay_seconds=0.0),
            **kwargs,
        )


class LdapInjectionClassificationTests(unittest.TestCase):
    def test_genuine_filter_error_with_status_change_is_confirmed(self) -> None:
        def responder(value):
            if value.endswith(")"):
                return _FakeResponse(
                    b"<html>ldap_search(): Search: Bad search filter</html>",
                    status=500,
                )
            return _FakeResponse(b"<html>ok</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.confidence.value, "confirmed")
        self.assertEqual([i.value for i in finding.identifiers], ["CWE-90"])
        self.assertEqual(
            result.records[0].outcome, LdapInjectionOutcome.CONFIRMED
        )

    def test_diagnostic_payload_appends_to_baseline_not_replaces_it(self) -> None:
        # The diagnostic value must be "<baseline>)" , not a bare ")",
        # per the module's own documented append-not-replace design.
        seen_values = []

        def responder(value):
            seen_values.append(value)
            return _FakeResponse(b"<html>ok</html>", status=200)

        _run(_ScriptedConnection(responder))
        self.assertEqual(seen_values[1], "1)")

    def test_disclosure_without_status_change_is_probable(self) -> None:
        def responder(value):
            if value.endswith(")"):
                return _FakeResponse(
                    b"<html>Error: bad search filter</html>", status=200
                )
            return _FakeResponse(b"<html>ok</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].confidence.value, "high")
        self.assertEqual(
            result.records[0].outcome, LdapInjectionOutcome.PROBABLE
        )

    def test_generic_500_with_no_signature_is_inconclusive(self) -> None:
        def responder(value):
            return _FakeResponse(b"<html>Internal Server Error</html>", status=500)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, LdapInjectionOutcome.INCONCLUSIVE
        )

    def test_reflected_payload_without_error_signature_is_inconclusive(
        self,
    ) -> None:
        def responder(value):
            return _FakeResponse(
                f"<html>Invalid uid: {value}</html>".encode(), status=400
            )

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, LdapInjectionOutcome.INCONCLUSIVE
        )

    def test_signature_already_in_baseline_is_inconclusive(self) -> None:
        # The exact same signature appears whether or not the probe is
        # sent: pre-existing content, not evidence of injection.
        def responder(value):
            return _FakeResponse(
                b"<html>Docs: what to do on 'bad search filter' errors</html>",
                status=200,
            )

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, LdapInjectionOutcome.INCONCLUSIVE
        )

    def test_each_documented_signature_is_matched(self) -> None:
        from webguard_scanner.ldap_injection_detector import (
            _LDAP_ERROR_SIGNATURES,
        )

        for signature in _LDAP_ERROR_SIGNATURES:

            def responder(value, signature=signature):
                if value.endswith(")"):
                    return _FakeResponse(
                        f"<html>{signature}</html>".encode(), status=500
                    )
                return _FakeResponse(b"<html>ok</html>", status=200)

            result = _run(_ScriptedConnection(responder))
            self.assertEqual(
                result.records[0].outcome,
                LdapInjectionOutcome.CONFIRMED,
                f"signature {signature!r} should be matched",
            )

    def test_multiple_parameters_each_classified_independently(self) -> None:
        def responder(value):
            if value.endswith(")"):
                return _FakeResponse(b"bad search filter", status=500)
            return _FakeResponse(b"<html>ok</html>", status=200)

        candidates = (
            _candidate(url="http://example.com/a"),
            _candidate(url="http://example.com/b"),
        )
        result = _run(
            _ScriptedConnection(responder),
            candidates=candidates,
            policy=ActiveDetectionPolicy(
                minimum_delay_seconds=0.0, maximum_probe_requests=25
            ),
        )
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(len(result.records), 2)

    def test_finding_evidence_never_contains_raw_signature_text(self) -> None:
        def responder(value):
            if value.endswith(")"):
                return _FakeResponse(b"bad search filter", status=500)
            return _FakeResponse(b"<html>ok</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        evidence_text = result.findings[0].evidence[0].summary
        self.assertNotIn("bad search filter", evidence_text)


class LdapInjectionSafetyBoundaryTests(unittest.TestCase):
    def test_off_origin_candidate_is_rejected_fail_closed(self) -> None:
        with self.assertRaises(ActiveDetectionError) as context:
            run_ldap_injection_detector(
                _target(),
                (_candidate(url="http://attacker.example/directory"),),
                _context(),
            )
        self.assertEqual(context.exception.code, "candidate_origin_mismatch")

    def test_probe_budget_accounts_for_two_requests_per_candidate(
        self,
    ) -> None:
        def responder(value):
            return _FakeResponse(b"<html>ok</html>", status=200)

        candidates = tuple(
            _candidate(url=f"http://example.com/d{i}") for i in range(3)
        )
        connection = _ScriptedConnection(responder)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(ActiveDetectionError) as context:
                run_ldap_injection_detector(
                    _target(),
                    candidates,
                    _context(),
                    # 3 candidates x 2 requests = 6, budget only allows 5.
                    policy=ActiveDetectionPolicy(maximum_probe_requests=5),
                )
        self.assertEqual(context.exception.code, "candidate_budget_exceeded")
        self.assertEqual(connection.requested_paths, [])

    def test_redirect_during_baseline_is_recorded_as_probe_error(
        self,
    ) -> None:
        class _RedirectingConnection(_ScriptedConnection):
            def getresponse(self):
                response = _FakeResponse(b"", status=302)
                response.reason = "Found"
                response.msg.add_header("Location", "http://example.com/x")
                return response

        result = _run(_RedirectingConnection(lambda v: None))
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records, ())
        self.assertEqual(result.probe_errors, ("redirect_blocked",))

    def test_connection_failure_is_recorded_as_probe_error(self) -> None:
        class _FailingConnection(_ScriptedConnection):
            def getresponse(self):
                raise ConnectionResetError("connection reset by peer")

        result = _run(_FailingConnection(lambda v: None))
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records, ())
        self.assertTrue(result.probe_errors)

    def test_cancellation_before_first_candidate_probes_nothing(
        self,
    ) -> None:
        connection = _ScriptedConnection(
            lambda value: _FakeResponse(b"<html>ok</html>", status=200)
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_ldap_injection_detector(
                _target(),
                (_candidate(),),
                _context(),
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
                cancellation_check=lambda: True,
            )
        self.assertTrue(result.cancelled)
        self.assertEqual(result.records, ())
        self.assertEqual(connection.requested_paths, [])

    def test_before_and_after_request_hooks_invoked_twice_per_candidate(
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
            run_ldap_injection_detector(
                _target(),
                (_candidate(),),
                _context(),
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
                before_request=lambda t, m: before_calls.append((t, m)),
                after_request=lambda t, m, r, e: after_calls.append((t, m, r, e)),
            )
        self.assertEqual(len(before_calls), 2)
        self.assertEqual(len(after_calls), 2)

    def test_non_get_candidate_is_rejected(self) -> None:
        with self.assertRaises(ActiveDetectionError):
            DetectionCandidate(
                url="http://example.com/directory",
                parameter="uid",
                method="POST",
            )


if __name__ == "__main__":
    unittest.main()
