"""Unit tests for the active OS command injection detector.

Covers the marker-based classification logic, false-positive resistance
(the exact marker never appears unless echoed back), and the same-origin/
budget/cancellation safety boundaries already proven for the SQL-
injection and path-traversal detectors, against a fake connection so
no network access is required.
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
    CommandInjectionOutcome,
    DetectionCandidate,
    ValidatedTarget,
    run_command_injection_detector,
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
        value = parse_qs(parsed.query).get("host", [""])[0]
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


def _candidate(url: str = "http://example.com/ping") -> DetectionCandidate:
    return DetectionCandidate(url=url, parameter="host")


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
        return run_command_injection_detector(
            _target(),
            candidates or (_candidate(),),
            _context(),
            policy=policy or ActiveDetectionPolicy(minimum_delay_seconds=0.0),
            **kwargs,
        )


class CommandInjectionClassificationTests(unittest.TestCase):
    def test_genuine_command_execution_echoes_marker_and_is_confirmed(
        self,
    ) -> None:
        def responder(value):
            if "; echo wgcmdi" in value:
                marker = value.split("echo ")[1].split(" #")[0]
                return _FakeResponse(
                    f"<html>PING 1 packets\n{marker}\n</html>".encode(),
                    status=200,
                )
            return _FakeResponse(b"<html>PING 1 packets</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity.value, "critical")
        self.assertEqual(finding.confidence.value, "confirmed")
        self.assertEqual([i.value for i in finding.identifiers], ["CWE-78"])
        self.assertEqual(
            result.records[0].outcome, CommandInjectionOutcome.CONFIRMED
        )

    def test_unmodified_reflection_of_the_raw_payload_is_inconclusive(
        self,
    ) -> None:
        # The target reflects whatever it was sent, verbatim, into an
        # error message, without ever executing it. The marker is
        # present only because the whole untouched payload (including
        # its ";" and "#" shell syntax) is present. No shell interpreted
        # anything here, so this must not be confirmed.
        def responder(value):
            return _FakeResponse(
                f"<html>Invalid host: {value}</html>".encode(), status=400
            )

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, CommandInjectionOutcome.INCONCLUSIVE
        )

    def test_generic_error_with_no_marker_is_inconclusive(self) -> None:
        def responder(value):
            return _FakeResponse(b"<html>Invalid hostname</html>", status=400)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, CommandInjectionOutcome.INCONCLUSIVE
        )

    def test_marker_is_unique_per_candidate(self) -> None:
        seen_markers = []

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
            result = run_command_injection_detector(
                _target(),
                candidates,
                _context(),
                policy=ActiveDetectionPolicy(
                    minimum_delay_seconds=0.0, maximum_probe_requests=25
                ),
            )
        for record in result.records:
            seen_markers.append(record.marker)
        self.assertEqual(len(seen_markers), len(set(seen_markers)))

    def test_finding_evidence_never_contains_raw_marker_text(self) -> None:
        def responder(value):
            if "; echo wgcmdi" in value:
                marker = value.split("echo ")[1].split(" #")[0]
                return _FakeResponse(f"<html>{marker}</html>".encode(), status=200)
            return _FakeResponse(b"<html>ok</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        evidence_text = result.findings[0].evidence[0].summary
        self.assertNotIn("wgcmdi", evidence_text)


class CommandInjectionSafetyBoundaryTests(unittest.TestCase):
    def test_off_origin_candidate_is_rejected_fail_closed(self) -> None:
        with self.assertRaises(ActiveDetectionError) as context:
            run_command_injection_detector(
                _target(),
                (_candidate(url="http://attacker.example/ping"),),
                _context(),
            )
        self.assertEqual(context.exception.code, "candidate_origin_mismatch")

    def test_probe_budget_accounts_for_two_requests_per_candidate(
        self,
    ) -> None:
        def responder(value):
            return _FakeResponse(b"<html>ok</html>", status=200)

        candidates = tuple(
            _candidate(url=f"http://example.com/p{i}") for i in range(3)
        )
        connection = _ScriptedConnection(responder)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(ActiveDetectionError) as context:
                run_command_injection_detector(
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
            result = run_command_injection_detector(
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
            run_command_injection_detector(
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
                url="http://example.com/ping",
                parameter="host",
                method="POST",
            )


if __name__ == "__main__":
    unittest.main()
