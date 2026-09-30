"""Slice 11 stabilization audit: finding-fingerprint determinism,
proven through each active detector's real code path, not only the
generic contract-level `FindingIdentity.fingerprint` tests in
`test_findings_contract.py`.

`FindingIdentity.fingerprint` is computed from `rule_id`, `asset`,
`path`, `method`, and `parameter` only (`webguard_contracts/findings.py`)
-- never from a timestamp, a per-probe marker, a callback token, or a
session token. This module proves that property survives the full
detector pipeline for XSS, SQLi, IDOR, and SSRF: running the identical
detector twice against an identical (mocked) target produces the same
fingerprint despite each run generating a fresh, high-entropy probe
marker/callback token internally, and running against a different
endpoint/parameter produces a different fingerprint.

This is required before any production finding-lifecycle/deduplication
feature (matching a finding across two scans) could be built safely.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from webguard_scanner import (
    ActiveDetectionPolicy,
    AuthorizationResourcePair,
    run_idor_authorization_detector,
    run_reflected_xss_detector,
    run_sqli_error_detector,
    run_ssrf_callback_detector,
)
from webguard_scanner.callback_broker import InMemoryCallbackBroker

from tests.unit.test_active_xss_reflected import (
    _ReflectingConnection,
    _candidate as _xss_candidate,
    _context as _xss_context,
    _target as _xss_target,
)
from tests.unit.test_idor_authorization_detector import (
    _IdentityAwareConnection,
    _A_TOKEN,
    _B_TOKEN,
    _context as _idor_context,
    _material,
    _policy as _idor_policy,
    _resource,
    _target as _idor_target,
)
from tests.unit.test_sqli_error_detector import (
    _FakeResponse as _SqliFakeResponse,
    _ScriptedConnection as _SqliScriptedConnection,
    _candidate as _sqli_candidate,
    _context as _sqli_context,
    _target as _sqli_target,
)
from tests.unit.test_ssrf_callback_detector import (
    _ScriptedConnection as _SsrfScriptedConnection,
    _context as _ssrf_context,
    _target as _ssrf_target,
    _template as _ssrf_template,
)


class XssFingerprintDeterminismTests(unittest.TestCase):
    def _run(self):
        connection = _ReflectingConnection(reflect=True, encode=False)
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            return run_reflected_xss_detector(
                _xss_target(), (_xss_candidate(),), _xss_context()
            )

    def test_same_vulnerability_two_runs_same_fingerprint(self) -> None:
        first = self._run().findings[0]
        second = self._run().findings[0]
        self.assertEqual(first.fingerprint, second.fingerprint)
        # The per-probe marker is fresh every run (a random uuid4 slice)
        # -- confirming the fingerprint is stable despite that, not
        # merely because nothing actually varied between runs.
        self.assertNotEqual(
            [e.summary for e in first.evidence],
            [e.summary for e in second.evidence],
        )

    def test_different_parameter_different_fingerprint(self) -> None:
        first = self._run().findings[0]
        connection = _ReflectingConnection(reflect=True, encode=False)
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            second_result = run_reflected_xss_detector(
                _xss_target(),
                (_xss_candidate(url="http://example.com/other-endpoint"),),
                _xss_context(),
            )
        second = second_result.findings[0]
        self.assertNotEqual(first.fingerprint, second.fingerprint)


class SqliFingerprintDeterminismTests(unittest.TestCase):
    def _responder(self, value):
        if value == "'":
            return _SqliFakeResponse(
                b"<html>You have an error in your SQL syntax</html>", status=500
            )
        return _SqliFakeResponse(b"<html>Product 1</html>", status=200)

    def _run(self, candidate=None):
        connection = _SqliScriptedConnection(self._responder)
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            return run_sqli_error_detector(
                _sqli_target(),
                (candidate or _sqli_candidate(),),
                _sqli_context(),
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
            )

    def test_same_vulnerability_two_runs_same_fingerprint(self) -> None:
        first = self._run().findings[0]
        second = self._run().findings[0]
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_different_endpoint_different_fingerprint(self) -> None:
        first = self._run().findings[0]
        second = self._run(
            candidate=_sqli_candidate(url="http://example.com/other")
        ).findings[0]
        self.assertNotEqual(first.fingerprint, second.fingerprint)


class IdorFingerprintDeterminismTests(unittest.TestCase):
    def _responder(self, path, token):
        if path == "/api/orders/A-001":
            if token == _A_TOKEN:
                return 200, b'{"order":"A-001","owner":"user-a"}'
            return 403, b"denied"
        if path == "/api/orders/B-001":
            if token in (_A_TOKEN, _B_TOKEN):
                return 200, b'{"order":"B-001","owner":"user-b"}'
            return 403, b"denied"
        return 404, b"not found"

    def _run(self, pair=None):
        connection = _IdentityAwareConnection(self._responder)
        resource_pair = pair or AuthorizationResourcePair(
            primary_resource=_resource(
                "http://example.com/api/orders/A-001", "user-a"
            ),
            secondary_resource=_resource(
                "http://example.com/api/orders/B-001", "user-b"
            ),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            return run_idor_authorization_detector(
                _idor_target(),
                (resource_pair,),
                _idor_context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_idor_policy(),
            )

    def test_same_vulnerability_two_runs_same_fingerprint(self) -> None:
        first = self._run().findings[0]
        second = self._run().findings[0]
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_different_resource_endpoint_different_fingerprint(self) -> None:
        first = self._run().findings[0]
        different_pair = AuthorizationResourcePair(
            primary_resource=_resource(
                "http://example.com/api/documents/A-DOC-1", "user-a"
            ),
            secondary_resource=_resource(
                "http://example.com/api/documents/B-DOC-1", "user-b"
            ),
        )

        def responder(path, token):
            if path == "/api/documents/A-DOC-1":
                if token == _A_TOKEN:
                    return 200, b'{"doc":"A-DOC-1","owner":"user-a"}'
                return 403, b"denied"
            if path == "/api/documents/B-DOC-1":
                if token in (_A_TOKEN, _B_TOKEN):
                    return 200, b'{"doc":"B-DOC-1","owner":"user-b"}'
                return 403, b"denied"
            return 404, b"not found"

        connection = _IdentityAwareConnection(responder)
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            second_result = run_idor_authorization_detector(
                _idor_target(),
                (different_pair,),
                _idor_context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_idor_policy(),
            )
        second = second_result.findings[0]
        self.assertNotEqual(first.fingerprint, second.fingerprint)


class SsrfFingerprintDeterminismTests(unittest.TestCase):
    def _run(self, template=None):
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _SsrfScriptedConnection(status=200, body=b"fetched")

        original_register = broker.register

        def register_and_deliver(**kwargs):
            token = original_register(**kwargs)
            broker.record_observation(token.value, method="GET")
            return token

        broker.register = register_and_deliver  # type: ignore[method-assign]

        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            return run_ssrf_callback_detector(
                _ssrf_target(),
                (template or _ssrf_template(endpoint="http://example.com/fetch-vulnerable"),),
                _ssrf_context(),
                callback_broker=broker,
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
            )

    def test_same_vulnerability_two_runs_same_fingerprint(self) -> None:
        # Each run registers a fresh, independent, high-entropy callback
        # token -- the fingerprint must not depend on it.
        first = self._run().findings[0]
        second = self._run().findings[0]
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertNotEqual(
            [e.summary for e in first.evidence],
            [e.summary for e in second.evidence],
        )

    def test_different_endpoint_different_fingerprint(self) -> None:
        first = self._run().findings[0]
        second = self._run(
            template=_ssrf_template(endpoint="http://example.com/fetch-vulnerable-2")
        ).findings[0]
        self.assertNotEqual(first.fingerprint, second.fingerprint)


if __name__ == "__main__":
    unittest.main()
