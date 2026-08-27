"""Unit tests for the active error-based SQL injection detector.

Covers the classification logic (baseline vs. diagnostic comparison,
database-error-signature matching), false-positive resistance, and the
same-origin/budget/cancellation safety boundaries already proven for the
reflected-XSS detector -- against a fake connection so no network access
is required. Real-network and end-to-end coverage live in separate files.
"""

from __future__ import annotations

import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import json

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    ContentType,
    DetectionCandidate,
    FetchPolicy,
    RequestTemplate,
    SqliDetectionOutcome,
    ValidatedTarget,
    run_sqli_error_detector,
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
        value = parse_qs(parsed.query).get("id", [""])[0]
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


def _candidate(url: str = "http://example.com/product") -> DetectionCandidate:
    return DetectionCandidate(url=url, parameter="id")


def _context() -> ActiveDetectionContext:
    return ActiveDetectionContext(
        scan_id="scan-1",
        authorization_id="auth-1",
        permit_id="permit-1",
        permit_fingerprint="fp-1",
    )


def _run(connection, candidates=None, policy=None):
    with patch(
        "webguard_scanner.safe_http._make_connection",
        return_value=connection,
    ):
        return run_sqli_error_detector(
            _target(),
            candidates or (_candidate(),),
            _context(),
            policy=policy or ActiveDetectionPolicy(minimum_delay_seconds=0.0),
        )


class SqliErrorClassificationTests(unittest.TestCase):
    def test_genuine_sql_error_signature_with_status_change_is_confirmed(
        self,
    ) -> None:
        def responder(value):
            if value == "'":
                return _FakeResponse(
                    b"<html>You have an error in your SQL syntax near line 1</html>",
                    status=500,
                )
            return _FakeResponse(b"<html>Product 1</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.confidence.value, "confirmed")
        self.assertEqual([i.value for i in finding.identifiers], ["CWE-89"])
        self.assertEqual(result.records[0].outcome, SqliDetectionOutcome.CONFIRMED)

    def test_signature_without_status_change_is_probable(self) -> None:
        def responder(value):
            if value == "'":
                return _FakeResponse(
                    b"<html>unclosed quotation mark after the character string</html>",
                    status=200,
                )
            return _FakeResponse(b"<html>Product 1</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].confidence.value, "high")
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.PROBABLE
        )

    def test_generic_500_with_no_signature_is_inconclusive(self) -> None:
        def responder(value):
            if value == "'":
                return _FakeResponse(b"<html>Internal Server Error</html>", status=500)
            return _FakeResponse(b"<html>Product 1</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_application_validation_error_is_inconclusive(self) -> None:
        def responder(value):
            if value == "'":
                return _FakeResponse(
                    b"<html>Invalid product identifier supplied</html>", status=400
                )
            return _FakeResponse(b"<html>Product 1</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_ordinary_apostrophe_in_legitimate_content_is_inconclusive(
        self,
    ) -> None:
        def responder(value):
            body = b"<html>It's a great day for shopping!</html>"
            return _FakeResponse(body, status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_reflected_probe_string_without_interpretation_is_inconclusive(
        self,
    ) -> None:
        def responder(value):
            return _FakeResponse(
                f"<html>You searched for: {value}</html>".encode(), status=200
            )

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_database_looking_text_already_in_baseline_is_inconclusive(
        self,
    ) -> None:
        # The exact same signature appears whether or not the probe is
        # sent -- pre-existing content, not evidence of injection.
        def responder(value):
            return _FakeResponse(
                b"<html>SQLite3::query available in admin panel</html>",
                status=200,
            )

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_changed_response_with_no_database_evidence_is_inconclusive(
        self,
    ) -> None:
        def responder(value):
            if value == "'":
                return _FakeResponse(b"<html>No results found</html>", status=200)
            return _FakeResponse(b"<html>Product 1</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE
        )

    def test_multiple_parameters_each_classified_independently(self) -> None:
        def responder(value):
            if value == "'":
                return _FakeResponse(
                    b"<html>you have an error in your sql syntax</html>",
                    status=500,
                )
            return _FakeResponse(b"<html>Product 1</html>", status=200)

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


class SqliErrorSafetyBoundaryTests(unittest.TestCase):
    def test_off_origin_candidate_is_rejected_fail_closed(self) -> None:
        with self.assertRaises(ActiveDetectionError) as context:
            run_sqli_error_detector(
                _target(),
                (_candidate(url="http://attacker.example/product"),),
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
                run_sqli_error_detector(
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
            result = run_sqli_error_detector(
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
            run_sqli_error_detector(
                _target(),
                (_candidate(),),
                _context(),
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
                before_request=lambda t, m: before_calls.append((t, m)),
                after_request=lambda t, m, r, e: after_calls.append(
                    (t, m, r, e)
                ),
            )
        self.assertEqual(len(before_calls), 2)
        self.assertEqual(len(after_calls), 2)

    def test_non_get_candidate_is_rejected(self) -> None:
        with self.assertRaises(ActiveDetectionError):
            DetectionCandidate(
                url="http://example.com/product",
                parameter="id",
                method="POST",
            )


class _BodyScriptedConnection:
    """A fake HTTP connection whose response is chosen by a caller-
    supplied function of the *request body* (form-urlencoded or JSON),
    simulating a POST/JSON endpoint with known baseline/diagnostic
    behaviour. Captures every sent body for inspection."""

    def __init__(self, responder, *, content_type: str) -> None:
        self.responder = responder
        self.content_type = content_type
        self.sock = None
        self._context = None
        self.sent_bodies: list[bytes] = []

    def putrequest(self, method, path, **kwargs) -> None:
        self._method = method
        self._path = path

    def putheader(self, name, value) -> None:
        return None

    def endheaders(self, message_body=None) -> None:
        self.sent_bodies.append(message_body or b"")

    def getresponse(self):
        body = self.sent_bodies[-1]
        if self.content_type == ContentType.JSON:
            value = json.loads(body).get("id", "") if body else ""
        else:
            value = parse_qs(body.decode()).get("id", [""])[0] if body else ""
        return self.responder(value)

    def close(self) -> None:
        pass


def _post_form_template(
    url: str = "http://example.com/product",
) -> RequestTemplate:
    return RequestTemplate(
        endpoint=url,
        method="POST",
        content_type=ContentType.FORM_URLENCODED,
        parameter="id",
        form_parameters=(("id", "1"),),
    )


def _json_template(url: str = "http://example.com/api/product") -> RequestTemplate:
    return RequestTemplate(
        endpoint=url,
        method="POST",
        content_type=ContentType.JSON,
        parameter="id",
        json_body=json.dumps({"id": "1", "session": "unrelated-value"}),
    )


def _post_policy() -> ActiveDetectionPolicy:
    return ActiveDetectionPolicy(
        minimum_delay_seconds=0.0,
        fetch_policy=FetchPolicy(allowed_methods=frozenset({"GET", "HEAD", "POST"})),
    )


_SQL_ERROR_BODY = b"<html>You have an error in your SQL syntax</html>"
_OK_BODY = b"<html>ok</html>"


class SqliPostFormDetectionTests(unittest.TestCase):
    def test_genuine_vulnerable_post_form_is_confirmed(self) -> None:
        def responder(value: str):
            if "'" in value:
                return _FakeResponse(_SQL_ERROR_BODY, status=500)
            return _FakeResponse(_OK_BODY, status=200)

        connection = _BodyScriptedConnection(
            responder, content_type=ContentType.FORM_URLENCODED
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_sqli_error_detector(
                _target(),
                (_post_form_template(),),
                _context(),
                policy=_post_policy(),
            )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.records[0].outcome, SqliDetectionOutcome.CONFIRMED)
        finding = result.findings[0]
        self.assertEqual(finding.identity.method, "POST")
        self.assertEqual(finding.identity.parameter, "id")

    def test_safe_parameterised_post_form_produces_no_finding(self) -> None:
        connection = _BodyScriptedConnection(
            lambda value: _FakeResponse(_OK_BODY, status=200),
            content_type=ContentType.FORM_URLENCODED,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_sqli_error_detector(
                _target(),
                (_post_form_template(),),
                _context(),
                policy=_post_policy(),
            )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE)

    def test_post_form_mutation_preserves_unrelated_form_fields(self) -> None:
        connection = _BodyScriptedConnection(
            lambda value: _FakeResponse(_OK_BODY, status=200),
            content_type=ContentType.FORM_URLENCODED,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            run_sqli_error_detector(
                _target(),
                (_post_form_template(),),
                _context(),
                policy=_post_policy(),
            )
        # Two requests: baseline then diagnostic. Neither ever sends an
        # empty body, and the diagnostic body must still carry only the
        # fields this template declared.
        for sent in connection.sent_bodies:
            fields = parse_qs(sent.decode())
            self.assertEqual(set(fields), {"id"})


class SqliJsonBodyDetectionTests(unittest.TestCase):
    def test_genuine_vulnerable_json_body_is_confirmed(self) -> None:
        def responder(value: str):
            if "'" in value:
                return _FakeResponse(_SQL_ERROR_BODY, status=500)
            return _FakeResponse(_OK_BODY, status=200)

        connection = _BodyScriptedConnection(responder, content_type=ContentType.JSON)
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_sqli_error_detector(
                _target(),
                (_json_template(),),
                _context(),
                policy=_post_policy(),
            )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.records[0].outcome, SqliDetectionOutcome.CONFIRMED)
        finding = result.findings[0]
        self.assertEqual(finding.identity.method, "POST")
        self.assertEqual(finding.identity.parameter, "id")

    def test_safe_json_body_produces_no_finding(self) -> None:
        connection = _BodyScriptedConnection(
            lambda value: _FakeResponse(_OK_BODY, status=200),
            content_type=ContentType.JSON,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_sqli_error_detector(
                _target(),
                (_json_template(),),
                _context(),
                policy=_post_policy(),
            )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, SqliDetectionOutcome.INCONCLUSIVE)

    def test_json_mutation_never_alters_unrelated_json_fields(self) -> None:
        connection = _BodyScriptedConnection(
            lambda value: _FakeResponse(_OK_BODY, status=200),
            content_type=ContentType.JSON,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            run_sqli_error_detector(
                _target(),
                (_json_template(),),
                _context(),
                policy=_post_policy(),
            )
        for sent in connection.sent_bodies:
            document = json.loads(sent)
            self.assertEqual(document["session"], "unrelated-value")

    def test_malformed_json_template_is_recorded_as_probe_error_not_a_crash(
        self,
    ) -> None:
        broken_template = RequestTemplate(
            endpoint="http://example.com/api/product",
            method="POST",
            content_type=ContentType.JSON,
            parameter="id",
            json_body="{not valid json",
        )
        connection = _BodyScriptedConnection(
            lambda value: _FakeResponse(_OK_BODY, status=200),
            content_type=ContentType.JSON,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_sqli_error_detector(
                _target(),
                (broken_template,),
                _context(),
                policy=_post_policy(),
            )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records, ())
        self.assertEqual(result.probe_errors, ("json_document_malformed",))

    def test_mixed_legacy_and_templated_candidates_in_one_run(self) -> None:
        """Cross-transport regression guard: a legacy GET DetectionCandidate
        and a new JSON RequestTemplate in the same call must each be probed
        with their own transport and classified independently."""

        get_connection_responses = {"baseline": True}

        class _MixedConnection:
            def __init__(self) -> None:
                self.sock = None
                self._context = None
                self._path = ""
                self._body = b""

            def putrequest(self, method, path, **kwargs) -> None:
                self._method = method
                self._path = path

            def putheader(self, name, value) -> None:
                return None

            def endheaders(self, message_body=None) -> None:
                self._body = message_body or b""

            def getresponse(self):
                if self._method == "GET":
                    value = parse_qs(urlsplit(self._path).query).get("q", [""])[0]
                    if "'" in value:
                        return _FakeResponse(_SQL_ERROR_BODY, status=500)
                    return _FakeResponse(_OK_BODY, status=200)
                value = json.loads(self._body).get("id", "") if self._body else ""
                if "'" in value:
                    return _FakeResponse(_SQL_ERROR_BODY, status=500)
                return _FakeResponse(_OK_BODY, status=200)

            def close(self) -> None:
                pass

        connection = _MixedConnection()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_sqli_error_detector(
                _target(),
                (
                    DetectionCandidate(
                        url="http://example.com/search", parameter="q"
                    ),
                    _json_template(),
                ),
                _context(),
                policy=_post_policy(),
            )

        self.assertEqual(len(result.records), 2)
        self.assertEqual(
            result.records[0].outcome, SqliDetectionOutcome.CONFIRMED
        )
        self.assertEqual(
            result.records[1].outcome, SqliDetectionOutcome.CONFIRMED
        )
        self.assertEqual(len(result.findings), 2)
        methods = {finding.identity.method for finding in result.findings}
        self.assertEqual(methods, {"GET", "POST"})


class SqliEvidenceSanitizationTests(unittest.TestCase):
    def test_finding_evidence_never_contains_raw_json_body_or_payload(
        self,
    ) -> None:
        connection = _BodyScriptedConnection(
            lambda value: (
                _FakeResponse(_SQL_ERROR_BODY, status=500)
                if "'" in value
                else _FakeResponse(_OK_BODY, status=200)
            ),
            content_type=ContentType.JSON,
        )
        template = RequestTemplate(
            endpoint="http://example.com/api/login",
            method="POST",
            content_type=ContentType.JSON,
            parameter="id",
            json_body=json.dumps(
                {"id": "1", "password": "super-secret-password", "token": "abc123"}
            ),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_sqli_error_detector(
                _target(),
                (template,),
                _context(),
                policy=_post_policy(),
            )

        self.assertEqual(len(result.findings), 1)
        evidence_text = " ".join(
            evidence.summary for evidence in result.findings[0].evidence
        )
        self.assertNotIn("super-secret-password", evidence_text)
        self.assertNotIn("abc123", evidence_text)
        self.assertNotIn("password", evidence_text.lower())
        # The parameter *name* is legitimate evidence; the JSON body text
        # (which would include the payload/other fields) must never appear.
        self.assertNotIn("{", evidence_text)


if __name__ == "__main__":
    unittest.main()
