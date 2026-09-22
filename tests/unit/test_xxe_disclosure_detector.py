"""Unit tests for the active in-band XXE disclosure detector.

Covers candidate selection (private, per-module copy: GET/legacy
candidates ignored, dedupe by endpoint+method, form/JSON only), the
baseline-vs-diagnostic /etc/passwd signature classification logic
(CONFIRMED/PROBABLE/INCONCLUSIVE), the payload shape actually sent, and
the same same-origin/budget/cancellation/hook safety boundaries already
proven for path traversal and the out-of-band XXE detector, against a
fake connection so no network access is required.
"""

from __future__ import annotations

from email.message import Message
from unittest.mock import patch

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    ContentType,
    DetectionCandidate,
    FetchPolicy,
    RequestTemplate,
    ValidatedTarget,
    XxeDisclosureOutcome,
    run_xxe_disclosure_detector,
)

import unittest


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
    return ActiveDetectionContext(scan_id="xxe-disclosure-scan-1")


def _template(
    *,
    endpoint: str = "http://example.com/upload",
    method: str = "POST",
    parameter: str = "notes",
    content_type: str = ContentType.FORM_URLENCODED,
    source_candidate_id: str = "cand-1",
) -> RequestTemplate:
    return RequestTemplate(
        endpoint=endpoint,
        method=method,
        content_type=content_type,
        parameter=parameter,
        form_parameters=((parameter, "hello"),) if content_type == ContentType.FORM_URLENCODED else (),
        json_body='{"notes": "hello"}' if content_type == ContentType.JSON else "",
        source_candidate_id=source_candidate_id,
    )


class _FakeResponse:
    def __init__(self, body: bytes = b"", status: int = 200) -> None:
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
    supplied function of the sent request body, simulating a server that
    behaves differently for the baseline vs. the diagnostic XML
    document."""

    def __init__(self, responder) -> None:
        self.responder = responder
        self.sock = None
        self._context = None
        self.requested_paths: list[str] = []
        self.sent_headers: list[tuple[str, str]] = []
        self.sent_bodies: list[bytes] = []

    def putrequest(self, method, path, **kwargs) -> None:
        self.requested_paths.append(path)

    def putheader(self, name, value) -> None:
        self.sent_headers.append((name, value))

    def endheaders(self, message_body=None, *, encode_chunked=False) -> None:
        if message_body is not None:
            self.sent_bodies.append(message_body)

    def send(self, data) -> None:
        return None

    def close(self) -> None:
        return None

    def getresponse(self):
        body = self.sent_bodies[-1] if self.sent_bodies else b""
        return self.responder(body.decode("utf-8", errors="replace"))


def _post_policy(**overrides) -> ActiveDetectionPolicy:
    defaults = dict(
        minimum_delay_seconds=0.0,
        fetch_policy=FetchPolicy(allowed_methods=frozenset({"GET", "HEAD", "POST"})),
    )
    defaults.update(overrides)
    return ActiveDetectionPolicy(**defaults)


def _run(connection, candidates=None, policy=None, **kwargs):
    with patch(
        "webguard_scanner.safe_http._make_connection", return_value=connection
    ):
        return run_xxe_disclosure_detector(
            _target(),
            candidates if candidates is not None else (_template(),),
            _context(),
            policy=policy or _post_policy(),
            **kwargs,
        )


_PASSWD_BODY = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"


class CandidateSelectionTests(unittest.TestCase):
    def test_get_only_legacy_candidate_is_never_probed(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        result = _run(
            connection,
            candidates=(DetectionCandidate(url="http://example.com/search", parameter="q"),),
        )
        self.assertEqual(result.records, ())
        self.assertEqual(result.findings, ())
        self.assertEqual(connection.requested_paths, [])

    def test_get_template_is_never_probed(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        get_template = _template(content_type=ContentType.NONE, method="GET")
        result = _run(connection, candidates=(get_template,))
        self.assertEqual(result.records, ())
        self.assertEqual(connection.requested_paths, [])

    def test_form_and_json_candidates_are_both_probed(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        result = _run(
            connection,
            candidates=(
                _template(content_type=ContentType.FORM_URLENCODED, endpoint="http://example.com/a"),
                _template(content_type=ContentType.JSON, endpoint="http://example.com/b"),
            ),
            policy=_post_policy(maximum_probe_requests=10),
        )
        self.assertEqual(len(result.records), 2)

    def test_dedupes_by_endpoint_and_method_not_by_parameter(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        templates = (
            _template(parameter="a", endpoint="http://example.com/same"),
            _template(parameter="b", endpoint="http://example.com/same"),
            _template(parameter="c", endpoint="http://example.com/same"),
        )
        result = _run(connection, candidates=templates)
        self.assertEqual(len(result.records), 1)


class PayloadShapeTests(unittest.TestCase):
    def test_baseline_document_declares_no_doctype_or_entity(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        _run(connection)
        baseline_sent = connection.sent_bodies[0].decode("utf-8")
        self.assertNotIn("<!DOCTYPE", baseline_sent)
        self.assertNotIn("<!ENTITY", baseline_sent)

    def test_diagnostic_document_declares_exactly_one_entity_targeting_etc_passwd(
        self,
    ) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        _run(connection)
        diagnostic_sent = connection.sent_bodies[1].decode("utf-8")
        self.assertIn("<!DOCTYPE", diagnostic_sent)
        self.assertEqual(diagnostic_sent.count("<!ENTITY"), 1)
        self.assertEqual(diagnostic_sent.count("SYSTEM"), 1)
        self.assertIn("file:///etc/passwd", diagnostic_sent)

    def test_both_probes_are_sent_with_xml_content_type_header(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        _run(connection)
        content_type_headers = [
            value for name, value in connection.sent_headers if name == "Content-Type"
        ]
        self.assertEqual(content_type_headers, [ContentType.XML, ContentType.XML])

    def test_original_form_body_is_fully_replaced_not_merged(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        _run(connection, candidates=(_template(parameter="notes", content_type=ContentType.FORM_URLENCODED),))
        for sent in connection.sent_bodies:
            self.assertNotIn(b"notes=hello", sent)


class ClassificationTests(unittest.TestCase):
    def test_disclosure_with_status_change_is_confirmed(self) -> None:
        def responder(body: str):
            if "file:///etc/passwd" in body:
                return _FakeResponse(_PASSWD_BODY, status=200)
            return _FakeResponse(b"<html>upload accepted</html>", status=201)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.confidence.value, "confirmed")
        self.assertEqual([i.value for i in finding.identifiers], ["CWE-611"])
        self.assertIsNone(finding.identity.parameter)
        self.assertEqual(result.records[0].outcome, XxeDisclosureOutcome.CONFIRMED)

    def test_disclosure_without_status_change_is_probable(self) -> None:
        def responder(body: str):
            if "file:///etc/passwd" in body:
                return _FakeResponse(b"<html>root:!:0:0:root:/root:/bin/bash</html>", status=200)
            return _FakeResponse(b"<html>ok</html>", status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].confidence.value, "high")
        self.assertEqual(result.records[0].outcome, XxeDisclosureOutcome.PROBABLE)

    def test_hardened_parser_rejection_with_no_signature_is_inconclusive(self) -> None:
        def responder(body: str):
            return _FakeResponse(b"<html>Bad Request: DOCTYPE is disallowed</html>", status=400)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, XxeDisclosureOutcome.INCONCLUSIVE)

    def test_reflection_of_raw_unresolved_payload_is_inconclusive(self) -> None:
        # The entity declaration text itself is reflected back verbatim,
        # unresolved, proof the parser never actually resolved it, since
        # the literal payload text cannot match _PASSWD_SIGNATURES.
        def responder(body: str):
            return _FakeResponse(f"<html>you sent: {body}</html>".encode(), status=200)

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, XxeDisclosureOutcome.INCONCLUSIVE)

    def test_passwd_looking_text_already_in_baseline_is_inconclusive(self) -> None:
        # The exact same signature appears whether or not the entity
        # resolves: pre-existing content, not evidence of XXE.
        def responder(body: str):
            return _FakeResponse(
                b"<html>Example config: root:x:0:0: (documentation)</html>", status=200
            )

        result = _run(_ScriptedConnection(responder))
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, XxeDisclosureOutcome.INCONCLUSIVE)

    def test_multiple_candidates_each_classified_independently(self) -> None:
        def responder(body: str):
            if "file:///etc/passwd" in body:
                return _FakeResponse(_PASSWD_BODY, status=200)
            return _FakeResponse(b"<html>ok</html>", status=201)

        candidates = (
            _template(endpoint="http://example.com/a"),
            _template(endpoint="http://example.com/b"),
        )
        result = _run(
            _ScriptedConnection(responder),
            candidates=candidates,
            policy=_post_policy(maximum_probe_requests=25),
        )
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(len(result.records), 2)

    def test_finding_evidence_never_contains_raw_signature_text(self) -> None:
        def responder(body: str):
            if "file:///etc/passwd" in body:
                return _FakeResponse(_PASSWD_BODY, status=200)
            return _FakeResponse(b"<html>ok</html>", status=201)

        result = _run(_ScriptedConnection(responder))
        evidence_text = result.findings[0].evidence[0].summary
        self.assertNotIn("root:x:0:0:", evidence_text)


class SafetyBoundaryTests(unittest.TestCase):
    def test_off_origin_candidate_is_rejected_fail_closed(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        with self.assertRaises(ActiveDetectionError) as caught:
            _run(
                connection,
                candidates=(_template(endpoint="http://attacker.example/upload"),),
            )
        self.assertEqual(caught.exception.code, "candidate_origin_mismatch")

    def test_probe_budget_accounts_for_two_requests_per_candidate(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        candidates = tuple(
            _template(endpoint=f"http://example.com/d{i}", source_candidate_id=f"c{i}")
            for i in range(3)
        )
        with self.assertRaises(ActiveDetectionError) as caught:
            _run(
                connection,
                candidates=candidates,
                # 3 candidates x 2 requests = 6, budget only allows 5.
                policy=_post_policy(maximum_probe_requests=5),
            )
        self.assertEqual(caught.exception.code, "candidate_budget_exceeded")
        self.assertEqual(connection.requested_paths, [])

    def test_diagnostic_connection_failure_is_recorded_as_probe_error(self) -> None:
        class _FailingConnection(_ScriptedConnection):
            def __init__(self) -> None:
                super().__init__(lambda body: _FakeResponse(b"ok", status=200))
                self._calls = 0

            def getresponse(self):
                self._calls += 1
                if self._calls == 1:
                    return _FakeResponse(b"ok", status=200)
                raise ConnectionResetError("connection reset by peer")

        result = _run(_FailingConnection())
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records, ())
        self.assertTrue(result.probe_errors)

    def test_baseline_connection_failure_is_recorded_as_probe_error(self) -> None:
        class _FailingConnection(_ScriptedConnection):
            def getresponse(self):
                raise ConnectionResetError("connection reset by peer")

        result = _run(_FailingConnection(lambda body: None))
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records, ())
        self.assertTrue(result.probe_errors)

    def test_cancellation_before_first_candidate_probes_nothing(self) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        result = _run(connection, cancellation_check=lambda: True)
        self.assertTrue(result.cancelled)
        self.assertEqual(result.records, ())
        self.assertEqual(connection.requested_paths, [])

    def test_before_and_after_request_hooks_invoked_twice_for_one_candidate(
        self,
    ) -> None:
        connection = _ScriptedConnection(lambda body: _FakeResponse(b"ok", status=200))
        before_calls = []
        after_calls = []
        _run(
            connection,
            before_request=lambda t, m: before_calls.append((t, m)),
            after_request=lambda t, m, r, e: after_calls.append((t, m, r, e)),
        )
        self.assertEqual(len(before_calls), 2)
        self.assertEqual(len(after_calls), 2)

    def test_evidence_never_contains_authentication_material(self) -> None:
        from webguard_scanner import AuthenticationMaterial

        def responder(body: str):
            if "file:///etc/passwd" in body:
                return _FakeResponse(_PASSWD_BODY, status=200)
            return _FakeResponse(b"<html>ok</html>", status=201)

        result = _run(
            _ScriptedConnection(responder),
            authentication_material=AuthenticationMaterial(
                bearer_token="super-secret-token-value"
            ),
        )
        self.assertEqual(len(result.findings), 1)
        evidence_text = " ".join(e.summary for e in result.findings[0].evidence)
        self.assertNotIn("super-secret-token-value", evidence_text)
        self.assertNotIn("Bearer", evidence_text)


if __name__ == "__main__":
    unittest.main()
