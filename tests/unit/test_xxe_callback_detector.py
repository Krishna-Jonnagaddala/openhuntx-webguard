"""Unit tests for the active XXE-callback detector.

Covers candidate selection (dedupe by endpoint+method, GET excluded),
the callback-correlation classification logic (CONFIRMED/PROBABLE/
NOT_VULNERABLE/INCONCLUSIVE/ERROR), the payload shape actually sent,
same-origin/budget/cancellation safety boundaries, and the same
false-positive controls ``test_ssrf_callback_detector.py`` requires,
against a fake connection and the real in-memory callback broker, so
no network access is required. Real-network and end-to-end coverage
are a stated, not-yet-done gap (see docs/audit/active-detection-
phase13-xxe-callback.md), matching path traversal and command
injection's own honestly-scoped v1 slices.
"""

from __future__ import annotations

import threading
import time
import unittest
from email.message import Message
from unittest.mock import patch

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    ContentType,
    FetchPolicy,
    RequestTemplate,
    ValidatedTarget,
)
from webguard_scanner.callback_broker import (
    CallbackBrokerError,
    CallbackPolicy,
    InMemoryCallbackBroker,
)
from webguard_scanner.xxe_callback_detector import (
    XxeDetectionOutcome,
    run_xxe_callback_detector,
    select_xxe_candidates,
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
    return ActiveDetectionContext(scan_id="xxe-scan-1")


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
    def __init__(self, status: int = 200, body: bytes = b"") -> None:
        self.status = status
        self.body = body
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
        return _FakeResponse(self.body, status=self.status)


def _post_policy() -> ActiveDetectionPolicy:
    return ActiveDetectionPolicy(
        minimum_delay_seconds=0.0,
        fetch_policy=FetchPolicy(allowed_methods=frozenset({"GET", "HEAD", "POST"})),
    )


def _run(
    connection,
    *,
    candidates,
    broker,
    policy=None,
    callback_policy=None,
    cancellation_check=None,
    authentication_material=None,
):
    with patch(
        "webguard_scanner.safe_http._make_connection", return_value=connection
    ):
        return run_xxe_callback_detector(
            _target(),
            candidates,
            _context(),
            callback_broker=broker,
            policy=policy or _post_policy(),
            callback_policy=callback_policy
            or CallbackPolicy(
                maximum_wait_seconds=0.2, grace_seconds=0.2, poll_interval_seconds=0.02
            ),
            cancellation_check=cancellation_check,
            authentication_material=authentication_material,
        )


class CandidateSelectionTests(unittest.TestCase):
    def test_get_only_candidate_is_never_selected(self) -> None:
        get_template = _template(content_type=ContentType.NONE, method="GET")
        selected = select_xxe_candidates((get_template,))
        self.assertEqual(selected, ())

    def test_form_and_json_candidates_are_selected(self) -> None:
        selected = select_xxe_candidates(
            (
                _template(content_type=ContentType.FORM_URLENCODED, endpoint="http://example.com/a"),
                _template(content_type=ContentType.JSON, endpoint="http://example.com/b"),
            )
        )
        self.assertEqual(len(selected), 2)

    def test_dedupes_by_endpoint_and_method_not_by_parameter(self) -> None:
        templates = (
            _template(parameter="a", endpoint="http://example.com/same"),
            _template(parameter="b", endpoint="http://example.com/same"),
            _template(parameter="c", endpoint="http://example.com/same"),
        )
        selected = select_xxe_candidates(templates)
        self.assertEqual(len(selected), 1)

    def test_same_endpoint_different_method_is_not_deduped(self) -> None:
        templates = (
            _template(endpoint="http://example.com/same", method="POST"),
            RequestTemplate(
                endpoint="http://example.com/same",
                method="PUT",
                content_type=ContentType.JSON,
                json_body='{"notes": "hello"}',
            ),
        )
        selected = select_xxe_candidates(templates)
        self.assertEqual(len(selected), 2)


class PayloadShapeTests(unittest.TestCase):
    def test_probe_body_declares_exactly_one_entity_pointing_at_the_callback_url(
        self,
    ) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")
        _run(connection, candidates=(_template(),), broker=broker)

        self.assertEqual(len(connection.sent_bodies), 1)
        sent = connection.sent_bodies[0].decode("utf-8")
        self.assertIn("<!DOCTYPE", sent)
        self.assertEqual(sent.count("<!ENTITY"), 1)
        self.assertEqual(sent.count("SYSTEM"), 1)
        self.assertNotIn("file://", sent)
        self.assertIn("http://127.0.0.1:9/xxe-scan-1/", sent)

    def test_probe_is_sent_with_xml_content_type_header(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")
        _run(connection, candidates=(_template(),), broker=broker)

        content_type_headers = [
            value for name, value in connection.sent_headers if name == "Content-Type"
        ]
        self.assertEqual(content_type_headers, [ContentType.XML])

    def test_original_form_body_is_fully_replaced_not_merged(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")
        _run(
            connection,
            candidates=(_template(parameter="notes", content_type=ContentType.FORM_URLENCODED),),
            broker=broker,
        )
        sent = connection.sent_bodies[0].decode("utf-8")
        self.assertNotIn("notes=hello", sent)


class ConfirmationTests(unittest.TestCase):
    def test_confirmed_when_callback_observed_within_primary_window(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")

        original_register = broker.register

        def register_and_deliver(**kwargs):
            token = original_register(**kwargs)

            def deliver() -> None:
                time.sleep(0.02)
                broker.record_observation(token.value, method="GET")

            threading.Thread(target=deliver).start()
            return token

        broker.register = register_and_deliver  # type: ignore[method-assign]

        result = _run(connection, candidates=(_template(),), broker=broker)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.CONFIRMED)
        finding = result.findings[0]
        cwe_values = [i.value for i in finding.identifiers if i.namespace == "CWE"]
        self.assertEqual(cwe_values, ["CWE-611"])
        self.assertIsNone(finding.identity.parameter)

    def test_probable_when_callback_only_observed_in_grace_window(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")

        original_register = broker.register

        def register_and_deliver(**kwargs):
            token = original_register(**kwargs)

            def deliver() -> None:
                time.sleep(0.15)
                broker.record_observation(token.value, method="GET")

            threading.Thread(target=deliver).start()
            return token

        broker.register = register_and_deliver  # type: ignore[method-assign]

        result = _run(
            connection,
            candidates=(_template(),),
            broker=broker,
            callback_policy=CallbackPolicy(
                maximum_wait_seconds=0.05,
                grace_seconds=0.5,
                poll_interval_seconds=0.02,
            ),
        )
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.PROBABLE)
        self.assertEqual(len(result.findings), 1)

    def test_hardened_parser_that_rejects_the_document_is_not_vulnerable(self) -> None:
        # The false-positive control this slice explicitly requires:
        # the target rejects the XML body outright (as a parser with
        # external entities disabled, or no XML parser at all, would),
        # and its rejection response happens to mention "DOCTYPE", the
        # exact vocabulary a naive in-band check could misread as
        # evidence. No callback ever arrives, so this must never
        # confirm regardless of what the response text says.
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")

        class _RejectingConnection(_ScriptedConnection):
            def getresponse(self):
                return _FakeResponse(
                    b"<html>Bad Request: DOCTYPE is disallowed</html>", status=400
                )

        result = _run(_RejectingConnection(), candidates=(_template(),), broker=broker)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.NOT_VULNERABLE)

    def test_reflection_of_callback_url_alone_produces_no_finding(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")

        class _ReflectingConnection(_ScriptedConnection):
            def getresponse(self):
                body = self.sent_bodies[-1] if self.sent_bodies else b""
                return _FakeResponse(
                    b"<html>you sent: " + body + b"</html>", status=200
                )

        result = _run(_ReflectingConnection(), candidates=(_template(),), broker=broker)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.NOT_VULNERABLE)

    def test_callback_from_another_scans_token_never_confirms_this_one(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        other_scan_token = broker.register(
            scan_id="a-completely-different-scan", candidate_fingerprint="cand-1"
        )
        broker.record_observation(other_scan_token.value, method="GET")

        connection = _ScriptedConnection(status=200, body=b"ok")
        result = _run(connection, candidates=(_template(),), broker=broker)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.NOT_VULNERABLE)

    def test_duplicate_callback_delivery_still_yields_exactly_one_finding(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")

        original_register = broker.register

        def register_and_deliver_twice(**kwargs):
            token = original_register(**kwargs)

            def deliver() -> None:
                time.sleep(0.02)
                broker.record_observation(token.value, method="GET")
                broker.record_observation(token.value, method="GET")

            threading.Thread(target=deliver).start()
            return token

        broker.register = register_and_deliver_twice  # type: ignore[method-assign]

        result = _run(connection, candidates=(_template(),), broker=broker)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.CONFIRMED)


class SafetyBoundaryTests(unittest.TestCase):
    def test_off_origin_candidate_is_rejected(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200)
        with self.assertRaises(ActiveDetectionError) as caught:
            _run(
                connection,
                candidates=(_template(endpoint="http://attacker.example/upload"),),
                broker=broker,
            )
        self.assertEqual(caught.exception.code, "candidate_origin_mismatch")

    def test_probe_budget_exceeded_raises_before_any_request(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200)
        candidates = tuple(
            _template(endpoint=f"http://example.com/p{i}", source_candidate_id=f"c{i}")
            for i in range(3)
        )
        with self.assertRaises(ActiveDetectionError) as caught:
            _run(
                connection,
                candidates=candidates,
                broker=broker,
                policy=ActiveDetectionPolicy(
                    maximum_probe_requests=2, minimum_delay_seconds=0.0
                ),
            )
        self.assertEqual(caught.exception.code, "candidate_budget_exceeded")
        self.assertEqual(connection.requested_paths, [])

    def test_cancellation_before_first_candidate_probes_nothing(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200)
        result = _run(
            connection,
            candidates=(_template(),),
            broker=broker,
            cancellation_check=lambda: True,
        )
        self.assertTrue(result.cancelled)
        self.assertEqual(result.records, ())
        self.assertEqual(connection.requested_paths, [])

    def test_cancellation_while_waiting_for_callback_is_inconclusive(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200)
        calls = {"count": 0}

        def cancel_after_probe() -> bool:
            calls["count"] += 1
            return calls["count"] > 1

        result = _run(
            connection,
            candidates=(_template(),),
            broker=broker,
            callback_policy=CallbackPolicy(
                maximum_wait_seconds=2.0, grace_seconds=2.0, poll_interval_seconds=0.02
            ),
            cancellation_check=cancel_after_probe,
        )
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.INCONCLUSIVE)
        self.assertEqual(result.findings, ())

    def test_callback_storage_failure_while_waiting_is_inconclusive_not_a_crash(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")

        def failing_wait(*args, **kwargs):
            raise CallbackBrokerError(
                "database_unavailable", "The database is currently unavailable."
            )

        broker.wait_for_observation = failing_wait  # type: ignore[method-assign]

        result = _run(connection, candidates=(_template(),), broker=broker)

        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.INCONCLUSIVE)
        self.assertEqual(result.findings, ())
        self.assertIn("database_unavailable", result.probe_errors)

    def test_registration_failure_is_inconclusive_not_a_crash(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")

        def failing_register(**kwargs):
            raise CallbackBrokerError(
                "callback_registration_limit_exceeded", "At the registration limit."
            )

        broker.register = failing_register  # type: ignore[method-assign]

        result = _run(connection, candidates=(_template(),), broker=broker)
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.INCONCLUSIVE)
        self.assertEqual(result.findings, ())
        self.assertEqual(connection.requested_paths, [])

    def test_probe_request_failure_is_error_outcome(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")

        class _FailingConnection(_ScriptedConnection):
            def getresponse(self):
                raise ConnectionResetError("connection reset by peer")

        result = _run(_FailingConnection(), candidates=(_template(),), broker=broker)
        self.assertEqual(result.records[0].outcome, XxeDetectionOutcome.ERROR)
        self.assertEqual(result.findings, ())
        self.assertTrue(result.probe_errors)

    def test_evidence_never_contains_authentication_material(self) -> None:
        from webguard_scanner import AuthenticationMaterial

        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")

        original_register = broker.register

        def register_and_deliver(**kwargs):
            token = original_register(**kwargs)

            def deliver() -> None:
                time.sleep(0.02)
                broker.record_observation(token.value, method="GET")

            threading.Thread(target=deliver).start()
            return token

        broker.register = register_and_deliver  # type: ignore[method-assign]

        result = _run(
            connection,
            candidates=(_template(),),
            broker=broker,
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
