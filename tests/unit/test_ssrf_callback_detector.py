"""Unit tests for the active SSRF-callback detector.

Covers candidate-name filtering (never evidence by itself), the
callback-correlation classification logic (CONFIRMED/PROBABLE/
NOT_VULNERABLE/INCONCLUSIVE/ERROR), same-origin/budget/cancellation
safety boundaries, and the false-positive controls this slice
requires -- against a fake connection and the real in-memory callback
broker, so no network access is required. Real-network and end-to-end
coverage live in separate files.
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
    RequestTemplate,
    ValidatedTarget,
)
from webguard_scanner.callback_broker import CallbackPolicy, InMemoryCallbackBroker
from webguard_scanner.ssrf_callback_detector import (
    SsrfDetectionOutcome,
    is_ssrf_candidate_parameter,
    run_ssrf_callback_detector,
    select_ssrf_candidates,
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
    return ActiveDetectionContext(scan_id="ssrf-scan-1")


def _template(
    *,
    parameter: str = "url",
    endpoint: str = "http://example.com/fetch",
    source_candidate_id: str = "cand-1",
) -> RequestTemplate:
    return RequestTemplate(
        endpoint=endpoint,
        method="GET",
        content_type=ContentType.NONE,
        parameter=parameter,
        query_parameters=((parameter, "http://example.com/default.png"),),
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

    def putrequest(self, method, path, **kwargs) -> None:
        self.requested_paths.append(path)

    def putheader(self, name, value) -> None:
        return None

    def endheaders(self, message_body=None, *, encode_chunked=False) -> None:
        return None

    def send(self, data) -> None:
        return None

    def close(self) -> None:
        return None

    def getresponse(self):
        return _FakeResponse(self.body, status=self.status)


def _run(connection, *, candidates, broker, policy=None, callback_policy=None, cancellation_check=None):
    with patch(
        "webguard_scanner.safe_http._make_connection", return_value=connection
    ):
        return run_ssrf_callback_detector(
            _target(),
            candidates,
            _context(),
            callback_broker=broker,
            policy=policy or ActiveDetectionPolicy(minimum_delay_seconds=0.0),
            callback_policy=callback_policy
            or CallbackPolicy(
                maximum_wait_seconds=0.2, grace_seconds=0.2, poll_interval_seconds=0.02
            ),
            cancellation_check=cancellation_check,
        )


class CandidateNameFilterTests(unittest.TestCase):
    def test_url_shaped_names_are_selected(self) -> None:
        for name in ("url", "URL", "callback", "webhook", "avatarUrl", "image_url"):
            self.assertTrue(is_ssrf_candidate_parameter(name), name)

    def test_unrelated_names_are_not_selected(self) -> None:
        for name in ("username", "password", "quantity", "email"):
            self.assertFalse(is_ssrf_candidate_parameter(name), name)

    def test_select_ssrf_candidates_filters_and_dedupes(self) -> None:
        templates = (
            _template(parameter="url", source_candidate_id="a"),
            _template(parameter="username", source_candidate_id="b"),
            _template(parameter="url", source_candidate_id="a"),
        )
        selected = select_ssrf_candidates(templates)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].parameter, "url")

    def test_parameter_name_alone_never_becomes_a_finding(self) -> None:
        # A URL-shaped name is only ever a discovery-time filter -- with
        # no callback observed, no finding is ever produced regardless
        # of how suggestive the name is.
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200, body=b"ok")
        result = _run(
            connection, candidates=(_template(parameter="callback_url"),), broker=broker
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.NOT_VULNERABLE)


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
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.CONFIRMED)
        finding = result.findings[0]
        cwe_values = [i.value for i in finding.identifiers if i.namespace == "CWE"]
        self.assertEqual(cwe_values, ["CWE-918"])
        owasp_values = [i.value for i in finding.identifiers if i.namespace == "OWASP"]
        self.assertEqual(owasp_values, ["A10:2021"])

    def test_reflection_of_callback_url_alone_produces_no_finding(self) -> None:
        # The false-positive control this slice explicitly requires:
        # the target's response *contains* the callback URL text, but
        # no actual callback was ever received.
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")

        class _ReflectingConnection(_ScriptedConnection):
            def getresponse(self):
                path = self.requested_paths[-1]
                return _FakeResponse(
                    f"<html>you asked for: {path}</html>".encode(), status=200
                )

        result = _run(
            _ReflectingConnection(), candidates=(_template(),), broker=broker
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.NOT_VULNERABLE)

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
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.PROBABLE)
        self.assertEqual(len(result.findings), 1)

    def test_callback_from_wrong_token_never_confirms_this_candidate(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        # Register and observe an unrelated token before the detector
        # even runs -- simulating a stray/forged/duplicate callback that
        # must never satisfy a different candidate's wait.
        unrelated = broker.register(scan_id="ssrf-scan-1", candidate_fingerprint="other")
        broker.record_observation(unrelated.value, method="GET")

        connection = _ScriptedConnection(status=200, body=b"ok")
        result = _run(connection, candidates=(_template(),), broker=broker)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.NOT_VULNERABLE)

    def test_generic_500_produces_no_finding(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=500, body=b"internal error")
        result = _run(connection, candidates=(_template(),), broker=broker)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.NOT_VULNERABLE)

    def test_response_merely_mentioning_the_callback_domain_produces_no_finding(
        self,
    ) -> None:
        # Broader than exact-URL reflection: the application's response
        # happens to mention the callback service's domain in an
        # unrelated context (e.g. a generic error page listing allowed
        # hosts) -- still never evidence without an actual observation.
        broker = InMemoryCallbackBroker(base_url="http://callback.webguard.invalid/")

        class _MentioningConnection(_ScriptedConnection):
            def getresponse(self):
                return _FakeResponse(
                    b"<html>Allowed hosts: callback.webguard.invalid, "
                    b"example.com</html>",
                    status=200,
                )

        result = _run(
            _MentioningConnection(), candidates=(_template(),), broker=broker
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.NOT_VULNERABLE)

    def test_duplicate_callback_delivery_still_yields_exactly_one_finding(
        self,
    ) -> None:
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
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.CONFIRMED)

    def test_callback_from_another_scans_token_never_confirms_this_one(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        # A different scan's token, observed before this detector run
        # even starts -- must never leak across scan boundaries.
        other_scan_token = broker.register(
            scan_id="a-completely-different-scan", candidate_fingerprint="url"
        )
        broker.record_observation(other_scan_token.value, method="GET")

        connection = _ScriptedConnection(status=200, body=b"ok")
        result = _run(connection, candidates=(_template(),), broker=broker)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.NOT_VULNERABLE)


class SafetyBoundaryTests(unittest.TestCase):
    def test_off_origin_candidate_is_rejected(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200)
        with self.assertRaises(ActiveDetectionError) as caught:
            _run(
                connection,
                candidates=(_template(endpoint="http://attacker.example/fetch"),),
                broker=broker,
            )
        self.assertEqual(caught.exception.code, "candidate_origin_mismatch")

    def test_probe_budget_exceeded_raises_before_any_request(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200)
        candidates = tuple(
            _template(parameter="url", source_candidate_id=f"c{i}") for i in range(3)
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
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.INCONCLUSIVE)
        self.assertEqual(result.findings, ())

    def test_probe_request_failure_is_error_outcome(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")

        class _FailingConnection(_ScriptedConnection):
            def getresponse(self):
                raise ConnectionResetError("connection reset by peer")

        result = _run(_FailingConnection(), candidates=(_template(),), broker=broker)
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.ERROR)
        self.assertEqual(result.findings, ())
        self.assertTrue(result.probe_errors)

    def test_malformed_candidate_parameter_is_recorded_as_error(self) -> None:
        broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")
        connection = _ScriptedConnection(status=200)
        # source parameter doesn't actually exist on the template.
        bad_template = RequestTemplate(
            endpoint="http://example.com/fetch",
            method="GET",
            content_type=ContentType.NONE,
            parameter="url",
            query_parameters=(("other", "value"),),
        )
        result = _run(connection, candidates=(bad_template,), broker=broker)
        self.assertEqual(result.records[0].outcome, SsrfDetectionOutcome.ERROR)
        self.assertEqual(result.findings, ())

    def test_evidence_never_contains_authentication_material_or_full_body(self) -> None:
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

        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_ssrf_callback_detector(
                _target(),
                (_template(),),
                _context(),
                callback_broker=broker,
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
                callback_policy=CallbackPolicy(
                    maximum_wait_seconds=0.2,
                    grace_seconds=0.2,
                    poll_interval_seconds=0.02,
                ),
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
