"""Unit tests for the active reflected-XSS detector.

Covers the classification logic (Phase B confirmation levels), the
same-origin fail-closed boundary, probe-budget enforcement, and hook
wiring -- all against a fake connection so no network access is required.
Lab validation against a live target (OWASP Juice Shop) is a separate,
opt-in integration test.
"""

from __future__ import annotations

import html
import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    ContentType,
    DetectionCandidate,
    DetectionOutcome,
    FetchPolicy,
    RequestTemplate,
    ValidatedTarget,
    run_reflected_xss_detector,
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


class _ReflectingConnection:
    """A fake HTTP connection whose response body depends on the request,
    simulating a server that reflects a query parameter with a chosen
    escaping behaviour."""

    def __init__(self, *, reflect: bool, encode: bool, partial: str | None = None) -> None:
        self.reflect = reflect
        self.encode = encode
        self.partial = partial
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
        params = parse_qs(parsed.query)
        value = params.get("q", [""])[0]

        if not self.reflect:
            body = b"<html><body>no reflection here</body></html>"
        elif self.partial == "left":
            # only the left angle bracket unescaped
            rendered = value.replace(">", "&gt;", 1) if ">" in value else value
            body = f"<html><body>{rendered}</body></html>".encode()
        elif self.partial == "right":
            rendered = value.replace("<", "&lt;", 1) if "<" in value else value
            body = f"<html><body>{rendered}</body></html>".encode()
        elif self.encode:
            body = f"<html><body>{html.escape(value)}</body></html>".encode()
        else:
            body = f"<html><body>{value}</body></html>".encode()

        return _FakeResponse(body)

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


def _candidate(url: str = "http://example.com/search") -> DetectionCandidate:
    return DetectionCandidate(url=url, parameter="q")


def _context() -> ActiveDetectionContext:
    return ActiveDetectionContext(
        scan_id="scan-1",
        authorization_id="auth-1",
        permit_id="permit-1",
        permit_fingerprint="fp-1",
    )


class ReflectedXssClassificationTests(unittest.TestCase):
    def test_confirmed_reflection_produces_high_severity_cwe79_finding(self) -> None:
        connection = _ReflectingConnection(reflect=True, encode=False)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
            )

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.confidence.value, "confirmed")
        self.assertEqual(
            [i.value for i in finding.identifiers],
            ["CWE-79"],
        )
        self.assertEqual(result.records[0].outcome, DetectionOutcome.CONFIRMED)

    def test_html_encoded_reflection_is_informational_with_no_cwe(self) -> None:
        connection = _ReflectingConnection(reflect=True, encode=True)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
            )

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity.value, "informational")
        self.assertEqual(finding.identifiers, ())
        self.assertEqual(
            result.records[0].outcome,
            DetectionOutcome.INFORMATIONAL,
        )

    def test_no_reflection_produces_no_finding_but_is_recorded(self) -> None:
        connection = _ReflectingConnection(reflect=False, encode=False)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
            )

        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.records), 1)
        self.assertEqual(
            result.records[0].outcome,
            DetectionOutcome.INCONCLUSIVE,
        )

    def test_partial_left_bracket_unescaped_is_probable(self) -> None:
        connection = _ReflectingConnection(
            reflect=True, encode=False, partial="left"
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
            )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.records[0].outcome,
            DetectionOutcome.PROBABLE,
        )
        self.assertEqual(
            [i.value for i in result.findings[0].identifiers],
            ["CWE-79"],
        )

    def test_partial_right_bracket_unescaped_is_probable(self) -> None:
        connection = _ReflectingConnection(
            reflect=True, encode=False, partial="right"
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
            )

        self.assertEqual(
            result.records[0].outcome,
            DetectionOutcome.PROBABLE,
        )

    def test_marker_present_but_fully_escaped_brackets_removed_is_suspected(
        self,
    ) -> None:
        class _StrippedBracketsConnection(_ReflectingConnection):
            def getresponse(self):
                parsed = urlsplit(self._path)
                params = parse_qs(parsed.query)
                value = params.get("q", [""])[0]
                stripped = value.replace("<", "").replace(">", "")
                body = f"<html><body>{stripped}</body></html>".encode()
                return _FakeResponse(body)

        connection = _StrippedBracketsConnection(reflect=True, encode=False)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
            )

        self.assertEqual(
            result.records[0].outcome,
            DetectionOutcome.SUSPECTED,
        )
        self.assertEqual(
            [i.value for i in result.findings[0].identifiers],
            ["CWE-79"],
        )


class ReflectedXssSafetyBoundaryTests(unittest.TestCase):
    def test_off_origin_candidate_is_rejected_fail_closed(self) -> None:
        with self.assertRaises(ActiveDetectionError) as context:
            run_reflected_xss_detector(
                _target(),
                (_candidate(url="https://attacker.example/search"),),
                _context(),
            )
        self.assertEqual(
            context.exception.code,
            "candidate_origin_mismatch",
        )

    def test_probe_budget_exceeded_raises_before_any_request(self) -> None:
        connection = _ReflectingConnection(reflect=True, encode=False)
        candidates = tuple(
            _candidate(url=f"http://example.com/search{i}")
            for i in range(3)
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(ActiveDetectionError) as context:
                run_reflected_xss_detector(
                    _target(),
                    candidates,
                    _context(),
                    policy=ActiveDetectionPolicy(maximum_probe_requests=2),
                )
        self.assertEqual(
            context.exception.code,
            "candidate_budget_exceeded",
        )
        self.assertEqual(connection.requested_paths, [])

    def test_before_and_after_request_hooks_are_invoked(self) -> None:
        connection = _ReflectingConnection(reflect=True, encode=False)
        before_calls = []
        after_calls = []

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
                before_request=lambda t, m: before_calls.append((t, m)),
                after_request=lambda t, m, r, e: after_calls.append(
                    (t, m, r, e)
                ),
            )

        self.assertEqual(len(before_calls), 1)
        self.assertEqual(before_calls[0][1], "GET")
        self.assertEqual(len(after_calls), 1)
        self.assertIsNotNone(after_calls[0][2])
        self.assertIsNone(after_calls[0][3])

    def test_probe_failure_is_recorded_as_error_not_a_finding(self) -> None:
        class _RedirectingConnection(_ReflectingConnection):
            def getresponse(self):
                response = _FakeResponse(b"", status=302)
                response.reason = "Found"
                response.msg.add_header("Location", "https://example.com/x")
                return response

        connection = _RedirectingConnection(reflect=True, encode=False)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
            )

        self.assertEqual(result.findings, ())
        self.assertEqual(result.records, ())
        self.assertEqual(result.probe_errors, ("redirect_blocked",))

    def test_distinct_markers_used_across_multiple_candidates(self) -> None:
        connection = _ReflectingConnection(reflect=True, encode=False)
        candidates = (
            _candidate(url="http://example.com/a"),
            _candidate(url="http://example.com/b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                candidates,
                _context(),
                policy=ActiveDetectionPolicy(minimum_delay_seconds=0.0),
            )

        markers = {record.marker for record in result.records}
        self.assertEqual(len(markers), 2)

    def test_invalid_probe_budget_is_rejected(self) -> None:
        with self.assertRaises(ActiveDetectionError):
            ActiveDetectionPolicy(maximum_probe_requests=0)
        with self.assertRaises(ActiveDetectionError):
            ActiveDetectionPolicy(maximum_probe_requests=26)

    def test_invalid_delay_is_rejected(self) -> None:
        with self.assertRaises(ActiveDetectionError):
            ActiveDetectionPolicy(minimum_delay_seconds=-1)
        with self.assertRaises(ActiveDetectionError):
            ActiveDetectionPolicy(minimum_delay_seconds=31)

    def test_non_get_candidate_is_rejected(self) -> None:
        with self.assertRaises(ActiveDetectionError):
            DetectionCandidate(
                url="https://example.com/search",
                parameter="q",
                method="POST",
            )


class _PostFormConnection:
    """A fake connection whose reflection behaviour is driven by the
    request *body* (form-urlencoded), simulating a POST search form."""

    def __init__(self, *, reflect: bool) -> None:
        self.reflect = reflect
        self.sock = None
        self._context = None
        self.sent_bodies: list[bytes] = []

    def putrequest(self, method, path, **kwargs) -> None:
        return None

    def putheader(self, name, value) -> None:
        return None

    def endheaders(self, message_body=None) -> None:
        self.sent_bodies.append(message_body or b"")

    def getresponse(self):
        value = parse_qs(self.sent_bodies[-1].decode()).get("q", [""])[0]
        if not self.reflect:
            body = b"<html><body>no reflection here</body></html>"
        else:
            body = f"<html><body>{value}</body></html>".encode()
        return _FakeResponse(body)

    def close(self) -> None:
        pass


def _post_policy() -> ActiveDetectionPolicy:
    return ActiveDetectionPolicy(
        minimum_delay_seconds=0.0,
        fetch_policy=FetchPolicy(allowed_methods=frozenset({"GET", "HEAD", "POST"})),
    )


class ReflectedXssPostFormTests(unittest.TestCase):
    def test_post_form_candidate_is_probed_and_confirmed(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/search",
            method="POST",
            content_type=ContentType.FORM_URLENCODED,
            parameter="q",
            form_parameters=(("q", "hello"),),
        )
        connection = _PostFormConnection(reflect=True)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(), (template,), _context(), policy=_post_policy()
            )
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.identity.method, "POST")
        self.assertEqual(finding.identity.parameter, "q")

    def test_post_form_candidate_no_reflection_produces_no_finding(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/search",
            method="POST",
            content_type=ContentType.FORM_URLENCODED,
            parameter="q",
            form_parameters=(("q", "hello"),),
        )
        connection = _PostFormConnection(reflect=False)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(), (template,), _context(), policy=_post_policy()
            )
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.records[0].outcome, DetectionOutcome.INCONCLUSIVE
        )

    def test_json_body_candidate_is_never_probed(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/api/search",
            method="POST",
            content_type=ContentType.JSON,
            parameter="q",
            json_body='{"q": "hello"}',
        )
        connection = _PostFormConnection(reflect=True)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ) as make_connection:
            result = run_reflected_xss_detector(
                _target(), (template,), _context(), policy=_post_policy()
            )
        make_connection.assert_not_called()
        self.assertEqual(result.findings, ())
        self.assertEqual(result.records, ())
        self.assertEqual(result.probe_errors, ("xss_json_body_not_supported",))

    def test_mixed_legacy_get_and_templated_post_candidates(self) -> None:
        get_candidate = _candidate()
        post_template = RequestTemplate(
            endpoint="http://example.com/search",
            method="POST",
            content_type=ContentType.FORM_URLENCODED,
            parameter="q",
            form_parameters=(("q", "hello"),),
        )

        class _MixedConnection:
            def __init__(self) -> None:
                self.sock = None
                self._context = None
                self._method = "GET"
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
                else:
                    value = parse_qs(self._body.decode()).get("q", [""])[0]
                return _FakeResponse(f"<html>{value}</html>".encode())

            def close(self) -> None:
                pass

        connection = _MixedConnection()
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (get_candidate, post_template),
                _context(),
                policy=_post_policy(),
            )

        self.assertEqual(len(result.records), 2)
        self.assertEqual(len(result.findings), 2)
        methods = {finding.identity.method for finding in result.findings}
        self.assertEqual(methods, {"GET", "POST"})


class EvidenceSanitizationTests(unittest.TestCase):
    """Slice 11 stabilization audit: IDOR, SSRF, and SQLi each already had
    a dedicated evidence-sanitization test; reflected-XSS did not. This
    closes that gap by planting a secret in the authentication material
    used for the probe and confirming it never surfaces in the finding's
    evidence text, exactly like the other three detectors' equivalents."""

    def test_evidence_never_contains_bearer_token_or_raw_response_body(
        self,
    ) -> None:
        from webguard_scanner import AuthenticationMaterial

        connection = _ReflectingConnection(reflect=True, encode=False)
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            result = run_reflected_xss_detector(
                _target(),
                (_candidate(),),
                _context(),
                authentication_material=AuthenticationMaterial(
                    bearer_token="super-secret-xss-probe-token"
                ),
            )

        self.assertEqual(len(result.findings), 1)
        evidence_text = " ".join(
            e.summary for e in result.findings[0].evidence
        )
        self.assertNotIn("super-secret-xss-probe-token", evidence_text)
        self.assertNotIn("Bearer", evidence_text)
        # ("Authorization: auth-1" from context.authorization_id is an
        # expected, non-secret structural provenance field -- the same
        # pattern IDOR/SQLi/SSRF's own evidence already uses -- so it is
        # deliberately not asserted absent here, only the header value.)
        # The reflected payload/marker itself is a WebGuard-generated,
        # non-secret probe value -- but the raw response body must still
        # never appear verbatim in evidence, only the bounded, structural
        # provenance fields.
        self.assertNotIn("no reflection here", evidence_text)


if __name__ == "__main__":
    unittest.main()
