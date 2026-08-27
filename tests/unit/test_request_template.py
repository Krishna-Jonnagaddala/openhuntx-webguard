"""Unit tests for the request-template and parameter-mutation engine
(Slice 6): GET mutation, POST form mutation, JSON mutation (including
nested paths), malformed JSON, maximum JSON depth, parameter-count
budget, baseline preservation, off-origin rejection, and issuance over a
fake connection (no real network access)."""

from __future__ import annotations

import json
import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from webguard_scanner import ActiveDetectionPolicy, FetchPolicy, ValidatedTarget
from webguard_scanner.request_template import (
    ContentType,
    JsonMutationBudget,
    RequestTemplate,
    RequestTemplateError,
    enumerate_json_parameter_paths,
    execute_baseline,
    issue_templated_request,
    load_bounded_json_document,
    mutate,
    parse_json_parameter_path,
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


class JsonPathParsingTests(unittest.TestCase):
    def test_simple_key(self) -> None:
        self.assertEqual(parse_json_parameter_path("email"), ("email",))

    def test_nested_key(self) -> None:
        self.assertEqual(
            parse_json_parameter_path("user.email"), ("user", "email")
        )

    def test_deeply_nested_key(self) -> None:
        self.assertEqual(
            parse_json_parameter_path("profile.address.postcode"),
            ("profile", "address", "postcode"),
        )

    def test_array_index(self) -> None:
        self.assertEqual(
            parse_json_parameter_path("items[0].name"), ("items", 0, "name")
        )

    def test_malformed_path_rejected(self) -> None:
        for bad in ("", "a..b", "a[x]", "a[", "[0]extra"):
            with self.assertRaises(RequestTemplateError):
                parse_json_parameter_path(bad)


class JsonParameterEnumerationTests(unittest.TestCase):
    def test_enumerates_nested_leaf_paths(self) -> None:
        document = {"email": "a@b.com", "profile": {"address": {"postcode": "1"}}}
        paths = enumerate_json_parameter_paths(document)
        self.assertEqual(set(paths), {"email", "profile.address.postcode"})

    def test_enumerates_array_indices(self) -> None:
        document = {"items": [{"name": "x"}, {"name": "y"}]}
        paths = enumerate_json_parameter_paths(document)
        self.assertEqual(set(paths), {"items[0].name", "items[1].name"})

    def test_skips_null_leaves(self) -> None:
        document = {"email": "a@b.com", "middle_name": None}
        paths = enumerate_json_parameter_paths(document)
        self.assertEqual(set(paths), {"email"})

    def test_maximum_depth_limits_enumeration(self) -> None:
        # 10 levels deep; budget only allows 3.
        document: dict = {"leaf": "bottom"}
        for _ in range(10):
            document = {"nested": document}
        budget = JsonMutationBudget(maximum_depth=3)
        paths = enumerate_json_parameter_paths(document, budget=budget)
        self.assertEqual(paths, ())  # the only leaf is far deeper than depth 3

    def test_parameter_count_budget_caps_enumeration(self) -> None:
        document = {f"field{i}": f"value{i}" for i in range(100)}
        budget = JsonMutationBudget(maximum_parameter_paths=5)
        paths = enumerate_json_parameter_paths(document, budget=budget)
        self.assertEqual(len(paths), 5)

    def test_array_index_budget_limits_array_traversal(self) -> None:
        document = {"items": [{"name": f"item{i}"} for i in range(50)]}
        budget = JsonMutationBudget(maximum_array_index=3, maximum_parameter_paths=100)
        paths = enumerate_json_parameter_paths(document, budget=budget)
        self.assertEqual(len(paths), 3)

    def test_does_not_recursively_explode_on_a_large_document(self) -> None:
        # A wide-and-deep document must still terminate quickly and
        # respect the parameter-count cap rather than enumerating
        # thousands of candidates.
        document = {
            f"group{i}": {f"field{j}": "v" for j in range(20)} for i in range(50)
        }
        budget = JsonMutationBudget(maximum_parameter_paths=25)
        paths = enumerate_json_parameter_paths(document, budget=budget)
        self.assertLessEqual(len(paths), 25)


class BoundedJsonLoadingTests(unittest.TestCase):
    def test_malformed_json_is_rejected_cleanly(self) -> None:
        with self.assertRaises(RequestTemplateError) as caught:
            load_bounded_json_document("{not valid json")
        self.assertEqual(caught.exception.code, "json_document_malformed")

    def test_oversized_document_is_rejected_before_parsing(self) -> None:
        budget = JsonMutationBudget(maximum_document_bytes=10)
        with self.assertRaises(RequestTemplateError) as caught:
            load_bounded_json_document(json.dumps({"a": "b" * 100}), budget=budget)
        self.assertEqual(caught.exception.code, "json_document_too_large")

    def test_excessive_depth_is_rejected(self) -> None:
        document: dict = {"leaf": 1}
        for _ in range(20):
            document = {"nested": document}
        budget = JsonMutationBudget(maximum_depth=5)
        with self.assertRaises(RequestTemplateError) as caught:
            load_bounded_json_document(json.dumps(document), budget=budget)
        self.assertEqual(caught.exception.code, "json_document_too_deep")


class MutationEngineTests(unittest.TestCase):
    def test_get_query_mutation_preserves_other_parameters(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/search",
            method="GET",
            content_type=ContentType.NONE,
            query_parameters=(("q", "hello"), ("page", "1")),
        )
        mutated = mutate(template, "q", "wgprobe")
        parsed = urlsplit(mutated.url)
        params = parse_qs(parsed.query)
        self.assertEqual(params["q"], ["wgprobe"])
        self.assertEqual(params["page"], ["1"])
        self.assertEqual(mutated.method, "GET")
        self.assertEqual(mutated.body, b"")

    def test_post_form_mutation_preserves_unrelated_fields(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/login",
            method="POST",
            content_type=ContentType.FORM_URLENCODED,
            form_parameters=(("email", "user@example.com"), ("password", "baseline")),
        )
        mutated = mutate(template, "email", "wgprobe'")
        body_fields = parse_qs(mutated.body.decode())
        self.assertEqual(body_fields["email"], ["wgprobe'"])
        self.assertEqual(body_fields["password"], ["baseline"])
        self.assertEqual(mutated.method, "POST")
        self.assertEqual(mutated.content_type, ContentType.FORM_URLENCODED)

    def test_json_mutation_preserves_unrelated_fields(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/api/login",
            method="POST",
            content_type=ContentType.JSON,
            json_body=json.dumps({"email": "user@example.com", "password": "baseline"}),
        )
        mutated = mutate(template, "email", "wgprobe'")
        document = json.loads(mutated.body)
        self.assertEqual(document["email"], "wgprobe'")
        self.assertEqual(document["password"], "baseline")
        self.assertEqual(mutated.content_type, ContentType.JSON)

    def test_nested_json_mutation_preserves_siblings(self) -> None:
        baseline = {
            "user": {"email": "user@example.com", "name": "Alice"},
            "items": [{"name": "widget", "qty": 2}],
        }
        template = RequestTemplate(
            endpoint="http://example.com/api/update",
            method="POST",
            content_type=ContentType.JSON,
            json_body=json.dumps(baseline),
        )
        mutated = mutate(template, "user.email", "wgprobe")
        document = json.loads(mutated.body)
        self.assertEqual(document["user"]["email"], "wgprobe")
        self.assertEqual(document["user"]["name"], "Alice")
        self.assertEqual(document["items"], [{"name": "widget", "qty": 2}])

        mutated_array = mutate(template, "items[0].name", "wgprobe2")
        document_array = json.loads(mutated_array.body)
        self.assertEqual(document_array["items"][0]["name"], "wgprobe2")
        self.assertEqual(document_array["items"][0]["qty"], 2)
        self.assertEqual(document_array["user"], baseline["user"])

    def test_mutating_malformed_json_template_fails_cleanly(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/api/login",
            method="POST",
            content_type=ContentType.JSON,
            json_body="{not valid json",
        )
        with self.assertRaises(RequestTemplateError) as caught:
            mutate(template, "email", "wgprobe")
        self.assertEqual(caught.exception.code, "json_document_malformed")

    def test_mutating_unknown_parameter_fails_closed(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/api/login",
            method="POST",
            content_type=ContentType.JSON,
            json_body=json.dumps({"email": "a@b.com"}),
        )
        with self.assertRaises(RequestTemplateError) as caught:
            mutate(template, "nonexistent", "wgprobe")
        self.assertEqual(caught.exception.code, "json_path_not_found")

    def test_mutating_unknown_form_field_fails_closed(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/login",
            method="POST",
            content_type=ContentType.FORM_URLENCODED,
            form_parameters=(("email", "a@b.com"),),
        )
        with self.assertRaises(RequestTemplateError) as caught:
            mutate(template, "nonexistent", "wgprobe")
        self.assertEqual(caught.exception.code, "request_template_parameter_not_found")

    def test_mutating_unknown_query_parameter_fails_closed(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/search",
            method="GET",
            content_type=ContentType.NONE,
            query_parameters=(("q", "1"),),
        )
        with self.assertRaises(RequestTemplateError) as caught:
            mutate(template, "nonexistent", "wgprobe")
        self.assertEqual(caught.exception.code, "request_template_parameter_not_found")

    def test_maximum_json_depth_enforced_during_mutation(self) -> None:
        document: dict = {"leaf": "value"}
        for _ in range(20):
            document = {"nested": document}
        template = RequestTemplate(
            endpoint="http://example.com/api",
            method="POST",
            content_type=ContentType.JSON,
            json_body=json.dumps(document),
        )
        budget = JsonMutationBudget(maximum_depth=3)
        with self.assertRaises(RequestTemplateError) as caught:
            mutate(template, "nested.nested.nested.nested.leaf", "wgprobe", budget=budget)
        self.assertEqual(caught.exception.code, "json_document_too_deep")


class _FakeHttpResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.status = status
        self.reason = "OK"
        self._body = body
        self._position = 0
        self.msg = Message()
        self.msg.add_header("Content-Length", str(len(body)))

    def getheaders(self):
        return [("Content-Length", str(len(self._body))), ("Content-Type", "application/json")]

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = len(self._body) - self._position
        chunk = self._body[self._position : self._position + amount]
        self._position += len(chunk)
        return chunk


class _CapturingConnection:
    """A fake connection accepting both bodyless (GET) and bodied (POST)
    endheaders() calls, capturing whatever body was actually sent."""

    def __init__(self, response_body: bytes = b"{}", status: int = 200) -> None:
        self.sock = None
        self._context = None
        self.sent_bodies: list[bytes] = []
        self.sent_headers: list[tuple[str, str]] = []
        self.requested_paths: list[str] = []
        self.requested_methods: list[str] = []
        self._response_body = response_body
        self._status = status

    def putrequest(self, method, path, **kwargs) -> None:
        self.requested_methods.append(method)
        self.requested_paths.append(path)

    def putheader(self, name, value) -> None:
        self.sent_headers.append((name, value))

    def endheaders(self, message_body=None) -> None:
        if message_body is not None:
            self.sent_bodies.append(message_body)

    def getresponse(self):
        return _FakeHttpResponse(self._response_body, status=self._status)

    def close(self) -> None:
        pass


def _policy() -> ActiveDetectionPolicy:
    return ActiveDetectionPolicy(
        maximum_probe_requests=25,
        fetch_policy=FetchPolicy(allowed_methods=frozenset({"GET", "HEAD", "POST"})),
    )


class IssuanceTests(unittest.TestCase):
    def test_post_json_mutation_is_sent_with_correct_body_and_content_type(
        self,
    ) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/api/login",
            method="POST",
            content_type=ContentType.JSON,
            json_body=json.dumps({"email": "a@b.com", "password": "baseline"}),
        )
        mutated = mutate(template, "email", "wgprobe")

        connection = _CapturingConnection(response_body=b'{"ok": true}')
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            attempt = issue_templated_request(_target(), mutated, policy=_policy())

        self.assertTrue(attempt.succeeded)
        self.assertEqual(connection.requested_methods, ["POST"])
        sent_body = connection.sent_bodies[0]
        self.assertEqual(json.loads(sent_body), {"email": "wgprobe", "password": "baseline"})
        self.assertIn(("Content-Type", "application/json"), connection.sent_headers)

    def test_post_form_mutation_is_sent_with_correct_body(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/login",
            method="POST",
            content_type=ContentType.FORM_URLENCODED,
            form_parameters=(("email", "a@b.com"), ("password", "baseline")),
        )
        mutated = mutate(template, "email", "wgprobe")

        connection = _CapturingConnection(response_body=b"ok")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            attempt = issue_templated_request(_target(), mutated, policy=_policy())

        self.assertTrue(attempt.succeeded)
        sent_body = parse_qs(connection.sent_bodies[0].decode())
        self.assertEqual(sent_body["email"], ["wgprobe"])
        self.assertEqual(sent_body["password"], ["baseline"])

    def test_off_origin_mutated_request_is_rejected_fail_closed(self) -> None:
        template = RequestTemplate(
            endpoint="http://third-party.example/api/login",
            method="POST",
            content_type=ContentType.JSON,
            json_body=json.dumps({"email": "a@b.com"}),
        )
        mutated = mutate(template, "email", "wgprobe")

        connection = _CapturingConnection()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ) as make_connection:
            with self.assertRaises(Exception):
                issue_templated_request(_target(), mutated, policy=_policy())
        make_connection.assert_not_called()

    def test_baseline_execution_records_bounded_characteristics(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/api/login",
            method="POST",
            content_type=ContentType.JSON,
            json_body=json.dumps({"email": "a@b.com", "password": "baseline"}),
        )
        connection = _CapturingConnection(response_body=b'{"ok": true}', status=200)
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            observation = execute_baseline(_target(), template, policy=_policy())

        self.assertIsNotNone(observation)
        self.assertEqual(observation.status, 200)
        self.assertEqual(observation.response_length, len(b'{"ok": true}'))
        self.assertTrue(len(observation.content_fingerprint) == 64)  # sha256 hex
        # The baseline body sent must be the template's own unmutated values.
        sent_body = connection.sent_bodies[0]
        self.assertEqual(json.loads(sent_body), {"email": "a@b.com", "password": "baseline"})

    def test_baseline_execution_returns_none_on_probe_failure(self) -> None:
        template = RequestTemplate(
            endpoint="http://example.com/api/login",
            method="POST",
            content_type=ContentType.JSON,
            json_body=json.dumps({"email": "a@b.com"}),
        )

        class _FailingConnection(_CapturingConnection):
            def getresponse(self):
                raise ConnectionResetError("boom")

        connection = _FailingConnection()
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            observation = execute_baseline(_target(), template, policy=_policy())
        self.assertIsNone(observation)


if __name__ == "__main__":
    unittest.main()
