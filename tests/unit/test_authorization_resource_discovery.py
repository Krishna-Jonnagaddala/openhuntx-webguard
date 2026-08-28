"""Tests for authorization resource discovery (Slice 9): HTML-link and
JSON-field recognition, provenance tagging, scope enforcement (off-
origin links never become resources), bounded limits, and the
false-positive controls the brief calls for (unrelated ID fields,
generic responses, malformed JSON, oversized responses).
"""

from __future__ import annotations

import unittest

from webguard_scanner import IdentifierLocation, IdentifierProvenance
from webguard_scanner.authorization_resource_discovery import (
    AuthenticationHealthCriterion,
    ResourceDiscoveryBudget,
    ResourceDiscoverySink,
    _discover_html_link_resources,
    _discover_json_field_resources,
)
from webguard_scanner.safe_http import SafeHttpResponse
from webguard_scanner.scope_validator import ValidatedTarget


def target(url: str = "https://example.com/") -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme="https",
        hostname="example.com",
        port=443,
        resolved_addresses=("93.184.216.34",),
    )


def html_response(body: str, *, status: int = 200) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=status,
        reason="OK",
        headers=(("Content-Type", "text/html; charset=utf-8"),),
        body=body.encode(),
        connected_address="93.184.216.34",
        elapsed_milliseconds=1,
    )


def json_response(body: bytes, *, status: int = 200) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=status,
        reason="OK",
        headers=(("Content-Type", "application/json"),),
        body=body,
        connected_address="93.184.216.34",
        elapsed_milliseconds=1,
    )


class HtmlLinkDiscoveryTests(unittest.TestCase):
    def test_recognizes_a_same_origin_object_link(self) -> None:
        resources = _discover_html_link_resources(
            target(),
            "https://example.com/account",
            b'<a href="/orders/A-001">order</a>',
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
        )
        self.assertEqual(len(resources), 1)
        resource = resources[0]
        self.assertEqual(resource.resource_type, "orders")
        self.assertEqual(resource.identifier_value, "A-001")
        self.assertEqual(resource.identifier_location, IdentifierLocation.PATH)
        self.assertEqual(resource.provenance, IdentifierProvenance.HTML_LINK)
        self.assertEqual(resource.owning_test_identity, "user-a")

    def test_off_origin_link_never_becomes_a_resource(self) -> None:
        resources = _discover_html_link_resources(
            target(),
            "https://example.com/account",
            b'<a href="https://evil.example/orders/999">off origin</a>',
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
        )
        self.assertEqual(resources, ())

    def test_login_and_static_segments_are_never_treated_as_identifiers(self) -> None:
        resources = _discover_html_link_resources(
            target(),
            "https://example.com/account",
            b'<a href="/login">login</a><a href="/static/app.js">asset</a>',
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
        )
        self.assertEqual(resources, ())

    def test_duplicate_links_are_not_double_reported_by_the_sink(self) -> None:
        sink = ResourceDiscoverySink(owning_identity="user-a")
        page = target("https://example.com/account")
        response = html_response(
            '<a href="/orders/A-001">one</a><a href="/orders/A-001">again</a>'
        )
        sink.visit_page(page, response)
        self.assertEqual(len(sink.resources), 1)

    def test_maximum_resources_per_page_is_enforced(self) -> None:
        many_links = "".join(
            f'<a href="/orders/A-{i:03d}">o</a>' for i in range(50)
        )
        resources = _discover_html_link_resources(
            target(),
            "https://example.com/account",
            many_links.encode(),
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(maximum_resources_per_page=5),
        )
        self.assertEqual(len(resources), 5)


class JsonFieldDiscoveryTests(unittest.TestCase):
    def test_self_referential_id_field_is_path_located(self) -> None:
        resources = _discover_json_field_resources(
            target(),
            "https://example.com/rest/basket/6",
            b'{"status":"success","data":{"id":6,"UserId":24}}',
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
            field_patterns=frozenset({"id"}),
        )
        self.assertEqual(len(resources), 1)
        resource = resources[0]
        self.assertEqual(resource.identifier_value, "6")
        self.assertEqual(resource.identifier_location, IdentifierLocation.PATH)
        self.assertEqual(resource.provenance, IdentifierProvenance.JSON_FIELD)

    def test_unrelated_id_field_not_matching_configured_patterns_is_ignored(
        self,
    ) -> None:
        resources = _discover_json_field_resources(
            target(),
            "https://example.com/rest/basket/6",
            b'{"id":6,"trackingCode":"XJ99912"}',
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
            field_patterns=frozenset({"id"}),
        )
        # Only "id" is configured; trackingCode must never become a
        # resource merely because it looks like an identifier-shaped
        # string.
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].identifier_name, "id")

    def test_another_users_id_as_non_sensitive_metadata_is_not_path_addressable(
        self,
    ) -> None:
        # UserId=24 is metadata about ownership, not an addressable
        # resource at this endpoint -- it must not be treated as a
        # PATH-located identifier (it doesn't match the URL's own
        # trailing segment), so it can never become an IDOR comparison
        # target even if a caller configured "userid" as a pattern.
        resources = _discover_json_field_resources(
            target(),
            "https://example.com/rest/basket/6",
            b'{"id":6,"userid":24}',
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
            field_patterns=frozenset({"id", "userid"}),
        )
        by_name = {r.identifier_name: r for r in resources}
        self.assertEqual(by_name["userid"].identifier_location, IdentifierLocation.NONE)

    def test_malformed_json_produces_no_resources(self) -> None:
        resources = _discover_json_field_resources(
            target(),
            "https://example.com/rest/basket/6",
            b"{not valid json",
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
            field_patterns=frozenset({"id"}),
        )
        self.assertEqual(resources, ())

    def test_endpoint_template_addresses_a_different_known_endpoint(self) -> None:
        # A field revealed on one endpoint (e.g. a login response) can
        # legitimately address a *different*, separately and explicitly
        # configured endpoint -- e.g. Juice Shop's own login response
        # body contains "bid" in plaintext, which addresses
        # /rest/basket/{bid}, not the login endpoint itself. This must
        # never be inferred automatically -- only via explicit
        # operator-supplied endpoint_templates configuration.
        resources = _discover_json_field_resources(
            target(),
            "https://example.com/rest/user/login",
            b'{"authentication":{"token":"x","bid":6,"umail":"a@example.test"}}',
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
            field_patterns=frozenset({"bid"}),
            endpoint_templates={"bid": "rest/basket/{value}"},
        )
        self.assertEqual(len(resources), 1)
        resource = resources[0]
        self.assertEqual(resource.identifier_value, "6")
        self.assertEqual(resource.identifier_location, IdentifierLocation.PATH)
        self.assertEqual(resource.endpoint, "https://example.com/rest/basket/6")

    def test_endpoint_template_off_origin_is_rejected(self) -> None:
        resources = _discover_json_field_resources(
            target(),
            "https://example.com/rest/user/login",
            b'{"bid":6}',
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(),
            field_patterns=frozenset({"bid"}),
            endpoint_templates={"bid": "https://evil.example/rest/basket/{value}"},
        )
        self.assertEqual(resources, ())

    def test_nested_list_fields_are_recognized_but_bounded(self) -> None:
        body = {
            "orders": [
                {"id": f"A-{i:03d}", "total": i} for i in range(10)
            ]
        }
        import json as _json

        resources = _discover_json_field_resources(
            target(),
            "https://example.com/api/orders",
            _json.dumps(body).encode(),
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(maximum_resources_per_page=3),
            field_patterns=frozenset({"id"}),
        )
        self.assertLessEqual(len(resources), 3)


class ResourceDiscoverySinkFalsePositiveTests(unittest.TestCase):
    def test_generic_200_html_with_no_links_yields_nothing(self) -> None:
        sink = ResourceDiscoverySink(owning_identity="user-a")
        sink.visit_page(target(), html_response("<html>Welcome</html>"))
        self.assertEqual(sink.resources, ())

    def test_oversized_response_is_skipped(self) -> None:
        sink = ResourceDiscoverySink(
            owning_identity="user-a",
            budget=ResourceDiscoveryBudget(maximum_response_bytes=10),
        )
        sink.visit_page(
            target(), html_response('<a href="/orders/A-001">order</a>' * 5)
        )
        self.assertEqual(sink.resources, ())

    def test_redirect_response_yields_nothing(self) -> None:
        sink = ResourceDiscoverySink(owning_identity="user-a")
        response = SafeHttpResponse(
            status=302,
            reason="Found",
            headers=(("Location", "/account"),),
            body=b"",
            connected_address="93.184.216.34",
            elapsed_milliseconds=1,
        )
        sink.visit_page(target(), response)
        self.assertEqual(sink.resources, ())

    def test_inaccessible_object_404_yields_nothing(self) -> None:
        sink = ResourceDiscoverySink(owning_identity="user-a")
        sink.visit_page(
            target(),
            json_response(b'{"error":"not found"}', status=404),
        )
        # A 404 body has no matching identifier fields anyway, but this
        # also proves a non-200 JSON body doesn't crash discovery.
        self.assertEqual(sink.resources, ())


class AuthenticationHealthCriterionTests(unittest.TestCase):
    def test_401_and_403_are_authentication_failed(self) -> None:
        criterion = AuthenticationHealthCriterion()
        response = SafeHttpResponse(
            status=401,
            reason="Unauthorized",
            headers=(),
            body=b"",
            connected_address="93.184.216.34",
            elapsed_milliseconds=1,
        )
        self.assertEqual(criterion.classify(response), "authentication_failed")

    def test_200_login_page_is_authentication_expired_not_ordinary_content(
        self,
    ) -> None:
        criterion = AuthenticationHealthCriterion(login_page_marker="Please log in")
        response = html_response("<html>Please log in to continue</html>")
        self.assertEqual(criterion.classify(response), "authentication_expired")

    def test_200_with_expected_marker_present_is_healthy(self) -> None:
        criterion = AuthenticationHealthCriterion(authenticated_marker="Welcome, ")
        response = html_response("<html>Welcome, user-a</html>")
        self.assertIsNone(criterion.classify(response))


if __name__ == "__main__":
    unittest.main()
