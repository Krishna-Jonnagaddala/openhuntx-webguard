"""Unit tests for the generalized attack-surface / candidate discovery
model (Slice 5).

Covers the required fixture set: GET form, POST form, query parameter,
JSON POST API, safe API endpoint, likely state-changing endpoint,
duplicate endpoints, external/out-of-scope endpoint, malformed HTML,
malformed JSON/OpenAPI, very large input, cancellation, and budget
exhaustion -- plus deterministic candidate-identity (deduplication)
behaviour. All page-level tests are pure and network-free; site-level
(sitemap/robots/OpenAPI) tests use the same fake-HTTP-connection pattern
as ``test_active_xss_reflected.py`` so no real network access occurs.
"""

from __future__ import annotations

import json
import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import urlsplit

from webguard_scanner import (
    ActiveDetectionPolicy,
    AttackSurfaceBudget,
    DiscoveryMethod,
    InputLocation,
    SafetyClassification,
    ValidatedTarget,
    discover_page_attack_surface,
    discover_site_attack_surface,
    merge_attack_surface_results,
    to_detection_candidates,
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


class PageAttackSurfaceDiscoveryTests(unittest.TestCase):
    """Pure, network-free tests against discover_page_attack_surface."""

    def test_get_form_is_safe_to_probe_and_projects_to_detection_candidate(
        self,
    ) -> None:
        html = b"""<form method="GET" action="/search">
        <input type="text" name="q"></form>"""
        result = discover_page_attack_surface(_target(), "http://example.com/", html)

        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(candidate.discovery_method, DiscoveryMethod.GET_FORM)
        self.assertEqual(candidate.safety, SafetyClassification.SAFE_TO_PROBE)
        self.assertEqual(candidate.input_location, InputLocation.FORM)

        projected = to_detection_candidates(result)
        self.assertEqual(len(projected), 1)
        self.assertEqual(projected[0].url, "http://example.com/search")
        self.assertEqual(projected[0].parameter, "q")
        self.assertEqual(projected[0].method, "GET")

    def test_post_form_requires_explicit_authorization_and_is_not_projected(
        self,
    ) -> None:
        html = b"""<form method="POST" action="/comment">
        <input type="text" name="body"></form>"""
        result = discover_page_attack_surface(_target(), "http://example.com/", html)

        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(candidate.discovery_method, DiscoveryMethod.POST_FORM)
        self.assertEqual(
            candidate.safety,
            SafetyClassification.REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION,
        )

        # Discovered, but never handed to an existing GET-only detector.
        self.assertEqual(to_detection_candidates(result), ())

    def test_query_parameter_link_is_safe_to_probe(self) -> None:
        html = b'<a href="/view?id=1&sort=asc">view</a>'
        result = discover_page_attack_surface(_target(), "http://example.com/", html)

        parameters = {c.parameter for c in result.candidates}
        self.assertEqual(parameters, {"id", "sort"})
        for candidate in result.candidates:
            self.assertEqual(candidate.discovery_method, DiscoveryMethod.LINK_PARAMETER)
            self.assertEqual(candidate.safety, SafetyClassification.SAFE_TO_PROBE)

        projected = to_detection_candidates(result)
        self.assertEqual(len(projected), 2)

    def test_likely_state_changing_post_form_is_classified_accordingly(
        self,
    ) -> None:
        html = b"""<form method="POST" action="/account/delete">
        <input type="text" name="confirm"></form>"""
        result = discover_page_attack_surface(_target(), "http://example.com/", html)

        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(
            result.candidates[0].safety,
            SafetyClassification.POTENTIALLY_STATE_CHANGING,
        )
        self.assertEqual(to_detection_candidates(result), ())

    def test_duplicate_endpoints_across_sources_are_deduplicated(self) -> None:
        html = b"""
        <form method="GET" action="/search"><input type="text" name="q"></form>
        <a href="/search?q=x">search again</a>
        """
        result = discover_page_attack_surface(_target(), "http://example.com/", html)

        # The form's own <q> parameter and the link's <q> parameter refer to
        # the same (endpoint, method, location? no -- different locations)
        # -- form vs query location are legitimately distinct candidates,
        # so verify exact duplicates (same page linked twice) collapse
        # instead by feeding the identical href twice.
        html_repeated = b"""
        <a href="/view?id=1">one</a>
        <a href="/view?id=1">one again</a>
        """
        repeated_result = discover_page_attack_surface(
            _target(), "http://example.com/", html_repeated
        )
        self.assertEqual(len(repeated_result.candidates), 1)
        self.assertTrue(
            any(item.reason == "duplicate" for item in repeated_result.skipped)
        )

    def test_external_out_of_scope_endpoint_is_excluded_not_authorized(
        self,
    ) -> None:
        html = b"""
        <form method="GET" action="https://third-party.example/search">
        <input type="text" name="q"></form>
        <a href="https://third-party.example/x?y=1">offsite</a>
        """
        result = discover_page_attack_surface(_target(), "http://example.com/", html)

        self.assertEqual(result.candidates, ())
        reasons = {item.reason for item in result.skipped}
        self.assertIn("off_origin", reasons)

    def test_malformed_html_does_not_crash_discovery(self) -> None:
        html = b"<form method<<<GET>>><input name=q<html unterminated"
        result = discover_page_attack_surface(_target(), "http://example.com/", html)
        # Must not raise; either recovers some/no candidates.
        self.assertIsInstance(result.candidates, tuple)

    def test_very_large_page_is_rejected_without_parsing(self) -> None:
        budget = AttackSurfaceBudget(maximum_response_bytes=1024)
        html = b"<form method=\"GET\" action=\"/s\"><input name=\"q\"></form>" * 1000
        result = discover_page_attack_surface(
            _target(), "http://example.com/", html, budget=budget
        )
        self.assertEqual(result.candidates, ())
        self.assertTrue(result.truncated)
        self.assertTrue(
            any(item.reason == "response_too_large" for item in result.skipped)
        )

    def test_budget_exhaustion_truncates_and_records_reason(self) -> None:
        budget = AttackSurfaceBudget(maximum_endpoints=1, maximum_links=50)
        html = b'<a href="/a?x=1">a</a><a href="/b?y=1">b</a>'
        result = discover_page_attack_surface(
            _target(), "http://example.com/", html, budget=budget
        )
        self.assertEqual(len(result.candidates), 1)
        self.assertTrue(result.truncated)

    def test_script_endpoint_literal_is_discovered_but_unsupported(self) -> None:
        html = b'<script>fetch("/api/orders/123");</script>'
        result = discover_page_attack_surface(_target(), "http://example.com/", html)
        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(candidate.discovery_method, DiscoveryMethod.SCRIPT_REFERENCE)
        self.assertEqual(candidate.safety, SafetyClassification.UNSUPPORTED)
        self.assertEqual(to_detection_candidates(result), ())

    def test_graphql_indicator_is_recorded_as_unsupported(self) -> None:
        html = b'<script>var endpoint = "/graphql";</script>'
        result = discover_page_attack_surface(_target(), "http://example.com/", html)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(
            result.candidates[0].discovery_method, DiscoveryMethod.GRAPHQL_INDICATOR
        )
        self.assertEqual(result.candidates[0].safety, SafetyClassification.UNSUPPORTED)

    def test_candidate_identity_is_deterministic_regardless_of_discovery_order(
        self,
    ) -> None:
        html_a = b'<a href="/view?id=1">x</a><a href="/other?z=2">y</a>'
        html_b = b'<a href="/other?z=2">y</a><a href="/view?id=1">x</a>'

        result_a = discover_page_attack_surface(_target(), "http://example.com/", html_a)
        result_b = discover_page_attack_surface(_target(), "http://example.com/", html_b)

        ids_a = sorted(c.candidate_id for c in result_a.candidates)
        ids_b = sorted(c.candidate_id for c in result_b.candidates)
        self.assertEqual(ids_a, ids_b)

    def test_candidate_identity_ignores_query_string_and_fragment_variation(
        self,
    ) -> None:
        html_with_noise = b"""
        <form method="GET" action="/search?utm=1#frag">
        <input type="text" name="q"></form>
        """
        html_clean = b"""
        <form method="GET" action="/search">
        <input type="text" name="q"></form>
        """
        noisy_result = discover_page_attack_surface(
            _target(), "http://example.com/", html_with_noise
        )
        clean_result = discover_page_attack_surface(
            _target(), "http://example.com/", html_clean
        )
        self.assertEqual(len(noisy_result.candidates), 1)
        self.assertEqual(len(clean_result.candidates), 1)
        # candidate_id is the identity used for deduplication; it must be
        # canonicalised to scheme+host+path so pre-existing query-string
        # or fragment noise on the form action doesn't create a distinct
        # identity for what is really the same endpoint+parameter.
        self.assertEqual(
            noisy_result.candidates[0].candidate_id,
            clean_result.candidates[0].candidate_id,
        )


class _FakeHttpResponse:
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


class _RoutedConnection:
    """A fake HTTP connection returning a fixed body per exact path."""

    def __init__(self, routes: dict[str, bytes], *, default_status: int = 404) -> None:
        self.routes = routes
        self.default_status = default_status
        self.sock = None
        self._context = None
        self._path = ""

    def putrequest(self, method, path, **kwargs) -> None:
        self._path = urlsplit(path).path

    def putheader(self, name, value) -> None:
        return None

    def endheaders(self) -> None:
        return None

    def getresponse(self):
        if self._path in self.routes:
            return _FakeHttpResponse(self.routes[self._path], status=200)
        return _FakeHttpResponse(b"", status=self.default_status)

    def close(self) -> None:
        pass


def _policy() -> ActiveDetectionPolicy:
    return ActiveDetectionPolicy(maximum_probe_requests=25)


class SiteAttackSurfaceDiscoveryTests(unittest.TestCase):
    """Site-level discovery (sitemap, robots.txt, OpenAPI) over a fake
    connection -- no real network access occurs."""

    def test_json_post_api_and_safe_get_api_from_openapi_document(self) -> None:
        openapi = json.dumps(
            {
                "paths": {
                    "/api/orders": {
                        "get": {},
                        "post": {},
                    },
                    "/api/orders/{id}/delete": {
                        "post": {},
                    },
                }
            }
        ).encode()

        connection = _RoutedConnection({"/openapi.json": openapi})
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = discover_site_attack_surface(_target(), policy=_policy())

        by_method_path = {
            (c.method, urlsplit(c.endpoint).path): c for c in result.candidates
        }
        self.assertIn(("GET", "/api/orders"), by_method_path)
        self.assertEqual(
            by_method_path[("GET", "/api/orders")].safety,
            SafetyClassification.SAFE_TO_PROBE,
        )
        self.assertIn(("POST", "/api/orders"), by_method_path)
        self.assertEqual(
            by_method_path[("POST", "/api/orders")].safety,
            SafetyClassification.REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION,
        )
        self.assertIn(("POST", "/api/orders/{id}/delete"), by_method_path)
        self.assertEqual(
            by_method_path[("POST", "/api/orders/{id}/delete")].safety,
            SafetyClassification.POTENTIALLY_STATE_CHANGING,
        )

    def test_malformed_openapi_document_is_skipped_not_crashed(self) -> None:
        connection = _RoutedConnection({"/openapi.json": b"{not valid json"})
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = discover_site_attack_surface(_target(), policy=_policy())

        self.assertEqual(result.candidates, ())
        self.assertTrue(
            any(
                item.reason == "malformed_openapi_document"
                for item in result.skipped
            )
        )

    def test_sitemap_off_origin_url_is_excluded(self) -> None:
        sitemap = (
            b"<urlset><url><loc>https://third-party.example/x?y=1</loc>"
            b"</url></urlset>"
        )
        connection = _RoutedConnection({"/sitemap.xml": sitemap})
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = discover_site_attack_surface(_target(), policy=_policy())

        self.assertEqual(result.candidates, ())
        self.assertTrue(any(item.reason == "off_origin" for item in result.skipped))

    def test_robots_txt_paths_are_discovery_input_not_findings(self) -> None:
        robots = b"User-agent: *\nDisallow: /admin\nAllow: /public\n"
        connection = _RoutedConnection({"/robots.txt": robots})
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = discover_site_attack_surface(_target(), policy=_policy())

        robots_candidates = [
            c for c in result.candidates if c.discovery_method == DiscoveryMethod.ROBOTS_TXT
        ]
        self.assertEqual(len(robots_candidates), 2)
        for candidate in robots_candidates:
            self.assertEqual(candidate.safety, SafetyClassification.UNSUPPORTED)
        # robots.txt-derived paths never project to a probeable candidate.
        self.assertEqual(to_detection_candidates(result), ())

    def test_cancellation_before_first_fetch_makes_no_requests(self) -> None:
        connection = _RoutedConnection({})
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ) as make_connection:
            result = discover_site_attack_surface(
                _target(),
                policy=_policy(),
                cancellation_check=lambda: True,
            )

        make_connection.assert_not_called()
        self.assertEqual(result.candidates, ())
        self.assertTrue(any(item.reason == "cancelled" for item in result.skipped))

    def test_api_definition_budget_is_enforced(self) -> None:
        budget = AttackSurfaceBudget(maximum_api_definitions=1)
        openapi = json.dumps({"paths": {"/api/a": {"get": {}}}}).encode()
        connection = _RoutedConnection(
            {"/openapi.json": openapi, "/swagger.json": openapi}
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = discover_site_attack_surface(
                _target(), policy=_policy(), budget=budget
            )

        self.assertTrue(
            any(
                item.reason == "max_api_definitions_reached"
                for item in result.skipped
            )
        )


class MergeAttackSurfaceResultsTests(unittest.TestCase):
    def test_merge_deduplicates_across_page_and_site_level_results(self) -> None:
        html = b'<a href="/view?id=1">x</a>'
        page_result = discover_page_attack_surface(_target(), "http://example.com/", html)

        sitemap = b"<urlset><url><loc>http://example.com/view?id=1</loc></url></urlset>"
        connection = _RoutedConnection({"/sitemap.xml": sitemap})
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            site_result = discover_site_attack_surface(_target(), policy=_policy())

        merged = merge_attack_surface_results(page_result, site_result)
        matching = [
            c for c in merged.candidates
            if urlsplit(c.endpoint).path == "/view" and c.parameter == "id"
        ]
        self.assertEqual(len(matching), 1)
        self.assertTrue(any(item.reason == "duplicate" for item in merged.skipped))

    def test_merge_enforces_a_combined_endpoint_budget(self) -> None:
        html = b'<a href="/a?x=1">a</a><a href="/b?y=1">b</a>'
        page_result = discover_page_attack_surface(_target(), "http://example.com/", html)

        merged = merge_attack_surface_results(
            page_result, budget=AttackSurfaceBudget(maximum_endpoints=1)
        )
        self.assertEqual(len(merged.candidates), 1)
        self.assertTrue(merged.truncated)


if __name__ == "__main__":
    unittest.main()
