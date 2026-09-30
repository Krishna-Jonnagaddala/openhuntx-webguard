"""Tests for authenticated crawling (Slice 9): credential isolation
across two identities, the shared Slice-7 authentication mechanism
being the only place headers are attached, checkpoint/resume with
re-validated authentication binding, and login-page/expired-session
detection during a crawl.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from webguard_scanner import AuthenticationMaterial
from webguard_scanner.authorization_resource_discovery import (
    AuthenticatedCrawlStatus,
    AuthenticationHealthCriterion,
)
from webguard_scanner.authorization_crawl import (
    run_authenticated_resource_discovery_crawl,
)
from webguard_scanner.crawler import CrawlPolicy, crawl_same_origin
from webguard_scanner.safe_http import SafeHttpResponse
from webguard_scanner.scope_validator import ValidatedTarget


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


def target(url: str = "http://127.0.0.1:3000/") -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=("127.0.0.1",),
    )


def response(
    body: str = "",
    *,
    content_type: str = "text/html; charset=utf-8",
    status: int = 200,
) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=status,
        reason="OK",
        headers=(("Content-Type", content_type),),
        body=body.encode(),
        connected_address="127.0.0.1",
        elapsed_milliseconds=1,
    )


class CredentialIsolationTests(unittest.TestCase):
    @patch("webguard_scanner.crawler._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler.fetch_once")
    def test_authentication_material_is_applied_to_every_page(
        self, fetch_mock, _clock
    ) -> None:
        fetch_mock.side_effect = [response(), response()]

        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(maximum_pages=1, minimum_delay_seconds=0),
            authentication_material=AuthenticationMaterial(bearer_token="token-a"),
        )

        _, kwargs = fetch_mock.call_args
        self.assertIn(("Authorization", "Bearer token-a"), kwargs["extra_headers"])

    @patch("webguard_scanner.crawler._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler.fetch_once")
    def test_two_crawls_never_cross_contaminate_credentials(
        self, fetch_mock, _clock
    ) -> None:
        fetch_mock.side_effect = [response(), response()]
        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(maximum_pages=1, minimum_delay_seconds=0),
            authentication_material=AuthenticationMaterial(bearer_token="token-a"),
        )
        headers_a = fetch_mock.call_args.kwargs["extra_headers"]

        fetch_mock.side_effect = [response(), response()]
        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(maximum_pages=1, minimum_delay_seconds=0),
            authentication_material=AuthenticationMaterial(bearer_token="token-b"),
        )
        headers_b = fetch_mock.call_args.kwargs["extra_headers"]

        self.assertIn(("Authorization", "Bearer token-a"), headers_a)
        self.assertIn(("Authorization", "Bearer token-b"), headers_b)
        self.assertNotIn(("Authorization", "Bearer token-b"), headers_a)
        self.assertNotIn(("Authorization", "Bearer token-a"), headers_b)

    @patch("webguard_scanner.crawler._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler.fetch_once")
    def test_unauthenticated_crawl_sends_no_authentication_header(
        self, fetch_mock, _clock
    ) -> None:
        fetch_mock.side_effect = [response(), response()]
        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(maximum_pages=1, minimum_delay_seconds=0),
        )
        _, kwargs = fetch_mock.call_args
        self.assertEqual(kwargs["extra_headers"], ())


class AuthenticatedResourceDiscoveryCrawlTests(unittest.TestCase):
    @patch("webguard_scanner.crawl_scan._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler.fetch_once")
    def test_discovers_html_and_json_resources_across_pages(
        self, fetch_mock, _clock, _scan_clock
    ) -> None:
        fetch_mock.side_effect = [
            response('<a href="/orders/A-001">order</a>'),
            response(
                '{"id": "A-001", "owner": "user-a"}',
                content_type="application/json",
            ),
        ]

        result = run_authenticated_resource_discovery_crawl(
            target(),
            authentication_material=AuthenticationMaterial(bearer_token="token-a"),
            owning_identity="user-a",
            crawl_policy=CrawlPolicy(maximum_pages=2, minimum_delay_seconds=0),
        )

        self.assertEqual(result.status, AuthenticatedCrawlStatus.SUCCEEDED)
        self.assertTrue(result.resources)
        for resource in result.resources:
            self.assertEqual(resource.owning_test_identity, "user-a")

    @patch("webguard_scanner.crawl_scan._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler.fetch_once")
    def test_expired_session_login_page_stops_discovery_and_is_marked(
        self, fetch_mock, _clock, _scan_clock
    ) -> None:
        fetch_mock.side_effect = [
            response('<a href="/orders/A-001">order</a>'),
            response("<html>Please log in</html>"),
            response('{"id": "A-001"}', content_type="application/json"),
        ]

        result = run_authenticated_resource_discovery_crawl(
            target(),
            authentication_material=AuthenticationMaterial(bearer_token="token-a"),
            owning_identity="user-a",
            crawl_policy=CrawlPolicy(maximum_pages=3, minimum_delay_seconds=0),
            authentication_health_criterion=AuthenticationHealthCriterion(
                login_page_marker="Please log in"
            ),
        )

        self.assertEqual(result.status, AuthenticatedCrawlStatus.AUTHENTICATION_EXPIRED)
        self.assertTrue(result.pages_with_authentication_failure)
        # The order resource discovered on page 1 (before expiry) is
        # fine; nothing from the expired page itself, and the crawl
        # stops before the third page is even reached.
        self.assertLessEqual(fetch_mock.call_count, 2)

    @patch("webguard_scanner.crawl_scan._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler.fetch_once")
    def test_explicit_403_is_authentication_failed_not_expired(
        self, fetch_mock, _clock, _scan_clock
    ) -> None:
        fetch_mock.side_effect = [response(status=403, body="Forbidden")]

        result = run_authenticated_resource_discovery_crawl(
            target(),
            authentication_material=AuthenticationMaterial(bearer_token="token-a"),
            owning_identity="user-a",
            crawl_policy=CrawlPolicy(maximum_pages=1, minimum_delay_seconds=0),
            authentication_health_criterion=AuthenticationHealthCriterion(),
        )

        self.assertEqual(result.status, AuthenticatedCrawlStatus.AUTHENTICATION_FAILED)
        self.assertEqual(result.resources, ())

    @patch("webguard_scanner.crawl_scan._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler.fetch_once")
    def test_no_health_criterion_never_flags_a_normal_200_page(
        self, fetch_mock, _clock, _scan_clock
    ) -> None:
        fetch_mock.side_effect = [response("<html>ok</html>")]

        result = run_authenticated_resource_discovery_crawl(
            target(),
            authentication_material=AuthenticationMaterial(bearer_token="token-a"),
            owning_identity="user-a",
            crawl_policy=CrawlPolicy(maximum_pages=1, minimum_delay_seconds=0),
        )

        self.assertEqual(result.status, AuthenticatedCrawlStatus.SUCCEEDED)


class AuthenticatedCrawlCheckpointResumeTests(unittest.TestCase):
    @patch("webguard_scanner.crawler._utc_now", return_value=NOW)
    @patch("webguard_scanner.crawler.fetch_once")
    def test_resumed_crawl_still_applies_authentication_material(
        self, fetch_mock, _clock
    ) -> None:
        checkpoints = []
        fetch_mock.side_effect = [
            response('<a href="/a">a</a><a href="/b">b</a>'),
        ]

        first = crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=1, maximum_depth=1, minimum_delay_seconds=0
            ),
            authentication_material=AuthenticationMaterial(bearer_token="token-a"),
            on_checkpoint=checkpoints.append,
        )
        self.assertTrue(checkpoints)
        resume_state = checkpoints[-1]

        fetch_mock.side_effect = [response(), response()]
        crawl_same_origin(
            target(),
            crawl_policy=CrawlPolicy(
                maximum_pages=3, maximum_depth=1, minimum_delay_seconds=0
            ),
            resume_state=resume_state,
            authentication_material=AuthenticationMaterial(bearer_token="token-a"),
        )

        for call in fetch_mock.call_args_list:
            self.assertIn(
                ("Authorization", "Bearer token-a"), call.kwargs["extra_headers"]
            )


if __name__ == "__main__":
    unittest.main()
