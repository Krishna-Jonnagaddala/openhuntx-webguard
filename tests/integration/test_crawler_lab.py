"""Authorised OWASP Juice Shop crawler smoke test."""

from __future__ import annotations

import os
import unittest
from urllib.parse import urlsplit

from webguard_scanner import (
    CrawlPageOutcome,
    CrawlPolicy,
    FetchPolicy,
    ValidationMode,
    ValidationPolicy,
    crawl_same_origin,
    validate_target_url,
)


RUN_INTEGRATION = os.getenv(
    "WEBGUARD_RUN_INTEGRATION"
) == "1"

LAB_TARGET = os.getenv(
    "WEBGUARD_LAB_TARGET",
    "http://127.0.0.1:3000/",
)


@unittest.skipUnless(
    RUN_INTEGRATION,
    "Authorised integration tests are disabled.",
)
class SameOriginCrawlerLabTests(unittest.TestCase):
    """Verify bounded crawling only against the configured lab target."""

    def test_crawls_only_the_authorised_juice_shop_origin(
        self,
    ) -> None:
        parsed = urlsplit(LAB_TARGET)

        if parsed.hostname is None:
            self.fail(
                "WEBGUARD_LAB_TARGET must contain a hostname."
            )

        target = validate_target_url(
            LAB_TARGET,
            ValidationPolicy(
                mode=ValidationMode.LAB,
                allowed_lab_hosts=frozenset(
                    {
                        parsed.hostname,
                        "127.0.0.1",
                        "localhost",
                    }
                ),
            ),
        )

        execution = crawl_same_origin(
            target,
            crawl_policy=CrawlPolicy(
                maximum_pages=5,
                maximum_depth=1,
                minimum_delay_seconds=0,
            ),
            fetch_policy=FetchPolicy(
                timeout_seconds=5,
                maximum_body_bytes=2_097_152,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
            ),
        )

        self.assertGreaterEqual(len(execution.pages), 1)
        self.assertLessEqual(len(execution.pages), 5)
        self.assertIs(
            execution.pages[0].outcome,
            CrawlPageOutcome.SUCCEEDED,
        )
        self.assertGreaterEqual(
            execution.requests_succeeded,
            1,
        )

        root_origin = (
            target.scheme,
            target.hostname,
            target.port,
        )

        for page in execution.pages:
            page_url = urlsplit(page.url)
            page_port = page_url.port

            if page_port is None:
                page_port = (
                    443
                    if page_url.scheme == "https"
                    else 80
                )

            self.assertEqual(
                (
                    page_url.scheme,
                    page_url.hostname,
                    page_port,
                ),
                root_origin,
            )
            self.assertEqual(page_url.query, "")
            self.assertEqual(page_url.fragment, "")


if __name__ == "__main__":
    unittest.main()
