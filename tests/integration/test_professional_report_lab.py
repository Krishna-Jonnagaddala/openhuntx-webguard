"""Authorised Juice Shop professional-report integration test."""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from urllib.parse import urlsplit

from webguard_scanner import (
    CrawlPolicy,
    FetchPolicy,
    ProfessionalReportProfile,
    ValidationMode,
    ValidationPolicy,
    render_professional_html,
    run_passive_crawl_scan,
    validate_target_url,
)


RUN_INTEGRATION = os.getenv("WEBGUARD_RUN_INTEGRATION") == "1"
LAB_TARGET = os.getenv(
    "WEBGUARD_LAB_TARGET",
    "http://127.0.0.1:3000/",
)


@unittest.skipUnless(
    RUN_INTEGRATION,
    "Set WEBGUARD_RUN_INTEGRATION=1 to run network integration tests.",
)
class ProfessionalReportLabIntegrationTests(unittest.TestCase):
    """Render a self-contained report from the authorised Juice Shop scan."""

    def test_renders_valid_html_from_juice_shop_result(self) -> None:
        parsed = urlsplit(LAB_TARGET)
        if parsed.hostname is None:
            self.fail("WEBGUARD_LAB_TARGET must contain a hostname.")

        target = validate_target_url(
            LAB_TARGET,
            ValidationPolicy(
                mode=ValidationMode.LAB,
                allowed_lab_hosts=frozenset(
                    {parsed.hostname, "127.0.0.1", "localhost"}
                ),
            ),
        )
        result = run_passive_crawl_scan(
            target,
            crawl_policy=CrawlPolicy(
                maximum_pages=2,
                maximum_depth=1,
                maximum_links_per_page=25,
                minimum_delay_seconds=0,
            ),
            fetch_policy=FetchPolicy(timeout_seconds=5),
        )
        rendered = render_professional_html(
            result,
            ProfessionalReportProfile(
                organization="OWASP Juice Shop Authorised Lab",
                generated_at=datetime.now(timezone.utc),
            ),
        )

        self.assertTrue(rendered.startswith("<!doctype html>"))
        self.assertIn("OpenHuntX WebGuard", rendered)
        self.assertIn(result.scan_id, rendered)
        self.assertIn("Passive same-origin crawl", rendered)
        self.assertNotIn("<script", rendered.lower())
        self.assertNotIn("response_body", rendered)


if __name__ == "__main__":
    unittest.main()
