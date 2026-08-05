"""Authorised OWASP Juice Shop passive HTML-analysis integration test."""

from __future__ import annotations

import os
import unittest

from webguard_contracts import ScanStatus
from webguard_scanner import (
    FetchPolicy,
    PASSIVE_HTML_CHECKS,
    ValidationMode,
    ValidationPolicy,
    run_passive_header_scan,
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
class HtmlAnalyzerLabIntegrationTests(unittest.TestCase):
    def test_html_checks_execute_without_persisting_response_body(self) -> None:
        target = validate_target_url(
            LAB_TARGET,
            ValidationPolicy(
                mode=ValidationMode.LAB,
                allowed_lab_hosts=frozenset(
                    {
                        "127.0.0.1",
                        "localhost",
                    }
                ),
            ),
        )

        result = run_passive_header_scan(
            target,
            fetch_policy=FetchPolicy(
                timeout_seconds=5,
                maximum_body_bytes=1_048_576,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
            ),
        )

        self.assertIs(result.status, ScanStatus.COMPLETED)
        self.assertTrue(
            set(PASSIVE_HTML_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertEqual(result.coverage.unaccounted_checks, ())

        document = result.to_json()
        self.assertNotIn("response_body", document)
        self.assertNotIn('"body"', document)


if __name__ == "__main__":
    unittest.main()
