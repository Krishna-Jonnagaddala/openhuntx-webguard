"""Authorised Juice Shop applicability test for passive TLS checks."""

from __future__ import annotations

import os
import unittest

from webguard_scanner import (
    PASSIVE_TLS_CHECKS,
    FetchPolicy,
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
class TlsAnalyzerLabIntegrationTests(unittest.TestCase):
    def test_http_juice_shop_skips_https_only_tls_checks(self) -> None:
        target = validate_target_url(
            LAB_TARGET,
            ValidationPolicy(
                mode=ValidationMode.LAB,
                allowed_lab_hosts=frozenset(
                    {"127.0.0.1", "localhost"}
                ),
            ),
        )
        result = run_passive_header_scan(
            target,
            fetch_policy=FetchPolicy(timeout_seconds=5),
        )
        skipped_ids = {
            item.check_id
            for item in result.coverage.skipped_checks
        }
        self.assertTrue(
            set(PASSIVE_TLS_CHECKS).issubset(skipped_ids)
        )
        self.assertFalse(
            set(PASSIVE_TLS_CHECKS).intersection(
                result.coverage.executed_checks
            )
        )
        self.assertEqual(result.coverage.unaccounted_checks, ())


if __name__ == "__main__":
    unittest.main()
