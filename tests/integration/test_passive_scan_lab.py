"""Integration test for the passive ScanResult lab flow."""

from __future__ import annotations

import os
import unittest

from webguard_contracts import (
    RequestAttemptOutcome,
    ScanResult,
    ScanStatus,
)

from webguard_scanner import (
    DEFAULT_PASSIVE_ANALYZERS,
    FetchPolicy,
    PASSIVE_CHECKS,
    PASSIVE_COOKIE_CHECKS,
    PASSIVE_CORS_CHECKS,
    PASSIVE_DISCLOSURE_CHECKS,
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
class PassiveScanLabIntegrationTests(unittest.TestCase):
    """Run the complete passive flow against authorised Juice Shop."""

    def test_returns_completed_scan_result(self) -> None:
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
                maximum_body_bytes=2_097_152,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
            ),
        )

        self.assertIsInstance(result, ScanResult)
        self.assertIs(
            result.status,
            ScanStatus.COMPLETED,
        )
        self.assertEqual(
            result.target,
            "http://127.0.0.1:3000/",
        )
        self.assertEqual(
            result.connected_addresses,
            ("127.0.0.1",),
        )
        self.assertEqual(result.http_statuses, (200,))
        self.assertEqual(result.errors, ())
        self.assertEqual(
            result.coverage.unaccounted_checks,
            (),
        )
        self.assertEqual(
            result.coverage.planned_checks,
            tuple(sorted(PASSIVE_CHECKS)),
        )
        self.assertEqual(len(DEFAULT_PASSIVE_ANALYZERS), 5)
        self.assertEqual(
            result.coverage.completion_percent,
            96.97,
        )
        self.assertTrue(
            set(PASSIVE_COOKIE_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertTrue(
            set(PASSIVE_CORS_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertTrue(
            set(PASSIVE_DISCLOSURE_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertTrue(
            set(PASSIVE_HTML_CHECKS).issubset(
                result.coverage.executed_checks
            )
        )
        self.assertEqual(len(result.request_attempts), 1)
        self.assertIs(
            result.request_attempts[0].outcome,
            RequestAttemptOutcome.SUCCEEDED,
        )


if __name__ == "__main__":
    unittest.main()
