"""Integration tests for the WebGuard safe HTTP client.

Real network requests run only when WEBGUARD_RUN_INTEGRATION=1.
The target must be an explicitly authorised local laboratory application.
"""

from __future__ import annotations

import os
import unittest

from webguard_scanner import (
    FetchPolicy,
    ValidationMode,
    ValidationPolicy,
    fetch_once,
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
class SafeHttpLabIntegrationTests(unittest.TestCase):
    """Exercise the safe HTTP client against authorised Juice Shop."""

    def test_fetches_juice_shop_using_validated_address(self) -> None:
        policy = ValidationPolicy(
            mode=ValidationMode.LAB,
            allowed_lab_hosts=frozenset(
                {
                    "127.0.0.1",
                    "localhost",
                }
            ),
        )

        target = validate_target_url(
            LAB_TARGET,
            policy,
        )

        response = fetch_once(
            target,
            method="GET",
            policy=FetchPolicy(
                timeout_seconds=5,
                maximum_body_bytes=2_097_152,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
            ),
        )

        self.assertEqual(response.status, 200)
        self.assertEqual(
            response.connected_address,
            "127.0.0.1",
        )
        self.assertGreater(len(response.body), 0)
        self.assertGreaterEqual(
            response.elapsed_milliseconds,
            0,
        )


if __name__ == "__main__":
    unittest.main()
