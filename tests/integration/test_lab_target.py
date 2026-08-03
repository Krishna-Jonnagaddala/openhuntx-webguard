"""Integration tests for the authorised local Juice Shop target.

These tests make real network requests and therefore run only when
WEBGUARD_RUN_INTEGRATION=1 is explicitly configured.
"""

from __future__ import annotations

import os
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from webguard_scanner import (
    TargetValidationError,
    ValidationMode,
    ValidationPolicy,
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
class JuiceShopScopeIntegrationTests(unittest.TestCase):
    """Verify commercial and laboratory policies against Juice Shop."""

    def test_commercial_policy_blocks_local_target(self) -> None:
        commercial_policy = ValidationPolicy(
            mode=ValidationMode.COMMERCIAL,
        )

        with self.assertRaises(TargetValidationError) as context:
            validate_target_url(
                LAB_TARGET,
                commercial_policy,
            )

        self.assertEqual(
            context.exception.code,
            "non_public_address",
        )

    def test_lab_policy_allows_and_reaches_local_target(self) -> None:
        lab_policy = ValidationPolicy(
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
            lab_policy,
        )

        request = Request(
            target.normalised_url,
            headers={
                "User-Agent": "OpenHuntX-WebGuard-Lab-Test/0.1",
                "Accept": "text/html,application/xhtml+xml",
            },
            method="GET",
        )

        try:
            with urlopen(request, timeout=5) as response:
                status = response.status
                response.read(1024)
        except HTTPError as exc:
            self.fail(
                f"Juice Shop returned HTTP error {exc.code}."
            )
        except URLError as exc:
            self.fail(
                f"Could not reach the Juice Shop lab target: {exc.reason}"
            )

        self.assertEqual(status, 200)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertEqual(
            target.resolved_addresses,
            ("127.0.0.1",),
        )


if __name__ == "__main__":
    unittest.main()
