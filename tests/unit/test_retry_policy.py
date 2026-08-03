"""Tests for bounded retry configuration."""

from __future__ import annotations

import math
import unittest

from webguard_scanner.retry_policy import (
    MAXIMUM_REQUEST_ATTEMPTS,
    RetryPolicy,
)


class RetryPolicyTests(unittest.TestCase):
    """Verify strict retry and backoff limits."""

    def test_defaults_disable_retries(self) -> None:
        policy = RetryPolicy()

        self.assertEqual(policy.maximum_attempts, 1)
        self.assertFalse(policy.retries_enabled)

    def test_rejects_attempt_count_below_one(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "between 1",
        ):
            RetryPolicy(maximum_attempts=0)

    def test_rejects_attempt_count_above_cap(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            str(MAXIMUM_REQUEST_ATTEMPTS),
        ):
            RetryPolicy(
                maximum_attempts=(
                    MAXIMUM_REQUEST_ATTEMPTS + 1
                )
            )

    def test_rejects_boolean_attempt_count(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "integer",
        ):
            RetryPolicy(maximum_attempts=True)

    def test_rejects_non_finite_backoff(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "finite",
        ):
            RetryPolicy(
                initial_backoff_seconds=math.inf,
            )

    def test_rejects_initial_delay_above_maximum(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "cannot exceed",
        ):
            RetryPolicy(
                initial_backoff_seconds=2,
                maximum_backoff_seconds=1,
            )

    def test_rejects_multiplier_below_one(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "between 1.0",
        ):
            RetryPolicy(
                backoff_multiplier=0.5,
            )

    def test_calculates_capped_exponential_delay(self) -> None:
        policy = RetryPolicy(
            maximum_attempts=3,
            initial_backoff_seconds=2,
            backoff_multiplier=4,
            maximum_backoff_seconds=5,
        )

        self.assertEqual(
            policy.delay_after_failure(1),
            2,
        )
        self.assertEqual(
            policy.delay_after_failure(2),
            5,
        )


if __name__ == "__main__":
    unittest.main()
