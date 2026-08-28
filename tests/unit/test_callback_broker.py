"""Tests for the controlled SSRF callback broker (Slice 10): token
authenticity (high-entropy, scan-bound, candidate-bound, time-limited,
bounded-use), fail-closed handling of unknown/expired/over-quota
tokens, and the wait/grace/cancellation timing contract.
"""

from __future__ import annotations

import threading
import time
import unittest
from datetime import datetime, timezone

from webguard_scanner.callback_broker import (
    CallbackBrokerError,
    CallbackPolicy,
    InMemoryCallbackBroker,
)

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


class TokenAuthenticityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")

    def test_token_is_high_entropy_and_unique(self) -> None:
        token_a = self.broker.register(scan_id="scan-1", candidate_fingerprint="c1")
        token_b = self.broker.register(scan_id="scan-1", candidate_fingerprint="c2")
        self.assertNotEqual(token_a.value, token_b.value)
        self.assertGreaterEqual(len(token_a.value), 32)

    def test_token_is_scan_and_candidate_bound(self) -> None:
        token = self.broker.register(scan_id="scan-42", candidate_fingerprint="url-param")
        self.assertEqual(token.scan_id, "scan-42")
        self.assertEqual(token.candidate_fingerprint, "url-param")
        self.assertIn("scan-42", token.url)
        self.assertIn(token.value, token.url)

    def test_arbitrary_user_supplied_id_is_never_accepted_as_proof(self) -> None:
        # No registration ever happened for this value -- a forged or
        # guessed token must be rejected, not silently accepted.
        accepted = self.broker.record_observation(
            "forged-token-value", method="GET", now=NOW
        )
        self.assertFalse(accepted)

    def test_expired_token_is_rejected(self) -> None:
        policy = CallbackPolicy(token_ttl_seconds=0.1)
        token = self.broker.register(
            scan_id="scan-1", candidate_fingerprint="c1", policy=policy
        )
        time.sleep(0.2)
        accepted = self.broker.record_observation(
            token.value, method="GET", policy=policy
        )
        self.assertFalse(accepted)

    def test_bounded_use_rejects_beyond_maximum_observations(self) -> None:
        policy = CallbackPolicy(maximum_observations_per_token=2)
        token = self.broker.register(
            scan_id="scan-1", candidate_fingerprint="c1", policy=policy
        )
        first = self.broker.record_observation(
            token.value, method="GET", now=NOW, policy=policy
        )
        second = self.broker.record_observation(
            token.value, method="GET", now=NOW, policy=policy
        )
        third = self.broker.record_observation(
            token.value, method="GET", now=NOW, policy=policy
        )
        self.assertTrue(first)
        self.assertTrue(second)
        self.assertFalse(third)

    def test_registration_limit_is_enforced(self) -> None:
        policy = CallbackPolicy(maximum_active_registrations=2)
        self.broker.register(scan_id="scan-1", candidate_fingerprint="c1", policy=policy)
        self.broker.register(scan_id="scan-1", candidate_fingerprint="c2", policy=policy)
        with self.assertRaises(CallbackBrokerError) as caught:
            self.broker.register(
                scan_id="scan-1", candidate_fingerprint="c3", policy=policy
            )
        self.assertEqual(caught.exception.code, "callback_registration_limit_exceeded")


class WaitTimingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.broker = InMemoryCallbackBroker(base_url="http://127.0.0.1:9/")

    def test_observation_within_primary_window_is_reported_as_such(self) -> None:
        policy = CallbackPolicy(
            maximum_wait_seconds=1.0, grace_seconds=1.0, poll_interval_seconds=0.02
        )
        token = self.broker.register(scan_id="scan-1", candidate_fingerprint="c1")

        def deliver() -> None:
            time.sleep(0.1)
            self.broker.record_observation(token.value, method="GET")

        threading.Thread(target=deliver).start()
        observation, within_primary, cancelled = self.broker.wait_for_observation(
            token, policy=policy
        )
        self.assertIsNotNone(observation)
        self.assertTrue(within_primary)
        self.assertFalse(cancelled)

    def test_observation_only_in_grace_window_is_reported_as_such(self) -> None:
        policy = CallbackPolicy(
            maximum_wait_seconds=0.2, grace_seconds=0.6, poll_interval_seconds=0.02
        )
        token = self.broker.register(scan_id="scan-1", candidate_fingerprint="c1")

        def deliver() -> None:
            time.sleep(0.4)
            self.broker.record_observation(token.value, method="GET")

        threading.Thread(target=deliver).start()
        observation, within_primary, cancelled = self.broker.wait_for_observation(
            token, policy=policy
        )
        self.assertIsNotNone(observation)
        self.assertFalse(within_primary)
        self.assertFalse(cancelled)

    def test_no_observation_times_out_cleanly(self) -> None:
        policy = CallbackPolicy(
            maximum_wait_seconds=0.1, grace_seconds=0.1, poll_interval_seconds=0.02
        )
        token = self.broker.register(scan_id="scan-1", candidate_fingerprint="c1")
        observation, within_primary, cancelled = self.broker.wait_for_observation(
            token, policy=policy
        )
        self.assertIsNone(observation)
        self.assertFalse(within_primary)
        self.assertFalse(cancelled)

    def test_cancellation_stops_the_wait_early(self) -> None:
        policy = CallbackPolicy(
            maximum_wait_seconds=5.0, grace_seconds=5.0, poll_interval_seconds=0.02
        )
        token = self.broker.register(scan_id="scan-1", candidate_fingerprint="c1")
        started = time.monotonic()
        observation, within_primary, cancelled = self.broker.wait_for_observation(
            token, policy=policy, cancellation_check=lambda: True
        )
        elapsed = time.monotonic() - started
        self.assertIsNone(observation)
        self.assertTrue(cancelled)
        self.assertLess(elapsed, 1.0)

    def test_observation_from_a_different_token_never_satisfies_this_wait(self) -> None:
        policy = CallbackPolicy(
            maximum_wait_seconds=0.2, grace_seconds=0.1, poll_interval_seconds=0.02
        )
        token_a = self.broker.register(scan_id="scan-1", candidate_fingerprint="c1")
        token_b = self.broker.register(scan_id="scan-1", candidate_fingerprint="c2")
        self.broker.record_observation(token_b.value, method="GET")
        observation, _within, _cancelled = self.broker.wait_for_observation(
            token_a, policy=policy
        )
        self.assertIsNone(observation)


if __name__ == "__main__":
    unittest.main()
