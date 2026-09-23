"""`_ssrf_callback_pipeline_confirmed_healthy` (executor.py) is the
positive-control canary that lets a NOT_VULNERABLE SSRF result be
trusted: without it, a sustained callback-persistence outage
(P1-12-R1, docs/PROJECT_EXECUTION_LEDGER.md) is indistinguishable from
a genuine negative, because the read side always sees the identical
`(None, False, False)` shape either way. These tests exercise the
canary in isolation, against a fake broker, rather than through the
full page-fetch/candidate-discovery pipeline `_apply_ssrf_callback_detection`
otherwise requires -- the executor-level integration proof against a
real, permanently-faulty PostgreSQL connection lives in
tests/integration/test_production_ssrf_callback_e2e.py's
test_no_fabricated_confirmation_when_persistence_never_recovers."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from webguard_api.executor import _ssrf_callback_pipeline_confirmed_healthy
from webguard_scanner.callback_broker import CallbackBrokerError, CallbackToken

_POLICY = object()


def _cancellation_check() -> bool:
    return False


def _canary_token(url: str = "https://callback.example/c/canary-token") -> CallbackToken:
    return CallbackToken(
        value="canary-token",
        url=url,
        scan_id="scan-1",
        candidate_fingerprint="webguard-positive-control",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=300),
    )


class _FakeBroker:
    def __init__(self, *, observation, register_error=None, wait_error=None, token=None) -> None:
        self._observation = observation
        self._register_error = register_error
        self._wait_error = wait_error
        self._token = token or _canary_token()
        self.registered_with: dict | None = None
        self.waited_on = None

    def register(self, *, scan_id: str, candidate_fingerprint: str) -> CallbackToken:
        self.registered_with = {"scan_id": scan_id, "candidate_fingerprint": candidate_fingerprint}
        if self._register_error is not None:
            raise self._register_error
        return self._token

    def wait_for_observation(self, token, *, policy, cancellation_check=None):
        self.waited_on = token
        if self._wait_error is not None:
            raise self._wait_error
        return (self._observation, self._observation is not None, False)


class SsrfCallbackPipelineHealthTests(unittest.TestCase):
    def test_healthy_when_the_canary_observation_is_recorded(self) -> None:
        broker = _FakeBroker(observation=object())
        with patch("webguard_api.executor.urllib.request.urlopen"):
            healthy = _ssrf_callback_pipeline_confirmed_healthy(
                broker, scan_id="scan-1", policy=_POLICY, cancellation_check=_cancellation_check
            )
        self.assertTrue(healthy)
        self.assertEqual(broker.registered_with["candidate_fingerprint"], "webguard-positive-control")

    def test_unhealthy_when_the_canary_is_never_observed(self) -> None:
        """The direct proof of the fix: a sustained write-path outage
        means the canary's own observation, like every real
        candidate's, never gets durably recorded."""
        broker = _FakeBroker(observation=None)
        with patch("webguard_api.executor.urllib.request.urlopen"):
            healthy = _ssrf_callback_pipeline_confirmed_healthy(
                broker, scan_id="scan-1", policy=_POLICY, cancellation_check=_cancellation_check
            )
        self.assertFalse(healthy)

    def test_unhealthy_when_canary_registration_itself_fails(self) -> None:
        broker = _FakeBroker(observation=None, register_error=CallbackBrokerError("db_down", "unavailable"))
        healthy = _ssrf_callback_pipeline_confirmed_healthy(
            broker, scan_id="scan-1", policy=_POLICY, cancellation_check=_cancellation_check
        )
        self.assertFalse(healthy)

    def test_unhealthy_when_waiting_on_the_canary_raises(self) -> None:
        broker = _FakeBroker(observation=None, wait_error=CallbackBrokerError("db_down", "unavailable"))
        with patch("webguard_api.executor.urllib.request.urlopen"):
            healthy = _ssrf_callback_pipeline_confirmed_healthy(
                broker, scan_id="scan-1", policy=_POLICY, cancellation_check=_cancellation_check
            )
        self.assertFalse(healthy)

    def test_unhealthy_and_never_opened_when_the_broker_returns_a_non_http_url(self) -> None:
        """The broker (never external input) is what builds this URL,
        but urlopen's own scheme handling covers file:// and other
        unintended schemes too, so this is a defense-in-depth check
        against a hypothetical broker bug, not a real attacker-facing
        path. A bad scheme must fail the canary without ever calling
        urlopen at all."""
        broker = _FakeBroker(observation=object(), token=_canary_token(url="file:///etc/passwd"))
        with patch("webguard_api.executor.urllib.request.urlopen") as mock_urlopen:
            healthy = _ssrf_callback_pipeline_confirmed_healthy(
                broker, scan_id="scan-1", policy=_POLICY, cancellation_check=_cancellation_check
            )
        self.assertFalse(healthy)
        mock_urlopen.assert_not_called()

    def test_the_canary_probe_itself_failing_to_connect_does_not_short_circuit(self) -> None:
        """The canary's own outbound GET is best-effort: what actually
        matters is whether an observation shows up, checked separately
        via wait_for_observation. A network-level failure sending the
        probe must not be treated as a different case from "no
        observation arrived" -- both still correctly resolve through
        the same wait_for_observation call below."""
        broker = _FakeBroker(observation=object())
        with patch("webguard_api.executor.urllib.request.urlopen", side_effect=OSError("connection refused")):
            healthy = _ssrf_callback_pipeline_confirmed_healthy(
                broker, scan_id="scan-1", policy=_POLICY, cancellation_check=_cancellation_check
            )
        self.assertTrue(healthy)
        self.assertIsNotNone(broker.waited_on)


if __name__ == "__main__":
    unittest.main()
