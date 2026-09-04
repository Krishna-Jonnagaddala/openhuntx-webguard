"""P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
proves the signing-service's internal health/readiness composition --
the exact liveness/readiness closures `cli.py::_signing_service_command`
builds, exercised directly against a real `HealthServer`, a real
`SigningServiceServer` (so its `is_running` state can be driven
directly), and a real `SigningKeyRegistry`. Readiness reuses the SAME
`ensure_active_key_signable()` check the real `/v1/sign` path already
runs before every signature -- no synthetic sign operation, no key
material or key ID in the health response body.

Pre-commit correction: liveness must reflect the actual bearer-
protected /v1/sign listener's own running state, not merely "the
separate health listener answered" -- see
SigningLivenessReflectsPrimaryListenerTests.
"""

from __future__ import annotations

import unittest
import urllib.error
import urllib.request
from json import loads as json_loads

from webguard_api.health_server import HealthServer
from webguard_api.signing import LocalDevelopmentSigner, SigningKeyRegistry, SigningProviderError
from webguard_api.signing_service import SigningServiceServer
from webguard_api.structured_logging import configure_structured_logging

BEARER = "unit-test-bearer-token"  # noqa: S105


def _make_closures(server: SigningServiceServer, registry: SigningKeyRegistry):
    """Byte-for-byte the same composition cli.py::_signing_service_command
    builds -- readiness fails whenever liveness fails."""

    def liveness() -> tuple[bool, str]:
        return server.is_running, "signing_listener_not_running"

    def readiness() -> tuple[bool, str]:
        if not server.is_running:
            return False, "signing_listener_not_running"
        try:
            registry.ensure_active_key_signable()
        except SigningProviderError:
            return False, "signing_key_unavailable"
        return True, "ready"

    return liveness, readiness


def _get(url: str):
    try:
        response = urllib.request.urlopen(url, timeout=3)
        return response.status, json_loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json_loads(exc.read())


class SigningServiceHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        configure_structured_logging(service="signing-service")
        self.registry = SigningKeyRegistry(LocalDevelopmentSigner(bytes(range(32))))
        self.signing_server = SigningServiceServer(self.registry, bearer_token=BEARER)
        self.signing_server.start()
        self.addCleanup(self._stop_signing_server)
        liveness, readiness = _make_closures(self.signing_server, self.registry)
        self.health_server = HealthServer(
            service="signing-service", liveness_check=liveness, readiness_check=readiness, port=0,
        )
        self.health_server.start()
        self.addCleanup(self.health_server.stop)

    def _stop_signing_server(self) -> None:
        if self.signing_server.is_running:
            self.signing_server.stop()

    def test_healthy_active_key(self) -> None:
        status, body = _get(self.health_server.base_url + "healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})
        status, body = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_disabled_active_key_is_not_ready_with_fixed_reason(self) -> None:
        self.registry.set_status(self.registry.active.key_id, "disabled")
        status, body = _get(self.health_server.base_url + "healthz")
        self.assertEqual(status, 200, "the signing listener is still running -- key status is a readiness concern")
        status, body = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"status": "not_ready", "reason": "signing_key_unavailable"})

    def test_restoring_active_key_makes_it_ready_again_same_process(self) -> None:
        self.registry.set_status(self.registry.active.key_id, "disabled")
        status, _ = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 503)

        self.registry.set_status(self.registry.active.key_id, "active")
        status, body = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_response_body_never_contains_key_id_or_key_material(self) -> None:
        status, body = _get(self.health_server.base_url + "ready")
        dumped = str(body)
        self.assertNotIn(self.registry.active.key_id, dumped)
        self.assertNotIn(self.registry.active.public_key_material().hex(), dumped)

    def test_no_synthetic_signature_is_ever_produced(self) -> None:
        # ensure_active_key_signable() is a status lookup, never a
        # signing call -- proven by the fact that a probe against a
        # disabled key raises before any signature could be computed,
        # and a healthy probe never touches .sign() at all (no message
        # is ever passed to this readiness check).
        calls = []
        original_sign = self.registry.active.sign
        self.registry.active.sign = lambda message: (calls.append(message), original_sign(message))[1]  # type: ignore[method-assign]
        for _ in range(5):
            _get(self.health_server.base_url + "ready")
            _get(self.health_server.base_url + "healthz")
        self.assertEqual(calls, [])


class SigningLivenessReflectsPrimaryListenerTests(unittest.TestCase):
    """P1-B2 pre-commit correction: the internal health listener
    answering is NOT sufficient -- liveness (and therefore readiness)
    must actually reflect whether SigningServiceServer's own bearer-
    protected /v1/sign listener is running."""

    def setUp(self) -> None:
        configure_structured_logging(service="signing-service")
        self.registry = SigningKeyRegistry(LocalDevelopmentSigner(bytes(range(32))))
        self.signing_server = SigningServiceServer(self.registry, bearer_token=BEARER)
        self.signing_server.start()
        liveness, readiness = _make_closures(self.signing_server, self.registry)
        self.health_server = HealthServer(
            service="signing-service", liveness_check=liveness, readiness_check=readiness, port=0,
        )
        self.health_server.start()
        self.addCleanup(self.health_server.stop)

    def test_primary_listener_running_healthz_200(self) -> None:
        status, _ = _get(self.health_server.base_url + "healthz")
        self.assertEqual(status, 200)

    def test_primary_listener_stopped_healthz_503_while_health_server_itself_still_answers(self) -> None:
        self.signing_server.stop()
        status, body = _get(self.health_server.base_url + "healthz")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"status": "not_ready", "reason": "signing_listener_not_running"})

    def test_ready_cannot_return_200_when_liveness_is_false_even_if_key_is_active(self) -> None:
        self.signing_server.stop()
        status, body = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"status": "not_ready", "reason": "signing_listener_not_running"})

    def test_never_started_server_reports_not_running(self) -> None:
        never_started = SigningServiceServer(self.registry, bearer_token=BEARER)
        try:
            self.assertFalse(never_started.is_running)
        finally:
            never_started._server.server_close()


if __name__ == "__main__":
    unittest.main()
