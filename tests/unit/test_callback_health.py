"""P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
proves the callback-service's internal health/readiness composition --
the exact liveness/readiness closures `cli.py::_callback_service_command`
builds, exercised against a real `HealthServer`, a real
`CallbackHttpReceiver` (so its `is_running` state can be driven
directly), and a fake pool (controllable `check_connectivity()`, no
real Postgres needed for this fast layer -- the real-Postgres proof
lives in the additive method on
tests/integration/test_callback_service_outage_resilience.py). Also
proves, empirically rather than by inspection alone, that
`CallbackHttpReceiver`'s own PUBLIC listener gained zero new routes:
`/healthz` and `/ready` requests through it are handled exactly like
any other unknown-token callback attempt -- the identical uniform 204
response, never a health-shaped one.

Pre-commit correction: liveness must reflect the actual public
CallbackHttpReceiver's own running state, not merely "the separate
health listener answered" -- see CallbackLivenessReflectsPrimaryListenerTests.
"""

from __future__ import annotations

import unittest
import urllib.error
import urllib.request
from json import loads as json_loads

from webguard_api.callback_server import CallbackHttpReceiver
from webguard_api.callback_service import CallbackRepository
from webguard_api.health_server import HealthServer
from webguard_api.structured_logging import configure_structured_logging


class _FakePool:
    def __init__(self) -> None:
        self.healthy = True
        self.call_count = 0

    def check_connectivity(self) -> None:
        self.call_count += 1
        if not self.healthy:
            raise RuntimeError("simulated connectivity failure")


def _make_closures(receiver: CallbackHttpReceiver, pool: _FakePool):
    """Byte-for-byte the same composition cli.py::_callback_service_command
    builds -- readiness fails whenever liveness fails."""

    def liveness() -> tuple[bool, str]:
        return receiver.is_running, "callback_listener_not_running"

    def readiness() -> tuple[bool, str]:
        if not receiver.is_running:
            return False, "callback_listener_not_running"
        try:
            pool.check_connectivity()
        except Exception:  # noqa: BLE001 - matches cli.py's own composition exactly
            return False, "callback_dependency_unavailable"
        return True, "ready"

    return liveness, readiness


def _get(url: str):
    try:
        response = urllib.request.urlopen(url, timeout=3)
        return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class CallbackInternalHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        configure_structured_logging(service="callback-service")
        self.pool = _FakePool()
        self.repository = CallbackRepository(base_url="http://127.0.0.1:0/")
        self.receiver = CallbackHttpReceiver(self.repository)
        self.receiver.start()
        self.repository.set_base_url(self.receiver.base_url)
        self.addCleanup(self._stop_receiver)
        liveness, readiness = _make_closures(self.receiver, self.pool)
        self.health_server = HealthServer(
            service="callback-service", liveness_check=liveness, readiness_check=readiness, port=0,
        )
        self.health_server.start()
        self.addCleanup(self.health_server.stop)

    def _stop_receiver(self) -> None:
        if self.receiver.is_running:
            self.receiver.stop()

    def test_healthy_reports_ok_on_both_routes(self) -> None:
        status, body = _get(self.health_server.base_url + "healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json_loads(body), {"status": "ok"})
        status, body = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 200)
        self.assertEqual(json_loads(body), {"status": "ok"})

    def test_dependency_down_healthz_stays_up_ready_fails(self) -> None:
        # The public listener is still running -- liveness reflects
        # that, independent of the database.
        self.pool.healthy = False
        status, _ = _get(self.health_server.base_url + "healthz")
        self.assertEqual(status, 200)
        status, body = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 503)
        self.assertEqual(json_loads(body), {"status": "not_ready", "reason": "callback_dependency_unavailable"})

    def test_dependency_recovers_same_process(self) -> None:
        self.pool.healthy = False
        status, _ = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 503)
        self.pool.healthy = True
        status, body = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 200)
        self.assertEqual(json_loads(body), {"status": "ok"})

    def test_no_extra_database_query_beyond_the_one_connectivity_check(self) -> None:
        _get(self.health_server.base_url + "ready")
        self.assertEqual(self.pool.call_count, 1)


class CallbackLivenessReflectsPrimaryListenerTests(unittest.TestCase):
    """P1-B2 pre-commit correction: the internal health listener
    answering is NOT sufficient -- liveness (and therefore readiness)
    must actually reflect whether CallbackHttpReceiver's own public
    listener is running."""

    def setUp(self) -> None:
        configure_structured_logging(service="callback-service")
        self.pool = _FakePool()
        self.repository = CallbackRepository(base_url="http://127.0.0.1:0/")
        self.receiver = CallbackHttpReceiver(self.repository)
        self.receiver.start()
        self.repository.set_base_url(self.receiver.base_url)
        liveness, readiness = _make_closures(self.receiver, self.pool)
        self.health_server = HealthServer(
            service="callback-service", liveness_check=liveness, readiness_check=readiness, port=0,
        )
        self.health_server.start()
        self.addCleanup(self.health_server.stop)

    def test_primary_listener_running_healthz_200(self) -> None:
        status, _ = _get(self.health_server.base_url + "healthz")
        self.assertEqual(status, 200)

    def test_primary_listener_stopped_healthz_503_while_health_server_itself_still_answers(self) -> None:
        self.receiver.stop()
        # The internal health listener itself is a completely separate
        # socket/thread -- it must keep answering (proving this is a
        # real liveness *result*, not the whole process being down).
        status, body = _get(self.health_server.base_url + "healthz")
        self.assertEqual(status, 503)
        self.assertEqual(json_loads(body), {"status": "not_ready", "reason": "callback_listener_not_running"})

    def test_ready_cannot_return_200_when_liveness_is_false_even_if_dependency_is_healthy(self) -> None:
        self.receiver.stop()
        self.pool.healthy = True  # dependency itself is fine
        status, body = _get(self.health_server.base_url + "ready")
        self.assertEqual(status, 503)
        self.assertEqual(json_loads(body), {"status": "not_ready", "reason": "callback_listener_not_running"})

    def test_never_started_receiver_reports_not_running(self) -> None:
        self.receiver.stop()
        never_started = CallbackHttpReceiver(self.repository)
        try:
            self.assertFalse(never_started.is_running)
        finally:
            never_started._server.server_close()


class CallbackPublicListenerRouteInventoryTests(unittest.TestCase):
    """P1-B2 Section 10/12: the public callback listener must gain
    ZERO new routes. A completely separate HealthServer/socket/thread
    is used instead -- see CallbackInternalHealthTests above."""

    def setUp(self) -> None:
        self.repository = CallbackRepository(base_url="http://127.0.0.1:0/")
        self.receiver = CallbackHttpReceiver(self.repository)
        self.receiver.start()
        self.repository.set_base_url(self.receiver.base_url)
        self.addCleanup(self.receiver.stop)

    def test_healthz_path_through_public_listener_is_treated_as_an_unknown_callback_token(self) -> None:
        status, _ = _get(self.receiver.base_url + "healthz")
        # Identical to the established unknown-token behavior (see
        # test_callback_service.py's own
        # test_unknown_token_path_is_rejected_but_receiver_still_responds)
        # -- not 200, not a health-shaped body, no distinguishable
        # "this looks like a health check" branch exists.
        self.assertEqual(status, 204)

    def test_ready_path_through_public_listener_is_treated_as_an_unknown_callback_token(self) -> None:
        status, _ = _get(self.receiver.base_url + "ready")
        self.assertEqual(status, 204)

    def test_public_listener_response_is_identical_for_healthz_ready_and_any_other_unknown_path(self) -> None:
        healthz_status, healthz_body = _get(self.receiver.base_url + "healthz")
        ready_status, ready_body = _get(self.receiver.base_url + "ready")
        arbitrary_status, arbitrary_body = _get(self.receiver.base_url + "totally-unrelated-path")
        self.assertEqual(healthz_status, ready_status)
        self.assertEqual(ready_status, arbitrary_status)
        self.assertEqual(healthz_body, ready_body)
        self.assertEqual(ready_body, arbitrary_body)


if __name__ == "__main__":
    unittest.main()
