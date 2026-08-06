from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webguard_api import ServiceConfig, ServiceConfigError


class ServiceConfigTests(unittest.TestCase):
    def test_default_binding_is_loopback(self) -> None:
        self.assertEqual(ServiceConfig().host, "127.0.0.1")

    def test_ipv6_loopback_is_allowed(self) -> None:
        self.assertEqual(ServiceConfig(host="::1").host, "::1")

    def test_public_binding_is_rejected(self) -> None:
        with self.assertRaisesRegex(ServiceConfigError, "loopback"):
            ServiceConfig(host="0.0.0.0")

    def test_hostname_binding_is_rejected(self) -> None:
        with self.assertRaisesRegex(ServiceConfigError, "IP literal"):
            ServiceConfig(host="localhost")

    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaisesRegex(ServiceConfigError, "0 to 65535"):
            ServiceConfig(port=70000)

    def test_request_limit_is_bounded(self) -> None:
        with self.assertRaisesRegex(ServiceConfigError, "131072"):
            ServiceConfig(maximum_request_bytes=200000)

    def test_poll_interval_is_bounded(self) -> None:
        with self.assertRaisesRegex(ServiceConfigError, "0.01"):
            ServiceConfig(worker_poll_seconds=0)

    def test_worker_lease_defaults_are_consistent(self) -> None:
        config = ServiceConfig()
        self.assertEqual(config.worker_lease_seconds, 30.0)
        self.assertEqual(config.worker_heartbeat_seconds, 10.0)
        self.assertEqual(config.worker_maximum_attempts, 3)
        self.assertLess(
            config.worker_heartbeat_seconds,
            config.worker_lease_seconds,
        )

    def test_worker_heartbeat_must_be_less_than_lease(self) -> None:
        with self.assertRaises(ServiceConfigError) as context:
            ServiceConfig(
                worker_lease_seconds=10,
                worker_heartbeat_seconds=10,
            )
        self.assertEqual(
            context.exception.code,
            "service_worker_heartbeat_invalid",
        )

    def test_worker_attempts_are_bounded(self) -> None:
        with self.assertRaises(ServiceConfigError) as context:
            ServiceConfig(worker_maximum_attempts=0)
        self.assertEqual(
            context.exception.code,
            "service_worker_attempts_invalid",
        )

    def test_worker_id_is_trimmed_and_validated(self) -> None:
        self.assertEqual(
            ServiceConfig(worker_id="  worker-a  ").worker_id,
            "worker-a",
        )
        with self.assertRaises(ServiceConfigError):
            ServiceConfig(worker_id="worker id with spaces")

    def test_path_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "same"
            with self.assertRaisesRegex(ServiceConfigError, "distinct"):
                ServiceConfig(
                    database_path=path,
                    authorization_directory=path,
                )

    def test_rate_limit_defaults_are_bounded(self) -> None:
        config = ServiceConfig()
        self.assertEqual(config.rate_limit_requests, 120)
        self.assertEqual(config.rate_limit_window_seconds, 60)

    def test_invalid_rate_limit_is_rejected(self) -> None:
        with self.assertRaises(ServiceConfigError):
            ServiceConfig(rate_limit_requests=0)
        with self.assertRaises(ServiceConfigError):
            ServiceConfig(rate_limit_window_seconds=0)


if __name__ == "__main__":
    unittest.main()
