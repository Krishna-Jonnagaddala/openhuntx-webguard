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

    def test_path_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "same"
            with self.assertRaisesRegex(ServiceConfigError, "distinct"):
                ServiceConfig(
                    database_path=path,
                    authorization_directory=path,
                )


if __name__ == "__main__":
    unittest.main()
