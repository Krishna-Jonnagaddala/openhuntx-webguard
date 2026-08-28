"""Slice 13 requirement 1: `webguard-api serve`/`worker`/`scheduler`
must select PostgreSQL-backed production components explicitly via
`--environment production`, never via a heuristic, and every other
environment value must run the pre-existing local SQLite/in-memory
path completely unchanged. `build_production_components` itself (real
PostgreSQL, real signing abstraction) is proven by
`tests/integration/test_production_mode_e2e.py`; this suite proves the
thin `cli.py` glue that decides *which* component builder to call --
without a real database, real AWS credentials, or a blocking server
loop -- by substituting fakes at the exact seams `cli.py` calls
through (`_production_components`, `_components`, `create_server`)."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from webguard_api import cli


class _FakeRecoverySummary:
    total = 0
    requeued = 0
    cancelled = 0
    failed = 0


class _FakeWorker:
    def __init__(self) -> None:
        self.worker_id = "fake-worker"
        self.lease_seconds = 30.0
        self.heartbeat_seconds = 10.0
        self.maximum_attempts = 3
        self.last_recovery_summary = _FakeRecoverySummary()
        self.run_once_called = False
        self.run_forever_called_with: object = None

    def run_once(self) -> bool:
        self.run_once_called = True
        return False

    def run_forever(self, stop_event: object) -> None:
        self.run_forever_called_with = stop_event


class _FakeScheduler:
    def __init__(self) -> None:
        self.poll_seconds = 5.0
        self.run_forever_called = False

    def run_forever(self, stop_event: object) -> None:
        self.run_forever_called = True


class _FakePool:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeProductionComponents:
    def __init__(self) -> None:
        self.worker = _FakeWorker()
        self.pool = _FakePool()
        self.service = object()
        self.authenticator = object()
        self.rate_limiter = object()


class _FakeServer:
    def __init__(self) -> None:
        self.server_address = ("127.0.0.1", 8765)
        self.served = False
        self.closed = False

    def serve_forever(self, poll_interval: float = 0.25) -> None:
        self.served = True

    def server_close(self) -> None:
        self.closed = True


def _args(command: str, *, environment: str, once: bool = False) -> SimpleNamespace:
    namespace = SimpleNamespace(environment=environment)
    if command in ("worker", "scheduler"):
        namespace.once = once
    return namespace


class ProductionEnvironmentSelectionTests(unittest.TestCase):
    def test_worker_command_production_environment_uses_production_components(self) -> None:
        fake_config = SimpleNamespace(host="127.0.0.1", port=8765)
        fake_components = _FakeProductionComponents()

        with patch.object(
            cli, "_production_components", return_value=(fake_config, fake_components)
        ) as production_call, patch.object(cli, "_components") as local_call:
            exit_code = cli._worker_command(_args("worker", environment="production", once=True))

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        production_call.assert_called_once()
        local_call.assert_not_called()
        self.assertTrue(fake_components.worker.run_once_called)
        self.assertTrue(fake_components.pool.closed, "the PostgreSQL pool must be closed on exit")

    def test_worker_command_default_environment_uses_local_components(self) -> None:
        fake_worker = _FakeWorker()

        with patch.object(cli, "_config") as config_call, patch.object(
            cli, "_components", return_value=(None, None, None, fake_worker, None, None, None)
        ) as local_call, patch.object(cli, "_production_components") as production_call:
            exit_code = cli._worker_command(_args("worker", environment="development", once=True))

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        config_call.assert_called_once()
        local_call.assert_called_once()
        production_call.assert_not_called()
        self.assertTrue(fake_worker.run_once_called)

    def test_scheduler_command_production_environment_fails_closed(self) -> None:
        with patch.object(cli, "_production_components") as production_call, patch.object(
            cli, "_components"
        ) as local_call:
            exit_code = cli._scheduler_command(_args("scheduler", environment="production", once=True))

        self.assertEqual(exit_code, cli.EXIT_USAGE)
        production_call.assert_not_called()
        local_call.assert_not_called()

    def test_serve_command_production_environment_skips_scheduler_and_closes_pool(self) -> None:
        fake_config = SimpleNamespace(host="127.0.0.1", port=8765)
        fake_components = _FakeProductionComponents()
        fake_server = _FakeServer()

        with patch.object(
            cli, "_production_components", return_value=(fake_config, fake_components)
        ) as production_call, patch.object(cli, "_components") as local_call, patch.object(
            cli, "create_server", return_value=fake_server
        ), patch.object(cli.signal, "signal"):
            exit_code = cli._serve_command(_args("serve", environment="production"))

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        production_call.assert_called_once()
        local_call.assert_not_called()
        self.assertTrue(fake_server.served)
        self.assertIsNotNone(fake_components.worker.run_forever_called_with)
        self.assertTrue(fake_components.pool.closed)

    def test_serve_command_default_environment_starts_scheduler(self) -> None:
        fake_worker = _FakeWorker()
        fake_scheduler = _FakeScheduler()
        fake_server = _FakeServer()
        fake_local_config = SimpleNamespace(
            host="127.0.0.1", port=0, maximum_request_bytes=8192
        )

        with patch.object(cli, "_config", return_value=fake_local_config), patch.object(
            cli,
            "_components",
            return_value=(None, None, object(), fake_worker, fake_scheduler, object(), object()),
        ) as local_call, patch.object(cli, "_production_components") as production_call, patch.object(
            cli, "create_server", return_value=fake_server
        ), patch.object(cli.signal, "signal"):
            exit_code = cli._serve_command(_args("serve", environment="development"))

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        local_call.assert_called_once()
        production_call.assert_not_called()
        self.assertTrue(fake_server.served)


if __name__ == "__main__":
    unittest.main()
