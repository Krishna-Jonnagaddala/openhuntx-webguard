"""`webguard-api serve` runs its worker in the same process as the API
(see cli.py's `_components`), so a completed job's scan record,
findings, and coverage rows must all be readable back through the same
service instance the HTTP API uses. `ScanJobExecutor` and
`WebGuardJobService` each default their `scan_repository`/
`finding_repository`/`coverage_repository` to a private in-memory
store when not given one explicitly: `_components` used to construct
both without passing any of the three, so the executor wrote records
nobody could ever read back through GET /v1/scans, GET /v1/findings,
or GET /v1/assets/{id}/coverage. This mirrors a bug already fixed once
for `artifact_store` (see the comment above that line in
`_components`); this test pins the same fix for all three repositories
so none of them can silently regress."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from webguard_api import cli
from webguard_api.config import ServiceConfig
from webguard_api.production_config import ProductionConfigError
from webguard_contracts import PlatformModule


class LocalComponentsWiringTests(unittest.TestCase):
    def test_serve_wiring_shares_scan_finding_and_coverage_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = ServiceConfig(
                database_path=root / "jobs.sqlite3",
                authorization_directory=root / "authorizations",
                artifact_directory=root / "artifacts",
            )
            _, _, service, worker, _, _, _ = cli._components(config)

            self.assertIs(
                worker.executor.scan_repository,
                service.scan_repository,
                "the embedded worker's executor and the API service must "
                "share one scan_repository, or a completed scan is "
                "invisible on GET /v1/scans",
            )
            self.assertIs(
                worker.executor.finding_repository,
                service.finding_repository,
                "the embedded worker's executor and the API service must "
                "share one finding_repository, or a scan's findings are "
                "invisible on GET /v1/findings",
            )
            self.assertIs(
                worker.executor.coverage_repository,
                service.coverage_repository,
                "the embedded worker's executor and the API service must "
                "share one coverage_repository, or a completed scan's "
                "coverage is invisible on GET /v1/assets/{id}/coverage",
            )


class LocalEnabledModulesWiringTests(unittest.TestCase):
    """WEBGUARD_ENABLED_MODULES lets an operator (or a manual release-
    configuration verification pass) exercise the same restriction
    production uses, without needing full production configuration.
    Unset must leave local/lab behavior exactly as it always was."""

    def _service(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = ServiceConfig(
                database_path=root / "jobs.sqlite3",
                authorization_directory=root / "authorizations",
                artifact_directory=root / "artifacts",
            )
            _, _, service, _, _, _, _ = cli._components(config)
            return service

    def test_unset_offers_every_module(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WEBGUARD_ENABLED_MODULES", None)
            service = self._service()
        self.assertIsNone(service.enabled_modules)

    def test_set_to_webguard_only_restricts_the_service(self) -> None:
        with patch.dict(os.environ, {"WEBGUARD_ENABLED_MODULES": "webguard"}):
            service = self._service()
        self.assertEqual(service.enabled_modules, frozenset({PlatformModule.WEBGUARD}))

    def test_set_to_all_three_offers_every_module_explicitly(self) -> None:
        with patch.dict(os.environ, {"WEBGUARD_ENABLED_MODULES": "webguard,soc,compliance"}):
            service = self._service()
        self.assertEqual(
            service.enabled_modules,
            frozenset({PlatformModule.WEBGUARD, PlatformModule.SOC, PlatformModule.COMPLIANCE}),
        )

    def test_invalid_value_fails_closed_not_silently_ignored(self) -> None:
        with patch.dict(os.environ, {"WEBGUARD_ENABLED_MODULES": "soc,compliance"}):
            with self.assertRaises(ProductionConfigError) as caught:
                self._service()
        self.assertEqual(caught.exception.code, "production_config_invalid")


if __name__ == "__main__":
    unittest.main()
