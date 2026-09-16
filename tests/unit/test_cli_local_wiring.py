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

import tempfile
import unittest
from pathlib import Path

from webguard_api import cli
from webguard_api.config import ServiceConfig


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


if __name__ == "__main__":
    unittest.main()
