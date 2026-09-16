"""`webguard-api serve` runs its worker in the same process as the API
(see cli.py's `_components`), so a completed job's coverage rows must
be readable back through the same service instance the HTTP API uses.
`ScanJobExecutor` and `WebGuardJobService` each default their
`coverage_repository` to a private in-memory store when not given one
explicitly: `_components` used to construct both without passing one,
so the executor wrote coverage records nobody could ever read back
through GET /v1/assets/{id}/coverage. This mirrors a bug already fixed
once for `scan_repository`/`finding_repository` (see the comment above
that line in `_components`); this test pins the same fix for
coverage_repository so it cannot silently regress."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webguard_api import cli
from webguard_api.config import ServiceConfig


class LocalComponentsWiringTests(unittest.TestCase):
    def test_serve_wiring_shares_coverage_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = ServiceConfig(
                database_path=root / "jobs.sqlite3",
                authorization_directory=root / "authorizations",
                artifact_directory=root / "artifacts",
            )
            _, _, service, worker, _, _, _ = cli._components(config)

            self.assertIs(
                worker.executor.coverage_repository,
                service.coverage_repository,
                "the embedded worker's executor and the API service must "
                "share one coverage_repository, or a completed scan's "
                "coverage is invisible on GET /v1/assets/{id}/coverage",
            )


if __name__ == "__main__":
    unittest.main()
