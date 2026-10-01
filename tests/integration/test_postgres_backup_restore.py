"""Backup/restore regression check against a real, disposable
PostgreSQL instance (docs/production/BACKUP_RESTORE.md,
docs/production/DEPLOYMENT_ROLLBACK.md). Both documents record manual
rehearsals of `scripts/backup-postgres.py`/`restore-postgres.py` (2026-
09-16 and 2026-09-23) proving the mechanics work at small scale; this
is that same proof, automated and wired into CI, so a future change to
either script (or to the schema it walks) cannot silently regress
without a human re-running the manual rehearsal to notice. It is not,
and does not claim to be, a real RDS snapshot-restore or an RPO/RTO
measurement -- see BACKUP_RESTORE.md's own P1-8 status for that
remaining, infrastructure-dependent gap.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`), matching every other Postgres
integration test's own gating convention.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _load_script_module(name: str, filename: str):
    # scripts/backup-postgres.py and restore-postgres.py use hyphenated
    # filenames (matching every other script in this directory), which
    # are not valid dotted module names for a plain `import` -- loaded
    # directly from their file path instead.
    spec = importlib.util.spec_from_file_location(name, _REPOSITORY_ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class PostgresBackupRestoreTests(unittest.TestCase):
    """Writes directly via plain SQL against the admin DSN rather than
    through PostgresIdentityRepository: that repository's writes run
    under the api_tenant_data role (P1-2 Phase H), which only exists
    once the tenant-isolation bootstrap SQL (infra/postgres/bootstrap/)
    has been applied -- a separate, heavier precondition this check has
    no need for for the backup/restore scripts to have real rows to walk."""

    def setUp(self) -> None:
        import psycopg

        self.dsn = POSTGRES_TEST_DSN
        self.connection = psycopg.connect(self.dsn, autocommit=True)
        self.addCleanup(self.connection.close)
        self.tables = [
            row[0]
            for row in self.connection.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
                "AND table_name != 'schema_migrations'"
            ).fetchall()
        ]
        # Start from a known-empty state: every base table this backup
        # walks, truncated in one statement (matching restore_database's
        # own identical single-statement CASCADE reasoning -- see that
        # script's own comment on why this must not be a per-table loop).
        self.connection.execute(f"TRUNCATE {', '.join(self.tables)} CASCADE")  # noqa: S608
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def _row_counts(self) -> dict[str, int]:
        return {
            table: self.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
            for table in self.tables
        }

    def _insert_organization(self, name: str) -> tuple[str, str]:
        from uuid import uuid4

        organization_id = str(uuid4())
        self.connection.execute(
            "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
            "VALUES (%s, %s, %s, 'active', %s)",
            (organization_id, name, name.lower(), _utc_now()),
        )
        return organization_id, name

    def test_backup_then_restore_round_trips_real_data_without_loss(self) -> None:
        backup_database = _load_script_module("backup_postgres", "backup-postgres.py").backup_database
        restore_database = _load_script_module("restore_postgres", "restore-postgres.py").restore_database

        organization_id, name = self._insert_organization("Backup Restore Regression Org")
        before_counts = self._row_counts()
        self.assertGreater(
            before_counts["organizations"], 0,
            "setup must have actually written a row to restore later",
        )

        backup_directory = Path(self.temporary.name) / "backup"
        manifest = backup_database(self.dsn, backup_directory)
        self.assertEqual(manifest["tables"]["organizations"], before_counts["organizations"])
        self.assertTrue((backup_directory / "organizations.copy").is_file())

        # Simulate the Case 3 rollback rehearsal shape (DEPLOYMENT_ROLLBACK.md):
        # wipe, then restore with --truncate-first, proving the backup
        # alone (not "the data never left") is what recovers the row.
        self.connection.execute(f"TRUNCATE {', '.join(manifest['tables'].keys())} CASCADE")  # noqa: S608
        wiped_counts = self._row_counts()
        self.assertEqual(wiped_counts["organizations"], 0, "the simulated incident must have actually removed the row")

        restored_counts = restore_database(self.dsn, backup_directory, truncate_first=True)
        self.assertEqual(restored_counts["organizations"], before_counts["organizations"])

        after_counts = self._row_counts()
        self.assertEqual(
            after_counts, before_counts,
            "every table's row count must match the pre-incident state exactly, not just the one table touched directly",
        )

        restored_row = self.connection.execute(
            "SELECT name FROM organizations WHERE organization_id = %s", (organization_id,)
        ).fetchone()
        self.assertIsNotNone(restored_row, "the specific restored row must exist, not just match the total count")
        self.assertEqual(restored_row[0], name)

    def test_restore_refuses_non_empty_tables_without_truncate_first(self) -> None:
        restore_module = _load_script_module("restore_postgres", "restore-postgres.py")
        backup_database = _load_script_module("backup_postgres", "backup-postgres.py").backup_database
        restore_database = restore_module.restore_database
        restore_error_type = restore_module.RestoreError

        self._insert_organization("Refuses Overwrite Org")
        backup_directory = Path(self.temporary.name) / "backup"
        backup_database(self.dsn, backup_directory)

        # The backed-up row is still live in the database (never wiped
        # this time): restoring on top of it without --truncate-first
        # must refuse outright, never silently duplicate or overwrite.
        with self.assertRaises(restore_error_type):
            restore_database(self.dsn, backup_directory, truncate_first=False)


if __name__ == "__main__":
    unittest.main()
