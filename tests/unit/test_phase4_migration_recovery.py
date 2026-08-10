from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from webguard_api import (
    DATABASE_SCHEMA_VERSION,
    JobStoreError,
    ScanJobStore,
)

from tests.unit.test_database_migrations import create_v4_database


def create_v5_database(path: Path) -> None:
    create_v4_database(path)

    connection = sqlite3.connect(
        path,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row

    try:
        ScanJobStore._migrate_v4_to_v5(connection)
    finally:
        connection.close()


def schema_version(path: Path) -> str | None:
    connection = sqlite3.connect(path)

    try:
        row = connection.execute(
            """
            SELECT value
            FROM service_metadata
            WHERE key = 'schema_version'
            """
        ).fetchone()

        if row is None:
            return None

        return row[0]
    finally:
        connection.close()


def table_exists(path: Path, name: str) -> bool:
    connection = sqlite3.connect(path)

    try:
        row = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = ?
            """,
            (name,),
        ).fetchone()

        return row is not None
    finally:
        connection.close()


class Phase4MigrationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def current_database(self) -> None:
        ScanJobStore(self.path)

        self.assertEqual(
            schema_version(self.path),
            str(DATABASE_SCHEMA_VERSION),
        )

    def test_current_schema_missing_safety_receipt_table_is_rejected_at_startup(
        self,
    ) -> None:
        self.current_database()

        connection = sqlite3.connect(self.path)

        try:
            connection.execute(
                "DROP TABLE job_safety_receipts"
            )
            connection.commit()
        finally:
            connection.close()

        self.assertFalse(
            table_exists(
                self.path,
                "job_safety_receipts",
            )
        )

        with self.assertRaises(JobStoreError):
            ScanJobStore(self.path)

    def test_current_schema_missing_trustscan_table_is_rejected_at_startup(
        self,
    ) -> None:
        self.current_database()

        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys = OFF")

        try:
            connection.execute(
                "DROP TABLE scan_permits"
            )
            connection.commit()
        finally:
            connection.close()

        self.assertFalse(
            table_exists(
                self.path,
                "scan_permits",
            )
        )

        with self.assertRaises(JobStoreError):
            ScanJobStore(self.path)

    def test_failed_startup_does_not_recreate_missing_schema_version(
        self,
    ) -> None:
        self.current_database()

        connection = sqlite3.connect(self.path)

        try:
            connection.execute(
                """
                DELETE FROM service_metadata
                WHERE key = 'schema_version'
                """
            )
            connection.commit()
        finally:
            connection.close()

        self.assertIsNone(
            schema_version(self.path)
        )

        with self.assertRaises(JobStoreError):
            ScanJobStore(self.path)

        self.assertIsNone(
            schema_version(self.path),
            msg=(
                "A failed startup must not rewrite missing "
                "schema metadata in an existing database."
            ),
        )

    def test_v5_to_v6_failure_rolls_back_schema_and_version(
        self,
    ) -> None:
        create_v5_database(self.path)

        self.assertEqual(
            schema_version(self.path),
            "5",
        )
        self.assertFalse(
            table_exists(
                self.path,
                "job_safety_receipts",
            )
        )

        connection = sqlite3.connect(self.path)

        try:
            connection.executescript(
                """
                CREATE TRIGGER force_v6_migration_failure
                BEFORE UPDATE OF value ON service_metadata
                WHEN OLD.key = 'schema_version'
                 AND NEW.value = '6'
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'forced v6 migration failure'
                    );
                END;
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(JobStoreError):
            ScanJobStore(self.path)

        self.assertEqual(
            schema_version(self.path),
            "5",
        )
        self.assertFalse(
            table_exists(
                self.path,
                "job_safety_receipts",
            ),
            msg=(
                "Failed migration must roll back newly "
                "created schema objects."
            ),
        )

    def test_v5_to_v6_can_resume_after_transaction_failure(
        self,
    ) -> None:
        create_v5_database(self.path)

        connection = sqlite3.connect(self.path)

        try:
            connection.executescript(
                """
                CREATE TRIGGER force_v6_migration_failure
                BEFORE UPDATE OF value ON service_metadata
                WHEN OLD.key = 'schema_version'
                 AND NEW.value = '6'
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'forced v6 migration failure'
                    );
                END;
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(JobStoreError):
            ScanJobStore(self.path)

        connection = sqlite3.connect(self.path)

        try:
            connection.execute(
                "DROP TRIGGER force_v6_migration_failure"
            )
            connection.commit()
        finally:
            connection.close()

        reopened = ScanJobStore(self.path)

        self.assertEqual(
            reopened.path,
            self.path,
        )
        self.assertEqual(
            schema_version(self.path),
            str(DATABASE_SCHEMA_VERSION),
        )
        self.assertTrue(
            table_exists(
                self.path,
                "job_safety_receipts",
            )
        )

    def test_invalid_schema_version_is_rejected_without_mutation(
        self,
    ) -> None:
        self.current_database()

        connection = sqlite3.connect(self.path)

        try:
            tables_before = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    """
                )
            }

            connection.execute(
                """
                UPDATE service_metadata
                SET value = 'not-a-version'
                WHERE key = 'schema_version'
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(JobStoreError) as caught:
            ScanJobStore(self.path)

        self.assertEqual(
            caught.exception.code,
            "job_store_schema_unsupported",
        )

        connection = sqlite3.connect(self.path)

        try:
            tables_after = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    """
                )
            }
        finally:
            connection.close()

        self.assertEqual(
            schema_version(self.path),
            "not-a-version",
        )
        self.assertEqual(
            tables_after,
            tables_before,
        )


if __name__ == "__main__":
    unittest.main()
