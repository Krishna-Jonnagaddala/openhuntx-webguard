"""Phase 5 migration and recovery tests for external service secrets."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from webguard_api import DATABASE_SCHEMA_VERSION, JobStoreError, ScanJobStore

from tests.unit.test_database_migrations import create_v4_database


SECRET_DOCUMENT_TYPE = "webguard_service_secrets"
SECRET_DOCUMENT_VERSION = 1

CURSOR_KEY = "pagination_cursor_hmac"
TRUSTSCAN_KEY = "trustscan_ed25519_private_key_v1"


def create_legacy_v6_database(path: Path) -> dict[str, str]:
    """Create a genuine legacy v6 database containing both service secrets."""

    create_v4_database(path)

    connection = sqlite3.connect(path)
    try:
        ScanJobStore._migrate_v4_to_v5(connection)
        ScanJobStore._migrate_v5_to_v6(connection)

        version = connection.execute(
            "SELECT value FROM service_metadata WHERE key = 'schema_version'"
        ).fetchone()

        rows = connection.execute(
            "SELECT key, value FROM service_secrets"
        ).fetchall()
    finally:
        connection.close()

    if version != ("6",):
        raise AssertionError(f"Expected legacy schema v6, got {version!r}")

    secrets = dict(rows)

    if CURSOR_KEY not in secrets or TRUSTSCAN_KEY not in secrets:
        raise AssertionError("Legacy v6 database does not contain both service secrets.")

    return secrets


def write_external_secret_document(
    path: Path,
    secrets: dict[str, str],
) -> None:
    """Create the expected owner-only external secret document."""

    document = {
        "type": SECRET_DOCUMENT_TYPE,
        "version": SECRET_DOCUMENT_VERSION,
        CURSOR_KEY: secrets[CURSOR_KEY],
        TRUSTSCAN_KEY: secrets[TRUSTSCAN_KEY],
    }

    data = (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")

    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Phase5ServiceSecretMigrationTests(unittest.TestCase):
    """Legacy database secrets must migrate externally without rotation."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "jobs.sqlite3"
        self.secret_path = (
            self.root / "jobs.sqlite3.service-secrets.json"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_legacy_v6_migration_preserves_keys_and_scrubs_database(
        self,
    ) -> None:
        legacy = create_legacy_v6_database(self.database)

        expected_cursor = base64.urlsafe_b64decode(
            legacy[CURSOR_KEY].encode("ascii")
        )
        expected_trustscan = base64.urlsafe_b64decode(
            legacy[TRUSTSCAN_KEY].encode("ascii")
        )

        store = ScanJobStore(self.database)

        self.assertEqual(
            store.cursor_signing_key(),
            expected_cursor,
        )
        self.assertEqual(
            store.trustscan_signing_private_key(),
            expected_trustscan,
        )

        connection = sqlite3.connect(self.database)
        try:
            version = connection.execute(
                """
                SELECT value
                FROM service_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()

            legacy_table = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'service_secrets'
                """
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(version, ("7",))
        self.assertIsNone(legacy_table)
        self.assertTrue(self.secret_path.exists())

        database_bytes = self.database.read_bytes()

        self.assertNotIn(
            legacy[CURSOR_KEY].encode("ascii"),
            database_bytes,
        )
        self.assertNotIn(
            legacy[TRUSTSCAN_KEY].encode("ascii"),
            database_bytes,
        )

    def test_matching_external_file_recovers_interrupted_v6_migration(
        self,
    ) -> None:
        legacy = create_legacy_v6_database(self.database)

        write_external_secret_document(
            self.secret_path,
            legacy,
        )

        store = ScanJobStore(self.database)

        self.assertEqual(
            store.cursor_signing_key(),
            base64.urlsafe_b64decode(
                legacy[CURSOR_KEY].encode("ascii")
            ),
        )
        self.assertEqual(
            store.trustscan_signing_private_key(),
            base64.urlsafe_b64decode(
                legacy[TRUSTSCAN_KEY].encode("ascii")
            ),
        )

        connection = sqlite3.connect(self.database)
        try:
            version = connection.execute(
                """
                SELECT value
                FROM service_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(version, ("7",))

    def test_mismatching_external_file_fails_closed_without_db_mutation(
        self,
    ) -> None:
        legacy = create_legacy_v6_database(self.database)

        mismatched = dict(legacy)
        mismatched[CURSOR_KEY] = base64.urlsafe_b64encode(
            b"x" * 32
        ).decode("ascii")

        write_external_secret_document(
            self.secret_path,
            mismatched,
        )

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_mismatch",
        )

        connection = sqlite3.connect(self.database)
        try:
            version = connection.execute(
                """
                SELECT value
                FROM service_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()

            persisted = dict(
                connection.execute(
                    "SELECT key, value FROM service_secrets"
                ).fetchall()
            )
        finally:
            connection.close()

        self.assertEqual(version, ("6",))
        self.assertEqual(persisted, legacy)

    def test_current_database_missing_external_secret_file_fails_closed(
        self,
    ) -> None:
        store = ScanJobStore(self.database)

        original_cursor = store.cursor_signing_key()
        original_trustscan = store.trustscan_signing_private_key()

        self.assertTrue(self.secret_path.exists())
        self.secret_path.unlink()

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_file_missing",
        )

        self.assertIsInstance(original_cursor, bytes)
        self.assertIsInstance(original_trustscan, bytes)

    def test_corrupt_external_secret_document_fails_closed(
        self,
    ) -> None:
        ScanJobStore(self.database)

        self.assertTrue(self.secret_path.exists())

        self.secret_path.write_text(
            "{not-valid-json}\n",
            encoding="utf-8",
        )
        os.chmod(self.secret_path, 0o600)

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_document_invalid",
        )

    def test_fresh_database_uses_v7_without_service_secrets_table(
        self,
    ) -> None:
        ScanJobStore(self.database)

        connection = sqlite3.connect(self.database)
        try:
            version = connection.execute(
                """
                SELECT value
                FROM service_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()

            legacy_table = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'service_secrets'
                """
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(
            DATABASE_SCHEMA_VERSION,
            7,
        )
        self.assertEqual(version, ("7",))
        self.assertIsNone(legacy_table)


if __name__ == "__main__":
    unittest.main()
