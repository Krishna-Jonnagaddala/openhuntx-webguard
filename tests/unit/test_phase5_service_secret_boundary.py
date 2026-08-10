"""Phase 5 adversarial tests for service-secret storage boundaries."""

from __future__ import annotations

import base64
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from webguard_api.config import ServiceConfig
from webguard_api.store import JobStoreError, ScanJobStore


class Phase5ServiceSecretBoundaryTests(unittest.TestCase):
    """Long-lived signing secrets must not be recoverable from the job database."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "jobs.sqlite3"

        # Desired default external secret location.
        self.secret_path = (
            self.root / "jobs.sqlite3.service-secrets.json"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_default_secret_paths_are_database_specific(
        self,
    ) -> None:
        first_database = self.root / "first.sqlite3"
        second_database = self.root / "second.sqlite3"

        first = ScanJobStore(first_database)
        second = ScanJobStore(second_database)

        self.assertEqual(
            first.service_secret_path,
            self.root / "first.sqlite3.service-secrets.json",
        )
        self.assertEqual(
            second.service_secret_path,
            self.root / "second.sqlite3.service-secrets.json",
        )
        self.assertNotEqual(
            first.service_secret_path,
            second.service_secret_path,
        )
        self.assertTrue(first.service_secret_path.is_file())
        self.assertTrue(second.service_secret_path.is_file())

    def test_service_config_derives_external_secret_file_from_database_directory(
        self,
    ) -> None:
        config = ServiceConfig(database_path=self.database)

        self.assertEqual(
            getattr(config, "service_secret_path", None),
            self.secret_path,
        )

    def test_database_file_does_not_contain_service_signing_secrets(
        self,
    ) -> None:
        store = ScanJobStore(self.database)

        cursor_key = store.cursor_signing_key()
        trustscan_key = store.trustscan_signing_private_key()

        database_bytes = self.database.read_bytes()

        self.assertNotIn(
            base64.urlsafe_b64encode(cursor_key),
            database_bytes,
        )
        self.assertNotIn(
            base64.urlsafe_b64encode(trustscan_key),
            database_bytes,
        )

    def test_external_secret_file_is_private_regular_file(
        self,
    ) -> None:
        ScanJobStore(self.database)

        self.assertTrue(
            self.secret_path.exists(),
            "Service signing secrets must be stored outside the SQLite database.",
        )

        metadata = self.secret_path.lstat()

        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertFalse(stat.S_ISLNK(metadata.st_mode))
        self.assertEqual(
            stat.S_IMODE(metadata.st_mode),
            0o600,
        )

    def test_database_copy_without_external_secret_file_fails_closed(
        self,
    ) -> None:
        store = ScanJobStore(self.database)

        original_cursor_key = store.cursor_signing_key()
        original_trustscan_key = store.trustscan_signing_private_key()

        backup_directory = self.root / "database-copy"
        backup_directory.mkdir()

        copied_database = backup_directory / "jobs.sqlite3"
        shutil.copy2(self.database, copied_database)

        with self.assertRaises(JobStoreError) as captured:
            copied_store = ScanJobStore(copied_database)

            # These lines must never become reachable for a database-only copy.
            self.assertNotEqual(
                copied_store.cursor_signing_key(),
                original_cursor_key,
            )
            self.assertNotEqual(
                copied_store.trustscan_signing_private_key(),
                original_trustscan_key,
            )

        self.assertEqual(
            captured.exception.code,
            "service_secret_file_missing",
        )

    def test_preexisting_service_secret_symlink_is_rejected(
        self,
    ) -> None:
        attacker_file = self.root / "attacker-controlled.json"
        attacker_file.write_text("{}\n", encoding="utf-8")

        self.secret_path.symlink_to(attacker_file)

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_symlink_not_allowed",
        )

    def test_insecure_service_secret_permissions_are_rejected(
        self,
    ) -> None:
        self.secret_path.write_text("{}\n", encoding="utf-8")
        os.chmod(self.secret_path, 0o644)

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_permissions_insecure",
        )


if __name__ == "__main__":
    unittest.main()
