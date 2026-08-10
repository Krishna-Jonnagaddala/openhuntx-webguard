"""Adversarial filesystem and parser tests for service-secret storage."""

from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from webguard_api.service_secrets import (
    CURSOR_SECRET_NAME,
    SERVICE_SECRET_DOCUMENT_TYPE,
    SERVICE_SECRET_DOCUMENT_VERSION,
    TRUSTSCAN_SECRET_NAME,
    ServiceSecretError,
    ServiceSecretFile,
)
from webguard_api.store import JobStoreError, ScanJobStore


def canonical_document(
    *,
    cursor: str | None = None,
    trustscan: str | None = None,
) -> bytes:
    document = {
        "type": SERVICE_SECRET_DOCUMENT_TYPE,
        "version": SERVICE_SECRET_DOCUMENT_VERSION,
        CURSOR_SECRET_NAME: (
            base64.urlsafe_b64encode(b"c" * 32).decode("ascii")
            if cursor is None
            else cursor
        ),
        TRUSTSCAN_SECRET_NAME: (
            base64.urlsafe_b64encode(b"t" * 32).decode("ascii")
            if trustscan is None
            else trustscan
        ),
    }

    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


class Phase5ServiceSecretHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "jobs.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _created_store(self) -> ScanJobStore:
        return ScanJobStore(self.database)

    @staticmethod
    def _replace_secret(
        path: Path,
        data: bytes,
    ) -> None:
        path.unlink()
        path.write_bytes(data)
        os.chmod(path, 0o600)

    def test_oversized_secret_document_is_rejected(
        self,
    ) -> None:
        store = self._created_store()

        self._replace_secret(
            store.service_secret_path,
            b"x" * 4097,
        )

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_document_invalid",
        )

    def test_invalid_base64_secret_is_rejected(
        self,
    ) -> None:
        store = self._created_store()

        self._replace_secret(
            store.service_secret_path,
            canonical_document(cursor="!!!!"),
        )

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_document_invalid",
        )

    def test_wrong_length_secret_is_rejected(
        self,
    ) -> None:
        store = self._created_store()

        short_key = base64.urlsafe_b64encode(
            b"x" * 31
        ).decode("ascii")

        self._replace_secret(
            store.service_secret_path,
            canonical_document(cursor=short_key),
        )

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_document_invalid",
        )

    def test_noncanonical_json_is_rejected(
        self,
    ) -> None:
        store = self._created_store()

        canonical = json.loads(
            canonical_document().decode("ascii")
        )

        noncanonical = (
            json.dumps(
                canonical,
                indent=2,
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")

        self._replace_secret(
            store.service_secret_path,
            noncanonical,
        )

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_document_invalid",
        )

    def test_directory_at_secret_path_is_rejected(
        self,
    ) -> None:
        store = self._created_store()

        store.service_secret_path.unlink()
        store.service_secret_path.mkdir()

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_not_regular_file",
        )

    def test_fifo_at_secret_path_is_rejected_without_opening_it(
        self,
    ) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable on this platform.")

        store = self._created_store()

        store.service_secret_path.unlink()
        os.mkfifo(store.service_secret_path, 0o600)

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(self.database)

        self.assertEqual(
            captured.exception.code,
            "service_secret_not_regular_file",
        )

    def test_secret_directory_owned_by_unrelated_uid_is_rejected(
        self,
    ) -> None:
        if os.name != "posix":
            self.skipTest(
                "POSIX ownership validation only applies on POSIX."
            )

        secret_path = (
            self.database.parent
            / "phase5-untrusted-owner.service-secrets.json"
        )
        secret_file = ServiceSecretFile(secret_path)

        real_lstat = Path.lstat
        unrelated_uid = os.geteuid() + 10000

        def unrelated_owner_lstat(path: Path):
            metadata = real_lstat(path)

            if path == secret_path.parent:
                values = {
                    name: getattr(metadata, name)
                    for name in dir(metadata)
                    if name.startswith("st_")
                }
                values["st_uid"] = unrelated_uid
                values["st_mode"] = (
                    metadata.st_mode & ~0o022
                )
                return SimpleNamespace(**values)

            return metadata

        with mock.patch.object(
            Path,
            "lstat",
            autospec=True,
            side_effect=unrelated_owner_lstat,
        ):
            with self.assertRaises(
                ServiceSecretError
            ) as captured:
                secret_file._validate_parent_directory()

        self.assertEqual(
            captured.exception.code,
            "service_secret_directory_owner_untrusted",
        )


    def test_group_or_world_writable_secret_directory_is_rejected_on_create(
        self,
    ) -> None:
        secret_directory = self.root / "shared-secrets"
        secret_directory.mkdir()
        os.chmod(secret_directory, 0o777)

        secret_path = secret_directory / "service.json"

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(
                self.database,
                service_secret_path=secret_path,
            )

        self.assertEqual(
            captured.exception.code,
            "service_secret_directory_permissions_insecure",
        )

    def test_group_or_world_writable_secret_directory_is_rejected_on_reopen(
        self,
    ) -> None:
        secret_directory = self.root / "private-secrets"
        secret_directory.mkdir(mode=0o700)

        secret_path = secret_directory / "service.json"

        ScanJobStore(
            self.database,
            service_secret_path=secret_path,
        )

        os.chmod(secret_directory, 0o777)

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(
                self.database,
                service_secret_path=secret_path,
            )

        self.assertEqual(
            captured.exception.code,
            "service_secret_directory_permissions_insecure",
        )

    def test_symlink_secret_directory_is_rejected(
        self,
    ) -> None:
        real_directory = self.root / "real-secrets"
        real_directory.mkdir(mode=0o700)

        linked_directory = self.root / "linked-secrets"
        linked_directory.symlink_to(
            real_directory,
            target_is_directory=True,
        )

        with self.assertRaises(JobStoreError) as captured:
            ScanJobStore(
                self.database,
                service_secret_path=(
                    linked_directory / "service.json"
                ),
            )

        self.assertEqual(
            captured.exception.code,
            "service_secret_directory_symlink_not_allowed",
        )

    def test_nonwritable_traversable_secret_directory_is_allowed(
        self,
    ) -> None:
        secret_directory = self.root / "traversable-secrets"
        secret_directory.mkdir()
        os.chmod(secret_directory, 0o755)

        secret_path = secret_directory / "service.json"

        store = ScanJobStore(
            self.database,
            service_secret_path=secret_path,
        )

        self.assertEqual(
            store.service_secret_path,
            secret_path,
        )
        self.assertTrue(secret_path.is_file())


    def test_symlinked_ancestor_inside_private_boundary_is_allowed(
        self,
    ) -> None:
        real_root = self.root / "real-root"
        real_root.mkdir(mode=0o700)

        private_directory = real_root / "private"
        private_directory.mkdir(mode=0o700)

        linked_root = self.root / "linked-root"
        linked_root.symlink_to(
            real_root,
            target_is_directory=True,
        )

        secret_path = linked_root / "private" / "service.json"

        store = ScanJobStore(
            self.database,
            service_secret_path=secret_path,
        )

        self.assertEqual(store.service_secret_path, secret_path)
        self.assertTrue(secret_path.is_file())

    def test_writable_inner_ancestor_behind_private_boundary_is_allowed(
        self,
    ) -> None:
        # TemporaryDirectory is owner-only here, so unrelated local
        # accounts cannot traverse into the writable inner directory.
        self.assertEqual(
            stat.S_IMODE(self.root.stat().st_mode) & 0o077,
            0,
        )

        shared_root = self.root / "shared-root"
        shared_root.mkdir(mode=0o700)
        os.chmod(shared_root, 0o777)

        private_directory = shared_root / "private"
        private_directory.mkdir(mode=0o700)

        secret_path = private_directory / "service.json"

        store = ScanJobStore(
            self.database,
            service_secret_path=secret_path,
        )

        self.assertEqual(store.service_secret_path, secret_path)
        self.assertTrue(secret_path.is_file())

    def test_secret_file_replacement_between_lstat_and_open_is_rejected(
        self,
    ) -> None:
        store = self._created_store()
        secret_path = store.service_secret_path

        replacement_cursor = base64.urlsafe_b64encode(
            b"r" * 32
        ).decode("ascii")
        replacement_trustscan = base64.urlsafe_b64encode(
            b"s" * 32
        ).decode("ascii")

        replacement_document = canonical_document(
            cursor=replacement_cursor,
            trustscan=replacement_trustscan,
        )

        replacement_path = (
            secret_path.parent
            / "phase5-service-secret-replacement.json"
        )
        replacement_path.write_bytes(
            replacement_document
        )
        replacement_path.chmod(0o600)

        real_open = os.open
        replaced = False

        def racing_open(
            target,
            flags,
            *args,
            **kwargs,
        ):
            nonlocal replaced

            if (
                not replaced
                and Path(target) == secret_path
            ):
                os.replace(
                    replacement_path,
                    secret_path,
                )
                replaced = True

            return real_open(
                target,
                flags,
                *args,
                **kwargs,
            )

        with mock.patch(
            "webguard_api.service_secrets.os.open",
            side_effect=racing_open,
        ):
            with self.assertRaises(JobStoreError) as captured:
                ScanJobStore(self.database)

        self.assertTrue(replaced)
        self.assertEqual(
            captured.exception.code,
            "service_secret_file_changed_during_read",
        )


if __name__ == "__main__":
    unittest.main()
