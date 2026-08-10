"""Adversarial filesystem tests for signed crawl checkpoints."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from webguard_contracts import (
    CrawlCheckpointLoadError,
    load_crawl_checkpoint_file,
    load_crawl_checkpoint_key_file,
    write_crawl_checkpoint_file,
)

from tests.unit.test_crawl_checkpoints import (
    KEY,
    OTHER_KEY,
    checkpoint,
)


class Phase5CheckpointFilesystemTests(unittest.TestCase):
    def test_checkpoint_replacement_between_lstat_and_open_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            checkpoint_path = root / "crawl.checkpoint.json"
            replacement_path = root / "replacement.checkpoint.json"

            write_crawl_checkpoint_file(
                checkpoint(),
                checkpoint_path,
                KEY,
                overwrite=False,
            )

            write_crawl_checkpoint_file(
                checkpoint(),
                replacement_path,
                KEY,
                overwrite=False,
            )

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
                    and Path(target) == checkpoint_path
                ):
                    # Keep the replacement alive before the race so
                    # it has a distinct filesystem identity. unlink()
                    # followed by create can immediately reuse an inode
                    # on Linux and makes the race injection nondeterministic.
                    os.replace(
                        replacement_path,
                        checkpoint_path,
                    )
                    replaced = True

                return real_open(
                    target,
                    flags,
                    *args,
                    **kwargs,
                )

            with mock.patch(
                "webguard_contracts.crawl_checkpoints.os.open",
                side_effect=racing_open,
            ):
                with self.assertRaises(
                    CrawlCheckpointLoadError
                ) as captured:
                    load_crawl_checkpoint_file(
                        checkpoint_path,
                        KEY,
                    )

            self.assertTrue(replaced)
            self.assertEqual(
                captured.exception.code,
                "checkpoint_file_changed_during_read",
            )

    def test_checkpoint_key_replacement_between_lstat_and_open_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            key_path = root / "checkpoint.key"
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)

            replacement_path = root / "checkpoint-replacement.key"
            replacement_path.write_bytes(OTHER_KEY)
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
                    and Path(target) == key_path
                ):
                    os.replace(
                        replacement_path,
                        key_path,
                    )
                    replaced = True

                return real_open(
                    target,
                    flags,
                    *args,
                    **kwargs,
                )

            with mock.patch(
                "webguard_contracts.crawl_checkpoints.os.open",
                side_effect=racing_open,
            ):
                with self.assertRaises(
                    CrawlCheckpointLoadError
                ) as captured:
                    load_crawl_checkpoint_key_file(
                        key_path
                    )

            self.assertTrue(replaced)
            self.assertEqual(
                captured.exception.code,
                "checkpoint_key_file_changed_during_read",
            )

    def test_no_overwrite_atomically_rejects_late_destination(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint_path = root / "crawl.checkpoint.json"

            real_link = os.link
            raced = False

            def racing_link(
                source,
                destination,
                *args,
                **kwargs,
            ):
                nonlocal raced

                if (
                    not raced
                    and Path(destination) == checkpoint_path
                ):
                    checkpoint_path.write_text(
                        "late-existing-file",
                        encoding="utf-8",
                    )
                    os.chmod(checkpoint_path, 0o600)
                    raced = True

                return real_link(
                    source,
                    destination,
                    *args,
                    **kwargs,
                )

            with mock.patch(
                "webguard_contracts.crawl_checkpoints.os.link",
                side_effect=racing_link,
            ):
                with self.assertRaises(
                    CrawlCheckpointLoadError
                ) as captured:
                    write_crawl_checkpoint_file(
                        checkpoint(),
                        checkpoint_path,
                        KEY,
                        overwrite=False,
                    )

            self.assertTrue(raced)
            self.assertEqual(
                captured.exception.code,
                "checkpoint_exists",
            )
            self.assertEqual(
                checkpoint_path.read_text(
                    encoding="utf-8"
                ),
                "late-existing-file",
            )

    @unittest.skipUnless(
        os.name == "posix",
        "POSIX permissions required",
    )
    def test_written_checkpoint_is_owner_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crawl.checkpoint.json"

            write_crawl_checkpoint_file(
                checkpoint(),
                path,
                KEY,
                overwrite=False,
            )

            self.assertEqual(
                path.stat().st_mode & 0o777,
                0o600,
            )


    @unittest.skipUnless(
        os.name == "posix",
        "POSIX permissions required",
    )
    def test_writable_checkpoint_key_directory_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            key_directory = root / "keys"
            key_directory.mkdir(mode=0o700)
            os.chmod(key_directory, 0o777)

            key_path = key_directory / "checkpoint.key"
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)

            with self.assertRaises(
                CrawlCheckpointLoadError
            ) as captured:
                load_crawl_checkpoint_key_file(
                    key_path
                )

            self.assertEqual(
                captured.exception.code,
                "checkpoint_key_directory_permissions_insecure",
            )

    @unittest.skipUnless(
        os.name == "posix",
        "POSIX permissions required",
    )
    def test_nonwritable_checkpoint_key_directory_is_allowed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            key_directory = root / "keys"
            key_directory.mkdir(mode=0o755)

            key_path = key_directory / "checkpoint.key"
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)

            self.assertEqual(
                load_crawl_checkpoint_key_file(
                    key_path
                ),
                KEY,
            )

    @unittest.skipUnless(
        os.name == "posix",
        "POSIX permissions required",
    )
    def test_writable_checkpoint_directory_alone_cannot_forge_checkpoint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            checkpoint_directory = root / "checkpoints"
            checkpoint_directory.mkdir(mode=0o700)
            os.chmod(checkpoint_directory, 0o777)

            trusted_path = (
                checkpoint_directory
                / "crawl.checkpoint.json"
            )

            attacker_path = (
                root
                / "attacker.checkpoint.json"
            )

            write_crawl_checkpoint_file(
                checkpoint(),
                trusted_path,
                KEY,
                overwrite=False,
            )

            write_crawl_checkpoint_file(
                checkpoint(),
                attacker_path,
                OTHER_KEY,
                overwrite=False,
            )

            trusted_path.write_bytes(
                attacker_path.read_bytes()
            )

            with self.assertRaises(
                CrawlCheckpointLoadError
            ) as captured:
                load_crawl_checkpoint_file(
                    trusted_path,
                    KEY,
                )

            self.assertEqual(
                captured.exception.code,
                "checkpoint_integrity_failed",
            )


    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "geteuid"),
        "POSIX ownership required",
    )
    def test_checkpoint_key_directory_owned_by_unrelated_uid_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            key_directory = root / "keys"
            key_directory.mkdir(mode=0o755)

            key_path = key_directory / "checkpoint.key"
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)

            euid = os.geteuid()
            unrelated_uid = (
                10001
                if euid not in {0, 10001}
                else 10002
            )

            real_lstat = Path.lstat

            def fake_lstat(candidate, *args, **kwargs):
                metadata = real_lstat(
                    candidate,
                    *args,
                    **kwargs,
                )

                if candidate == key_directory:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_uid=unrelated_uid,
                    )

                return metadata

            with mock.patch.object(
                Path,
                "lstat",
                autospec=True,
                side_effect=fake_lstat,
            ):
                with self.assertRaises(
                    CrawlCheckpointLoadError
                ) as captured:
                    load_crawl_checkpoint_key_file(
                        key_path
                    )

            self.assertEqual(
                captured.exception.code,
                "checkpoint_key_directory_owner_untrusted",
            )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "geteuid"),
        "POSIX ownership required",
    )
    def test_root_owned_nonwritable_checkpoint_key_directory_is_allowed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            key_directory = root / "keys"
            key_directory.mkdir(mode=0o755)

            key_path = key_directory / "checkpoint.key"
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)

            real_lstat = Path.lstat

            def fake_lstat(candidate, *args, **kwargs):
                metadata = real_lstat(
                    candidate,
                    *args,
                    **kwargs,
                )

                if candidate == key_directory:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_uid=0,
                    )

                return metadata

            with mock.patch.object(
                Path,
                "lstat",
                autospec=True,
                side_effect=fake_lstat,
            ):
                self.assertEqual(
                    load_crawl_checkpoint_key_file(
                        key_path
                    ),
                    KEY,
                )


if __name__ == "__main__":
    unittest.main()
