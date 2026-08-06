from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from webguard_api import AuthorizationRepository, AuthorizationRepositoryError
from webguard_contracts import write_owned_target_authorization_file

from tests.unit.service_test_support import AUTH_ID, authorization, write_authorization


class AuthorizationRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.directory = self.root / "authorizations"
        write_authorization(self.directory)
        self.repository = AuthorizationRepository(self.directory)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_loads_authorization_by_id(self) -> None:
        result = self.repository.get(AUTH_ID)
        self.assertEqual(result.organization, "InternStack")

    def test_unknown_id_is_controlled(self) -> None:
        with self.assertRaisesRegex(AuthorizationRepositoryError, "No server-side"):
            self.repository.get("b6a39765-16c6-42b4-91f0-998bf07f1912")

    def test_duplicate_id_is_rejected(self) -> None:
        second = self.directory / "second.json"
        write_owned_target_authorization_file(authorization(), second)
        os.chmod(second, 0o600)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "Multiple"):
            self.repository.get(AUTH_ID)

    def test_insecure_permissions_are_rejected(self) -> None:
        path = self.directory / "internstack.in.json"
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "owner-only"):
            self.repository.get(AUTH_ID)

    def test_symlink_file_is_rejected(self) -> None:
        target = self.directory / "internstack.in.json"
        link = self.directory / "linked.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "symbolic link"):
            self.repository.get(AUTH_ID)

    def test_symlink_directory_is_rejected(self) -> None:
        link = self.root / "linked-authorizations"
        link.symlink_to(self.directory, target_is_directory=True)
        repository = AuthorizationRepository(link)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "symbolic link"):
            repository.get(AUTH_ID)

    def test_missing_directory_is_controlled(self) -> None:
        repository = AuthorizationRepository(self.root / "missing")
        with self.assertRaisesRegex(AuthorizationRepositoryError, "Unable to inspect"):
            repository.get(AUTH_ID)

    def test_invalid_document_is_rejected(self) -> None:
        path = self.directory / "invalid.json"
        path.write_text("{}", encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "invalid"):
            self.repository.get(AUTH_ID)

    def test_non_json_file_is_ignored(self) -> None:
        (self.directory / "README.txt").write_text("not an authorization", encoding="utf-8")
        self.assertEqual(self.repository.get(AUTH_ID).authorization_id, AUTH_ID)


if __name__ == "__main__":
    unittest.main()
