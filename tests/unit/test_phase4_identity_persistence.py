from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from webguard_api import IdentityStore, ScanJobStore
from webguard_api.identity import IdentityStoreError
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
)

from tests.unit.service_test_support import (
    NOW,
    ORG_ID,
    OWNER_ID,
)


class Phase4IdentityPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"

        ScanJobStore(self.path)
        self.identity = IdentityStore(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def execute(
        self,
        sql: str,
        parameters: tuple[object, ...] = (),
    ) -> None:
        connection = sqlite3.connect(self.path)

        try:
            connection.execute(sql, parameters)
            connection.commit()
        finally:
            connection.close()

    def identity_schema_version(self) -> str | None:
        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT value
                FROM identity_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()
        finally:
            connection.close()

        return None if row is None else row[0]

    def table_exists(self, table_name: str) -> bool:
        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = ?
                """,
                (table_name,),
            ).fetchone()
        finally:
            connection.close()

        return row is not None

    def create_principal(self) -> None:
        self.identity.create_organization(
            "Phase 4 Identity Tenant",
            now=NOW,
            organization_id=ORG_ID,
        )

        self.identity.create_principal(
            ORG_ID,
            "Phase 4 Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )

    def test_initialized_identity_store_missing_api_tokens_is_rejected(
        self,
    ) -> None:
        self.execute(
            "DROP TABLE api_tokens"
        )

        self.assertFalse(
            self.table_exists("api_tokens")
        )

        with self.assertRaises(IdentityStoreError):
            IdentityStore(self.path)

        self.assertFalse(
            self.table_exists("api_tokens"),
            msg=(
                "Startup must not silently recreate a missing "
                "security-critical identity table."
            ),
        )

    def test_initialized_identity_store_missing_authorization_table_is_rejected(
        self,
    ) -> None:
        self.execute(
            "DROP TABLE organization_authorizations"
        )

        self.assertFalse(
            self.table_exists(
                "organization_authorizations"
            )
        )

        with self.assertRaises(IdentityStoreError):
            IdentityStore(self.path)

        self.assertFalse(
            self.table_exists(
                "organization_authorizations"
            ),
            msg=(
                "Startup must not silently recreate missing "
                "authorization state."
            ),
        )

    def test_missing_identity_schema_version_is_rejected_without_mutation(
        self,
    ) -> None:
        self.execute(
            """
            DELETE FROM identity_metadata
            WHERE key = 'schema_version'
            """
        )

        self.assertIsNone(
            self.identity_schema_version()
        )

        with self.assertRaises(IdentityStoreError):
            IdentityStore(self.path)

        self.assertIsNone(
            self.identity_schema_version(),
            msg=(
                "Failed identity startup must not rewrite "
                "missing schema metadata."
            ),
        )

    def test_invalid_identity_schema_version_is_controlled(
        self,
    ) -> None:
        self.execute(
            """
            UPDATE identity_metadata
            SET value = ?
            WHERE key = 'schema_version'
            """,
            ("not-a-version",),
        )

        with self.assertRaises(IdentityStoreError):
            IdentityStore(self.path)

        self.assertEqual(
            self.identity_schema_version(),
            "not-a-version",
        )

    def test_malformed_principal_role_is_controlled_on_read(
        self,
    ) -> None:
        self.create_principal()

        self.execute(
            """
            UPDATE principals
            SET role = ?
            WHERE principal_id = ?
            """,
            (
                "not-a-role",
                OWNER_ID,
            ),
        )

        with self.assertRaises(IdentityStoreError):
            self.identity.get_principal(
                OWNER_ID
            )

    def test_malformed_principal_timestamp_is_controlled_on_read(
        self,
    ) -> None:
        self.create_principal()

        self.execute(
            """
            UPDATE principals
            SET created_at = ?
            WHERE principal_id = ?
            """,
            (
                "not-a-timestamp",
                OWNER_ID,
            ),
        )

        with self.assertRaises(IdentityStoreError):
            self.identity.get_principal(
                OWNER_ID
            )


if __name__ == "__main__":
    unittest.main()
