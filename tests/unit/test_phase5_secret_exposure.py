from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.unit.service_test_support import NOW
from webguard_api import IdentityStore, ScanJobStore
from webguard_api.auth import (
    ApiTokenAuthenticator,
    AuthenticationError,
)
from webguard_api.identity import IdentityStoreError
from webguard_contracts import OrganizationRole, PrincipalType


class Phase5SecretExposureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "jobs.sqlite3"

        ScanJobStore(self.database)
        self.identity = IdentityStore(self.database)

        self.organization = self.identity.create_organization(
            "Phase5 Secret Exposure",
            now=NOW,
        )

        self.principal = self.identity.create_principal(
            self.organization.organization_id,
            "Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_issued_api_token_repr_does_not_expose_raw_secret(self) -> None:
        issued = self.identity.create_token(
            self.principal.principal_id,
            label="phase5-secret-repr",
            now=NOW,
        )

        representation = repr(issued)

        self.assertNotIn(
            issued.token,
            representation,
            "IssuedApiToken repr must never expose the raw bearer token.",
        )


    def test_database_does_not_contain_raw_api_token(
        self,
    ) -> None:
        issued = self.identity.create_token(
            self.principal.principal_id,
            label="phase5-database-secret",
            now=NOW,
        )

        database_bytes = self.database.read_bytes()

        self.assertNotIn(
            issued.token.encode("utf-8"),
            database_bytes,
        )

    def test_authentication_errors_do_not_expose_secret(
        self,
    ) -> None:
        issued = self.identity.create_token(
            self.principal.principal_id,
            label="phase5-auth-error",
            now=NOW,
        )

        prefix = issued.token.rsplit("_", 1)[0]
        secret = "Phase5InvalidSecret0123456789"
        invalid_token = f"{prefix}_{secret}"

        with self.assertRaises(
            IdentityStoreError
        ) as identity_error:
            self.identity.authenticate_token(
                invalid_token,
                now=NOW,
            )

        for exposed in (
            str(identity_error.exception),
            repr(identity_error.exception),
            identity_error.exception.message,
        ):
            self.assertNotIn(
                invalid_token,
                exposed,
            )
            self.assertNotIn(
                secret,
                exposed,
            )

        authenticator = ApiTokenAuthenticator(
            self.identity
        )

        with self.assertRaises(
            AuthenticationError
        ) as authentication_error:
            authenticator.authenticate(
                [f"Bearer {invalid_token}"],
                now=NOW,
            )

        for exposed in (
            str(authentication_error.exception),
            repr(authentication_error.exception),
            authentication_error.exception.message,
        ):
            self.assertNotIn(
                invalid_token,
                exposed,
            )
            self.assertNotIn(
                secret,
                exposed,
            )


if __name__ == "__main__":
    unittest.main()
