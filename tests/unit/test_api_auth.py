from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webguard_api import (
    ApiPermission,
    ApiTokenAuthenticator,
    AuthenticationError,
    FixedWindowRateLimiter,
    IdentityStore,
    RateLimitError,
    ScanJobStore,
)
from webguard_contracts import OrganizationRole, PrincipalType
from tests.unit.service_test_support import NOW, ORG_ID, OWNER_ID


class ApiAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        database = Path(self.temp.name) / "jobs.sqlite3"
        ScanJobStore(database)
        identity = IdentityStore(database)
        identity.create_organization("InternStack", now=NOW, organization_id=ORG_ID)
        principal = identity.create_principal(
            ORG_ID, "Krishna", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW, principal_id=OWNER_ID
        )
        self.issued = identity.create_token(principal.principal_id, label="owner", now=NOW)
        self.authenticator = ApiTokenAuthenticator(identity)

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_bearer_token_returns_context(self):
        context = self.authenticator.authenticate(
            [f"Bearer {self.issued.token}"], now=NOW
        )
        self.assertEqual(context.organization_id, ORG_ID)
        self.assertEqual(context.role, OrganizationRole.OWNER)

    def test_scheme_is_case_insensitive(self):
        context = self.authenticator.authenticate(
            [f"bearer {self.issued.token}"], now=NOW
        )
        self.assertEqual(context.principal_id, OWNER_ID)

    def test_missing_header_is_rejected(self):
        with self.assertRaises(AuthenticationError) as caught:
            self.authenticator.authenticate([], now=NOW)
        self.assertEqual(caught.exception.status, 401)

    def test_duplicate_headers_are_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.authenticator.authenticate(
                [f"Bearer {self.issued.token}", f"Bearer {self.issued.token}"], now=NOW
            )

    def test_basic_scheme_is_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.authenticator.authenticate(["Basic abc"], now=NOW)

    def test_owner_has_all_permissions(self):
        context = self.authenticator.authenticate([f"Bearer {self.issued.token}"], now=NOW)
        for permission in ApiPermission:
            self.assertTrue(context.permits(permission))

    def test_viewer_permissions_are_read_only(self):
        from webguard_api import AuthContext
        context = AuthContext(ORG_ID, "InternStack", OWNER_ID, "Viewer", OrganizationRole.VIEWER, self.issued.metadata.token_id)
        self.assertTrue(context.permits(ApiPermission.JOB_READ))
        self.assertFalse(context.permits(ApiPermission.JOB_SUBMIT))
        with self.assertRaises(AuthenticationError) as caught:
            context.require(ApiPermission.JOB_CANCEL)
        self.assertEqual(caught.exception.status, 403)


class RateLimiterTests(unittest.TestCase):
    def test_allows_until_limit(self):
        limiter = FixedWindowRateLimiter(requests=2, window_seconds=60)
        first = limiter.check("token", now_epoch=1)
        second = limiter.check("token", now_epoch=2)
        self.assertEqual(first.remaining, 1)
        self.assertEqual(second.remaining, 0)

    def test_rejects_above_limit(self):
        limiter = FixedWindowRateLimiter(requests=1, window_seconds=60)
        limiter.check("token", now_epoch=1)
        with self.assertRaises(RateLimitError) as caught:
            limiter.check("token", now_epoch=2)
        self.assertEqual(caught.exception.status, 429)

    def test_new_window_resets(self):
        limiter = FixedWindowRateLimiter(requests=1, window_seconds=10)
        limiter.check("token", now_epoch=1)
        decision = limiter.check("token", now_epoch=11)
        self.assertEqual(decision.remaining, 0)

    def test_tokens_have_independent_windows(self):
        limiter = FixedWindowRateLimiter(requests=1, window_seconds=60)
        limiter.check("a", now_epoch=1)
        limiter.check("b", now_epoch=1)

    def test_release_refunds_only_one_reservation(self):
        limiter = FixedWindowRateLimiter(
            requests=2,
            window_seconds=60,
        )

        limiter.check(
            "token",
            now_epoch=1,
        )
        limiter.check(
            "token",
            now_epoch=2,
        )

        limiter.release(
            "token",
            now_epoch=2,
        )

        decision = limiter.check(
            "token",
            now_epoch=3,
        )

        self.assertEqual(
            decision.remaining,
            0,
        )

        with self.assertRaises(RateLimitError):
            limiter.check(
                "token",
                now_epoch=4,
            )

    def test_invalid_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            FixedWindowRateLimiter(requests=0, window_seconds=60)
        with self.assertRaises(ValueError):
            FixedWindowRateLimiter(requests=1, window_seconds=0)


if __name__ == "__main__":
    unittest.main()
