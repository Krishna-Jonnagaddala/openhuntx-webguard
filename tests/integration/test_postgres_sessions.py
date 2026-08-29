"""PostgreSQL-backed browser session and auth-rate-limiter tests
(Slice 16). Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and
a reachable `WEBGUARD_POSTGRES_TEST_DSN`), matching every other
Postgres-only integration test in this repository.
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone

from webguard_contracts import OrganizationRole, PrincipalType

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class PostgresSessionRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_sessions import PostgresSessionRepository

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, minimum_connections=2, maximum_connections=5)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")

        self.identity = PostgresIdentityRepository(self.pool)
        self.sessions = PostgresSessionRepository(self.pool)

        now = datetime.now(timezone.utc)
        organization = self.identity.create_organization("Postgres Session Test Org", now=now)
        owner = self.identity.create_principal(
            organization.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=now,
        )
        self.organization_id = organization.organization_id
        self.principal_id = owner.principal_id

    def test_create_authenticate_and_touch_updates_idle_expiry(self) -> None:
        now = datetime.now(timezone.utc)
        issued = self.sessions.create_session(
            self.principal_id, self.organization_id, now=now, idle_ttl=timedelta(minutes=30),
        )
        record = self.sessions.authenticate_session(issued.session_token, now=now + timedelta(minutes=5))
        self.assertEqual(record.principal_id, self.principal_id)
        self.assertGreater(record.idle_expires_at, issued.record.idle_expires_at)

    def test_csrf_header_must_match_the_stored_hash(self) -> None:
        from webguard_api.identity import IdentityStoreError

        now = datetime.now(timezone.utc)
        issued = self.sessions.create_session(self.principal_id, self.organization_id, now=now)
        with self.assertRaises(IdentityStoreError) as ctx:
            self.sessions.authenticate_session(
                issued.session_token, now=now, require_csrf=True, csrf_header="wrong-token"
            )
        self.assertEqual(ctx.exception.code, "csrf_token_invalid")
        record = self.sessions.authenticate_session(
            issued.session_token, now=now, require_csrf=True, csrf_header=issued.csrf_token
        )
        self.assertEqual(record.principal_id, self.principal_id)

    def test_absolute_expiry_is_enforced_even_with_recent_activity(self) -> None:
        from webguard_api.identity import IdentityStoreError

        now = datetime.now(timezone.utc)
        issued = self.sessions.create_session(
            self.principal_id, self.organization_id, now=now,
            idle_ttl=timedelta(hours=1), absolute_ttl=timedelta(seconds=1),
        )
        with self.assertRaises(IdentityStoreError) as ctx:
            self.sessions.authenticate_session(issued.session_token, now=now + timedelta(seconds=2))
        self.assertEqual(ctx.exception.code, "session_expired")

    def test_revoke_all_sessions_for_principal_excludes_the_given_session(self) -> None:
        from webguard_api.identity import IdentityStoreError

        now = datetime.now(timezone.utc)
        keep = self.sessions.create_session(self.principal_id, self.organization_id, now=now)
        drop = self.sessions.create_session(self.principal_id, self.organization_id, now=now)
        revoked = self.sessions.revoke_all_sessions_for_principal(
            self.principal_id, now=now, except_session_id=keep.record.session_id
        )
        self.assertEqual(revoked, 1)
        self.sessions.authenticate_session(keep.session_token, now=now)
        with self.assertRaises(IdentityStoreError):
            self.sessions.authenticate_session(drop.session_token, now=now)

    def test_get_session_returns_none_for_unknown_id(self) -> None:
        self.assertIsNone(self.sessions.get_session("00000000-0000-0000-0000-000000000000"))

    def test_list_sessions_for_principal_only_returns_that_principals_sessions(self) -> None:
        now = datetime.now(timezone.utc)
        other_owner = self.identity.create_principal(
            self.organization_id, "Other", principal_type=PrincipalType.USER,
            role=OrganizationRole.VIEWER, now=now,
        )
        self.sessions.create_session(self.principal_id, self.organization_id, now=now)
        self.sessions.create_session(self.principal_id, self.organization_id, now=now)
        self.sessions.create_session(other_owner.principal_id, self.organization_id, now=now)
        mine = self.sessions.list_sessions_for_principal(self.principal_id)
        self.assertEqual(len(mine), 2)
        self.assertTrue(all(s.principal_id == self.principal_id for s in mine))


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class PostgresAuthRateLimiterTests(unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, minimum_connections=2, maximum_connections=5)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE auth_rate_limit_events")

    def test_bounded_attempts_then_rate_limited_then_resets_after_window(self) -> None:
        from webguard_api.auth_rate_limit import PostgresAuthRateLimiter
        from webguard_api.rate_limit import RateLimitError

        limiter = PostgresAuthRateLimiter(self.pool, max_attempts=3, window_seconds=60)
        now = datetime.now(timezone.utc)
        bucket = "login:127.0.0.1:pg-rate-limit-test@example.com"
        for _ in range(3):
            limiter.check_and_record(bucket, now=now)
        with self.assertRaises(RateLimitError):
            limiter.check_and_record(bucket, now=now)
        limiter.check_and_record(bucket, now=now + timedelta(seconds=61))

    def test_separate_buckets_do_not_interfere(self) -> None:
        from webguard_api.auth_rate_limit import PostgresAuthRateLimiter
        from webguard_api.rate_limit import RateLimitError

        limiter = PostgresAuthRateLimiter(self.pool, max_attempts=1, window_seconds=60)
        now = datetime.now(timezone.utc)
        limiter.check_and_record("login:1.2.3.4:a@example.com", now=now)
        limiter.check_and_record("login:5.6.7.8:b@example.com", now=now)
        with self.assertRaises(RateLimitError):
            limiter.check_and_record("login:1.2.3.4:a@example.com", now=now)


if __name__ == "__main__":
    unittest.main()
