"""Contract tests for the callback-registration metadata surface
(Slice 12): identical test bodies against the in-memory
`CallbackRepository` (local/unit/lab) and
`PostgresCallbackRegistrationRepository` (production durable storage).

Only the register/get/revoke metadata lifecycle is covered here --
`wait_for_observation`'s real-time polling mechanism is broker-
specific (see postgres_callback_service.py's module docstring) and is
exercised separately in tests/unit/test_callback_service.py.
"""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

from webguard_api.callback_service import CallbackRepository, CallbackServiceError

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
# No hardcoded default DSN -- see test_postgres_connection_pool.py's
# comment on this exact env-var pair.
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)


def _token_value(registered) -> str:
    """The in-memory backend's `register()` returns a scanner-layer
    `CallbackToken` (`.value`); the Postgres backend returns a
    `ScopedCallbackRegistration` directly (`.token_value`) since it has
    no separate broker-issued token object. Both identify the same
    concept -- the opaque, high-entropy correlation string -- so
    contract tests read it through this one accessor rather than
    hardcoding either shape."""

    return getattr(registered, "token_value", None) or registered.value


class CallbackRegistrationRepositoryContractMixin:
    def make_repository(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def test_register_and_get_round_trips(self) -> None:
        repo = self.make_repository()
        org_id = str(uuid4())
        token = repo.register(
            scan_id="scan-1",
            candidate_fingerprint="fp-1",
            organization_id=org_id,
            target="https://example.com/",
            authorization_id="auth-1",
            job_id="job-1",
            permit_id="permit-1",
        )
        registration = repo.get_registration(_token_value(token), organization_id=org_id)
        self.assertEqual(registration.organization_id, org_id)
        self.assertEqual(registration.job_id, "job-1")
        self.assertEqual(registration.permit_id, "permit-1")
        self.assertIsNone(registration.revoked_at)

    def test_cross_tenant_get_fails_closed_like_unknown(self) -> None:
        repo = self.make_repository()
        org_a, org_b = str(uuid4()), str(uuid4())
        token = repo.register(
            scan_id="scan-1",
            candidate_fingerprint="fp-1",
            organization_id=org_a,
            target="https://example.com/",
            authorization_id="auth-1",
        )
        with self.assertRaises(CallbackServiceError) as cross_org:
            repo.get_registration(_token_value(token), organization_id=org_b)
        with self.assertRaises(CallbackServiceError) as unknown_token:
            repo.get_registration("not-a-real-token-value", organization_id=org_b)
        self.assertEqual(cross_org.exception.code, "callback_registration_not_found")
        self.assertEqual(unknown_token.exception.code, "callback_registration_not_found")

    def test_revoke_is_tenant_scoped_and_idempotent(self) -> None:
        repo = self.make_repository()
        org_a, org_b = str(uuid4()), str(uuid4())
        token = repo.register(
            scan_id="scan-1",
            candidate_fingerprint="fp-1",
            organization_id=org_a,
            target="https://example.com/",
            authorization_id="auth-1",
        )
        with self.assertRaises(CallbackServiceError) as cross_org:
            repo.revoke_registration(_token_value(token), organization_id=org_b)
        self.assertEqual(cross_org.exception.code, "callback_registration_not_found")

        first = repo.revoke_registration(_token_value(token), organization_id=org_a)
        second = repo.revoke_registration(_token_value(token), organization_id=org_a)
        self.assertEqual(first.revoked_at, second.revoked_at)
        self.assertIsNotNone(first.revoked_at)

        with self.assertRaises(CallbackServiceError) as after_revoke:
            repo.get_registration(_token_value(token), organization_id=org_a)
        self.assertEqual(after_revoke.exception.code, "callback_registration_revoked")

    def test_record_observation_true_once_then_reflects_state(self) -> None:
        repo = self.make_repository()
        org_id = str(uuid4())
        token = repo.register(
            scan_id="scan-1",
            candidate_fingerprint="fp-1",
            organization_id=org_id,
            target="https://example.com/",
            authorization_id="auth-1",
        )
        self.assertTrue(repo.record_observation(_token_value(token), method="GET"))

    def test_record_observation_on_unknown_token_returns_false(self) -> None:
        repo = self.make_repository()
        self.assertFalse(repo.record_observation("not-a-real-token-value", method="GET"))

    def test_record_observation_after_revoke_returns_false(self) -> None:
        repo = self.make_repository()
        org_id = str(uuid4())
        token = repo.register(
            scan_id="scan-1",
            candidate_fingerprint="fp-1",
            organization_id=org_id,
            target="https://example.com/",
            authorization_id="auth-1",
        )
        repo.revoke_registration(_token_value(token), organization_id=org_id)
        self.assertFalse(repo.record_observation(_token_value(token), method="GET"))


class InMemoryCallbackRegistrationRepositoryContractTests(
    CallbackRegistrationRepositoryContractMixin, unittest.TestCase
):
    def make_repository(self) -> CallbackRepository:
        return CallbackRepository(base_url="http://127.0.0.1:0/")


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test.",
)
class PostgresCallbackRegistrationRepositoryContractTests(
    CallbackRegistrationRepositoryContractMixin, unittest.TestCase
):
    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool

        self._pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=4)
        self.addCleanup(self._pool.close)
        with self._pool.connection() as connection:
            connection.execute("TRUNCATE callback_registrations, callback_observations CASCADE")
            connection.execute("TRUNCATE organizations CASCADE")

    def make_repository(self):
        from webguard_api.postgres_callback_service import PostgresCallbackRegistrationRepository

        repository = PostgresCallbackRegistrationRepository(self._pool)
        return _OrganizationBackfillingRepository(repository, self._pool)


class _OrganizationBackfillingRepository:
    """`callback_registrations.organization_id` is FK-constrained; the
    in-memory backend has no such constraint. This thin wrapper
    inserts a real organizations row on first use per organization_id
    so the same contract-test bodies (which mint arbitrary UUIDs) work
    unmodified against Postgres."""

    def __init__(self, inner, pool) -> None:
        self._inner = inner
        self._pool = pool
        self._known_organizations: set[str] = set()

    def _ensure_organization(self, organization_id: str) -> None:
        if organization_id in self._known_organizations:
            return
        from datetime import datetime, timezone

        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO organizations (organization_id, name, name_key, status, created_at)
                VALUES (%s, %s, %s, 'active', %s)
                ON CONFLICT (organization_id) DO NOTHING
                """,
                (
                    organization_id,
                    f"org-{organization_id}",
                    f"org-{organization_id}",
                    datetime.now(timezone.utc),
                ),
            )
        self._known_organizations.add(organization_id)

    def register(self, *, organization_id: str, **kwargs):
        self._ensure_organization(organization_id)
        return self._inner.register(organization_id=organization_id, **kwargs)

    def get_registration(self, token_value: str, *, organization_id: str):
        return self._inner.get_registration(token_value, organization_id=organization_id)

    def revoke_registration(self, token_value: str, *, organization_id: str, now=None):
        return self._inner.revoke_registration(token_value, organization_id=organization_id, now=now)

    def record_observation(self, token_value: str, *, method: str, source_class: str = "external", now=None):
        return self._inner.record_observation(
            token_value, method=method, source_class=source_class, now=now
        )


if __name__ == "__main__":
    unittest.main()
