"""Unit tests for AuthenticationContextRepository (Slice 7): metadata and
secret storage are physically separate, status transitions (expiry,
revocation) are correct, and organization/target/authorization binding
is enforced fail-closed.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from webguard_api import (
    AuthenticationContextError,
    AuthenticationContextRepository,
    AuthenticationContextStatus,
    AuthenticationMethod,
)
from webguard_scanner import AuthenticationMaterial


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class AuthenticationContextRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = AuthenticationContextRepository()

    def _create(self, **overrides):
        defaults = dict(
            organization_id="org-1",
            target="https://app.example.com/",
            authorization_id="auth-1",
            identity_label="user-a",
            method=AuthenticationMethod.BEARER_TOKEN,
            secret=AuthenticationMaterial(bearer_token="secret-token-value"),
            expires_at=NOW + timedelta(hours=1),
            now=NOW,
        )
        defaults.update(overrides)
        return self.repo.create(**defaults)

    def test_metadata_never_contains_secret_material(self) -> None:
        record = self._create()
        public = record.to_public_dict(now=NOW)
        self.assertNotIn("secret-token-value", str(public))
        self.assertNotIn("bearer_token", public)
        self.assertNotIn("secret", public)

    def test_metadata_and_secret_are_looked_up_separately(self) -> None:
        record = self._create()
        metadata = self.repo.get_metadata(record.authentication_context_id)
        secret = self.repo.get_secret(record.authentication_context_id)
        self.assertEqual(metadata.identity_label, "user-a")
        self.assertEqual(secret.bearer_token, "secret-token-value")
        # Metadata object has no field that could hold the secret.
        self.assertFalse(hasattr(metadata, "bearer_token"))
        self.assertFalse(hasattr(metadata, "secret"))

    def test_unknown_context_id_fails_closed(self) -> None:
        with self.assertRaises(AuthenticationContextError) as caught:
            self.repo.get_metadata("nonexistent")
        self.assertEqual(caught.exception.code, "authentication_context_not_found")

    def test_status_active_before_expiry(self) -> None:
        record = self._create(expires_at=NOW + timedelta(hours=1))
        self.assertEqual(record.status_at(NOW), AuthenticationContextStatus.ACTIVE)

    def test_status_expired_after_expiry(self) -> None:
        record = self._create(expires_at=NOW + timedelta(seconds=1))
        later = NOW + timedelta(seconds=2)
        self.assertEqual(record.status_at(later), AuthenticationContextStatus.EXPIRED)

    def test_revoke_transitions_status(self) -> None:
        record = self._create()
        revoked = self.repo.revoke(record.authentication_context_id, now=NOW)
        self.assertEqual(
            revoked.status_at(NOW), AuthenticationContextStatus.REVOKED
        )

    def test_revoke_is_idempotent(self) -> None:
        record = self._create()
        first = self.repo.revoke(record.authentication_context_id, now=NOW)
        second = self.repo.revoke(
            record.authentication_context_id, now=NOW + timedelta(minutes=5)
        )
        self.assertEqual(first.revoked_at, second.revoked_at)

    def test_require_bound_succeeds_for_matching_binding(self) -> None:
        record = self._create()
        result = self.repo.require_bound(
            record.authentication_context_id,
            organization_id="org-1",
            target="https://app.example.com/",
            authorization_id="auth-1",
            now=NOW,
        )
        self.assertEqual(result.authentication_context_id, record.authentication_context_id)

    def test_require_bound_rejects_wrong_organization(self) -> None:
        record = self._create()
        with self.assertRaises(AuthenticationContextError) as caught:
            self.repo.require_bound(
                record.authentication_context_id,
                organization_id="org-2",
                target="https://app.example.com/",
                authorization_id="auth-1",
                now=NOW,
            )
        self.assertEqual(
            caught.exception.code, "authentication_context_organization_mismatch"
        )

    def test_require_bound_rejects_wrong_target(self) -> None:
        record = self._create()
        with self.assertRaises(AuthenticationContextError) as caught:
            self.repo.require_bound(
                record.authentication_context_id,
                organization_id="org-1",
                target="https://other.example.com/",
                authorization_id="auth-1",
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "authentication_context_target_mismatch")

    def test_require_bound_rejects_wrong_authorization(self) -> None:
        record = self._create()
        with self.assertRaises(AuthenticationContextError) as caught:
            self.repo.require_bound(
                record.authentication_context_id,
                organization_id="org-1",
                target="https://app.example.com/",
                authorization_id="auth-2",
                now=NOW,
            )
        self.assertEqual(
            caught.exception.code, "authentication_context_authorization_mismatch"
        )

    def test_require_bound_rejects_expired_context(self) -> None:
        record = self._create(expires_at=NOW + timedelta(seconds=1))
        with self.assertRaises(AuthenticationContextError) as caught:
            self.repo.require_bound(
                record.authentication_context_id,
                organization_id="org-1",
                target="https://app.example.com/",
                authorization_id="auth-1",
                now=NOW + timedelta(seconds=2),
            )
        self.assertEqual(caught.exception.code, "authentication_context_expired")

    def test_require_bound_rejects_revoked_context(self) -> None:
        record = self._create()
        self.repo.revoke(record.authentication_context_id, now=NOW)
        with self.assertRaises(AuthenticationContextError) as caught:
            self.repo.require_bound(
                record.authentication_context_id,
                organization_id="org-1",
                target="https://app.example.com/",
                authorization_id="auth-1",
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "authentication_context_revoked")

    def test_expiry_must_be_in_the_future_at_creation(self) -> None:
        with self.assertRaises(AuthenticationContextError) as caught:
            self._create(expires_at=NOW - timedelta(seconds=1))
        self.assertEqual(caught.exception.code, "authentication_context_expiry_invalid")


if __name__ == "__main__":
    unittest.main()
