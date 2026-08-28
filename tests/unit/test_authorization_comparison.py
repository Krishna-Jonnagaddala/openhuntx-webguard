"""Unit tests for AuthorizationComparisonPlanRepository (Slice 8): the
two-identity requirement enforced in code (not merely documented),
resource-scope bounds, status transitions, and organization/target/
authorization binding.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from webguard_api import (
    AuthorizationComparisonError,
    AuthorizationComparisonPlanRepository,
    AuthorizationComparisonPlanStatus,
    ResourcePairSpec,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _resource_pair(**overrides) -> ResourcePairSpec:
    defaults = dict(
        resource_type="order",
        method="GET",
        primary_endpoint="https://app.example.com/api/orders/A-001",
        secondary_endpoint="https://app.example.com/api/orders/B-001",
        identifier_location="path",
        identifier_name="id",
        expected_access="private_to_owner",
    )
    defaults.update(overrides)
    return ResourcePairSpec(**defaults)


class AuthorizationComparisonPlanRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = AuthorizationComparisonPlanRepository()

    def _create(self, **overrides):
        defaults = dict(
            organization_id="org-1",
            target="https://app.example.com/",
            authorization_id="auth-1",
            primary_context_id="context-a",
            secondary_context_id="context-b",
            permitted_active_check="active.authorization.idor",
            allowed_http_methods=("GET",),
            resource_scope=(_resource_pair(),),
            expires_at=NOW + timedelta(hours=1),
            now=NOW,
        )
        defaults.update(overrides)
        return self.repo.create(**defaults)

    def test_two_distinct_identities_required(self) -> None:
        """The two-identity requirement is enforced in code: identical
        primary/secondary context IDs are rejected at creation time."""

        with self.assertRaises(AuthorizationComparisonError) as caught:
            self._create(primary_context_id="same", secondary_context_id="same")
        self.assertEqual(
            caught.exception.code, "authorization_comparison_identities_not_distinct"
        )

    def test_empty_resource_scope_is_rejected(self) -> None:
        with self.assertRaises(AuthorizationComparisonError) as caught:
            self._create(resource_scope=())
        self.assertEqual(
            caught.exception.code, "authorization_comparison_resource_scope_empty"
        )

    def test_too_many_resource_pairs_is_rejected(self) -> None:
        pairs = tuple(
            _resource_pair(
                primary_endpoint=f"https://app.example.com/api/orders/A-{i}",
                secondary_endpoint=f"https://app.example.com/api/orders/B-{i}",
            )
            for i in range(11)
        )
        with self.assertRaises(AuthorizationComparisonError) as caught:
            self._create(resource_scope=pairs)
        self.assertEqual(
            caught.exception.code, "authorization_comparison_too_many_resources"
        )

    def test_expiry_must_be_in_the_future(self) -> None:
        with self.assertRaises(AuthorizationComparisonError) as caught:
            self._create(expires_at=NOW - timedelta(seconds=1))
        self.assertEqual(
            caught.exception.code, "authorization_comparison_expiry_invalid"
        )

    def test_plan_contains_no_secret_material(self) -> None:
        record = self._create()
        public = record.to_public_dict(now=NOW)
        self.assertNotIn("cookie", str(public).lower())
        self.assertNotIn("password", str(public).lower())
        self.assertNotIn("bearer", str(public).lower())
        # Only structural references appear.
        self.assertEqual(public["primary_context_id"], "context-a")
        self.assertEqual(public["secondary_context_id"], "context-b")

    def test_status_transitions(self) -> None:
        record = self._create(expires_at=NOW + timedelta(seconds=1))
        self.assertEqual(record.status_at(NOW), AuthorizationComparisonPlanStatus.ACTIVE)
        self.assertEqual(
            record.status_at(NOW + timedelta(seconds=2)),
            AuthorizationComparisonPlanStatus.EXPIRED,
        )
        revoked = self.repo.revoke(record.comparison_plan_id, now=NOW)
        self.assertEqual(
            revoked.status_at(NOW), AuthorizationComparisonPlanStatus.REVOKED
        )

    def test_require_bound_rejects_wrong_organization(self) -> None:
        record = self._create()
        with self.assertRaises(AuthorizationComparisonError) as caught:
            self.repo.require_bound(
                record.comparison_plan_id,
                organization_id="org-2",
                target="https://app.example.com/",
                authorization_id="auth-1",
                now=NOW,
            )
        self.assertEqual(
            caught.exception.code, "authorization_comparison_organization_mismatch"
        )

    def test_require_bound_rejects_wrong_target(self) -> None:
        record = self._create()
        with self.assertRaises(AuthorizationComparisonError) as caught:
            self.repo.require_bound(
                record.comparison_plan_id,
                organization_id="org-1",
                target="https://other.example.com/",
                authorization_id="auth-1",
                now=NOW,
            )
        self.assertEqual(
            caught.exception.code, "authorization_comparison_target_mismatch"
        )

    def test_require_bound_rejects_revoked_plan(self) -> None:
        record = self._create()
        self.repo.revoke(record.comparison_plan_id, now=NOW)
        with self.assertRaises(AuthorizationComparisonError) as caught:
            self.repo.require_bound(
                record.comparison_plan_id,
                organization_id="org-1",
                target="https://app.example.com/",
                authorization_id="auth-1",
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "authorization_comparison_plan_revoked")

    def test_unknown_plan_fails_closed(self) -> None:
        with self.assertRaises(AuthorizationComparisonError) as caught:
            self.repo.get("nonexistent")
        self.assertEqual(
            caught.exception.code, "authorization_comparison_plan_not_found"
        )


if __name__ == "__main__":
    unittest.main()
