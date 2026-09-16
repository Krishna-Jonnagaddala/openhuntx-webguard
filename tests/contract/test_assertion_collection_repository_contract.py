"""Contract tests for the technical assertion collection repository
(platform expansion, handoff sections 10.1-10.3, Phase 5 of the
2026-09-14 scope audit). Postgres-only, matching
scoped_control_implementations' own precedent: every write here would
need a real organization/principal foreign-key target to mean
anything, and this is a genuinely new, additive table with no
pre-existing local/test behavior to preserve (see
assertion_collections.py's own module docstring for the in-memory
backend's own, separate unit-level coverage).
"""

from __future__ import annotations

import os
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)

_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
_ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
_TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
_FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
_CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"
_RUNTIME_GRANT_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_runtime_grant.sql"
_ALL_BOOTSTRAP_ROLES = (
    "api_tenant_data",
    "worker_tenant_data",
    "scheduler_tenant_data",
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
)


def _new_id() -> str:
    return str(uuid.uuid4())


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test.",
)
class PostgresAssertionCollectionRepositoryContractTests(unittest.TestCase):
    @classmethod
    def _connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def setUpClass(cls) -> None:
        for sql_path in (
            _ROLES_SQL_PATH,
            _TENANT_ACL_SQL_PATH,
            _FUNCTION_ACL_SQL_PATH,
            _CONTROL_FUNCTIONS_SQL_PATH,
            _RUNTIME_GRANT_SQL_PATH,
        ):
            with cls._connect() as connection:
                connection.execute(sql_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        with cls._connect() as connection:
            connection.autocommit = True
            connection.execute("DROP SCHEMA IF EXISTS webguard_control CASCADE")
            for role in _ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool

        self._pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=4)
        self.addCleanup(self._pool.close)
        self._organization_id = _new_id()
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (self._organization_id, "Contract Test Org", f"org-{self._organization_id}", "active", NOW),
            )
        self.addCleanup(self._delete_organization)
        self._principal_id = self._make_principal(self._organization_id)

    def _make_principal(self, organization_id: str) -> str:
        principal_id = _new_id()
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO principals "
                "(principal_id, organization_id, display_name, principal_type, role, active, created_at) "
                "VALUES (%s, %s, 'Test Reviewer', 'user', 'owner', TRUE, %s)",
                (principal_id, organization_id, NOW),
            )
        return principal_id

    def _delete_organization(self) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "DELETE FROM technical_assertion_collections WHERE organization_id = %s",
                (self._organization_id,),
            )
            connection.execute("DELETE FROM principals WHERE organization_id = %s", (self._organization_id,))
            connection.execute(
                "DELETE FROM organizations WHERE organization_id = %s", (self._organization_id,)
            )

    def make_repository(self):
        from webguard_api.postgres_assertion_collections import PostgresAssertionCollectionRepository

        return PostgresAssertionCollectionRepository(self._pool)

    def _satisfied_record(self, **overrides):
        from webguard_api.assertion_collections import collect_and_evaluate, EvidenceSource

        kwargs = dict(
            organization_id=self._organization_id,
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.FIXTURE,
            collected_by=self._principal_id,
            now=NOW,
            fixture_name="entra_ca_policies_one_enforced",
        )
        kwargs.update(overrides)
        return collect_and_evaluate(**kwargs)

    def test_a_succeeded_collection_round_trips_with_its_evidence_and_outcome(self) -> None:
        from webguard_api.assertion_collections import CollectionStatus
        from webguard_api.technical_assertions import AssertionOutcome

        repo = self.make_repository()
        stored = repo.record(self._satisfied_record())
        self.assertEqual(stored.collection_status, CollectionStatus.SUCCEEDED)
        self.assertEqual(stored.outcome, AssertionOutcome.SATISFIED)
        self.assertEqual(stored.assertion_version, "1.0")
        self.assertEqual(stored.evidence_provenance, "fixture:entra_ca_policies_one_enforced")
        self.assertIsNotNone(stored.raw_evidence)
        self.assertIsNotNone(stored.evaluated_at)

        listed = repo.list_for_assertion(self._organization_id, "entra_conditional_access_policy_mode")
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].collection_id, stored.collection_id)
        self.assertEqual(listed[0].raw_evidence, stored.raw_evidence)

    def test_a_failed_collection_round_trips_with_no_evidence_or_outcome(self) -> None:
        from webguard_api.assertion_collections import CollectionStatus, EvidenceSource

        repo = self.make_repository()
        stored = repo.record(
            self._satisfied_record(evidence_source=EvidenceSource.FIXTURE, fixture_name="does_not_exist")
        )
        self.assertEqual(stored.collection_status, CollectionStatus.FAILED)
        self.assertIsNotNone(stored.collection_error)
        self.assertIsNone(stored.outcome)
        self.assertIsNone(stored.raw_evidence)
        self.assertIsNone(stored.evaluated_at)

        fetched = repo.list_for_assertion(self._organization_id, "entra_conditional_access_policy_mode")[0]
        self.assertEqual(fetched.collection_status, CollectionStatus.FAILED)
        self.assertIsNone(fetched.outcome)

    def test_multiple_attempts_are_all_retained_most_recent_first(self) -> None:
        from datetime import timedelta

        repo = self.make_repository()
        first = repo.record(self._satisfied_record(now=NOW))
        second = repo.record(self._satisfied_record(now=NOW + timedelta(days=1)))

        listed = repo.list_for_assertion(self._organization_id, "entra_conditional_access_policy_mode")
        self.assertEqual(len(listed), 2)
        self.assertEqual(listed[0].collection_id, second.collection_id, "most recent attempt first")
        self.assertEqual(listed[1].collection_id, first.collection_id)

    def test_listing_is_tenant_scoped(self) -> None:
        repo = self.make_repository()
        repo.record(self._satisfied_record())

        other_organization_id = _new_id()
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO organizations (organization_id, name, name_key, status, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (other_organization_id, "Other Org", f"org-{other_organization_id}", "active", NOW),
            )
        try:
            mine = repo.list_for_assertion(self._organization_id, "entra_conditional_access_policy_mode")
            theirs = repo.list_for_assertion(other_organization_id, "entra_conditional_access_policy_mode")
            self.assertEqual(len(mine), 1)
            self.assertEqual(theirs, ())
        finally:
            with self._pool.connection() as connection:
                connection.execute(
                    "DELETE FROM organizations WHERE organization_id = %s", (other_organization_id,)
                )

    def test_indeterminate_outcome_is_persisted_distinctly_from_satisfied_or_failed(self) -> None:
        from webguard_api.assertion_collections import EvidenceSource
        from webguard_api.technical_assertions import AssertionOutcome

        repo = self.make_repository()
        stored = repo.record(
            self._satisfied_record(
                evidence_source=EvidenceSource.FIXTURE,
                fixture_name="entra_ca_policies_missing_state_field",
            )
        )
        self.assertEqual(stored.outcome, AssertionOutcome.INDETERMINATE)
        self.assertIn("ca-005", stored.outcome_detail)


if __name__ == "__main__":
    unittest.main()
