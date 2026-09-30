"""Unit tests for assertion_collections.py's collection/evaluation
logic (platform expansion, Phase 5 of the 2026-09-14 scope audit).
No database dependency: collect_and_evaluate and its evaluator are
pure functions over evidence already in hand. Postgres persistence has
its own contract coverage in
tests/contract/test_assertion_collection_repository_contract.py.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from webguard_api.assertion_collections import (
    AssertionCollectionError,
    CollectionStatus,
    EvidenceSource,
    collect_and_evaluate,
)
from webguard_api.technical_assertions import AssertionOutcome

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
ORG_ID = "11111111-1111-1111-1111-111111111111"
PRINCIPAL_ID = "22222222-2222-2222-2222-222222222222"


class CollectAndEvaluateTests(unittest.TestCase):
    def test_fixture_with_one_enabled_policy_is_satisfied(self) -> None:
        record = collect_and_evaluate(
            organization_id=ORG_ID,
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.FIXTURE,
            collected_by=PRINCIPAL_ID,
            now=NOW,
            fixture_name="entra_ca_policies_one_enforced",
        )
        self.assertEqual(record.collection_status, CollectionStatus.SUCCEEDED)
        self.assertEqual(record.outcome, AssertionOutcome.SATISFIED)
        self.assertIn("1 of 2", record.outcome_detail)
        self.assertEqual(record.evidence_source, EvidenceSource.FIXTURE)
        self.assertEqual(record.evidence_provenance, "fixture:entra_ca_policies_one_enforced")
        self.assertEqual(record.assertion_version, "1.0")
        self.assertIsNotNone(record.raw_evidence)
        self.assertEqual(record.evaluated_at, NOW)
        self.assertEqual(record.collected_at, NOW)
        self.assertIsNone(record.collection_error)

    def test_fixture_with_no_enabled_policies_is_violated(self) -> None:
        record = collect_and_evaluate(
            organization_id=ORG_ID,
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.FIXTURE,
            collected_by=PRINCIPAL_ID,
            now=NOW,
            fixture_name="entra_ca_policies_none_enforced",
        )
        self.assertEqual(record.collection_status, CollectionStatus.SUCCEEDED)
        self.assertEqual(record.outcome, AssertionOutcome.VIOLATED)
        self.assertIn("0 of 2", record.outcome_detail)

    def test_empty_evidence_list_is_violated_not_indeterminate(self) -> None:
        """Zero policies is a definitive, successfully collected
        answer (no enforcement exists), not missing evidence: a real
        distinction this test pins down explicitly."""

        record = collect_and_evaluate(
            organization_id=ORG_ID,
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.MANUAL,
            collected_by=PRINCIPAL_ID,
            now=NOW,
            manual_evidence=[],
        )
        self.assertEqual(record.collection_status, CollectionStatus.SUCCEEDED)
        self.assertEqual(record.outcome, AssertionOutcome.VIOLATED)
        self.assertIn("0 Conditional Access policies", record.outcome_detail)

    def test_fixture_with_missing_state_field_is_indeterminate(self) -> None:
        record = collect_and_evaluate(
            organization_id=ORG_ID,
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.FIXTURE,
            collected_by=PRINCIPAL_ID,
            now=NOW,
            fixture_name="entra_ca_policies_missing_state_field",
        )
        self.assertEqual(record.collection_status, CollectionStatus.SUCCEEDED)
        self.assertEqual(record.outcome, AssertionOutcome.INDETERMINATE)
        self.assertIn("ca-005", record.outcome_detail)

    def test_unknown_fixture_name_fails_collection_with_no_outcome(self) -> None:
        record = collect_and_evaluate(
            organization_id=ORG_ID,
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.FIXTURE,
            collected_by=PRINCIPAL_ID,
            now=NOW,
            fixture_name="does_not_exist",
        )
        self.assertEqual(record.collection_status, CollectionStatus.FAILED)
        self.assertIsNotNone(record.collection_error)
        self.assertIsNone(record.outcome)
        self.assertIsNone(record.raw_evidence)
        self.assertIsNone(record.evaluated_at)

    def test_manual_evidence_satisfies_when_a_policy_is_enabled(self) -> None:
        record = collect_and_evaluate(
            organization_id=ORG_ID,
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.MANUAL,
            collected_by=PRINCIPAL_ID,
            now=NOW,
            manual_evidence=[{"id": "ca-manual-1", "state": "enabled"}],
        )
        self.assertEqual(record.outcome, AssertionOutcome.SATISFIED)
        self.assertIn("manually supplied", record.evidence_provenance)
        self.assertIn(str(PRINCIPAL_ID), record.evidence_provenance)

    def test_unknown_assertion_id_raises(self) -> None:
        with self.assertRaises(AssertionCollectionError) as ctx:
            collect_and_evaluate(
                organization_id=ORG_ID,
                assertion_id="not_a_real_assertion",
                evidence_source=EvidenceSource.MANUAL,
                collected_by=PRINCIPAL_ID,
                now=NOW,
                manual_evidence=[],
            )
        self.assertEqual(ctx.exception.code, "technical_assertion_unknown")

    def test_assertion_with_no_evaluator_yet_raises_not_a_wrong_result(self) -> None:
        """entra_privileged_role_inventory is a real, registered
        assertion with no evaluation logic in this version: this must
        fail loudly, never silently return a fabricated outcome."""

        with self.assertRaises(AssertionCollectionError) as ctx:
            collect_and_evaluate(
                organization_id=ORG_ID,
                assertion_id="entra_privileged_role_inventory",
                evidence_source=EvidenceSource.MANUAL,
                collected_by=PRINCIPAL_ID,
                now=NOW,
                manual_evidence=[],
            )
        self.assertEqual(ctx.exception.code, "technical_assertion_not_evaluatable")

    def test_fixture_source_requires_fixture_name_not_manual_evidence(self) -> None:
        with self.assertRaises(AssertionCollectionError) as ctx:
            collect_and_evaluate(
                organization_id=ORG_ID,
                assertion_id="entra_conditional_access_policy_mode",
                evidence_source=EvidenceSource.FIXTURE,
                collected_by=PRINCIPAL_ID,
                now=NOW,
                manual_evidence=[{"id": "x", "state": "enabled"}],
            )
        self.assertEqual(ctx.exception.code, "assertion_collection_request_invalid")

    def test_manual_source_requires_manual_evidence_not_fixture_name(self) -> None:
        with self.assertRaises(AssertionCollectionError) as ctx:
            collect_and_evaluate(
                organization_id=ORG_ID,
                assertion_id="entra_conditional_access_policy_mode",
                evidence_source=EvidenceSource.MANUAL,
                collected_by=PRINCIPAL_ID,
                now=NOW,
                fixture_name="entra_ca_policies_one_enforced",
            )
        self.assertEqual(ctx.exception.code, "assertion_collection_request_invalid")


class InMemoryAssertionCollectionRepositoryTests(unittest.TestCase):
    def test_record_and_list_round_trips_and_is_tenant_scoped(self) -> None:
        from webguard_api.assertion_collections import InMemoryAssertionCollectionRepository

        repo = InMemoryAssertionCollectionRepository()
        record_a = collect_and_evaluate(
            organization_id=ORG_ID,
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.FIXTURE,
            collected_by=PRINCIPAL_ID,
            now=NOW,
            fixture_name="entra_ca_policies_one_enforced",
        )
        repo.record(record_a)
        other_org_record = collect_and_evaluate(
            organization_id="33333333-3333-3333-3333-333333333333",
            assertion_id="entra_conditional_access_policy_mode",
            evidence_source=EvidenceSource.FIXTURE,
            collected_by=PRINCIPAL_ID,
            now=NOW,
            fixture_name="entra_ca_policies_one_enforced",
        )
        repo.record(other_org_record)

        listed = repo.list_for_assertion(ORG_ID, "entra_conditional_access_policy_mode")
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].collection_id, record_a.collection_id)


if __name__ == "__main__":
    unittest.main()
