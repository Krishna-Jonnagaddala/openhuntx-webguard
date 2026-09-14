from __future__ import annotations

import unittest
from datetime import datetime, timezone

from webguard_contracts import (
    ApplicabilityStatus,
    ComplianceScopeError,
    ScopedControlImplementation,
)

NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
ORG = "11111111-1111-4111-8111-111111111111"
PRINCIPAL = "22222222-2222-4222-8222-222222222222"


class ScopedControlImplementationContractTests(unittest.TestCase):
    def test_unresolved_carries_no_decision(self) -> None:
        value = ScopedControlImplementation(
            organization_id=ORG,
            framework_id="soc2",
            control_id="soc2-cc1-1",
            applicability_status=ApplicabilityStatus.UNRESOLVED,
            created_at=NOW,
            updated_at=NOW,
        )
        self.assertIsNone(value.rationale)
        self.assertIsNone(value.decided_by)
        self.assertIsNone(value.decided_at)

    def test_unresolved_rejects_a_rationale(self) -> None:
        with self.assertRaises(ComplianceScopeError) as caught:
            ScopedControlImplementation(
                organization_id=ORG,
                framework_id="soc2",
                control_id="soc2-cc1-1",
                applicability_status=ApplicabilityStatus.UNRESOLVED,
                created_at=NOW,
                updated_at=NOW,
                rationale="Not applicable, we think.",
            )
        self.assertEqual(caught.exception.code, "compliance_scope_unresolved_must_be_undecided")

    def test_unresolved_rejects_a_deciding_principal(self) -> None:
        with self.assertRaises(ComplianceScopeError) as caught:
            ScopedControlImplementation(
                organization_id=ORG,
                framework_id="soc2",
                control_id="soc2-cc1-1",
                applicability_status=ApplicabilityStatus.UNRESOLVED,
                created_at=NOW,
                updated_at=NOW,
                decided_by=PRINCIPAL,
                decided_at=NOW,
            )
        self.assertEqual(caught.exception.code, "compliance_scope_unresolved_must_be_undecided")

    def test_applicable_requires_decided_by_and_decided_at(self) -> None:
        with self.assertRaises(ComplianceScopeError) as caught:
            ScopedControlImplementation(
                organization_id=ORG,
                framework_id="soc2",
                control_id="soc2-cc1-1",
                applicability_status=ApplicabilityStatus.APPLICABLE,
                created_at=NOW,
                updated_at=NOW,
            )
        self.assertEqual(caught.exception.code, "compliance_scope_decision_requires_principal_and_time")

    def test_applicable_does_not_require_a_rationale(self) -> None:
        value = ScopedControlImplementation(
            organization_id=ORG,
            framework_id="soc2",
            control_id="soc2-cc1-1",
            applicability_status=ApplicabilityStatus.APPLICABLE,
            created_at=NOW,
            updated_at=NOW,
            decided_by=PRINCIPAL,
            decided_at=NOW,
        )
        self.assertIsNone(value.rationale)
        self.assertEqual(value.decided_by, PRINCIPAL)

    def test_not_applicable_requires_a_rationale(self) -> None:
        with self.assertRaises(ComplianceScopeError) as caught:
            ScopedControlImplementation(
                organization_id=ORG,
                framework_id="soc2",
                control_id="soc2-cc1-1",
                applicability_status=ApplicabilityStatus.NOT_APPLICABLE_WITH_RATIONALE,
                created_at=NOW,
                updated_at=NOW,
                decided_by=PRINCIPAL,
                decided_at=NOW,
            )
        self.assertEqual(caught.exception.code, "compliance_scope_not_applicable_requires_rationale")

    def test_not_applicable_with_rationale_round_trips(self) -> None:
        value = ScopedControlImplementation(
            organization_id=ORG,
            framework_id="soc2",
            control_id="soc2-cc1-1",
            applicability_status=ApplicabilityStatus.NOT_APPLICABLE_WITH_RATIONALE,
            created_at=NOW,
            updated_at=NOW,
            rationale="No cardholder data is processed by this organization.",
            decided_by=PRINCIPAL,
            decided_at=NOW,
        )
        as_dict = value.to_dict()
        self.assertEqual(as_dict["applicability_status"], "not_applicable_with_rationale")
        self.assertEqual(as_dict["rationale"], "No cardholder data is processed by this organization.")

    def test_rejects_non_enum_applicability_status(self) -> None:
        with self.assertRaises(ComplianceScopeError) as caught:
            ScopedControlImplementation(
                organization_id=ORG,
                framework_id="soc2",
                control_id="soc2-cc1-1",
                applicability_status="applicable",
                created_at=NOW,
                updated_at=NOW,
                decided_by=PRINCIPAL,
                decided_at=NOW,
            )
        self.assertEqual(caught.exception.code, "compliance_scope_applicability_status_invalid")

    def test_control_id_and_framework_id_are_canonicalized(self) -> None:
        value = ScopedControlImplementation(
            organization_id=ORG,
            framework_id=" SOC2 ",
            control_id=" SOC2-CC1-1 ",
            applicability_status=ApplicabilityStatus.UNRESOLVED,
            created_at=NOW,
            updated_at=NOW,
        )
        self.assertEqual(value.framework_id, "soc2")
        self.assertEqual(value.control_id, "soc2-cc1-1")


if __name__ == "__main__":
    unittest.main()
