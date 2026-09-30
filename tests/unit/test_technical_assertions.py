"""Tests for the Compliance technical assertion catalog (platform
expansion, docs/PLATFORM_SCOPE.md, handoff section 10.1 and 10.3).
These validate the catalog's own internal consistency against
SOC_CONNECTOR_REGISTRY (every assertion's source connector and
required permissions are real), not any live collection behavior: no
network call is made anywhere in this file, matching soc_connectors.py's
own "contract only" scope.
"""

from __future__ import annotations

import unittest

from webguard_api.soc_connectors import SOC_CONNECTOR_REGISTRY
from webguard_api.technical_assertions import (
    TECHNICAL_ASSERTION_REGISTRY,
    AssertionOutcome,
    TechnicalAssertion,
    TechnicalAssertionError,
)


class TechnicalAssertionCatalogTests(unittest.TestCase):
    def test_registry_keys_match_assertion_ids(self) -> None:
        for assertion_id, assertion in TECHNICAL_ASSERTION_REGISTRY.items():
            self.assertEqual(assertion_id, assertion.assertion_id)

    def test_every_assertion_references_a_registered_connector(self) -> None:
        for assertion in TECHNICAL_ASSERTION_REGISTRY.values():
            self.assertIn(assertion.source_connector_id, SOC_CONNECTOR_REGISTRY)

    def test_every_required_permission_is_declared_on_its_connector(self) -> None:
        for assertion in TECHNICAL_ASSERTION_REGISTRY.values():
            connector = SOC_CONNECTOR_REGISTRY[assertion.source_connector_id]
            manifest_permissions = {permission.name for permission in connector.permissions}
            for permission in assertion.required_permissions:
                self.assertIn(permission, manifest_permissions)

    def test_construction_rejects_unknown_connector(self) -> None:
        with self.assertRaises(TechnicalAssertionError) as caught:
            TechnicalAssertion(
                assertion_id="broken",
                title="Broken",
                objective="test",
                version="1.0",
                source_connector_id="does-not-exist",
                required_permissions=(),
            )
        self.assertEqual(caught.exception.code, "technical_assertion_unknown_connector")

    def test_construction_rejects_undeclared_permission(self) -> None:
        with self.assertRaises(TechnicalAssertionError) as caught:
            TechnicalAssertion(
                assertion_id="broken",
                title="Broken",
                objective="test",
                version="1.0",
                source_connector_id="entra",
                required_permissions=("Not.A.Real.Permission",),
            )
        self.assertEqual(caught.exception.code, "technical_assertion_undeclared_permission")

    def test_assertion_outcome_matches_handoff_vocabulary(self) -> None:
        """handoff section 10.2's own "Assertion" dimension table:
        Satisfied, violated, indeterminate, not tested."""

        self.assertEqual(
            {outcome.value for outcome in AssertionOutcome},
            {"satisfied", "violated", "indeterminate", "not_tested"},
        )

    def test_stale_privileged_account_assertion_requires_both_permissions(self) -> None:
        """A cross-referencing assertion (role inventory joined with
        sign-in activity) genuinely needs both source permissions, not
        just one; catalog entries must not understate their own
        requirement."""

        assertion = TECHNICAL_ASSERTION_REGISTRY["entra_stale_privileged_account"]
        self.assertIn("User.Read.All", assertion.required_permissions)
        self.assertIn("AuditLog.Read.All", assertion.required_permissions)

    def test_sentinel_sourced_assertions_are_cataloged(self) -> None:
        """Log-source health and detection enablement, the two
        Sentinel-specific families handoff section 10.3 names, must
        both be present now that the Sentinel connector manifest
        exists to source them from."""

        self.assertIn("sentinel_data_connector_health", TECHNICAL_ASSERTION_REGISTRY)
        self.assertIn("sentinel_detection_rule_enablement", TECHNICAL_ASSERTION_REGISTRY)
        for assertion_id in ("sentinel_data_connector_health", "sentinel_detection_rule_enablement"):
            self.assertEqual(
                TECHNICAL_ASSERTION_REGISTRY[assertion_id].source_connector_id, "sentinel"
            )


if __name__ == "__main__":
    unittest.main()
