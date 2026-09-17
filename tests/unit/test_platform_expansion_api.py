"""Platform expansion: module entitlements, SOC connector manifests,
and the Compliance framework/assertion/collection read-and-collect
surface (docs/PLATFORM_SCOPE.md). These repositories and their
underlying logic (module_entitlements.py, soc_connectors.py,
technical_assertions.py, assertion_collections.py) already existed
with no HTTP or service-layer caller; this suite proves the new
service methods and the RBAC/entitlement gates around them, not the
underlying collection/evaluation logic itself (covered by
tests/unit/test_assertion_collections.py and
tests/contract/test_compliance_catalog_repository_contract.py)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from webguard_api import AuthorizationRepository, ScanJobStore, WebGuardJobService
from webguard_api.module_entitlements import InMemoryModuleEntitlementRepository
from webguard_contracts import ModuleEntitlementStatus, OrganizationRole, PlatformModule

from tests.unit.service_test_support import (
    ADMINISTRATOR_ID,
    ADMINISTRATOR_TOKEN_ID,
    NOW,
    VIEWER_ID,
    VIEWER_TOKEN_ID,
    create_identity_fixture,
    write_authorization,
)


def _rid() -> str:
    return str(uuid4())


class PlatformExpansionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.owner, _ = create_identity_fixture(store.path)
        _, self.viewer, _ = create_identity_fixture(
            store.path, role=OrganizationRole.VIEWER, principal_id=VIEWER_ID, token_id=VIEWER_TOKEN_ID,
        )
        self.entitlements = InMemoryModuleEntitlementRepository()
        self.service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
            module_entitlements=self.entitlements,
        )

    def test_module_entitlements_empty_for_an_organization_with_no_rows(self) -> None:
        payload = self.service.list_module_entitlements(self.owner, request_id=_rid())
        self.assertEqual(payload, {"entitlements": []})

    def test_module_entitlements_reflects_granted_defaults(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        payload = self.service.list_module_entitlements(self.owner, request_id=_rid())
        by_module = {row["module"]: row["status"] for row in payload["entitlements"]}
        self.assertEqual(
            by_module,
            {"webguard": "enabled", "soc": "disabled", "compliance": "disabled"},
        )

    def test_owner_can_enable_then_disable_soc(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)

        enabled = self.service.set_module_entitlement(
            self.owner, "soc", {"status": "enabled"}, request_id=_rid()
        )
        self.assertEqual(enabled["module"], "soc")
        self.assertEqual(enabled["status"], "enabled")
        self.assertIsNotNone(enabled["enabled_at"])
        listed = self.service.list_module_entitlements(self.owner, request_id=_rid())
        by_module = {row["module"]: row["status"] for row in listed["entitlements"]}
        self.assertEqual(by_module["soc"], "enabled")

        disabled = self.service.set_module_entitlement(
            self.owner, "soc", {"status": "disabled"}, request_id=_rid()
        )
        self.assertEqual(disabled["status"], "disabled")
        # enabled_at records the last time the module *was* enabled, not
        # whether it is currently enabled, so it stays set through a
        # disable (ModuleEntitlement itself has no separate "was ever
        # enabled" flag to clear).
        self.assertIsNotNone(disabled["enabled_at"])
        listed = self.service.list_module_entitlements(self.owner, request_id=_rid())
        by_module = {row["module"]: row["status"] for row in listed["entitlements"]}
        self.assertEqual(by_module["soc"], "disabled")

    def test_owner_can_enable_compliance(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        payload = self.service.set_module_entitlement(
            self.owner, "compliance", {"status": "enabled"}, request_id=_rid()
        )
        self.assertEqual(payload, {
            "module": "compliance",
            "status": "enabled",
            "updated_at": payload["updated_at"],
            "enabled_at": payload["enabled_at"],
        })
        self.assertIsNotNone(payload["enabled_at"])

    def test_webguard_is_rejected_as_not_manageable(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        with self.assertRaises(Exception) as ctx:
            self.service.set_module_entitlement(
                self.owner, "webguard", {"status": "disabled"}, request_id=_rid()
            )
        self.assertEqual(ctx.exception.code, "module_entitlement_not_manageable")
        self.assertEqual(ctx.exception.status, 400)

    def test_unknown_module_name_is_rejected_with_a_distinct_error_from_webguard(self) -> None:
        # "webguard" and an actually-unknown name are different failures
        # with different meanings; they must not share webguard's own
        # error message (a caller asking about "xyz" should never be
        # told "the webguard module is always enabled").
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        with self.assertRaises(Exception) as ctx:
            self.service.set_module_entitlement(
                self.owner, "xyz", {"status": "enabled"}, request_id=_rid()
            )
        self.assertEqual(ctx.exception.code, "module_entitlement_unknown")
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn("xyz", ctx.exception.message)

    def test_invalid_status_value_is_rejected(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        with self.assertRaises(Exception) as ctx:
            self.service.set_module_entitlement(
                self.owner, "soc", {"status": "trial"}, request_id=_rid()
            )
        self.assertEqual(ctx.exception.code, "module_entitlement_body_invalid")
        self.assertEqual(ctx.exception.status, 400)

    def test_viewer_and_administrator_cannot_manage_module_entitlements(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)

        with self.assertRaises(Exception) as ctx:
            self.service.set_module_entitlement(
                self.viewer, "soc", {"status": "enabled"}, request_id=_rid()
            )
        self.assertEqual(ctx.exception.code, "permission_denied")
        self.assertEqual(ctx.exception.status, 403)

        _, administrator, _ = create_identity_fixture(
            self.service.store.path,
            role=OrganizationRole.ADMINISTRATOR,
            principal_id=ADMINISTRATOR_ID,
            token_id=ADMINISTRATOR_TOKEN_ID,
        )
        with self.assertRaises(Exception) as ctx:
            self.service.set_module_entitlement(
                administrator, "compliance", {"status": "disabled"}, request_id=_rid()
            )
        self.assertEqual(ctx.exception.code, "permission_denied")
        self.assertEqual(ctx.exception.status, 403)

    def test_manage_404s_for_an_organization_with_no_entitlement_rows(self) -> None:
        # Mirrors test_collect_assertion_denied_without_an_entitlement_row:
        # self.entitlements starts with zero rows granted in setUp, and
        # this must fail closed with 404, never silently create a row.
        with self.assertRaises(Exception) as ctx:
            self.service.set_module_entitlement(
                self.owner, "soc", {"status": "enabled"}, request_id=_rid()
            )
        self.assertEqual(ctx.exception.code, "module_entitlement_not_found")
        self.assertEqual(ctx.exception.status, 404)

    def test_soc_connectors_lists_all_three_real_manifests_sorted(self) -> None:
        payload = self.service.list_soc_connectors(self.owner, request_id=_rid())
        ids = [connector["connector_id"] for connector in payload["connectors"]]
        self.assertEqual(ids, ["defender_xdr", "entra", "sentinel"])
        for connector in payload["connectors"]:
            self.assertEqual(connector["live_validation_state"], "contract_designed")
            self.assertGreater(len(connector["permissions"]), 0)

    def test_compliance_frameworks_names_five_placeholders_with_zero_controls(self) -> None:
        payload = self.service.list_compliance_frameworks(self.owner, request_id=_rid())
        self.assertEqual(len(payload["frameworks"]), 5)
        for framework in payload["frameworks"]:
            self.assertEqual(framework["status"], "placeholder")
            self.assertEqual(framework["control_count"], 0)

    def test_compliance_assertions_names_exactly_one_evaluatable_assertion(self) -> None:
        payload = self.service.list_compliance_assertions(self.owner, request_id=_rid())
        self.assertEqual(len(payload["assertions"]), 5)
        evaluatable = [a["assertion_id"] for a in payload["assertions"] if a["evaluatable"]]
        self.assertEqual(evaluatable, ["entra_conditional_access_policy_mode"])
        self.assertIn("entra_ca_policies_one_enforced", payload["fixture_evidence_sets"])

    def test_assertion_collections_empty_for_never_attempted(self) -> None:
        payload = self.service.list_assertion_collections(
            self.owner, "entra_conditional_access_policy_mode", request_id=_rid()
        )
        self.assertEqual(payload, {"collections": []})

    def test_assertion_collections_404s_on_unknown_assertion(self) -> None:
        with self.assertRaises(Exception) as ctx:
            self.service.list_assertion_collections(self.owner, "not_a_real_assertion", request_id=_rid())
        self.assertEqual(ctx.exception.code, "technical_assertion_unknown")
        self.assertEqual(ctx.exception.status, 404)

    def test_collect_assertion_denied_without_an_entitlement_row(self) -> None:
        with self.assertRaises(Exception) as ctx:
            self.service.collect_assertion(
                self.owner, "entra_conditional_access_policy_mode",
                {"evidence_source": "fixture", "fixture_name": "entra_ca_policies_one_enforced"},
                request_id=_rid(),
            )
        self.assertEqual(ctx.exception.code, "compliance_module_not_entitled")
        self.assertEqual(ctx.exception.status, 403)

    def test_collect_assertion_denied_while_compliance_stays_disabled(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        with self.assertRaises(Exception) as ctx:
            self.service.collect_assertion(
                self.owner, "entra_conditional_access_policy_mode",
                {"evidence_source": "fixture", "fixture_name": "entra_ca_policies_one_enforced"},
                request_id=_rid(),
            )
        self.assertEqual(ctx.exception.code, "compliance_module_not_entitled")

    def test_collect_assertion_succeeds_once_compliance_is_enabled_and_is_then_listed(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        self.entitlements.set_entitlement(
            self.owner.organization_id, PlatformModule.COMPLIANCE,
            status=ModuleEntitlementStatus.ENABLED, now=NOW,
        )
        result = self.service.collect_assertion(
            self.owner, "entra_conditional_access_policy_mode",
            {"evidence_source": "fixture", "fixture_name": "entra_ca_policies_one_enforced"},
            request_id=_rid(),
        )
        self.assertEqual(result["collection_status"], "succeeded")
        self.assertEqual(result["outcome"], "satisfied")
        self.assertEqual(result["evidence_source"], "fixture")

        listed = self.service.list_assertion_collections(
            self.owner, "entra_conditional_access_policy_mode", request_id=_rid()
        )
        self.assertEqual(len(listed["collections"]), 1)
        self.assertEqual(listed["collections"][0]["collection_id"], result["collection_id"])

    def test_collect_assertion_unknown_fixture_is_a_recorded_failure_not_an_exception(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        self.entitlements.set_entitlement(
            self.owner.organization_id, PlatformModule.COMPLIANCE,
            status=ModuleEntitlementStatus.ENABLED, now=NOW,
        )
        result = self.service.collect_assertion(
            self.owner, "entra_conditional_access_policy_mode",
            {"evidence_source": "fixture", "fixture_name": "does_not_exist"},
            request_id=_rid(),
        )
        self.assertEqual(result["collection_status"], "failed")
        self.assertIsNone(result["outcome"])

    def test_collect_assertion_manual_evidence_path(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        self.entitlements.set_entitlement(
            self.owner.organization_id, PlatformModule.COMPLIANCE,
            status=ModuleEntitlementStatus.ENABLED, now=NOW,
        )
        result = self.service.collect_assertion(
            self.owner, "entra_conditional_access_policy_mode",
            {"evidence_source": "manual", "manual_evidence": [{"id": "ca-1", "state": "enabled"}]},
            request_id=_rid(),
        )
        self.assertEqual(result["collection_status"], "succeeded")
        self.assertEqual(result["outcome"], "satisfied")
        self.assertIn("manually supplied", result["evidence_provenance"])

    def test_collect_assertion_rejects_a_non_evaluatable_assertion(self) -> None:
        self.entitlements.grant_default_entitlements(self.owner.organization_id, now=NOW)
        self.entitlements.set_entitlement(
            self.owner.organization_id, PlatformModule.COMPLIANCE,
            status=ModuleEntitlementStatus.ENABLED, now=NOW,
        )
        with self.assertRaises(Exception) as ctx:
            self.service.collect_assertion(
                self.owner, "entra_privileged_role_inventory",
                {"evidence_source": "fixture", "fixture_name": "entra_ca_policies_one_enforced"},
                request_id=_rid(),
            )
        self.assertEqual(ctx.exception.code, "technical_assertion_not_evaluatable")
        self.assertEqual(ctx.exception.status, 400)

    def test_viewer_can_read_but_not_collect(self) -> None:
        self.entitlements.grant_default_entitlements(self.viewer.organization_id, now=NOW)
        self.entitlements.set_entitlement(
            self.viewer.organization_id, PlatformModule.COMPLIANCE,
            status=ModuleEntitlementStatus.ENABLED, now=NOW,
        )
        # Reads succeed for a viewer.
        self.service.list_module_entitlements(self.viewer, request_id=_rid())
        self.service.list_soc_connectors(self.viewer, request_id=_rid())
        self.service.list_compliance_frameworks(self.viewer, request_id=_rid())
        self.service.list_compliance_assertions(self.viewer, request_id=_rid())
        # Collecting is not.
        with self.assertRaises(Exception) as ctx:
            self.service.collect_assertion(
                self.viewer, "entra_conditional_access_policy_mode",
                {"evidence_source": "fixture", "fixture_name": "entra_ca_policies_one_enforced"},
                request_id=_rid(),
            )
        self.assertEqual(ctx.exception.code, "permission_denied")
        self.assertEqual(ctx.exception.status, 403)

    def test_register_account_grants_default_entitlements(self) -> None:
        # Uses the real local/lab IdentityStore path (not
        # create_identity_fixture, which bypasses register_account
        # entirely) to prove the actual registration route grants
        # defaults, closing the gap this session found: local/lab
        # organization creation never granted entitlements before.
        from webguard_api.identity import IdentityStore

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity = IdentityStore(store.path)
        service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(root / "authorizations"),
            identity=identity,
            clock=lambda: NOW,
        )
        context, _issued = service.register_account(
            {
                "organization_name": "Acme",
                "display_name": "Ada",
                "email": "ada@acme.test",
                "password": "CorrectHorseBattery9!",
            },
            request_id=_rid(), user_agent="test", ip_address="127.0.0.1",
        )
        payload = service.list_module_entitlements(context, request_id=_rid())
        by_module = {row["module"]: row["status"] for row in payload["entitlements"]}
        self.assertEqual(
            by_module,
            {"webguard": "enabled", "soc": "disabled", "compliance": "disabled"},
        )

    def test_register_account_does_not_double_grant_when_the_identity_backend_already_did(self) -> None:
        # Regression test for a real bug this session shipped and CI
        # caught: PostgresIdentityRepository.create_organization already
        # calls grant_default_entitlements internally when constructed
        # with a module_entitlements repository (production_startup.py
        # always does). grant_default_entitlements itself is a plain
        # INSERT with no ON CONFLICT handling -- calling it a second
        # time for the same organization_id raises a unique-constraint
        # violation against a real database, which broke registration
        # outright (every Playwright spec that registers through the
        # real HTTP route failed, CI caught it). This test builds a
        # fake identity backend that reproduces exactly that
        # already-granted-internally behavior (a plain dict cannot
        # reproduce a unique-constraint violation, so the fake raises
        # the same way Postgres would on a second call), and proves
        # the real register_account -- not a reimplementation of its
        # guard -- calls through cleanly.
        from webguard_api.identity import IdentityStore

        class AlreadyGrantsInternallyIdentityStore(IdentityStore):
            def __init__(self, path, entitlements):
                super().__init__(path)
                self._entitlements = entitlements

            def create_organization(self, name, *, now, organization_id=None):
                organization = super().create_organization(name, now=now, organization_id=organization_id)
                # Mirrors PostgresIdentityRepository.create_organization
                # exactly: grants immediately, unconditionally, as part
                # of creating the organization itself.
                self._entitlements.grant_default_entitlements(organization.organization_id, now=now)
                return organization

        entitlements = InMemoryModuleEntitlementRepository()
        original_grant = entitlements.grant_default_entitlements
        seen_organizations: set[str] = set()

        def grant_or_raise_on_duplicate(organization_id, *, now):
            if organization_id in seen_organizations:
                raise AssertionError(
                    "grant_default_entitlements called twice for the same organization -- "
                    "this is the exact real-database unique-constraint violation this test guards against."
                )
            seen_organizations.add(organization_id)
            return original_grant(organization_id, now=now)

        entitlements.grant_default_entitlements = grant_or_raise_on_duplicate

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity = AlreadyGrantsInternallyIdentityStore(store.path, entitlements)
        service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(root / "authorizations"),
            identity=identity,
            clock=lambda: NOW,
            module_entitlements=entitlements,
        )

        # Must not raise: register_account's own call has to see the
        # row create_organization already inserted and skip granting
        # again, not blindly call through and hit the same violation a
        # real Postgres unique constraint would raise.
        context, _issued = service.register_account(
            {
                "organization_name": "Acme",
                "display_name": "Ada",
                "email": "ada2@acme.test",
                "password": "CorrectHorseBattery9!",
            },
            request_id=_rid(), user_agent="test", ip_address="127.0.0.1",
        )
        payload = service.list_module_entitlements(context, request_id=_rid())
        by_module = {row["module"]: row["status"] for row in payload["entitlements"]}
        self.assertEqual(
            by_module,
            {"webguard": "enabled", "soc": "disabled", "compliance": "disabled"},
        )


if __name__ == "__main__":
    unittest.main()
