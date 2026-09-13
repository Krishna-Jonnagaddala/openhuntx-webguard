"""Tests for SOC connector manifests (platform expansion,
docs/CONNECTOR_CAPABILITIES.md). These validate the manifest's own
internal consistency (every endpoint's required permission is
actually declared, every field is populated), not any live API
behavior: no network call is made anywhere in this file, matching
the module's own "contract only, no live client" scope.
"""

from __future__ import annotations

import unittest

from webguard_api.soc_connectors import (
    SOC_CONNECTOR_REGISTRY,
    ConnectorLiveValidationState,
    ConnectorManifest,
)


class SocConnectorRegistryTests(unittest.TestCase):
    def test_registry_keys_match_manifest_connector_ids(self) -> None:
        for connector_id, manifest in SOC_CONNECTOR_REGISTRY.items():
            self.assertEqual(connector_id, manifest.connector_id)

    def test_every_manifest_declares_at_least_one_permission_and_endpoint(self) -> None:
        for manifest in SOC_CONNECTOR_REGISTRY.values():
            self.assertTrue(manifest.permissions, f"{manifest.connector_id} has no permissions")
            self.assertTrue(manifest.endpoints, f"{manifest.connector_id} has no endpoints")

    def test_every_endpoint_permission_is_declared_on_the_manifest(self) -> None:
        # ConnectorManifest.__post_init__ already enforces this at
        # construction time; this test proves that enforcement is
        # real by attempting to build a manifest that violates it.
        from webguard_api.soc_connectors import ConnectorEndpoint, ConnectorPermission, ConnectorPermissionType

        with self.assertRaises(ValueError):
            ConnectorManifest(
                connector_id="broken",
                display_name="Broken",
                vendor="Test",
                api_family="Test API",
                licensing_dependency="none",
                regional_availability="none",
                permissions=(
                    ConnectorPermission(
                        name="Declared.Permission",
                        permission_type=ConnectorPermissionType.APPLICATION,
                        purpose="test",
                    ),
                ),
                endpoints=(
                    ConnectorEndpoint(
                        label="Uses an undeclared permission",
                        method="GET",
                        path="/v1.0/test",
                        api_version="v1.0",
                        stability="stable",
                        required_permissions=("Undeclared.Permission",),
                    ),
                ),
                pagination="none",
                incremental_cursor_support="none",
                credential_refresh_notes="none",
                retry_policy="none",
                rate_limit_notes="none",
                backfill_limit_notes="none",
                deletion_semantics="none",
                live_validation_state=ConnectorLiveValidationState.NOT_STARTED,
            )

    def test_no_manifest_claims_live_validated_yet(self) -> None:
        """This platform has no live connector client built yet; every
        manifest must say so honestly rather than claiming a state
        this codebase cannot back up."""

        for manifest in SOC_CONNECTOR_REGISTRY.values():
            self.assertNotEqual(
                manifest.live_validation_state,
                ConnectorLiveValidationState.LIVE_VALIDATED,
                f"{manifest.connector_id} claims live_validated with no live client in this codebase",
            )

    def test_entra_manifest_documents_mfa_registration_versus_enforcement_limitation(self) -> None:
        """Handoff-mandated distinction: per-user authentication method
        registration is not the same fact as Conditional Access
        enforcement. This must be a documented limitation, not left
        implicit."""

        entra = SOC_CONNECTOR_REGISTRY["entra"]
        self.assertTrue(
            any("enforcement" in limitation.lower() for limitation in entra.known_limitations),
            "Entra manifest must document the registration-vs-enforcement distinction",
        )

    def test_defender_xdr_manifest_documents_device_inventory_deferral(self) -> None:
        """Machine.Read.All belongs to a different API (Defender for
        Endpoint, not Microsoft Graph) with a different OAuth resource
        audience than every other endpoint in this manifest. That gap
        must be named explicitly, not silently absent."""

        defender_xdr = SOC_CONNECTOR_REGISTRY["defender_xdr"]
        self.assertTrue(
            any("machine" in limitation.lower() for limitation in defender_xdr.known_limitations),
            "Defender XDR manifest must document why device/machine inventory is out of scope",
        )

    def test_defender_xdr_manifest_uses_only_graph_permissions(self) -> None:
        """This slice is deliberately scoped to the unified Microsoft
        Graph security namespace; Machine.Read.All (a non-Graph
        permission) must not appear until the schema is extended to
        model a second API family and OAuth resource."""

        defender_xdr = SOC_CONNECTOR_REGISTRY["defender_xdr"]
        permission_names = {permission.name for permission in defender_xdr.permissions}
        self.assertNotIn("Machine.Read.All", permission_names)
        for endpoint in defender_xdr.endpoints:
            self.assertTrue(endpoint.path.startswith("/v1.0/") or endpoint.path.startswith("/beta/"))


if __name__ == "__main__":
    unittest.main()
