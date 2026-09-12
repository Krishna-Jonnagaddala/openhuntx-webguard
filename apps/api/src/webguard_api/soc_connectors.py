"""SOC connector manifests (platform expansion, docs/PLATFORM_SCOPE.md
and docs/CONNECTOR_CAPABILITIES.md).

A manifest describes what a connector *can* do (its permission needs,
its endpoints, its operational limits): a property of this codebase's
own supported capability at a given version, not a specific
organization's live connection. It has no organization_id and needs
no database table, mirroring how ``ACTIVE_DETECTOR_REGISTRY``
(workers/scanner/src/webguard_scanner/active_detector_registry.py)
describes what scan checks this codebase can run, not any one scan's
own results. A future, separate, tenant-scoped table tracks an
organization's actual configured connector instance (credential
reference, health, last sync); nothing here is that table, and none
should be built until a real live client exists to populate it, per
docs/PLATFORM_SCOPE.md's own instruction against speculative
infrastructure.

Every permission name below was verified 2026-09-12 against Microsoft
Graph's own permissions reference and the graphpermissions.merill.net
mirror of it, not assumed from prior training knowledge: an initial
draft of this manifest included ``DirectoryRole.Read.All``, which does
not exist as a real Microsoft Graph permission, and was caught and
corrected to the real permission (``RoleManagement.Read.Directory``)
before this file was written. Re-verify against Microsoft's own
documentation before this manifest is used to request real consent,
since permission names and required roles can change between this
verification date and whenever a live client is actually built.

``live_validation_state`` on every manifest here is
``CONTRACT_DESIGNED``: no live HTTP client exists yet, and none should
claim otherwise (docs/CONNECTOR_CAPABILITIES.md's own review
discipline). This module intentionally makes no network call and
depends on no credential.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ConnectorPermissionType(str, Enum):
    APPLICATION = "application"
    DELEGATED = "delegated"


class ConnectorLiveValidationState(str, Enum):
    NOT_STARTED = "not_started"
    CONTRACT_DESIGNED = "contract_designed"
    FIXTURE_TESTED = "fixture_tested"
    BLOCKED_ON_CREDENTIALS = "blocked_on_credentials"
    LIVE_VALIDATED = "live_validated"


@dataclass(frozen=True, slots=True)
class ConnectorPermission:
    name: str
    permission_type: ConnectorPermissionType
    purpose: str


@dataclass(frozen=True, slots=True)
class ConnectorEndpoint:
    label: str
    method: str
    path: str
    api_version: str
    stability: str
    required_permissions: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.stability not in ("stable", "preview"):
            raise ValueError(f"stability must be 'stable' or 'preview', got {self.stability!r}.")
        if self.api_version not in ("v1.0", "beta"):
            raise ValueError(f"api_version must be 'v1.0' or 'beta', got {self.api_version!r}.")


@dataclass(frozen=True, slots=True)
class ConnectorManifest:
    connector_id: str
    display_name: str
    vendor: str
    api_family: str
    licensing_dependency: str
    regional_availability: str
    permissions: tuple[ConnectorPermission, ...]
    endpoints: tuple[ConnectorEndpoint, ...]
    pagination: str
    incremental_cursor_support: str
    credential_refresh_notes: str
    retry_policy: str
    rate_limit_notes: str
    backfill_limit_notes: str
    deletion_semantics: str
    live_validation_state: ConnectorLiveValidationState
    known_limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        endpoint_permissions = {name for endpoint in self.endpoints for name in endpoint.required_permissions}
        manifest_permissions = {permission.name for permission in self.permissions}
        unlisted = endpoint_permissions - manifest_permissions
        if unlisted:
            raise ValueError(
                f"endpoints reference permissions not listed in this manifest's own "
                f"permissions tuple: {sorted(unlisted)}."
            )


# Verified 2026-09-12 against https://learn.microsoft.com/en-us/graph/permissions-reference
# and graphpermissions.merill.net. Application permissions throughout,
# since a connector polling on a schedule is a background,
# non-interactive process, not acting on behalf of a signed-in user.
_ENTRA_PERMISSIONS = (
    ConnectorPermission(
        name="RoleManagement.Read.Directory",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose="Privileged-role inventory: directory role assignments and eligible/active PIM membership.",
    ),
    ConnectorPermission(
        name="Policy.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose=(
            "Conditional Access policy mode (enabled/report-only/disabled) and exclusions. "
            "Microsoft's own documentation is explicit that a report-only policy does not "
            "enforce access decisions; this connector must read and preserve that mode, "
            "never collapse it into a plain enabled/disabled boolean."
        ),
    ),
    ConnectorPermission(
        name="UserAuthenticationMethod.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose=(
            "Per-user authentication method registration state (e.g. registered "
            "authenticator app, phone). Microsoft's own documentation distinguishes this "
            "per-user state from Conditional Access enforcement; this connector's own "
            "collected fact is registration, never a claim that MFA is enforced for that user."
        ),
    ),
    ConnectorPermission(
        name="User.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose="User inventory: identify emergency/break-glass accounts and stale privileged accounts by last activity.",
    ),
    ConnectorPermission(
        name="AuditLog.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose="Sign-in activity evidence backing stale-account and authentication-event assertions.",
    ),
    ConnectorPermission(
        name="Application.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose="Application and service-principal inventory, credential expiry metadata, and ownership.",
    ),
)

_ENTRA_ENDPOINTS = (
    ConnectorEndpoint(
        label="List directory role assignments",
        method="GET",
        path="/v1.0/roleManagement/directory/roleAssignments",
        api_version="v1.0",
        stability="stable",
        required_permissions=("RoleManagement.Read.Directory",),
    ),
    ConnectorEndpoint(
        label="List Conditional Access policies",
        method="GET",
        path="/v1.0/identity/conditionalAccess/policies",
        api_version="v1.0",
        stability="stable",
        required_permissions=("Policy.Read.All",),
    ),
    ConnectorEndpoint(
        label="Get a user's registered authentication methods",
        method="GET",
        path="/v1.0/users/{id}/authentication/methods",
        api_version="v1.0",
        stability="stable",
        required_permissions=("UserAuthenticationMethod.Read.All",),
    ),
    ConnectorEndpoint(
        label="List users",
        method="GET",
        path="/v1.0/users",
        api_version="v1.0",
        stability="stable",
        required_permissions=("User.Read.All",),
    ),
    ConnectorEndpoint(
        label="List sign-ins",
        method="GET",
        path="/v1.0/auditLogs/signIns",
        api_version="v1.0",
        stability="stable",
        required_permissions=("AuditLog.Read.All",),
    ),
    ConnectorEndpoint(
        label="List service principals",
        method="GET",
        path="/v1.0/servicePrincipals",
        api_version="v1.0",
        stability="stable",
        required_permissions=("Application.Read.All",),
    ),
)

ENTRA_CONNECTOR_MANIFEST = ConnectorManifest(
    connector_id="entra",
    display_name="Microsoft Entra ID",
    vendor="Microsoft",
    api_family="Microsoft Graph",
    licensing_dependency="Requires an Entra tenant; Conditional Access and PIM-backed role assignment reads require Entra ID P1/P2 licensing on the relevant users.",
    regional_availability="Follows the customer's own Microsoft 365/Azure tenant region; no separate regional selection.",
    permissions=_ENTRA_PERMISSIONS,
    endpoints=_ENTRA_ENDPOINTS,
    pagination="@odata.nextLink cursor-based pagination, standard across all listed endpoints.",
    incremental_cursor_support=(
        "signIns and directory audit endpoints support delta/incremental queries via "
        "$filter on time fields; roleAssignments, conditionalAccess policies, and "
        "servicePrincipals have no delta endpoint and must be fully re-listed each cycle."
    ),
    credential_refresh_notes="OAuth 2.0 client-credentials flow against Entra's own token endpoint; tokens are short-lived and refreshed per call batch, never cached beyond their own expiry.",
    retry_policy="Exponential backoff honoring the Retry-After header on 429/503 responses; Microsoft Graph throttling documentation is the source of truth for backoff floors, not a value invented here.",
    rate_limit_notes="Per-tenant and per-app throttling limits are workload-specific and documented per Graph service; not a single global number.",
    backfill_limit_notes="signIns retention is bounded by the tenant's own Entra ID license tier (commonly 30 days); a backfill request older than that retention window returns an empty result, not an error, and must not be reported as zero findings.",
    deletion_semantics="Deleted users/service principals move to a soft-deleted state retrievable for a limited window via the directory's deleted-items endpoints; a connector cycle that stops seeing a resource must distinguish deletion from a transient read failure before recording it as removed.",
    live_validation_state=ConnectorLiveValidationState.CONTRACT_DESIGNED,
    known_limitations=(
        "No live HTTP client exists yet; this is a manifest only, blocked on real Entra tenant credentials for live validation.",
        "Per-user authentication method registration is not the same fact as Conditional Access enforcement; an assertion built on this connector must keep the two separate, never inferring 'protected by MFA' from a registered method alone.",
        "A Conditional Access policy in report-only mode is not enforcing anything; an assertion must surface policy mode as a first-class field, not silently treat report-only the same as enabled.",
    ),
)

SOC_CONNECTOR_REGISTRY: dict[str, ConnectorManifest] = {
    ENTRA_CONNECTOR_MANIFEST.connector_id: ENTRA_CONNECTOR_MANIFEST,
}

__all__ = [
    "SOC_CONNECTOR_REGISTRY",
    "ENTRA_CONNECTOR_MANIFEST",
    "ConnectorEndpoint",
    "ConnectorLiveValidationState",
    "ConnectorManifest",
    "ConnectorPermission",
    "ConnectorPermissionType",
]
