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

Every permission name below was verified against Microsoft's own
current documentation, not assumed from prior training knowledge: the
Entra manifest was verified 2026-09-12 against Microsoft Graph's own
permissions reference (catching a fabricated ``DirectoryRole.Read.All``
before it shipped, corrected to the real ``RoleManagement.Read.Directory``).
The Defender XDR manifest was verified 2026-09-14, also against
Microsoft's own current docs. That pass surfaced a real architectural
split worth calling out here: Defender XDR's device/machine inventory
(``Machine.Read.All``) is not a Microsoft Graph permission at all. It
belongs to the separate Microsoft Defender for Endpoint API
(``api.security.microsoft.com``), which as of Microsoft's own July 2026
documentation still requires an access token issued for the legacy
OAuth resource ``https://api.securitycenter.microsoft.com``, not
``https://graph.microsoft.com``, or the request fails with 403 even
though the endpoint host itself is the newer ``api.security.microsoft.com``.
That is a second token audience, a second app-registration permission
grant, and a versioning scheme this module's ``ConnectorEndpoint``
does not model (Graph's ``v1.0``/``beta`` monikers do not apply to
that API). Rather than weaken that validation to force a fit, the
Defender XDR manifest below is scoped to the four endpoints that are
genuinely Microsoft Graph, and device inventory is named as an
explicit, deferred gap in its own ``known_limitations``. Re-verify
every permission against Microsoft's own documentation before any
manifest here is used to request real consent, since names, required
roles, and resource audiences can change between a verification date
and whenever a live client is actually built.

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

# Verified 2026-09-14 against https://learn.microsoft.com/en-us/graph/permissions-reference
# and each endpoint's own Microsoft Graph reference page. Application
# permissions throughout, for the same background-polling reason as
# Entra's. Scoped to the unified Microsoft Graph Security API only:
# Machine.Read.All (device/machine inventory) belongs to the separate
# Defender for Endpoint API and is deliberately excluded here, see this
# module's own docstring and DEFENDER_XDR_CONNECTOR_MANIFEST's
# known_limitations.
_DEFENDER_XDR_PERMISSIONS = (
    ConnectorPermission(
        name="SecurityIncident.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose="Incident stream: Microsoft 365 Defender's own correlation of related alerts into a single tracked attack.",
    ),
    ConnectorPermission(
        name="SecurityAlert.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose=(
            "Alert stream feeding incidents, including alerts Microsoft has not yet "
            "correlated into any incident. An assertion built on both this and "
            "SecurityIncident.Read.All must not double-count an alert that already "
            "appears nested under an incident."
        ),
    ),
    ConnectorPermission(
        name="ThreatHunting.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose="Advanced hunting over raw device/identity/email telemetry via Kusto query, for detection depth beyond what a generated alert already surfaces.",
    ),
    ConnectorPermission(
        name="SecurityEvents.Read.All",
        permission_type=ConnectorPermissionType.APPLICATION,
        purpose="Microsoft Secure Score: a point-in-time posture score and its per-control breakdown, for a posture-trend assertion built from repeated collection, not from any single call.",
    ),
)

_DEFENDER_XDR_ENDPOINTS = (
    ConnectorEndpoint(
        label="List incidents",
        method="GET",
        path="/v1.0/security/incidents",
        api_version="v1.0",
        stability="stable",
        required_permissions=("SecurityIncident.Read.All",),
    ),
    ConnectorEndpoint(
        label="List alerts_v2",
        method="GET",
        path="/v1.0/security/alerts_v2",
        api_version="v1.0",
        stability="stable",
        required_permissions=("SecurityAlert.Read.All",),
    ),
    ConnectorEndpoint(
        label="Run hunting query",
        method="POST",
        path="/v1.0/security/runHuntingQuery",
        api_version="v1.0",
        stability="stable",
        required_permissions=("ThreatHunting.Read.All",),
    ),
    ConnectorEndpoint(
        label="List secure scores",
        method="GET",
        path="/v1.0/security/secureScores",
        api_version="v1.0",
        stability="stable",
        required_permissions=("SecurityEvents.Read.All",),
    ),
)

DEFENDER_XDR_CONNECTOR_MANIFEST = ConnectorManifest(
    connector_id="defender_xdr",
    display_name="Microsoft Defender XDR",
    vendor="Microsoft",
    api_family="Microsoft Graph (security namespace)",
    licensing_dependency="Requires Defender XDR / Microsoft 365 Defender licensing for incidents, alerts_v2 and hunting; Secure Score requires the relevant workload licenses (Defender for Endpoint/Office/Identity) to populate beyond an empty baseline.",
    regional_availability="Follows the customer's own Microsoft 365 tenant region; no separate regional selection. Not available in the China-operated-by-21Vianet cloud per Microsoft's own national-cloud availability table for these endpoints.",
    permissions=_DEFENDER_XDR_PERMISSIONS,
    endpoints=_DEFENDER_XDR_ENDPOINTS,
    pagination="@odata.nextLink cursor-based pagination on incidents and alerts_v2; runHuntingQuery and secureScores return a single bounded result set with no cursor.",
    incremental_cursor_support=(
        "incidents and alerts_v2 support $filter on lastUpdateDateTime/createdDateTime for "
        "incremental polling; runHuntingQuery has no incremental mode, each call re-runs the "
        "full query over its own Timespan (default 30 days if omitted, per Microsoft's own "
        "documentation) and a connector must not silently narrow a requested longer lookback "
        "to that default without surfacing the discrepancy; secureScores has no incremental "
        "mode either and must be fully re-listed each cycle."
    ),
    credential_refresh_notes="OAuth 2.0 client-credentials flow against Entra's own token endpoint, scoped to https://graph.microsoft.com/.default; tokens are short-lived and refreshed per call batch, never cached beyond their own expiry.",
    retry_policy="Exponential backoff honoring the Retry-After header on 429/503 responses; Microsoft Graph throttling documentation is the source of truth for backoff floors, not a value invented here.",
    rate_limit_notes="Per-tenant and per-app throttling limits are workload-specific and documented per Graph service; runHuntingQuery additionally carries its own query-complexity and result-size limits distinct from simple request-rate throttling.",
    backfill_limit_notes="incidents/alerts_v2 retention follows the tenant's own Microsoft 365 Defender data retention configuration; runHuntingQuery's advanced-hunting tables have their own fixed retention (commonly 30 days) independent of the incident/alert retention setting, and a query requesting data older than that returns an empty result, not an error.",
    deletion_semantics="Incidents and alerts are not deleted by Microsoft; an incident can be marked redirectIncidentId when merged into another, and a connector cycle must follow that redirect rather than reporting the original incident as vanished.",
    live_validation_state=ConnectorLiveValidationState.CONTRACT_DESIGNED,
    known_limitations=(
        "No live HTTP client exists yet; this is a manifest only, blocked on real Defender XDR tenant credentials for live validation.",
        "Device/machine inventory (Machine.Read.All) is deliberately out of scope for this manifest: it is not a Microsoft Graph permission, it belongs to the separate Defender for Endpoint API (api.security.microsoft.com) which, per Microsoft's own July 2026 documentation, still requires an access token audience of https://api.securitycenter.microsoft.com rather than https://graph.microsoft.com, and this module's ConnectorEndpoint has no api_version model for that API's own versioning scheme. Adding it needs a schema change, not just a new endpoint entry, and is deferred rather than forced.",
        "alerts_v2 and incidents overlap by design (an incident is Microsoft's own correlation of one or more alerts); an assertion or evidence record built from both endpoints must treat an alert already nested under an incident as the same evidence, not as two independent findings.",
        "Secure Score is a snapshot at query time, not a time series; any posture-trend claim requires this connector's own repeated collection over time, never a single call's result presented as a trend.",
    ),
)

SOC_CONNECTOR_REGISTRY: dict[str, ConnectorManifest] = {
    ENTRA_CONNECTOR_MANIFEST.connector_id: ENTRA_CONNECTOR_MANIFEST,
    DEFENDER_XDR_CONNECTOR_MANIFEST.connector_id: DEFENDER_XDR_CONNECTOR_MANIFEST,
}

__all__ = [
    "SOC_CONNECTOR_REGISTRY",
    "DEFENDER_XDR_CONNECTOR_MANIFEST",
    "ENTRA_CONNECTOR_MANIFEST",
    "ConnectorEndpoint",
    "ConnectorLiveValidationState",
    "ConnectorManifest",
    "ConnectorPermission",
    "ConnectorPermissionType",
]
