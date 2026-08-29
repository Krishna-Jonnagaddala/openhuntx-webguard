"""Bearer-token and browser-session authentication, and role-based
authorization shared identically by both (Slice 16 requirement 15:
a browser session resolves into the exact same ``AuthContext`` /
``ApiPermission`` model an API token does -- there is no separate
frontend permission model)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from webguard_contracts import OrganizationRole

from .identity import IdentityStoreError
from .repository_contracts import IdentityRepository
from .sessions import DEFAULT_IDLE_TIMEOUT


class ApiPermission(str, Enum):
    JOB_SUBMIT = "jobs.submit"
    JOB_READ = "jobs.read"
    JOB_CANCEL = "jobs.cancel"
    SCHEDULE_CREATE = "schedules.create"
    SCHEDULE_READ = "schedules.read"
    SCHEDULE_UPDATE = "schedules.update"
    AUDIT_READ = "audit.read"
    IDENTITY_MANAGE = "identity.manage"
    AUTHORIZATION_ASSIGN = "authorization.assign"
    PERMIT_ISSUE = "permits.issue"
    PERMIT_ISSUE_ACTIVE = "permits.issue_active"
    PERMIT_READ = "permits.read"
    PERMIT_REVOKE = "permits.revoke"
    AUTHENTICATION_CONTEXT_REGISTER = "authentication_contexts.register"
    AUTHENTICATION_CONTEXT_READ = "authentication_contexts.read"
    AUTHENTICATION_CONTEXT_REVOKE = "authentication_contexts.revoke"
    AUTHORIZATION_COMPARISON_REGISTER = "authorization_comparisons.register"
    AUTHORIZATION_COMPARISON_READ = "authorization_comparisons.read"
    AUTHORIZATION_COMPARISON_REVOKE = "authorization_comparisons.revoke"
    FINDING_READ = "findings.read"
    FINDING_UPDATE = "findings.update"
    REPORT_CREATE = "reports.create"
    REPORT_READ = "reports.read"
    ASSET_READ = "assets.read"
    ASSET_MANAGE = "assets.manage"
    TEAM_READ = "team.read"
    TEAM_MANAGE = "team.manage"


_ROLE_PERMISSIONS = {
    OrganizationRole.OWNER: frozenset(ApiPermission),
    # Administrators may issue ordinary (passive-only) permits, but not
    # ones that authorize active/intrusive checks, nor anything involving
    # authenticated-scanning credentials -- both deliberately reserved
    # for the organization owner. See PERMIT_ISSUE_ACTIVE and the
    # AUTHENTICATION_CONTEXT_* permissions.
    OrganizationRole.ADMINISTRATOR: frozenset(ApiPermission) - {
        ApiPermission.PERMIT_ISSUE_ACTIVE,
        ApiPermission.AUTHENTICATION_CONTEXT_REGISTER,
        ApiPermission.AUTHENTICATION_CONTEXT_READ,
        ApiPermission.AUTHENTICATION_CONTEXT_REVOKE,
        ApiPermission.AUTHORIZATION_COMPARISON_REGISTER,
        ApiPermission.AUTHORIZATION_COMPARISON_READ,
        ApiPermission.AUTHORIZATION_COMPARISON_REVOKE,
    },
    OrganizationRole.ANALYST: frozenset(
        {
            ApiPermission.JOB_SUBMIT,
            ApiPermission.JOB_READ,
            ApiPermission.JOB_CANCEL,
            ApiPermission.SCHEDULE_CREATE,
            ApiPermission.SCHEDULE_READ,
            ApiPermission.SCHEDULE_UPDATE,
            ApiPermission.PERMIT_READ,
            ApiPermission.FINDING_READ,
            ApiPermission.FINDING_UPDATE,
            ApiPermission.REPORT_CREATE,
            ApiPermission.REPORT_READ,
            ApiPermission.ASSET_READ,
            ApiPermission.ASSET_MANAGE,
            ApiPermission.TEAM_READ,
        }
    ),
    OrganizationRole.VIEWER: frozenset(
        {
            ApiPermission.JOB_READ,
            ApiPermission.SCHEDULE_READ,
            ApiPermission.PERMIT_READ,
            ApiPermission.FINDING_READ,
            ApiPermission.REPORT_READ,
            ApiPermission.ASSET_READ,
            ApiPermission.TEAM_READ,
        }
    ),
}


class AuthenticationError(ValueError):
    """Controlled authentication failure."""

    def __init__(self, code: str, message: str, *, status: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True, slots=True)
class AuthContext:
    organization_id: str
    organization_name: str
    principal_id: str
    principal_name: str
    role: OrganizationRole
    token_id: str
    # Slice 16: which credential kind authenticated this request. Every
    # other field above is identical regardless -- RBAC resolution
    # (`permits`/`require`) does not look at this at all. It exists
    # only for the two places that legitimately must behave
    # differently by transport: the CSRF gate (browser sessions only)
    # and audit logging (records which kind of credential acted).
    auth_method: str = "api_token"

    def permits(self, permission: ApiPermission) -> bool:
        return permission in _ROLE_PERMISSIONS[self.role]

    def require(self, permission: ApiPermission) -> None:
        if not self.permits(permission):
            raise AuthenticationError(
                "permission_denied",
                "The authenticated principal is not permitted to perform this action.",
                status=403,
            )

    def to_public_dict(self) -> dict[str, str]:
        return {
            "organization_id": self.organization_id,
            "organization_name": self.organization_name,
            "principal_id": self.principal_id,
            "principal_name": self.principal_name,
            "role": self.role.value,
            "token_id": self.token_id,
            "auth_method": self.auth_method,
        }


class ApiTokenAuthenticator:
    """Authenticate exactly one HTTP Bearer token against the identity store."""

    def __init__(self, identity: IdentityRepository) -> None:
        self.identity = identity

    def authenticate(self, authorization_headers: list[str], *, now: datetime) -> AuthContext:
        if len(authorization_headers) != 1:
            raise AuthenticationError(
                "authorization_header_required",
                "Exactly one Authorization header is required.",
            )
        value = authorization_headers[0]
        scheme, separator, token = value.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token or token.strip() != token:
            raise AuthenticationError(
                "authorization_header_invalid",
                "Authorization must use the Bearer scheme.",
            )
        try:
            metadata, principal, organization = self.identity.authenticate_token(token, now=now)
        except IdentityStoreError as exc:
            raise AuthenticationError(exc.code, exc.message) from exc
        return AuthContext(
            organization_id=organization.organization_id,
            organization_name=organization.name,
            principal_id=principal.principal_id,
            principal_name=principal.display_name,
            role=principal.role,
            token_id=metadata.token_id,
        )


class BrowserSessionAuthenticator:
    """Authenticate exactly one browser session cookie against the
    session store, resolving into the identical ``AuthContext`` shape
    ``ApiTokenAuthenticator`` produces -- same RBAC, same
    ``_require``/``_audit`` call sites in ``service.py``, no parallel
    permission model for browser users (Slice 16 requirement 15)."""

    def __init__(self, identity: IdentityRepository, sessions) -> None:  # noqa: ANN001 - see repository_contracts
        self.identity = identity
        self.sessions = sessions

    def authenticate(
        self,
        session_token: object,
        *,
        now: datetime,
        csrf_header: str | None = None,
        require_csrf: bool = False,
        idle_ttl: timedelta = DEFAULT_IDLE_TIMEOUT,
    ) -> AuthContext:
        try:
            session = self.sessions.authenticate_session(
                session_token,
                now=now,
                idle_ttl=idle_ttl,
                csrf_header=csrf_header,
                require_csrf=require_csrf,
            )
        except IdentityStoreError as exc:
            # A missing/wrong CSRF token means the session itself is
            # genuinely valid -- the caller is simply forbidden from
            # this specific request without also proving it, which is
            # a 403 (authenticated but not permitted), not a 401
            # (not authenticated at all).
            status = 403 if exc.code == "csrf_token_invalid" else 401
            raise AuthenticationError(exc.code, exc.message, status=status) from exc
        try:
            principal = self.identity.get_principal(session.principal_id)
            organization = self.identity.get_organization(session.organization_id)
        except IdentityStoreError as exc:
            raise AuthenticationError(exc.code, exc.message) from exc
        if not principal.active:
            raise AuthenticationError("principal_disabled", "Principal is disabled.")
        if organization.status.value != "active":
            raise AuthenticationError("organization_disabled", "Organization is disabled.")
        return AuthContext(
            organization_id=organization.organization_id,
            organization_name=organization.name,
            principal_id=principal.principal_id,
            principal_name=principal.display_name,
            role=principal.role,
            token_id=session.session_id,
            auth_method="browser_session",
        )


__all__ = [
    "ApiPermission",
    "ApiTokenAuthenticator",
    "AuthContext",
    "AuthenticationError",
    "BrowserSessionAuthenticator",
]
