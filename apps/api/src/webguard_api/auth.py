"""Bearer-token authentication and role-based authorization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from webguard_contracts import OrganizationRole

from .identity import IdentityStore, IdentityStoreError


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
        }
    ),
    OrganizationRole.VIEWER: frozenset(
        {ApiPermission.JOB_READ, ApiPermission.SCHEDULE_READ, ApiPermission.PERMIT_READ}
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
        }


class ApiTokenAuthenticator:
    """Authenticate exactly one HTTP Bearer token against the identity store."""

    def __init__(self, identity: IdentityStore) -> None:
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


__all__ = [
    "ApiPermission",
    "ApiTokenAuthenticator",
    "AuthContext",
    "AuthenticationError",
]
