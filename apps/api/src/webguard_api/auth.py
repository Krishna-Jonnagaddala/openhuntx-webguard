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
    AUDIT_READ = "audit.read"
    IDENTITY_MANAGE = "identity.manage"
    AUTHORIZATION_ASSIGN = "authorization.assign"


_ROLE_PERMISSIONS = {
    OrganizationRole.OWNER: frozenset(ApiPermission),
    OrganizationRole.ADMINISTRATOR: frozenset(ApiPermission),
    OrganizationRole.ANALYST: frozenset(
        {ApiPermission.JOB_SUBMIT, ApiPermission.JOB_READ, ApiPermission.JOB_CANCEL}
    ),
    OrganizationRole.VIEWER: frozenset({ApiPermission.JOB_READ}),
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
