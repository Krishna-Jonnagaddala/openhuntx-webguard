"""PostgreSQL-backed authentication-context metadata repository (Slice
13 requirement 9; live-wired into the production runtime in Slice 14
requirement 1).

Metadata only -- this class has no ``get_secret`` method and no
parameter anywhere that accepts raw credential material (password,
bearer token, API secret, session cookie), and never will. ``create()``
takes an optional ``secret_reference_id`` -- a pointer to wherever the
actual secret lives -- never the secret itself. Resolving that
reference into real ``AuthenticationMaterial`` is ``secret_provider.py``'s
job, not this class's; see that module for the production
(``SecretsManagerSecretProvider``) and local (``LocalSecretProvider``)
implementations. The in-memory ``AuthenticationContextRepository``
(``authentication_contexts.py``) remains the local/dev/test/lab
backend, unchanged and untouched by this class.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from .authentication_contexts import (
    AuthenticationContextError,
    AuthenticationContextRecord,
    AuthenticationContextStatus,
    AuthenticationMethod,
)
from .postgres_pool import API_TENANT_DATA_ROLE, WebGuardPostgresPool

_COLUMNS = (
    "authentication_context_id, organization_id, target, authorization_id, "
    "identity_label, method, created_at, expires_at, revoked_at, secret_reference_id"
)


class PostgresAuthenticationContextRepository:
    """P1-2 Phase H: api_tenant_data has the full SELECT, INSERT,
    UPDATE authentication_contexts needs. create, get_metadata_scoped,
    and revoke_scoped all take organization_id and run under
    api_tenant_data via tenant_connection, setting real tenant context.
    get_metadata and revoke take no organization_id at all (by design:
    they serve create/revoke's own post-write re-reads and
    require_bound's trusted-reference fetch, called from both
    executor.py and service.py, neither of which has resolved a single
    org to scope by at that call site), so they run under
    api_tenant_data via role_scoped_connection instead: the role
    narrows, but no tenant-context GUC can be set without an
    organization_id to set it to. This is a real, open limitation, not
    a stopgap awaiting a trivial fix: closing it needs either a
    resolver (this table's own SECURITY DEFINER function, matching the
    pre-auth pattern Phase F already used elsewhere) or accepting that
    RLS cannot be forced on this table while these two methods stay
    reachable in their current unscoped form."""

    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple) -> AuthenticationContextRecord:
        (
            context_id, organization_id, target, authorization_id,
            identity_label, method, created_at, expires_at, revoked_at,
            secret_reference_id,
        ) = row
        return AuthenticationContextRecord(
            authentication_context_id=str(context_id),
            organization_id=str(organization_id),
            target=target,
            authorization_id=authorization_id,
            identity_label=identity_label,
            method=AuthenticationMethod(method),
            created_at=created_at.astimezone(timezone.utc),
            expires_at=expires_at.astimezone(timezone.utc),
            revoked_at=revoked_at.astimezone(timezone.utc) if revoked_at else None,
            secret_reference_id=secret_reference_id,
        )

    def create(
        self,
        *,
        organization_id: str,
        target: str,
        authorization_id: str,
        identity_label: str,
        method: AuthenticationMethod,
        expires_at: datetime,
        now: datetime,
        secret_reference_id: str | None = None,
        authentication_context_id: str | None = None,
    ) -> AuthenticationContextRecord:
        if not identity_label or not isinstance(identity_label, str):
            raise AuthenticationContextError(
                "authentication_context_identity_label_invalid",
                "identity_label must be a non-empty string.",
            )
        if expires_at <= now:
            raise AuthenticationContextError(
                "authentication_context_expiry_invalid",
                "expires_at must be later than the current time.",
            )
        effective_id = str(uuid4()) if authentication_context_id is None else authentication_context_id
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            connection.execute(
                """
                INSERT INTO authentication_contexts (
                    authentication_context_id, organization_id, target, authorization_id,
                    identity_label, method, created_at, expires_at, secret_reference_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    effective_id, organization_id, target, authorization_id,
                    identity_label, method.value, now, expires_at, secret_reference_id,
                ),
            )
        return self.get_metadata(effective_id)

    def get_metadata(self, authentication_context_id: str) -> AuthenticationContextRecord:
        with self._pool.role_scoped_connection(API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM authentication_contexts WHERE authentication_context_id = %s",  # noqa: S608
                (authentication_context_id,),
            ).fetchone()
        if row is None:
            raise AuthenticationContextError(
                "authentication_context_not_found", "No authentication context matches the requested ID."
            )
        return self._record_from_row(row)

    def revoke(self, authentication_context_id: str, *, now: datetime) -> AuthenticationContextRecord:
        with self._pool.role_scoped_connection(API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT revoked_at FROM authentication_contexts WHERE authentication_context_id = %s",
                (authentication_context_id,),
            ).fetchone()
            if row is None:
                raise AuthenticationContextError(
                    "authentication_context_not_found", "No authentication context matches the requested ID."
                )
            if row[0] is None:
                connection.execute(
                    "UPDATE authentication_contexts SET revoked_at = %s WHERE authentication_context_id = %s",
                    (now, authentication_context_id),
                )
        return self.get_metadata(authentication_context_id)

    def get_metadata_scoped(
        self, authentication_context_id: str, *, organization_id: str
    ) -> AuthenticationContextRecord:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        atomically scoped by ``organization_id`` in the SQL predicate
        itself -- a wrong-org lookup and a nonexistent ID raise the
        identical ``authentication_context_not_found`` error, never a
        distinguishable existence oracle. Prefer this over ``get_metadata``
        for any caller-supplied ID reaching this repository from an
        authenticated HTTP request; ``get_metadata`` itself remains for
        internal same-record fetches (``create``/``revoke``'s own
        post-write read) and ``require_bound``'s defense-in-depth mismatch
        reporting, where the ID already comes from a trusted, previously
        org-validated reference (a permit or comparison plan), not
        directly from an untrusted caller."""

        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM authentication_contexts "  # noqa: S608
                "WHERE authentication_context_id = %s AND organization_id = %s",
                (authentication_context_id, organization_id),
            ).fetchone()
        if row is None:
            raise AuthenticationContextError(
                "authentication_context_not_found", "No authentication context matches the requested ID."
            )
        return self._record_from_row(row)

    def revoke_scoped(
        self, authentication_context_id: str, *, organization_id: str, now: datetime
    ) -> AuthenticationContextRecord:
        """P1-C1: mirrors ``get_metadata_scoped``'s ownership scope --
        see that method's docstring."""

        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                "SELECT revoked_at FROM authentication_contexts "
                "WHERE authentication_context_id = %s AND organization_id = %s",
                (authentication_context_id, organization_id),
            ).fetchone()
            if row is None:
                raise AuthenticationContextError(
                    "authentication_context_not_found", "No authentication context matches the requested ID."
                )
            if row[0] is None:
                connection.execute(
                    "UPDATE authentication_contexts SET revoked_at = %s "
                    "WHERE authentication_context_id = %s AND organization_id = %s",
                    (now, authentication_context_id, organization_id),
                )
        return self.get_metadata_scoped(authentication_context_id, organization_id=organization_id)

    def require_bound(
        self,
        authentication_context_id: str,
        *,
        organization_id: str,
        target: str,
        authorization_id: str,
        now: datetime,
    ) -> AuthenticationContextRecord:
        record = self.get_metadata(authentication_context_id)
        if record.organization_id != organization_id:
            raise AuthenticationContextError(
                "authentication_context_organization_mismatch",
                "Authentication context does not belong to this organization.",
            )
        if record.target != target:
            raise AuthenticationContextError(
                "authentication_context_target_mismatch",
                "Authentication context is not bound to this target.",
            )
        if record.authorization_id != authorization_id:
            raise AuthenticationContextError(
                "authentication_context_authorization_mismatch",
                "Authentication context is not bound to this authorization.",
            )
        status = record.status_at(now)
        if status is not AuthenticationContextStatus.ACTIVE:
            raise AuthenticationContextError(
                f"authentication_context_{status.value}",
                f"Authentication context is {status.value} and cannot be used.",
            )
        return record


__all__ = ["PostgresAuthenticationContextRepository"]
