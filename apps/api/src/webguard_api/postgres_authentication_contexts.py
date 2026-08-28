"""PostgreSQL-backed authentication-context metadata repository (Slice
13 requirement 9).

Status: POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED.

Metadata only -- this class has no ``get_secret`` method and no
parameter anywhere that accepts raw credential material (password,
bearer token, API secret, session cookie). ``create()`` takes an
optional ``secret_reference_id`` -- a pointer to wherever the actual
secret will eventually live (a future KMS/secrets-manager key name) --
never the secret itself. No such production secret store exists yet;
every call in this codebase today passes ``secret_reference_id=None``,
and that is the honest, correct state until one is built (see this
slice's audit doc). The in-memory ``AuthenticationContextRepository``
(``authentication_contexts.py``) remains the only place actual secret
material is ever held, unchanged and untouched by this class.
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
from .postgres_pool import WebGuardPostgresPool

_COLUMNS = (
    "authentication_context_id, organization_id, target, authorization_id, "
    "identity_label, method, created_at, expires_at, revoked_at"
)


class PostgresAuthenticationContextRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple) -> AuthenticationContextRecord:
        (
            context_id, organization_id, target, authorization_id,
            identity_label, method, created_at, expires_at, revoked_at,
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
        with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
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
        with self._pool.connection() as connection:
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
