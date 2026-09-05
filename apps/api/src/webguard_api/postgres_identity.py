"""PostgreSQL-backed identity, RBAC, and audit repository (Slice 12
requirement 4/9). Satisfies the same ``IdentityRepository`` protocol
as the existing SQLite ``IdentityStore`` -- same method names, same
signatures, same error codes on the same failure conditions -- so
contract tests can run unmodified against either backend, and so
callers never need a backend-specific branch.

Password/token-secret hashing reuses ``identity.py``'s own
``_hash_secret``/``_verify_secret``/``_token_parts`` helpers rather
than reimplementing scrypt parameters a second time -- there must be
exactly one reviewed implementation of that logic in this codebase,
not two that could quietly drift apart.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from webguard_contracts import (
    ApiTokenMetadata,
    AuditOutcome,
    Organization,
    OrganizationRole,
    OrganizationStatus,
    Principal,
    PrincipalType,
    SecurityAuditEvent,
)

from .db_errors import DatabaseIntegrityError
from .identity import (
    DEFAULT_TOKEN_VALIDITY_DAYS,
    IDENTITY_TOKEN_PREFIX,
    MAXIMUM_TOKEN_VALIDITY_DAYS,
    IdentityStoreError,
    IdentityTokenPurpose,
    IdentityTokenRecord,
    IssuedApiToken,
    IssuedIdentityToken,
    _hash_secret,
    _parse_prefixed_secret,
    _token_parts,
    _verify_secret,
)
from .postgres_pool import WebGuardPostgresPool


class PostgresIdentityRepository:
    """Production identity store. Every method mirrors
    ``IdentityStore``'s behavior and error codes; the only intended
    difference is durability across a restart and safety under
    concurrent writers across multiple hosts (SQLite's single-file
    design supports neither)."""

    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    def create_organization(
        self, name: str, *, now: datetime, organization_id: str | None = None
    ) -> Organization:
        value = Organization(
            organization_id=str(uuid4()) if organization_id is None else organization_id,
            name=name,
            status=OrganizationStatus.ACTIVE,
            created_at=now,
        )
        try:
            with self._pool.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO organizations (organization_id, name, name_key, status, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        value.organization_id,
                        value.name,
                        value.name.casefold(),
                        value.status.value,
                        value.created_at,
                    ),
                )
        except DatabaseIntegrityError as exc:
            raise IdentityStoreError(
                "organization_conflict",
                "An organization with that identifier or name already exists.",
            ) from exc
        return value

    def get_organization(self, organization_id: str) -> Organization:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT organization_id, name, status, created_at
                FROM organizations WHERE organization_id = %s
                """,
                (organization_id,),
            ).fetchone()
        if row is None:
            raise IdentityStoreError("organization_not_found", "Organization was not found.")
        return Organization(
            organization_id=str(row[0]),
            name=row[1],
            status=OrganizationStatus(row[2]),
            created_at=row[3].astimezone(timezone.utc),
        )

    _PRINCIPAL_COLUMNS = (
        "principal_id, organization_id, display_name, principal_type, role, active, created_at, "
        "email, email_verified_at, last_login_at"
    )

    def create_principal(
        self,
        organization_id: str,
        display_name: str,
        *,
        principal_type: PrincipalType,
        role: OrganizationRole,
        now: datetime,
        principal_id: str | None = None,
        email: str | None = None,
    ) -> Principal:
        organization = self.get_organization(organization_id)
        if organization.status is not OrganizationStatus.ACTIVE:
            raise IdentityStoreError("organization_disabled", "Organization is disabled.")
        value = Principal(
            principal_id=str(uuid4()) if principal_id is None else principal_id,
            organization_id=organization.organization_id,
            display_name=display_name,
            principal_type=principal_type,
            role=role,
            active=True,
            created_at=now,
            email=email,
        )
        try:
            with self._pool.connection() as connection:
                with connection.transaction():
                    connection.execute(
                        """
                        INSERT INTO principals
                            (principal_id, organization_id, display_name, principal_type, role, active, created_at, email)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            value.principal_id,
                            value.organization_id,
                            value.display_name,
                            value.principal_type.value,
                            value.role.value,
                            True,
                            value.created_at,
                            value.email,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO memberships
                            (membership_id, organization_id, principal_id, role, assigned_by, assigned_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            str(uuid4()),
                            value.organization_id,
                            value.principal_id,
                            value.role.value,
                            value.principal_id,
                            value.created_at,
                        ),
                    )
        except DatabaseIntegrityError as exc:
            if value.email is not None:
                raise IdentityStoreError(
                    "principal_email_conflict",
                    "An account with that email address already exists.",
                ) from exc
            raise IdentityStoreError(
                "principal_conflict", "Principal already exists."
            ) from exc
        return value

    def get_principal(self, principal_id: str) -> Principal:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {self._PRINCIPAL_COLUMNS} FROM principals WHERE principal_id = %s",  # noqa: S608
                (principal_id,),
            ).fetchone()
        if row is None:
            raise IdentityStoreError("principal_not_found", "Principal was not found.")
        return self._principal_from_row(row)

    def get_principal_by_email(self, email: str) -> Principal | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {self._PRINCIPAL_COLUMNS} FROM principals WHERE email = %s",  # noqa: S608
                (email.strip().casefold(),),
            ).fetchone()
        return None if row is None else self._principal_from_row(row)

    @staticmethod
    def _principal_from_row(row: tuple) -> Principal:
        return Principal(
            principal_id=str(row[0]),
            organization_id=str(row[1]),
            display_name=row[2],
            principal_type=PrincipalType(row[3]),
            role=OrganizationRole(row[4]),
            active=bool(row[5]),
            created_at=row[6].astimezone(timezone.utc),
            email=row[7],
            email_verified_at=row[8].astimezone(timezone.utc) if row[8] else None,
            last_login_at=row[9].astimezone(timezone.utc) if row[9] else None,
        )

    def get_principal_scoped(self, principal_id: str, *, organization_id: str) -> Principal:
        principal = self.get_principal(principal_id)
        if principal.organization_id != organization_id:
            raise IdentityStoreError("principal_not_found", "Principal was not found.")
        return principal

    def list_principals(self, organization_id: str) -> tuple[Principal, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"SELECT {self._PRINCIPAL_COLUMNS} FROM principals WHERE organization_id = %s ORDER BY created_at",  # noqa: S608
                (organization_id,),
            ).fetchall()
        return tuple(self._principal_from_row(row) for row in rows)

    def update_principal_role(
        self, principal_id: str, *, organization_id: str, role: OrganizationRole, now: datetime
    ) -> Principal:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        ``get_principal_scoped`` already fails closed before this method
        ever reaches the mutation, and ``organization_id`` is never
        updated anywhere on ``principals`` (immutable post-creation, like
        ``scan_jobs.organization_id``), so there was never a TOCTOU
        window in practice -- but the ``UPDATE`` predicate itself now
        also carries ``organization_id`` directly, so this mutation is
        atomically self-scoped and does not rely on a separate
        preceding call or on that invariant holding forever."""

        principal = self.get_principal_scoped(principal_id, organization_id=organization_id)
        with self._pool.connection() as connection:
            connection.execute(
                "UPDATE principals SET role = %s WHERE principal_id = %s AND organization_id = %s",
                (role.value, principal_id, organization_id),
            )
        return Principal(
            principal_id=principal.principal_id,
            organization_id=principal.organization_id,
            display_name=principal.display_name,
            principal_type=principal.principal_type,
            role=role,
            active=principal.active,
            created_at=principal.created_at,
            email=principal.email,
            email_verified_at=principal.email_verified_at,
            last_login_at=principal.last_login_at,
        )

    def set_principal_active(
        self, principal_id: str, *, organization_id: str, active: bool, now: datetime
    ) -> Principal:
        """P1-C1: mirrors ``update_principal_role``'s atomic-mutation
        fix -- see that method's docstring."""

        principal = self.get_principal_scoped(principal_id, organization_id=organization_id)
        with self._pool.connection() as connection:
            connection.execute(
                "UPDATE principals SET active = %s WHERE principal_id = %s AND organization_id = %s",
                (active, principal_id, organization_id),
            )
        return Principal(
            principal_id=principal.principal_id,
            organization_id=principal.organization_id,
            display_name=principal.display_name,
            principal_type=principal.principal_type,
            role=principal.role,
            active=active,
            created_at=principal.created_at,
            email=principal.email,
            email_verified_at=principal.email_verified_at,
            last_login_at=principal.last_login_at,
        )

    def set_principal_email_verified(self, principal_id: str, *, now: datetime) -> Principal:
        principal = self.get_principal(principal_id)
        with self._pool.connection() as connection:
            connection.execute(
                "UPDATE principals SET email_verified_at = %s WHERE principal_id = %s",
                (now, principal_id),
            )
        return Principal(
            principal_id=principal.principal_id,
            organization_id=principal.organization_id,
            display_name=principal.display_name,
            principal_type=principal.principal_type,
            role=principal.role,
            active=principal.active,
            created_at=principal.created_at,
            email=principal.email,
            email_verified_at=now,
            last_login_at=principal.last_login_at,
        )

    def touch_last_login(self, principal_id: str, *, now: datetime) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "UPDATE principals SET last_login_at = %s WHERE principal_id = %s",
                (now, principal_id),
            )

    def set_password_hash(self, principal_id: str, *, algorithm: str, password_hash: str, now: datetime) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (principal_id) DO UPDATE SET
                    algorithm = EXCLUDED.algorithm,
                    password_hash = EXCLUDED.password_hash,
                    updated_at = EXCLUDED.updated_at
                """,
                (principal_id, algorithm, password_hash, now, now),
            )

    def get_password_hash(self, principal_id: str) -> str | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT password_hash FROM password_credentials WHERE principal_id = %s",
                (principal_id,),
            ).fetchone()
        return None if row is None else row[0]

    def create_identity_token(
        self,
        principal_id: str,
        organization_id: str,
        *,
        purpose: IdentityTokenPurpose,
        ttl: timedelta,
        now: datetime,
    ) -> IssuedIdentityToken:
        token_id = str(uuid4())
        secret = secrets.token_urlsafe(32)
        raw = f"{IDENTITY_TOKEN_PREFIX}_{token_id}_{secret}"
        expires_at = now + ttl
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO identity_tokens
                    (token_id, principal_id, organization_id, purpose, secret_hash, created_at, expires_at, used_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NULL)
                """,
                (token_id, principal_id, organization_id, purpose.value, _hash_secret(secret), now, expires_at),
            )
        record = IdentityTokenRecord(
            token_id=token_id,
            principal_id=principal_id,
            organization_id=organization_id,
            purpose=purpose,
            created_at=now,
            expires_at=expires_at,
        )
        return IssuedIdentityToken(record=record, token=raw)

    def consume_identity_token(
        self, token: object, *, purpose: IdentityTokenPurpose, now: datetime
    ) -> IdentityTokenRecord:
        token_id, secret = _parse_prefixed_secret(
            token, prefix=IDENTITY_TOKEN_PREFIX, error_code="identity_token_invalid"
        )
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT token_id, principal_id, organization_id, purpose, secret_hash,
                       created_at, expires_at, used_at
                FROM identity_tokens WHERE token_id = %s
                """,
                (token_id,),
            ).fetchone()
            if row is None or not _verify_secret(secret, row[4]):
                raise IdentityStoreError("identity_token_invalid", "Token is invalid.")
            if row[3] != purpose.value:
                raise IdentityStoreError("identity_token_invalid", "Token is invalid.")
            if row[7] is not None:
                raise IdentityStoreError("identity_token_used", "Token has already been used.")
            expires_at = row[6].astimezone(timezone.utc)
            if now.astimezone(timezone.utc) >= expires_at:
                raise IdentityStoreError("identity_token_expired", "Token has expired.")
            connection.execute(
                "UPDATE identity_tokens SET used_at = %s WHERE token_id = %s",
                (now, token_id),
            )
        return IdentityTokenRecord(
            token_id=str(row[0]),
            principal_id=str(row[1]),
            organization_id=str(row[2]),
            purpose=IdentityTokenPurpose(row[3]),
            created_at=row[5].astimezone(timezone.utc),
            expires_at=expires_at,
            used_at=now,
        )

    def invalidate_identity_tokens(
        self, principal_id: str, *, purpose: IdentityTokenPurpose, now: datetime
    ) -> None:
        """Mark every still-usable token of this purpose for this
        principal as used, without needing its secret -- used when a new
        token supersedes an older, still-pending one (e.g. requesting a
        second password reset invalidates the first)."""

        with self._pool.connection() as connection:
            connection.execute(
                """
                UPDATE identity_tokens SET used_at = %s
                WHERE principal_id = %s AND purpose = %s AND used_at IS NULL
                """,
                (now, principal_id, purpose.value),
            )

    def list_tokens_for_principal(self, principal_id: str) -> tuple[ApiTokenMetadata, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT token_id, organization_id, principal_id, label,
                       created_at, expires_at, revoked_at, last_used_at
                FROM api_tokens WHERE principal_id = %s ORDER BY created_at DESC
                """,
                (principal_id,),
            ).fetchall()
        return tuple(
            ApiTokenMetadata(
                token_id=str(row[0]),
                organization_id=str(row[1]),
                principal_id=str(row[2]),
                label=row[3],
                created_at=row[4].astimezone(timezone.utc),
                expires_at=row[5].astimezone(timezone.utc),
                revoked_at=row[6].astimezone(timezone.utc) if row[6] else None,
                last_used_at=row[7].astimezone(timezone.utc) if row[7] else None,
            )
            for row in rows
        )

    def revoke_token_owned(self, token_id: str, *, principal_id: str, now: datetime) -> ApiTokenMetadata:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT token_id, organization_id, principal_id, label,
                       created_at, expires_at, revoked_at, last_used_at
                FROM api_tokens WHERE token_id = %s
                """,
                (token_id,),
            ).fetchone()
            if row is None or str(row[2]) != principal_id:
                raise IdentityStoreError("api_token_not_found", "API token was not found.")
            revoked_at = row[6]
            if revoked_at is None:
                connection.execute(
                    "UPDATE api_tokens SET revoked_at = %s WHERE token_id = %s", (now, token_id)
                )
                revoked_at = now
            else:
                revoked_at = revoked_at.astimezone(timezone.utc)
        return ApiTokenMetadata(
            token_id=str(row[0]),
            organization_id=str(row[1]),
            principal_id=str(row[2]),
            label=row[3],
            created_at=row[4].astimezone(timezone.utc),
            expires_at=row[5].astimezone(timezone.utc),
            revoked_at=revoked_at,
            last_used_at=row[7].astimezone(timezone.utc) if row[7] else None,
        )

    def create_token(
        self,
        principal_id: str,
        *,
        label: str,
        now: datetime,
        validity_days: int = DEFAULT_TOKEN_VALIDITY_DAYS,
        token_id: str | None = None,
    ) -> IssuedApiToken:
        if (
            isinstance(validity_days, bool)
            or not isinstance(validity_days, int)
            or not 1 <= validity_days <= MAXIMUM_TOKEN_VALIDITY_DAYS
        ):
            raise IdentityStoreError(
                "token_validity_invalid",
                f"Token validity must be from 1 to {MAXIMUM_TOKEN_VALIDITY_DAYS} days.",
            )
        principal = self.get_principal(principal_id)
        if not principal.active:
            raise IdentityStoreError("principal_disabled", "Principal is disabled.")
        organization = self.get_organization(principal.organization_id)
        if organization.status is not OrganizationStatus.ACTIVE:
            raise IdentityStoreError("organization_disabled", "Organization is disabled.")
        effective_id = str(uuid4()) if token_id is None else token_id
        secret = secrets.token_urlsafe(32)
        raw = f"wgt_{effective_id}_{secret}"
        metadata = ApiTokenMetadata(
            token_id=effective_id,
            organization_id=principal.organization_id,
            principal_id=principal.principal_id,
            label=label,
            created_at=now,
            expires_at=now + timedelta(days=validity_days),
        )
        try:
            with self._pool.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO api_tokens
                        (token_id, organization_id, principal_id, label, secret_hash, created_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        metadata.token_id,
                        metadata.organization_id,
                        metadata.principal_id,
                        metadata.label,
                        _hash_secret(secret),
                        metadata.created_at,
                        metadata.expires_at,
                    ),
                )
        except DatabaseIntegrityError as exc:
            raise IdentityStoreError(
                "api_token_conflict", "API token already exists."
            ) from exc
        return IssuedApiToken(metadata=metadata, token=raw)

    def authenticate_token(
        self, token: object, *, now: datetime
    ) -> tuple[ApiTokenMetadata, Principal, Organization]:
        token_id, secret = _token_parts(token)
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT token_id, organization_id, principal_id, label, secret_hash,
                       created_at, expires_at, revoked_at, last_used_at
                FROM api_tokens WHERE token_id = %s
                """,
                (token_id,),
            ).fetchone()
            if row is None or not _verify_secret(secret, row[4]):
                raise IdentityStoreError("api_token_invalid", "API token is invalid.")
            metadata = ApiTokenMetadata(
                token_id=str(row[0]),
                organization_id=str(row[1]),
                principal_id=str(row[2]),
                label=row[3],
                created_at=row[5].astimezone(timezone.utc),
                expires_at=row[6].astimezone(timezone.utc),
                revoked_at=row[7].astimezone(timezone.utc) if row[7] else None,
                last_used_at=row[8].astimezone(timezone.utc) if row[8] else None,
            )
            if metadata.revoked_at is not None:
                raise IdentityStoreError("api_token_revoked", "API token has been revoked.")
            if now.astimezone(timezone.utc) >= metadata.expires_at:
                raise IdentityStoreError("api_token_expired", "API token has expired.")
            principal_row = connection.execute(
                f"SELECT {self._PRINCIPAL_COLUMNS} FROM principals WHERE principal_id = %s",  # noqa: S608
                (metadata.principal_id,),
            ).fetchone()
            organization_row = connection.execute(
                """
                SELECT organization_id, name, status, created_at
                FROM organizations WHERE organization_id = %s
                """,
                (metadata.organization_id,),
            ).fetchone()
            if principal_row is None or organization_row is None:
                raise IdentityStoreError("api_token_invalid", "API token is invalid.")
            principal = self._principal_from_row(principal_row)
            organization = Organization(
                organization_id=str(organization_row[0]),
                name=organization_row[1],
                status=OrganizationStatus(organization_row[2]),
                created_at=organization_row[3].astimezone(timezone.utc),
            )
            if not principal.active:
                raise IdentityStoreError("principal_disabled", "Principal is disabled.")
            if organization.status is not OrganizationStatus.ACTIVE:
                raise IdentityStoreError("organization_disabled", "Organization is disabled.")
            connection.execute(
                "UPDATE api_tokens SET last_used_at = %s WHERE token_id = %s",
                (now, token_id),
            )
        updated = ApiTokenMetadata(
            token_id=metadata.token_id,
            organization_id=metadata.organization_id,
            principal_id=metadata.principal_id,
            label=metadata.label,
            created_at=metadata.created_at,
            expires_at=metadata.expires_at,
            revoked_at=metadata.revoked_at,
            last_used_at=now,
        )
        return updated, principal, organization

    def revoke_token(self, token_id: str, *, now: datetime) -> ApiTokenMetadata:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT token_id, organization_id, principal_id, label,
                       created_at, expires_at, revoked_at, last_used_at
                FROM api_tokens WHERE token_id = %s
                """,
                (token_id,),
            ).fetchone()
            if row is None:
                raise IdentityStoreError("api_token_not_found", "API token was not found.")
            revoked_at = row[6]
            if revoked_at is None:
                connection.execute(
                    "UPDATE api_tokens SET revoked_at = %s WHERE token_id = %s",
                    (now, token_id),
                )
                revoked_at = now
            else:
                revoked_at = revoked_at.astimezone(timezone.utc)
        return ApiTokenMetadata(
            token_id=str(row[0]),
            organization_id=str(row[1]),
            principal_id=str(row[2]),
            label=row[3],
            created_at=row[4].astimezone(timezone.utc),
            expires_at=row[5].astimezone(timezone.utc),
            revoked_at=revoked_at,
            last_used_at=row[7].astimezone(timezone.utc) if row[7] else None,
        )

    def assign_authorization(
        self,
        organization_id: str,
        authorization_id: str,
        *,
        assigned_by: str,
        now: datetime,
    ) -> None:
        principal = self.get_principal(assigned_by)
        if principal.organization_id != organization_id:
            raise IdentityStoreError(
                "cross_tenant_assignment_rejected",
                "The assigning principal does not belong to the organization.",
            )
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO organization_authorizations
                    (organization_id, authorization_id, assigned_by, assigned_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (organization_id, authorization_id) DO NOTHING
                """,
                (organization_id, authorization_id, assigned_by, now),
            )

    def authorization_is_assigned(self, organization_id: str, authorization_id: str) -> bool:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM organization_authorizations
                WHERE organization_id = %s AND authorization_id = %s
                """,
                (organization_id, authorization_id),
            ).fetchone()
            return row is not None

    def list_assigned_authorization_ids(self, organization_id: str) -> tuple[str, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                "SELECT authorization_id FROM organization_authorizations WHERE organization_id = %s",
                (organization_id,),
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def record_audit_event(self, event: SecurityAuditEvent) -> None:
        if not isinstance(event, SecurityAuditEvent):
            raise IdentityStoreError("audit_event_invalid", "event must be a SecurityAuditEvent.")
        try:
            with self._pool.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO security_audit_events
                        (event_id, request_id, organization_id, principal_id, token_id,
                         action, resource_type, resource_id, outcome, occurred_at, detail_code)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        event.event_id,
                        event.request_id,
                        event.organization_id,
                        event.principal_id,
                        event.token_id,
                        event.action,
                        event.resource_type,
                        event.resource_id,
                        event.outcome.value,
                        event.occurred_at,
                        event.detail_code,
                    ),
                )
        except DatabaseIntegrityError as exc:
            raise IdentityStoreError(
                "audit_event_conflict", "Audit event already exists."
            ) from exc

    def list_audit_events_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        outcome: AuditOutcome | None = None,
    ) -> tuple[tuple[SecurityAuditEvent, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise IdentityStoreError(
                "audit_limit_invalid", "Audit limit must be from 1 to 100."
            )
        clauses = ["organization_id = %s"]
        parameters: list[object] = [organization_id]
        if outcome is not None:
            if not isinstance(outcome, AuditOutcome):
                raise IdentityStoreError(
                    "audit_outcome_invalid", "Audit outcome filter is invalid."
                )
            clauses.append("outcome = %s")
            parameters.append(outcome.value)
        if after is not None:
            if (
                not isinstance(after, tuple)
                or len(after) != 2
                or not all(isinstance(value, str) and value for value in after)
            ):
                raise IdentityStoreError(
                    "audit_cursor_invalid", "Audit cursor position is invalid."
                )
            clauses.append("(occurred_at < %s OR (occurred_at = %s AND event_id < %s))")
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT event_id, request_id, organization_id, principal_id, token_id,
                       action, resource_type, resource_id, outcome, occurred_at, detail_code
                FROM security_audit_events
                WHERE {' AND '.join(clauses)}
                ORDER BY occurred_at DESC, event_id DESC
                LIMIT %s
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        has_more = len(rows) > limit
        events = tuple(self._audit_event_from_row(row) for row in rows[:limit])
        return events, has_more

    @staticmethod
    def _audit_event_from_row(row: tuple) -> SecurityAuditEvent:
        return SecurityAuditEvent(
            event_id=str(row[0]),
            request_id=row[1],
            organization_id=str(row[2]),
            principal_id=str(row[3]),
            token_id=str(row[4]),
            action=row[5],
            resource_type=row[6],
            resource_id=row[7],
            outcome=AuditOutcome(row[8]),
            occurred_at=row[9].astimezone(timezone.utc),
            detail_code=row[10],
        )

    def list_audit_events(
        self, organization_id: str, *, limit: int = 100
    ) -> tuple[SecurityAuditEvent, ...]:
        events, _ = self.list_audit_events_page(organization_id, limit=min(limit, 100))
        return events


__all__ = ["PostgresIdentityRepository"]
