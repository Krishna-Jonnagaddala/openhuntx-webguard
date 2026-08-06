"""SQLite-backed organizations, principals, API tokens, and audit events."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
    TenancyContractError,
)


IDENTITY_SCHEMA_VERSION = 1
DEFAULT_TOKEN_VALIDITY_DAYS = 90
MAXIMUM_TOKEN_VALIDITY_DAYS = 366
TOKEN_PREFIX = "wgt"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


class IdentityStoreError(ValueError):
    """Controlled identity, authentication, or authorization-store failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class IssuedApiToken:
    """One-time API token result; the raw token is never persisted."""

    metadata: ApiTokenMetadata
    token: str


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _hash_secret(secret: str, *, salt: bytes | None = None) -> str:
    effective_salt = secrets.token_bytes(16) if salt is None else salt
    digest = hashlib.scrypt(
        secret.encode("utf-8"),
        salt=effective_salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(effective_salt)}${_b64(digest)}"


def _verify_secret(secret: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_text, digest_text = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        salt = _unb64(salt_text)
        expected = _unb64(digest_text)
        actual = hashlib.scrypt(
            secret.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _token_parts(token: object) -> tuple[str, str]:
    if not isinstance(token, str):
        raise IdentityStoreError("api_token_invalid", "API token is invalid.")
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not parts[2]:
        raise IdentityStoreError("api_token_invalid", "API token is invalid.")
    try:
        metadata = ApiTokenMetadata(
            token_id=parts[1],
            organization_id="00000000-0000-0000-0000-000000000000",
            principal_id="00000000-0000-0000-0000-000000000000",
            label="validation",
            created_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2000, 1, 2, tzinfo=timezone.utc),
        )
    except TenancyContractError as exc:
        raise IdentityStoreError("api_token_invalid", "API token is invalid.") from exc
    return metadata.token_id, parts[2]


class IdentityStore:
    """Persistent tenant identity and access-control metadata."""

    def __init__(self, database_path: Path) -> None:
        self.path = Path(database_path).expanduser()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        if not self.path.is_file():
            raise IdentityStoreError(
                "identity_database_missing",
                "Initialize the scan-job database before the identity store.",
            )
        connection = self._connect()
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS identity_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS organizations (
                    organization_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    name_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS principals (
                    principal_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    principal_type TEXT NOT NULL,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (organization_id) REFERENCES organizations(organization_id)
                );
                CREATE INDEX IF NOT EXISTS idx_principals_organization
                    ON principals(organization_id, active, role);
                CREATE TABLE IF NOT EXISTS api_tokens (
                    token_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    secret_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    last_used_at TEXT,
                    FOREIGN KEY (organization_id) REFERENCES organizations(organization_id),
                    FOREIGN KEY (principal_id) REFERENCES principals(principal_id)
                );
                CREATE INDEX IF NOT EXISTS idx_api_tokens_principal
                    ON api_tokens(principal_id, revoked_at, expires_at);
                CREATE TABLE IF NOT EXISTS organization_authorizations (
                    organization_id TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    assigned_by TEXT NOT NULL,
                    assigned_at TEXT NOT NULL,
                    PRIMARY KEY (organization_id, authorization_id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(organization_id),
                    FOREIGN KEY (assigned_by) REFERENCES principals(principal_id)
                );
                CREATE TABLE IF NOT EXISTS security_audit_events (
                    event_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    organization_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    token_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    detail_code TEXT,
                    FOREIGN KEY (organization_id) REFERENCES organizations(organization_id),
                    FOREIGN KEY (principal_id) REFERENCES principals(principal_id),
                    FOREIGN KEY (token_id) REFERENCES api_tokens(token_id)
                );
                CREATE INDEX IF NOT EXISTS idx_security_audit_org_time
                    ON security_audit_events(organization_id, occurred_at DESC, event_id DESC);
                INSERT OR IGNORE INTO identity_metadata(key, value)
                    VALUES ('schema_version', '1');
                COMMIT;
                """
            )
            row = connection.execute(
                "SELECT value FROM identity_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or int(row["value"]) != IDENTITY_SCHEMA_VERSION:
                raise IdentityStoreError(
                    "identity_schema_unsupported",
                    "The identity-store schema version is unsupported.",
                )
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise IdentityStoreError(
                "identity_initialize_failed",
                "Unable to initialize identity and RBAC tables.",
            ) from exc
        finally:
            connection.close()
        os.chmod(self.path, 0o600)

    @staticmethod
    def _organization(row: sqlite3.Row) -> Organization:
        created_at = _parse_timestamp(row["created_at"])
        assert created_at is not None
        return Organization(
            organization_id=row["organization_id"],
            name=row["name"],
            status=OrganizationStatus(row["status"]),
            created_at=created_at,
        )

    @staticmethod
    def _principal(row: sqlite3.Row) -> Principal:
        created_at = _parse_timestamp(row["created_at"])
        assert created_at is not None
        return Principal(
            principal_id=row["principal_id"],
            organization_id=row["organization_id"],
            display_name=row["display_name"],
            principal_type=PrincipalType(row["principal_type"]),
            role=OrganizationRole(row["role"]),
            active=bool(row["active"]),
            created_at=created_at,
        )

    @staticmethod
    def _token_metadata(row: sqlite3.Row) -> ApiTokenMetadata:
        created_at = _parse_timestamp(row["created_at"])
        expires_at = _parse_timestamp(row["expires_at"])
        assert created_at is not None and expires_at is not None
        return ApiTokenMetadata(
            token_id=row["token_id"],
            organization_id=row["organization_id"],
            principal_id=row["principal_id"],
            label=row["label"],
            created_at=created_at,
            expires_at=expires_at,
            revoked_at=_parse_timestamp(row["revoked_at"]),
            last_used_at=_parse_timestamp(row["last_used_at"]),
        )

    def create_organization(
        self,
        name: str,
        *,
        now: datetime,
        organization_id: str | None = None,
    ) -> Organization:
        value = Organization(
            organization_id=str(uuid4()) if organization_id is None else organization_id,
            name=name,
            status=OrganizationStatus.ACTIVE,
            created_at=now,
        )
        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO organizations VALUES (?, ?, ?, ?, ?)",
                (
                    value.organization_id,
                    value.name,
                    value.name.casefold(),
                    value.status.value,
                    _timestamp(value.created_at),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError(
                "organization_conflict",
                "An organization with that identifier or name already exists.",
            ) from exc
        finally:
            connection.close()
        return value

    def get_organization(self, organization_id: str) -> Organization:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM organizations WHERE organization_id = ?",
                (organization_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise IdentityStoreError("organization_not_found", "Organization was not found.")
        return self._organization(row)

    def create_principal(
        self,
        organization_id: str,
        display_name: str,
        *,
        principal_type: PrincipalType,
        role: OrganizationRole,
        now: datetime,
        principal_id: str | None = None,
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
        )
        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO principals VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    value.principal_id,
                    value.organization_id,
                    value.display_name,
                    value.principal_type.value,
                    value.role.value,
                    1,
                    _timestamp(value.created_at),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError("principal_conflict", "Principal already exists.") from exc
        finally:
            connection.close()
        return value

    def get_principal(self, principal_id: str) -> Principal:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM principals WHERE principal_id = ?", (principal_id,)
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise IdentityStoreError("principal_not_found", "Principal was not found.")
        return self._principal(row)

    def create_token(
        self,
        principal_id: str,
        *,
        label: str,
        now: datetime,
        validity_days: int = DEFAULT_TOKEN_VALIDITY_DAYS,
        token_id: str | None = None,
    ) -> IssuedApiToken:
        if isinstance(validity_days, bool) or not isinstance(validity_days, int) or not 1 <= validity_days <= MAXIMUM_TOKEN_VALIDITY_DAYS:
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
        raw = f"{TOKEN_PREFIX}_{effective_id}_{secret}"
        metadata = ApiTokenMetadata(
            token_id=effective_id,
            organization_id=principal.organization_id,
            principal_id=principal.principal_id,
            label=label,
            created_at=now,
            expires_at=now + timedelta(days=validity_days),
        )
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO api_tokens (
                    token_id, organization_id, principal_id, label, secret_hash,
                    created_at, expires_at, revoked_at, last_used_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    metadata.token_id,
                    metadata.organization_id,
                    metadata.principal_id,
                    metadata.label,
                    _hash_secret(secret),
                    _timestamp(metadata.created_at),
                    _timestamp(metadata.expires_at),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError("api_token_conflict", "API token already exists.") from exc
        finally:
            connection.close()
        return IssuedApiToken(metadata=metadata, token=raw)

    def authenticate_token(self, token: object, *, now: datetime) -> tuple[ApiTokenMetadata, Principal, Organization]:
        token_id, secret = _token_parts(token)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM api_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if row is None or not _verify_secret(secret, row["secret_hash"]):
                raise IdentityStoreError("api_token_invalid", "API token is invalid.")
            metadata = self._token_metadata(row)
            if metadata.revoked_at is not None:
                raise IdentityStoreError("api_token_revoked", "API token has been revoked.")
            if now.astimezone(timezone.utc) >= metadata.expires_at:
                raise IdentityStoreError("api_token_expired", "API token has expired.")
            principal_row = connection.execute(
                "SELECT * FROM principals WHERE principal_id = ?", (metadata.principal_id,)
            ).fetchone()
            organization_row = connection.execute(
                "SELECT * FROM organizations WHERE organization_id = ?",
                (metadata.organization_id,),
            ).fetchone()
            if principal_row is None or organization_row is None:
                raise IdentityStoreError("api_token_invalid", "API token is invalid.")
            principal = self._principal(principal_row)
            organization = self._organization(organization_row)
            if not principal.active:
                raise IdentityStoreError("principal_disabled", "Principal is disabled.")
            if organization.status is not OrganizationStatus.ACTIVE:
                raise IdentityStoreError("organization_disabled", "Organization is disabled.")
            connection.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE token_id = ?",
                (_timestamp(now), token_id),
            )
        finally:
            connection.close()
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
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM api_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if row is None:
                raise IdentityStoreError("api_token_not_found", "API token was not found.")
            metadata = self._token_metadata(row)
            if metadata.revoked_at is None:
                connection.execute(
                    "UPDATE api_tokens SET revoked_at = ? WHERE token_id = ?",
                    (_timestamp(now), token_id),
                )
                metadata = ApiTokenMetadata(
                    token_id=metadata.token_id,
                    organization_id=metadata.organization_id,
                    principal_id=metadata.principal_id,
                    label=metadata.label,
                    created_at=metadata.created_at,
                    expires_at=metadata.expires_at,
                    revoked_at=now,
                    last_used_at=metadata.last_used_at,
                )
            return metadata
        finally:
            connection.close()

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
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT OR IGNORE INTO organization_authorizations
                    (organization_id, authorization_id, assigned_by, assigned_at)
                VALUES (?, ?, ?, ?)
                """,
                (organization_id, authorization_id, assigned_by, _timestamp(now)),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError(
                "authorization_assignment_invalid",
                "Unable to assign the authorization to the organization.",
            ) from exc
        finally:
            connection.close()

    def authorization_is_assigned(self, organization_id: str, authorization_id: str) -> bool:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT 1 FROM organization_authorizations
                WHERE organization_id = ? AND authorization_id = ?
                """,
                (organization_id, authorization_id),
            ).fetchone()
            return row is not None
        finally:
            connection.close()

    def record_audit_event(self, event: SecurityAuditEvent) -> None:
        if not isinstance(event, SecurityAuditEvent):
            raise IdentityStoreError("audit_event_invalid", "event must be a SecurityAuditEvent.")
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO security_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    _timestamp(event.occurred_at),
                    event.detail_code,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError("audit_event_conflict", "Audit event already exists.") from exc
        finally:
            connection.close()

    def list_audit_events(self, organization_id: str, *, limit: int = 100) -> tuple[SecurityAuditEvent, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise IdentityStoreError("audit_limit_invalid", "Audit limit must be from 1 to 500.")
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM security_audit_events
                WHERE organization_id = ?
                ORDER BY occurred_at DESC, event_id DESC
                LIMIT ?
                """,
                (organization_id, limit),
            ).fetchall()
        finally:
            connection.close()
        return tuple(
            SecurityAuditEvent(
                event_id=row["event_id"],
                request_id=row["request_id"],
                organization_id=row["organization_id"],
                principal_id=row["principal_id"],
                token_id=row["token_id"],
                action=row["action"],
                resource_type=row["resource_type"],
                resource_id=row["resource_id"],
                outcome=AuditOutcome(row["outcome"]),
                occurred_at=_parse_timestamp(row["occurred_at"]),
                detail_code=row["detail_code"],
            )
            for row in rows
        )


__all__ = [
    "DEFAULT_TOKEN_VALIDITY_DAYS",
    "IDENTITY_SCHEMA_VERSION",
    "IdentityStore",
    "IdentityStoreError",
    "IssuedApiToken",
    "MAXIMUM_TOKEN_VALIDITY_DAYS",
    "TOKEN_PREFIX",
]
