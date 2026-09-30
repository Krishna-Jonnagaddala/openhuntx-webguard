"""Authentication-context metadata and secret storage for authenticated
scanning (Slice 7).

Two deliberately separate stores behind one repository object:

- **Metadata** (`AuthenticationContextRecord`): organization/target/
  authorization binding, identity label, method, timestamps, status.
  Contains no secret material whatsoever -- safe to log, audit, return
  over the API, and serialize.
- **Secret material** (`webguard_scanner.authentication.AuthenticationMaterial`):
  the actual bearer token / session cookies / basic-auth credentials.
  Looked up separately, by the same ID, and never joined onto the
  metadata record. Nothing in this module ever returns both together.

This slice's implementation is deliberately **in-memory only**, for two
reasons stated directly rather than left implicit: (1) secret material
must never be written to SQLite or a plain file as a substitute for real
KMS/encrypted-secret-manager storage -- an in-memory store is honest
about not solving that problem rather than pretending a local file is
"good enough for now," and (2) the project's own stated production
sequencing defers a PostgreSQL-backed metadata redesign to a later,
dedicated slice; building a throwaway SQLite schema for authentication-
context metadata now would just be rework. Both stores share this
repository's one interface, so a future persistent metadata store and a
future KMS-backed secret store can each replace their half without
touching any caller.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from webguard_scanner.authentication import AuthenticationMaterial


class AuthenticationContextError(ValueError):
    """Controlled authentication-context failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AuthenticationMethod(str, Enum):
    BEARER_TOKEN = "bearer_token"  # noqa: S105 - an enum tag, not a credential
    COOKIE_SESSION = "cookie_session"
    BASIC_AUTH = "basic_auth"
    LOGIN_WORKFLOW = "login_workflow"


class AuthenticationContextStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class AuthenticationContextRecord:
    """Authentication-context metadata. Contains no secret material --
    safe to log, audit, and return over the API as-is."""

    authentication_context_id: str
    organization_id: str
    target: str
    authorization_id: str
    identity_label: str
    method: AuthenticationMethod
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    # Slice 14 requirement 1: a pointer to where a SecretProvider should
    # resolve real secret material -- never the secret itself. None in
    # every local/dev/test/lab context (the in-memory repository below
    # keeps the secret directly, keyed by this record's own ID) and in
    # every context created before this field existed.
    secret_reference_id: str | None = None

    def status_at(self, now: datetime) -> AuthenticationContextStatus:
        if self.revoked_at is not None:
            return AuthenticationContextStatus.REVOKED
        if now >= self.expires_at:
            return AuthenticationContextStatus.EXPIRED
        return AuthenticationContextStatus.ACTIVE

    def to_public_dict(self, *, now: datetime) -> dict[str, object]:
        return {
            "authentication_context_id": self.authentication_context_id,
            "organization_id": self.organization_id,
            "target": self.target,
            "authorization_id": self.authorization_id,
            "identity_label": self.identity_label,
            "method": self.method.value,
            "status": self.status_at(now).value,
            "created_at": self.created_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "expires_at": self.expires_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "revoked_at": None
            if self.revoked_at is None
            else self.revoked_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        }


class AuthenticationContextRepository:
    """In-memory metadata + secret storage, keyed identically but stored
    in two separate dicts so a caller reading metadata physically cannot
    also receive secret material from the same call."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._metadata: dict[str, AuthenticationContextRecord] = {}
        self._secrets: dict[str, AuthenticationMaterial] = {}

    def create(
        self,
        *,
        organization_id: str,
        target: str,
        authorization_id: str,
        identity_label: str,
        method: AuthenticationMethod,
        secret: AuthenticationMaterial,
        expires_at: datetime,
        now: datetime,
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
        record = AuthenticationContextRecord(
            authentication_context_id=str(uuid4()),
            organization_id=organization_id,
            target=target,
            authorization_id=authorization_id,
            identity_label=identity_label,
            method=method,
            created_at=now,
            expires_at=expires_at,
        )
        with self._lock:
            self._metadata[record.authentication_context_id] = record
            self._secrets[record.authentication_context_id] = secret
        return record

    def get_metadata(self, authentication_context_id: str) -> AuthenticationContextRecord:
        with self._lock:
            record = self._metadata.get(authentication_context_id)
        if record is None:
            raise AuthenticationContextError(
                "authentication_context_not_found",
                "No authentication context matches the requested ID.",
            )
        return record

    def get_metadata_scoped(
        self, authentication_context_id: str, *, organization_id: str
    ) -> AuthenticationContextRecord:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        atomically scoped by ``organization_id`` -- a wrong-org lookup and
        a nonexistent ID raise the identical ``authentication_context_not_found``
        error, never a distinguishable existence oracle. Prefer this over
        ``get_metadata`` for any caller-supplied ID reaching this repository
        from an authenticated HTTP request; ``get_metadata`` itself remains
        for internal same-record fetches (``create``/``revoke``'s own
        post-write read) and ``require_bound``'s defense-in-depth mismatch
        reporting, where the ID already comes from a trusted, previously
        org-validated reference (a permit or comparison plan), not directly
        from an untrusted caller."""

        with self._lock:
            record = self._metadata.get(authentication_context_id)
        if record is None or record.organization_id != organization_id:
            raise AuthenticationContextError(
                "authentication_context_not_found",
                "No authentication context matches the requested ID.",
            )
        return record

    def revoke_scoped(
        self, authentication_context_id: str, *, organization_id: str, now: datetime
    ) -> AuthenticationContextRecord:
        """P1-C1: mirrors ``get_metadata_scoped``'s ownership scope --
        see that method's docstring."""

        with self._lock:
            record = self._metadata.get(authentication_context_id)
            if record is None or record.organization_id != organization_id:
                raise AuthenticationContextError(
                    "authentication_context_not_found",
                    "No authentication context matches the requested ID.",
                )
            if record.revoked_at is None:
                record = AuthenticationContextRecord(
                    authentication_context_id=record.authentication_context_id,
                    organization_id=record.organization_id,
                    target=record.target,
                    authorization_id=record.authorization_id,
                    identity_label=record.identity_label,
                    method=record.method,
                    created_at=record.created_at,
                    expires_at=record.expires_at,
                    revoked_at=now,
                    secret_reference_id=record.secret_reference_id,
                )
                self._metadata[authentication_context_id] = record
        return record

    def get_secret(self, authentication_context_id: str) -> AuthenticationMaterial:
        with self._lock:
            secret = self._secrets.get(authentication_context_id)
        if secret is None:
            raise AuthenticationContextError(
                "authentication_context_not_found",
                "No authentication context matches the requested ID.",
            )
        return secret

    def revoke(
        self, authentication_context_id: str, *, now: datetime
    ) -> AuthenticationContextRecord:
        with self._lock:
            record = self._metadata.get(authentication_context_id)
            if record is None:
                raise AuthenticationContextError(
                    "authentication_context_not_found",
                    "No authentication context matches the requested ID.",
                )
            if record.revoked_at is None:
                record = AuthenticationContextRecord(
                    authentication_context_id=record.authentication_context_id,
                    organization_id=record.organization_id,
                    target=record.target,
                    authorization_id=record.authorization_id,
                    identity_label=record.identity_label,
                    method=record.method,
                    created_at=record.created_at,
                    expires_at=record.expires_at,
                    revoked_at=now,
                    secret_reference_id=record.secret_reference_id,
                )
                self._metadata[authentication_context_id] = record
        return record

    def require_bound(
        self,
        authentication_context_id: str,
        *,
        organization_id: str,
        target: str,
        authorization_id: str,
        now: datetime,
    ) -> AuthenticationContextRecord:
        """Fail closed unless the context exists, is ACTIVE, and is
        bound to exactly this organization/target/authorization. Used at
        permit-issuance time and, defensively, again at scan-execution
        time -- the same double-check pattern this codebase already uses
        for TrustScan permits themselves."""

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


__all__ = [
    "AuthenticationContextError",
    "AuthenticationContextRecord",
    "AuthenticationContextRepository",
    "AuthenticationContextStatus",
    "AuthenticationMethod",
]
