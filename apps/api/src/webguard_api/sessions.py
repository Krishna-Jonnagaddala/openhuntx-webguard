"""Browser session storage (Slice 16 requirements 4-7).

A browser session is deliberately its own module pair (this file plus
``postgres_sessions.py``), the same way Slice 15 gave target-ownership
verification its own pair -- it is identity-adjacent but has a
meaningfully different access pattern (looked up and touched on nearly
every authenticated browser request, with its own idle/absolute expiry
and revocation lifecycle) from everything already living in
``identity.py``.

The session's own bearer secret is never persisted, only its hash
(reusing ``identity.py``'s existing ``_hash_secret``/``_verify_secret``
scrypt implementation -- there must be exactly one reviewed secret-
hashing implementation in this codebase). The CSRF token issued
alongside a session is likewise stored only as a hash. Neither hash is
ever exposed on ``BrowserSessionRecord`` (mirroring ``ApiTokenMetadata``,
which never carries its own ``secret_hash`` either) -- CSRF verification
happens inside ``authenticate_session`` itself, the one place both the
caller-supplied header and the stored hash are naturally in scope,
rather than leaking the hash out to a caller that would otherwise have
to compare it.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .identity import IdentityStoreError, _hash_secret, _parse_prefixed_secret, _verify_secret

SESSION_TOKEN_PREFIX = "wgs"  # noqa: S105
DEFAULT_IDLE_TIMEOUT = timedelta(minutes=30)
DEFAULT_ABSOLUTE_TIMEOUT = timedelta(hours=12)
ASSURANCE_LEVEL_PASSWORD = "password"  # noqa: S105 - reserved for a future "mfa" level, not a secret


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class BrowserSessionRecord:
    session_id: str
    principal_id: str
    organization_id: str
    assurance_level: str
    issued_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    user_agent: str | None = None
    ip_address: str | None = None

    def is_usable(self, *, now: datetime) -> bool:
        if self.revoked_at is not None:
            return False
        now_utc = now.astimezone(timezone.utc)
        return now_utc < self.idle_expires_at and now_utc < self.absolute_expires_at

    def to_public_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "assurance_level": self.assurance_level,
            "issued_at": _iso(self.issued_at),
            "idle_expires_at": _iso(self.idle_expires_at),
            "absolute_expires_at": _iso(self.absolute_expires_at),
            "last_used_at": _iso(self.last_used_at) if self.last_used_at else None,
        }


@dataclass(frozen=True, slots=True)
class IssuedBrowserSession:
    record: BrowserSessionRecord
    session_token: str
    csrf_token: str


@dataclass
class _InternalSessionState:
    record: BrowserSessionRecord
    secret_hash: str
    csrf_hash: str


class InMemorySessionRepository:
    """Local/dev/lab/test backend -- process-local, matching
    ``PostgresSessionRepository``'s surface exactly."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, _InternalSessionState] = {}

    def create_session(
        self,
        principal_id: str,
        organization_id: str,
        *,
        now: datetime,
        idle_ttl: timedelta = DEFAULT_IDLE_TIMEOUT,
        absolute_ttl: timedelta = DEFAULT_ABSOLUTE_TIMEOUT,
        assurance_level: str = ASSURANCE_LEVEL_PASSWORD,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> IssuedBrowserSession:
        session_id = str(uuid4())
        secret = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        record = BrowserSessionRecord(
            session_id=session_id,
            principal_id=principal_id,
            organization_id=organization_id,
            assurance_level=assurance_level,
            issued_at=now,
            idle_expires_at=now + idle_ttl,
            absolute_expires_at=now + absolute_ttl,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        with self._lock:
            self._sessions[session_id] = _InternalSessionState(
                record=record,
                secret_hash=_hash_secret(secret),
                csrf_hash=_hash_secret(csrf_token),
            )
        return IssuedBrowserSession(
            record=record,
            session_token=f"{SESSION_TOKEN_PREFIX}_{session_id}_{secret}",
            csrf_token=csrf_token,
        )

    def authenticate_session(
        self,
        token: object,
        *,
        now: datetime,
        idle_ttl: timedelta = DEFAULT_IDLE_TIMEOUT,
        csrf_header: str | None = None,
        require_csrf: bool = False,
    ) -> BrowserSessionRecord:
        session_id, secret = _parse_prefixed_secret(
            token, prefix=SESSION_TOKEN_PREFIX, error_code="session_invalid"
        )
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None or not _verify_secret(secret, state.secret_hash):
                raise IdentityStoreError("session_invalid", "Session is invalid.")
            if not state.record.is_usable(now=now):
                raise IdentityStoreError("session_expired", "Session has expired or was revoked.")
            if require_csrf and (csrf_header is None or not _verify_secret(csrf_header, state.csrf_hash)):
                raise IdentityStoreError("csrf_token_invalid", "CSRF token is missing or invalid.")
            record = state.record
            touched = BrowserSessionRecord(
                session_id=record.session_id,
                principal_id=record.principal_id,
                organization_id=record.organization_id,
                assurance_level=record.assurance_level,
                issued_at=record.issued_at,
                idle_expires_at=min(now + idle_ttl, record.absolute_expires_at),
                absolute_expires_at=record.absolute_expires_at,
                last_used_at=now,
                revoked_at=record.revoked_at,
                user_agent=record.user_agent,
                ip_address=record.ip_address,
            )
            state.record = touched
        return touched

    def get_session(self, session_id: str) -> BrowserSessionRecord | None:
        with self._lock:
            state = self._sessions.get(session_id)
            return None if state is None else state.record

    def revoke_session(self, session_id: str, *, principal_id: str, now: datetime) -> None:
        """P1-C1: mirrors PostgresSessionRepository.revoke_session's own
        ownership scope exactly -- see that method's docstring."""

        with self._lock:
            state = self._sessions.get(session_id)
            if state is None or state.record.principal_id != principal_id or state.record.revoked_at is not None:
                return
            record = state.record
            state.record = BrowserSessionRecord(
                session_id=record.session_id,
                principal_id=record.principal_id,
                organization_id=record.organization_id,
                assurance_level=record.assurance_level,
                issued_at=record.issued_at,
                idle_expires_at=record.idle_expires_at,
                absolute_expires_at=record.absolute_expires_at,
                last_used_at=record.last_used_at,
                revoked_at=now,
                user_agent=record.user_agent,
                ip_address=record.ip_address,
            )

    def revoke_all_sessions_for_principal(
        self, principal_id: str, *, now: datetime, except_session_id: str | None = None
    ) -> int:
        with self._lock:
            targets = [
                sid
                for sid, state in self._sessions.items()
                if state.record.principal_id == principal_id
                and state.record.revoked_at is None
                and sid != except_session_id
            ]
        for sid in targets:
            self.revoke_session(sid, principal_id=principal_id, now=now)
        return len(targets)

    def list_sessions_for_principal(self, principal_id: str) -> tuple[BrowserSessionRecord, ...]:
        with self._lock:
            return tuple(
                state.record for state in self._sessions.values() if state.record.principal_id == principal_id
            )


__all__ = [
    "ASSURANCE_LEVEL_PASSWORD",
    "DEFAULT_ABSOLUTE_TIMEOUT",
    "DEFAULT_IDLE_TIMEOUT",
    "SESSION_TOKEN_PREFIX",
    "BrowserSessionRecord",
    "InMemorySessionRepository",
    "IssuedBrowserSession",
]
