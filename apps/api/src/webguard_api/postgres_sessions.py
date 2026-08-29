"""PostgreSQL-backed browser session repository (Slice 16). Satisfies
the same surface as ``sessions.InMemorySessionRepository`` -- see that
module's docstring for why sessions are a separate module pair from
``identity.py``/``postgres_identity.py``.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .identity import IdentityStoreError, _hash_secret, _parse_prefixed_secret, _verify_secret
from .postgres_pool import WebGuardPostgresPool
from .sessions import (
    ASSURANCE_LEVEL_PASSWORD,
    DEFAULT_ABSOLUTE_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    SESSION_TOKEN_PREFIX,
    BrowserSessionRecord,
    IssuedBrowserSession,
)

_COLUMNS = (
    "session_id, principal_id, organization_id, secret_hash, csrf_hash, assurance_level, "
    "issued_at, idle_expires_at, absolute_expires_at, last_used_at, revoked_at, user_agent, ip_address"
)


def _record_from_row(row: tuple) -> BrowserSessionRecord:
    return BrowserSessionRecord(
        session_id=str(row[0]),
        principal_id=str(row[1]),
        organization_id=str(row[2]),
        assurance_level=row[5],
        issued_at=row[6].astimezone(timezone.utc),
        idle_expires_at=row[7].astimezone(timezone.utc),
        absolute_expires_at=row[8].astimezone(timezone.utc),
        last_used_at=row[9].astimezone(timezone.utc) if row[9] else None,
        revoked_at=row[10].astimezone(timezone.utc) if row[10] else None,
        user_agent=row[11],
        ip_address=row[12],
    )


class PostgresSessionRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

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
        idle_expires_at = now + idle_ttl
        absolute_expires_at = now + absolute_ttl
        with self._pool.connection() as connection:
            connection.execute(
                f"""
                INSERT INTO browser_sessions ({_COLUMNS})
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, %s, %s)
                """,  # noqa: S608
                (
                    session_id,
                    principal_id,
                    organization_id,
                    _hash_secret(secret),
                    _hash_secret(csrf_token),
                    assurance_level,
                    now,
                    idle_expires_at,
                    absolute_expires_at,
                    user_agent,
                    ip_address,
                ),
            )
        record = BrowserSessionRecord(
            session_id=session_id,
            principal_id=principal_id,
            organization_id=organization_id,
            assurance_level=assurance_level,
            issued_at=now,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
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
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM browser_sessions WHERE session_id = %s",  # noqa: S608
                (session_id,),
            ).fetchone()
            if row is None or not _verify_secret(secret, row[3]):
                raise IdentityStoreError("session_invalid", "Session is invalid.")
            record = _record_from_row(row)
            if not record.is_usable(now=now):
                raise IdentityStoreError("session_expired", "Session has expired or was revoked.")
            if require_csrf and (csrf_header is None or not _verify_secret(csrf_header, row[4])):
                raise IdentityStoreError("csrf_token_invalid", "CSRF token is missing or invalid.")
            new_idle_expires_at = min(now + idle_ttl, record.absolute_expires_at)
            connection.execute(
                "UPDATE browser_sessions SET last_used_at = %s, idle_expires_at = %s WHERE session_id = %s",
                (now, new_idle_expires_at, session_id),
            )
        return BrowserSessionRecord(
            session_id=record.session_id,
            principal_id=record.principal_id,
            organization_id=record.organization_id,
            assurance_level=record.assurance_level,
            issued_at=record.issued_at,
            idle_expires_at=new_idle_expires_at,
            absolute_expires_at=record.absolute_expires_at,
            last_used_at=now,
            revoked_at=record.revoked_at,
            user_agent=record.user_agent,
            ip_address=record.ip_address,
        )

    def get_session(self, session_id: str) -> BrowserSessionRecord | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM browser_sessions WHERE session_id = %s",  # noqa: S608
                (session_id,),
            ).fetchone()
        return None if row is None else _record_from_row(row)

    def revoke_session(self, session_id: str, *, now: datetime) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "UPDATE browser_sessions SET revoked_at = %s WHERE session_id = %s AND revoked_at IS NULL",
                (now, session_id),
            )

    def revoke_all_sessions_for_principal(
        self, principal_id: str, *, now: datetime, except_session_id: str | None = None
    ) -> int:
        with self._pool.connection() as connection:
            if except_session_id is None:
                cursor = connection.execute(
                    "UPDATE browser_sessions SET revoked_at = %s WHERE principal_id = %s AND revoked_at IS NULL",
                    (now, principal_id),
                )
            else:
                cursor = connection.execute(
                    """
                    UPDATE browser_sessions SET revoked_at = %s
                    WHERE principal_id = %s AND revoked_at IS NULL AND session_id != %s
                    """,
                    (now, principal_id, except_session_id),
                )
            return cursor.rowcount

    def list_sessions_for_principal(self, principal_id: str) -> tuple[BrowserSessionRecord, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM browser_sessions WHERE principal_id = %s ORDER BY issued_at DESC",  # noqa: S608
                (principal_id,),
            ).fetchall()
        return tuple(_record_from_row(row) for row in rows)


__all__ = ["PostgresSessionRepository"]
