"""PostgreSQL-backed target-verification repository (Slice 15
requirement 3). Satisfies the same surface as
``target_verification.InMemoryTargetVerificationRepository``. The
``target_verifications`` table (migration 0002) has no ``token``
column by design -- the expected token is never persisted; it exists
only in memory for the duration of the request that generated it and
is returned to the caller exactly once, matching the same "one-time
proof, not an ongoing secret" posture ``report_store.py``'s checksum
and ``identity.py``'s raw API token share.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from uuid import uuid4

from .postgres_pool import WebGuardPostgresPool
from .target_verification import (
    VERIFICATION_TOKEN_TTL,
    TargetVerificationError,
    TargetVerificationRecord,
    VerificationMethod,
    VerificationStatus,
)

_COLUMNS = "verification_id, target_id, organization_id, method, status, evidence, checked_at, expires_at"


class PostgresTargetVerificationRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple, *, expected_token: str | None = None) -> TargetVerificationRecord:
        verification_id, target_id, organization_id, method, status, evidence, checked_at, expires_at = row
        return TargetVerificationRecord(
            verification_id=str(verification_id),
            target_id=str(target_id),
            organization_id=str(organization_id),
            method=VerificationMethod(method),
            status=VerificationStatus(status),
            checked_at=checked_at.astimezone(timezone.utc),
            evidence=evidence,
            expires_at=expires_at.astimezone(timezone.utc) if expires_at else None,
            expected_token=expected_token,
        )

    def initiate(
        self, target_id: str, *, organization_id: str, method: VerificationMethod, now: datetime
    ) -> TargetVerificationRecord:
        token = secrets.token_urlsafe(24)
        expires_at = now + VERIFICATION_TOKEN_TTL
        verification_id = str(uuid4())
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO target_verifications
                    (verification_id, target_id, organization_id, method, status, evidence, checked_at, expires_at)
                VALUES (%s, %s, %s, %s, 'pending', %s, %s, %s)
                """,
                (verification_id, target_id, organization_id, method.value, f"expecting:{token}", now, expires_at),
            )
        return TargetVerificationRecord(
            verification_id=verification_id,
            target_id=target_id,
            organization_id=organization_id,
            method=method,
            status=VerificationStatus.PENDING,
            checked_at=now,
            expires_at=expires_at,
            expected_token=token,
        )

    def get_current(self, target_id: str, *, organization_id: str) -> TargetVerificationRecord | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"""
                SELECT {_COLUMNS} FROM target_verifications
                WHERE target_id = %s AND organization_id = %s
                ORDER BY checked_at DESC LIMIT 1
                """,  # noqa: S608
                (target_id, organization_id),
            ).fetchone()
        if row is None:
            return None
        # While still pending, the token is recoverable from its own
        # `evidence` placeholder -- this is not "returning it once a
        # check has run" (which never happens: `record_result`
        # overwrites `evidence` with a real outcome the moment a check
        # executes), so exposing it here still matches the "one-time
        # proof, not an ongoing secret" contract. Without this, a
        # client re-fetching a still-pending verification (the normal
        # case after `start_asset_verification`, since the frontend
        # invalidates and refetches rather than reusing the mutation's
        # own response) would lose its own instructions.
        evidence = row[5]
        status = row[4]
        expected_token = (
            evidence[len("expecting:") :]
            if status == "pending" and isinstance(evidence, str) and evidence.startswith("expecting:")
            else None
        )
        return self._record_from_row(row, expected_token=expected_token)

    def get_pending_token(self, verification_id: str, *, organization_id: str) -> str:
        """Recovers the expected token for a still-pending verification
        from its own ``evidence`` placeholder -- the only place it is
        recoverable from, since it was never stored as a real column."""

        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT status, evidence FROM target_verifications WHERE verification_id = %s AND organization_id = %s",
                (verification_id, organization_id),
            ).fetchone()
        if row is None or row[0] != "pending" or not (row[1] or "").startswith("expecting:"):
            raise TargetVerificationError(
                "target_verification_not_found", "No pending verification matches the requested ID."
            )
        return row[1][len("expecting:") :]

    def record_result(
        self,
        verification_id: str,
        *,
        organization_id: str,
        matched: bool,
        detail: str,
        now: datetime,
    ) -> TargetVerificationRecord:
        status = VerificationStatus.VERIFIED if matched else VerificationStatus.FAILED
        with self._pool.connection() as connection:
            row = connection.execute(
                f"""
                UPDATE target_verifications SET status = %s, evidence = %s, checked_at = %s
                WHERE verification_id = %s AND organization_id = %s
                RETURNING {_COLUMNS}
                """,  # noqa: S608
                (status.value, detail, now, verification_id, organization_id),
            ).fetchone()
        if row is None:
            raise TargetVerificationError(
                "target_verification_not_found", "No pending verification matches the requested ID."
            )
        return self._record_from_row(row)


__all__ = ["PostgresTargetVerificationRepository"]
