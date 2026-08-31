"""PostgreSQL-backed durable callback registration repository (Slice
12 requirement 4/9). Satisfies the metadata-lifecycle surface of the
in-memory ``CallbackRepository`` (register / get_registration /
revoke_registration / record_observation), reusing its
``ScopedCallbackRegistration`` return type and ``CallbackServiceError``
error codes so both backends are contract-test-compatible.

Scope, stated plainly: this repository proves durable, tenant-isolated
callback-registration storage in PostgreSQL -- it does not itself
implement the real-time wait/correlate mechanism a live scan uses
(``wait_for_observation``); that now lives in
``postgres_callback_broker.PostgresCallbackBroker``, a thin adapter
over this repository that polls ``callback_observations`` instead of
consulting an in-process dict, because Slice 18 made the callback
receiver a separately-deployable process (``webguard-api
callback-service``) that can no longer share memory with the worker
process waiting on an observation. Wiring that adapter in as the
executor's live callback broker was previously named as future work
here (Slice 12's audit doc's "Known limitations") -- it is now done;
see ``production_startup.py``.

``maximum_active_registrations`` enforcement (the one policy control
the in-memory broker had that this repository previously did not
reproduce) is implemented directly below, scoped per-organization
rather than process-wide the way ``InMemoryCallbackBroker`` scopes it
-- a shared production deployment must not let one noisy-neighbor
organization exhaust a global budget that affects every other tenant's
scans. It is a best-effort count-then-insert, not a hard
serialization-guaranteed cap (no ``SELECT ... FOR UPDATE`` on a
sentinel row): this is a soft abuse control, not a security invariant,
so a small race window under a heavy concurrent-registration burst
(briefly exceeding the limit by a handful of rows) is an accepted
trade-off against added lock contention on every single registration.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from webguard_scanner.callback_broker import CallbackPolicy

from .callback_service import CallbackServiceError, ScopedCallbackRegistration
from .postgres_pool import WebGuardPostgresPool


class PostgresCallbackRegistrationRepository:
    """Token generation reuses the identical ``secrets.token_urlsafe(32)``
    primitive ``InMemoryCallbackBroker.register`` uses (the only
    security-relevant property of a callback token is its entropy, a
    single stdlib call, not a bespoke scheme worth abstracting further)
    -- callers see the same ``register(...) -> ScopedCallbackRegistration``
    shape as the in-memory repository. What this repository does not
    reproduce is the in-memory broker's *active-registration-limit*
    policy enforcement or its real-time wait/correlate mechanism -- see
    the module docstring."""

    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    def register(
        self,
        *,
        scan_id: str,
        candidate_fingerprint: str,
        organization_id: str,
        target: str,
        authorization_id: str,
        job_id: str | None = None,
        permit_id: str | None = None,
        policy: CallbackPolicy | None = None,
        now: datetime | None = None,
    ) -> ScopedCallbackRegistration:
        effective_policy = policy or CallbackPolicy()
        token_value = secrets.token_urlsafe(32)
        created_at = now or datetime.now(timezone.utc)
        expires_at = created_at + timedelta(seconds=effective_policy.token_ttl_seconds)
        with self._pool.connection() as connection:
            active_count = connection.execute(
                """
                SELECT COUNT(*) FROM callback_registrations
                WHERE organization_id = %s AND revoked_at IS NULL AND expires_at > %s
                """,
                (organization_id, created_at),
            ).fetchone()[0]
            if active_count >= effective_policy.maximum_active_registrations:
                raise CallbackServiceError(
                    "callback_registration_limit_exceeded",
                    f"{active_count} active callback registrations already exist for "
                    f"this organization, at the {effective_policy.maximum_active_registrations} limit.",
                )
            connection.execute(
                """
                INSERT INTO callback_registrations
                    (token_value, organization_id, scan_id, job_id, permit_id, target,
                     authorization_id, candidate_fingerprint, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    token_value,
                    organization_id,
                    scan_id,
                    job_id,
                    permit_id,
                    target,
                    authorization_id,
                    candidate_fingerprint,
                    created_at,
                    expires_at,
                ),
            )
        return ScopedCallbackRegistration(
            token_value=token_value,
            scan_id=scan_id,
            organization_id=organization_id,
            target=target,
            authorization_id=authorization_id,
            candidate_fingerprint=candidate_fingerprint,
            created_at=created_at,
            expires_at=expires_at,
            job_id=job_id,
            permit_id=permit_id,
        )

    def get_registration(
        self, token_value: str, *, organization_id: str
    ) -> ScopedCallbackRegistration:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT token_value, organization_id, scan_id, job_id, permit_id, target,
                       authorization_id, candidate_fingerprint, created_at, expires_at, revoked_at
                FROM callback_registrations
                WHERE token_value = %s AND organization_id = %s
                """,
                (token_value, organization_id),
            ).fetchone()
        if row is None:
            raise CallbackServiceError(
                "callback_registration_not_found",
                "No callback registration matches the requested token.",
            )
        registration = self._registration_from_row(row)
        if registration.revoked_at is not None:
            raise CallbackServiceError(
                "callback_registration_revoked",
                "This callback registration has been revoked.",
            )
        return registration

    def revoke_registration(
        self, token_value: str, *, organization_id: str, now: datetime | None = None
    ) -> ScopedCallbackRegistration:
        moment = now or datetime.now(timezone.utc)
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                UPDATE callback_registrations
                SET revoked_at = COALESCE(revoked_at, %s)
                WHERE token_value = %s AND organization_id = %s
                RETURNING token_value, organization_id, scan_id, job_id, permit_id, target,
                          authorization_id, candidate_fingerprint, created_at, expires_at, revoked_at
                """,
                (moment, token_value, organization_id),
            ).fetchone()
        if row is None:
            raise CallbackServiceError(
                "callback_registration_not_found",
                "No callback registration matches the requested token.",
            )
        return self._registration_from_row(row)

    def record_observation(
        self,
        token_value: str,
        *,
        method: str,
        source_class: str = "external",
        now: datetime | None = None,
    ) -> bool:
        moment = now or datetime.now(timezone.utc)
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT revoked_at, expires_at FROM callback_registrations WHERE token_value = %s",
                (token_value,),
            ).fetchone()
            if row is None or row[0] is not None or row[1].astimezone(timezone.utc) <= moment:
                return False
            connection.execute(
                """
                INSERT INTO callback_observations (observation_id, token_value, method, source_class, observed_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (str(uuid4()), token_value, method, source_class, moment),
            )
        return True

    @staticmethod
    def _registration_from_row(row: tuple) -> ScopedCallbackRegistration:
        return ScopedCallbackRegistration(
            token_value=row[0],
            organization_id=str(row[1]),
            scan_id=row[2],
            job_id=row[3],
            permit_id=row[4],
            target=row[5],
            authorization_id=row[6],
            candidate_fingerprint=row[7],
            created_at=row[8].astimezone(timezone.utc),
            expires_at=row[9].astimezone(timezone.utc),
            revoked_at=row[10].astimezone(timezone.utc) if row[10] else None,
        )


__all__ = ["PostgresCallbackRegistrationRepository"]
