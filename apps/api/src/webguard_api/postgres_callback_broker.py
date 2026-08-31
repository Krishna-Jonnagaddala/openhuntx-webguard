"""Durable, cross-process-capable SSRF-callback broker (fixes the
production wiring gap ``postgres_callback_service.py``'s own module
docstring previously named as future work).

Background: ``ScanJobExecutor`` needs a *live* broker satisfying
``repository_contracts.TenantScopedCallbackBroker`` -- something with
a ``.policy`` and a ``register()``/``wait_for_observation()`` pair the
detector can actually correlate against, in real time, from inside one
worker's execution of one scan. Before this module existed, production
wiring (``production_startup.py``) passed the raw
``PostgresCallbackRegistrationRepository`` directly into
``ScanJobExecutor`` as if it already were that broker. It structurally
is not: it has no ``.policy``, no ``wait_for_observation()``, and its
``register()`` returns a ``ScopedCallbackRegistration`` with no `.url`
-- the very first line of `_apply_ssrf_callback_detection` that touches
it (`callback_repository.policy`) raised `AttributeError` before a scan
even reached the point of registering a token, so every production
scan with `active.ssrf.callback` in its permit failed outright.

This class is the adapter: it wraps a
``PostgresCallbackRegistrationRepository`` for durable storage and adds
exactly the three things the durable repository cannot provide by
itself:

1. ``policy`` -- a ``CallbackPolicy`` for this broker's lifetime,
   handed straight through to the detector, mirroring
   ``CallbackRepository.policy``.
2. A ``register()`` that builds the real, publicly-reachable callback
   URL from an explicit ``base_url`` (production wiring constructs this
   from ``ProductionServiceConfig.callback_service_hostname`` -- the
   config field ``ProductionServiceConfig`` already validated but no
   code ever read) and returns a genuine scanner-layer ``CallbackToken``
   (not the durable-storage ``ScopedCallbackRegistration``), exactly
   the shape ``ssrf_callback_detector.py`` mutates a candidate request
   with (`token.url`).
3. A ``wait_for_observation()`` that *polls* ``callback_observations``
   instead of consulting an in-process dict. This is the one piece that
   cannot be a thin pass-through: Slice 18 made the callback receiver
   (``webguard-api callback-service``) an independently deployable
   process (see ``callback_server.py`` / ``cli.py``) that calls
   ``PostgresCallbackRegistrationRepository.record_observation()``
   directly against PostgreSQL. It shares no process memory with the
   worker that is waiting -- an ``InMemoryCallbackBroker``-style
   ``threading.Event`` literally cannot be signalled across that
   boundary. Polling Postgres is the only option available without
   introducing a new piece of infrastructure (Redis pub/sub) purely for
   this; ``docs/production/INFRASTRUCTURE_REQUIREMENTS.md``'s own
   Queue/Redis section already names "ephemeral callback correlation"
   as Redis's nearest-term future role, not something required today.

Timing budget: this broker keeps ``CallbackPolicy``'s
``maximum_wait_seconds``/``grace_seconds`` defaults (3s/2s) unchanged --
those are the security-relevant CONFIRMED-vs-PROBABLE classification
thresholds documented in ``ssrf_callback_detector.py``, not an
implementation detail to casually widen. The one field this broker does
override is ``poll_interval_seconds`` (default 0.05s in
``CallbackPolicy``, tuned for an in-process dict): a 20-query/sec tight
loop against PostgreSQL per in-flight probe is unnecessary load for a
signal that, once it exists, does not need sub-100ms resolution --
``DEFAULT_POSTGRES_POLL_INTERVAL_SECONDS`` (0.25s) keeps the same
5-second overall window at roughly 20 queries total instead of 100.

Known limitation, stated plainly rather than hidden: a registration
whose wait times out with no observation (the overwhelming common case
-- most probed candidates are not vulnerable) is left in
``callback_registrations`` exactly as-is; this broker does not revoke
or delete it. Marking a normal, expected timeout as "revoked" would
conflate two different audit concepts (explicit operator revocation vs.
ordinary NOT_VULNERABLE), so it deliberately does not do that. Physical
cleanup of long-expired rows (a scheduled reaper deleting
``WHERE expires_at < now() - retention_window``) is not built --
durable storage growth is bounded only by ``token_ttl_seconds``
semantics, not by row deletion. This is a named gap, not a silent one.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from webguard_scanner.callback_broker import CallbackObservation, CallbackPolicy, CallbackToken

from .callback_service import CallbackServiceError
from .db_errors import DatabaseError
from .postgres_callback_service import PostgresCallbackRegistrationRepository
from .postgres_pool import WebGuardPostgresPool

DEFAULT_POSTGRES_POLL_INTERVAL_SECONDS = 0.25


class PostgresCallbackBroker:
    """Satisfies ``repository_contracts.TenantScopedCallbackBroker`` --
    a drop-in replacement for the in-memory ``CallbackRepository`` at
    every call site inside ``executor.py`` (``ScanJobExecutor``,
    ``_ScanScopedCallbackBroker``), backed by durable, cross-process
    PostgreSQL storage instead of one process's memory."""

    def __init__(
        self,
        repository: PostgresCallbackRegistrationRepository,
        pool: WebGuardPostgresPool,
        *,
        base_url: str,
        policy: CallbackPolicy | None = None,
    ) -> None:
        self._repository = repository
        self._pool = pool
        self._base_url = base_url if base_url.endswith("/") else base_url + "/"
        self._policy = policy or CallbackPolicy(
            poll_interval_seconds=DEFAULT_POSTGRES_POLL_INTERVAL_SECONDS
        )

    @property
    def policy(self) -> CallbackPolicy:
        return self._policy

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
    ) -> CallbackToken:
        try:
            registration = self._repository.register(
                scan_id=scan_id,
                candidate_fingerprint=candidate_fingerprint,
                organization_id=organization_id,
                target=target,
                authorization_id=authorization_id,
                job_id=job_id,
                permit_id=permit_id,
                policy=self._policy,
            )
        except DatabaseError as exc:
            # Mirrors `CallbackRepository.register()`'s own translation
            # of a broker-level failure into `CallbackServiceError` --
            # `_ScanScopedCallbackBroker.register()` already knows how
            # to catch exactly this and re-raise as the scanner-layer
            # `CallbackBrokerError`, so a transient database hiccup
            # degrades this one candidate to INCONCLUSIVE rather than
            # aborting the entire scan job.
            raise CallbackServiceError(exc.code, exc.message) from exc
        return CallbackToken(
            value=registration.token_value,
            url=f"{self._base_url}{scan_id}/{registration.token_value}",
            scan_id=scan_id,
            candidate_fingerprint=candidate_fingerprint,
            expires_at=registration.expires_at,
        )

    def wait_for_observation(
        self,
        token: CallbackToken,
        *,
        organization_id: str,
        policy: CallbackPolicy,
        cancellation_check=None,
    ):
        # Ownership-checked before ever polling, identically to
        # `CallbackRepository.wait_for_observation` -- a mismatch here
        # is a genuine integrity violation in correct code (the caller
        # is holding a token it did not register for this
        # organization), so this is allowed to raise `CallbackServiceError`
        # rather than degrade to "no observation". A `DatabaseError` here
        # (Postgres unreachable at wait-start) is translated the same
        # way -- see the identical `except DatabaseError` below for why.
        try:
            self._repository.get_registration(token.value, organization_id=organization_id)
        except DatabaseError as exc:
            raise CallbackServiceError(exc.code, exc.message) from exc

        deadline_primary = time.monotonic() + policy.maximum_wait_seconds
        deadline_grace = deadline_primary + policy.grace_seconds
        while True:
            if cancellation_check is not None and cancellation_check():
                return None, False, True
            # A storage failure here (e.g. Postgres becomes unavailable
            # mid-poll) must never be silently folded into "no
            # observation yet" -- that would be indistinguishable from
            # a genuine NOT_VULNERABLE result to every caller above this
            # one. Translating to `CallbackServiceError` mirrors
            # `register()`'s own DatabaseError handling exactly, so this
            # candidate degrades to INCONCLUSIVE (scanner-layer, via
            # `_ScanScopedCallbackBroker`/`ssrf_callback_detector.py`)
            # rather than crashing the whole scan job.
            try:
                observation = self._latest_observation(token.value)
            except DatabaseError as exc:
                raise CallbackServiceError(exc.code, exc.message) from exc
            if observation is not None:
                return observation, time.monotonic() <= deadline_primary, False
            if time.monotonic() >= deadline_grace:
                return None, False, False
            time.sleep(policy.poll_interval_seconds)

    def _latest_observation(self, token_value: str) -> CallbackObservation | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT method, source_class, observed_at
                FROM callback_observations
                WHERE token_value = %s
                ORDER BY observed_at ASC
                LIMIT 1
                """,
                (token_value,),
            ).fetchone()
        if row is None:
            return None
        method, source_class, observed_at = row
        return CallbackObservation(
            token_value=token_value,
            observed_at=observed_at.astimezone(timezone.utc),
            method=method,
            source_class=source_class,
        )

    def revoke_registration(
        self, token_value: str, *, organization_id: str, now: datetime | None = None
    ):
        return self._repository.revoke_registration(
            token_value, organization_id=organization_id, now=now
        )

    def record_observation(
        self,
        token_value: str,
        *,
        method: str,
        source_class: str = "external",
        now: datetime | None = None,
    ) -> bool:
        return self._repository.record_observation(
            token_value, method=method, source_class=source_class, now=now
        )


__all__ = ["DEFAULT_POSTGRES_POLL_INTERVAL_SECONDS", "PostgresCallbackBroker"]
