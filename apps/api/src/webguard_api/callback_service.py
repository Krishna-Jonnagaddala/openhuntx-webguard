"""Multi-tenant callback registration for SSRF detection (Slice 10).

Wraps `webguard_scanner.callback_broker.InMemoryCallbackBroker` (the
actual token/observation correlation storage) with organization/
target/authorization-scoped bookkeeping, mirroring
`AuthenticationContextRepository`/`AuthorizationComparisonPlanRepository`'s
own precedent: in-memory only, for the identical reasons those give
(this is short-lived diagnostic correlation state, not a secret, but
still not worth a throwaway SQLite schema before the project's planned
PostgreSQL/Redis migration -- see the phase 10 audit doc's production
requirements).

`CallbackRepository` is intentionally *not* itself the object handed
to the detector -- its `register()` takes tenancy fields the
scanner-side `CallbackBroker` protocol does not know about.
`executor.py` binds one scan's organization/target/authorization once
via a small local adapter that satisfies the protocol exactly (see
`_ScanScopedCallbackBroker` there), so the detector never needs to
know tenancy exists.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from webguard_scanner.callback_broker import (
    CallbackBrokerError,
    CallbackObservation,
    CallbackPolicy,
    CallbackToken,
    InMemoryCallbackBroker,
)


class CallbackServiceError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ScopedCallbackRegistration:
    """Tenancy metadata recorded alongside a token -- references only,
    never a secret. Used only for audit/lookup; the actual
    authenticity/expiry/bounded-use enforcement lives in
    `InMemoryCallbackBroker`, unchanged and un-duplicated here."""

    token_value: str
    scan_id: str
    organization_id: str
    target: str
    authorization_id: str
    candidate_fingerprint: str
    created_at: datetime
    expires_at: datetime


class CallbackRepository:
    """Owns one shared `InMemoryCallbackBroker` for the whole API
    process's lifetime -- tokens are globally unique
    (`secrets.token_urlsafe`), so one broker instance safely serves
    every concurrent scan; `scan_id`/organization/target/authorization
    are recorded per-registration for audit and lookup, not used to
    partition storage."""

    def __init__(self, *, base_url: str, policy: CallbackPolicy | None = None) -> None:
        self._broker = InMemoryCallbackBroker(base_url=base_url)
        self._policy = policy or CallbackPolicy()
        self._lock = threading.Lock()
        self._registrations: dict[str, ScopedCallbackRegistration] = {}

    @property
    def policy(self) -> CallbackPolicy:
        return self._policy

    def set_base_url(self, base_url: str) -> None:
        """Updates the URL prefix used for every *subsequent*
        registration. Exists only to resolve the local-testing
        construction-order dependency between a repository and a real
        `CallbackHttpReceiver` bound to an OS-assigned ephemeral port
        (the receiver's real address is only known after it starts,
        but it needs a repository to construct). A real production
        deployment behind a fixed, stable hostname would never call
        this after startup."""

        self._broker.set_base_url(base_url)

    def register(
        self,
        *,
        scan_id: str,
        candidate_fingerprint: str,
        organization_id: str,
        target: str,
        authorization_id: str,
    ) -> CallbackToken:
        try:
            token = self._broker.register(
                scan_id=scan_id,
                candidate_fingerprint=candidate_fingerprint,
                policy=self._policy,
            )
        except CallbackBrokerError as exc:
            raise CallbackServiceError(exc.code, exc.message) from exc
        with self._lock:
            self._registrations[token.value] = ScopedCallbackRegistration(
                token_value=token.value,
                scan_id=scan_id,
                organization_id=organization_id,
                target=target,
                authorization_id=authorization_id,
                candidate_fingerprint=candidate_fingerprint,
                created_at=_utc_now(),
                expires_at=token.expires_at,
            )
        return token

    def wait_for_observation(
        self, token: CallbackToken, *, policy: CallbackPolicy, cancellation_check=None
    ):
        return self._broker.wait_for_observation(
            token, policy=policy, cancellation_check=cancellation_check
        )

    def record_observation(
        self,
        token_value: str,
        *,
        method: str,
        source_class: str = "external",
        now: datetime | None = None,
    ) -> bool:
        """Called by the real local HTTP receiver
        (`callback_server.py`) when an inbound request presents
        ``token_value`` in its path. Fails closed (returns False,
        never raises) for any unknown/expired/over-quota token -- see
        `InMemoryCallbackBroker.record_observation`."""

        return self._broker.record_observation(
            token_value,
            method=method,
            source_class=source_class,
            policy=self._policy,
            now=now,
        )

    def registration_for(self, token_value: str) -> ScopedCallbackRegistration | None:
        with self._lock:
            return self._registrations.get(token_value)


__all__ = [
    "CallbackRepository",
    "CallbackServiceError",
    "ScopedCallbackRegistration",
]
