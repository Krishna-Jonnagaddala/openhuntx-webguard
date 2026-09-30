"""Multi-tenant callback registration for SSRF detection (Slice 10;
tenant-isolation remediation Slice 12).

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

Slice 11's stabilization audit flagged this module as the one
partially-isolated tenant-owned resource: `registration_for()` took
only a token value, with no organization check on the read path at
all -- isolation rested entirely on token secrecy/entropy, not an
explicit ownership check, unlike every other resource type in this
codebase (`<resource>_scoped(id, organization_id)`). Slice 12 closes
that gap: every read/wait/revoke operation now requires the caller's
`organization_id` and fails closed (the identical "matches unknown"
signal, never a distinct "forbidden" that would leak existence) on any
mismatch. Token possession alone -- knowing or guessing the
high-entropy value -- is no longer sufficient to retrieve, wait on, or
revoke a registration that belongs to a different organization; the
registration's own recorded `organization_id` is authoritative and is
always checked, never trusted from the caller alone but never skipped
either. Callback token authenticity and bounded-use semantics
(`secrets.token_urlsafe` generation, scan/candidate binding,
expiry, bounded observation count) are entirely unchanged from Slice
10 -- this remediation adds an ownership check in front of that
existing mechanism, it does not touch it.
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
    job_id: str | None = None
    permit_id: str | None = None
    revoked_at: datetime | None = None


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
        job_id: str | None = None,
        permit_id: str | None = None,
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
                job_id=job_id,
                permit_id=permit_id,
            )
        return token

    def get_registration(
        self, token_value: str, *, organization_id: str
    ) -> ScopedCallbackRegistration:
        """The one, authoritative, organization-checked read path.
        Fails closed with the identical signal for "no such
        registration" and "registration belongs to a different
        organization" -- token possession alone (knowing or guessing
        the value) is never sufficient; the registration's own
        recorded `organization_id` is always checked."""

        with self._lock:
            registration = self._registrations.get(token_value)
        if registration is None or registration.organization_id != organization_id:
            raise CallbackServiceError(
                "callback_registration_not_found",
                "No callback registration matches the requested token.",
            )
        if registration.revoked_at is not None:
            raise CallbackServiceError(
                "callback_registration_revoked",
                "This callback registration has been revoked.",
            )
        return registration

    def wait_for_observation(
        self,
        token: CallbackToken,
        *,
        organization_id: str,
        policy: CallbackPolicy,
        cancellation_check=None,
    ):
        """Organization-checked before ever polling for an
        observation. A mismatch here means the caller is holding a
        token it did not itself register for this organization -- a
        genuine integrity violation in correct code, not a normal
        "not found" case an external caller could otherwise trigger,
        so this fails loudly (raises) rather than silently degrading
        to "no observation"."""

        self.get_registration(token.value, organization_id=organization_id)
        return self._broker.wait_for_observation(
            token, policy=policy, cancellation_check=cancellation_check
        )

    def revoke_registration(
        self, token_value: str, *, organization_id: str, now: datetime | None = None
    ) -> ScopedCallbackRegistration:
        """Explicit delete/expire lifecycle operation (requirement 1).
        Organization-checked identically to `get_registration`;
        idempotent (revoking an already-revoked registration returns
        the same record rather than raising)."""

        moment = now or _utc_now()
        with self._lock:
            registration = self._registrations.get(token_value)
            if registration is None or registration.organization_id != organization_id:
                raise CallbackServiceError(
                    "callback_registration_not_found",
                    "No callback registration matches the requested token.",
                )
            if registration.revoked_at is None:
                registration = ScopedCallbackRegistration(
                    token_value=registration.token_value,
                    scan_id=registration.scan_id,
                    organization_id=registration.organization_id,
                    target=registration.target,
                    authorization_id=registration.authorization_id,
                    candidate_fingerprint=registration.candidate_fingerprint,
                    created_at=registration.created_at,
                    expires_at=registration.expires_at,
                    job_id=registration.job_id,
                    permit_id=registration.permit_id,
                    revoked_at=moment,
                )
                self._registrations[token_value] = registration
        return registration

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
        never raises) for any unknown/expired/over-quota/revoked
        token -- see `InMemoryCallbackBroker.record_observation`.

        Deliberately takes no `organization_id`: the receiver has no
        tenancy context for an inbound request (it is the *target
        application's* server connecting back, not an authenticated
        WebGuard API caller) -- this is a write-only, token-correlated
        recording step, not a read/retrieve/correlate operation, so it
        is outside the scope of this remediation's ownership check
        (which governs every path that *reveals* registration data
        back to a caller). A revoked registration's token is rejected
        here too, via the broker's own expiry-style bookkeeping being
        consulted through `_registrations` -- see below.
        """

        with self._lock:
            registration = self._registrations.get(token_value)
        if registration is not None and registration.revoked_at is not None:
            return False
        return self._broker.record_observation(
            token_value,
            method=method,
            source_class=source_class,
            policy=self._policy,
            now=now,
        )


__all__ = [
    "CallbackRepository",
    "CallbackServiceError",
    "ScopedCallbackRegistration",
]
