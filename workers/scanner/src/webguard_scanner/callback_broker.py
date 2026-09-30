"""Controlled out-of-band callback infrastructure for SSRF detection
(Slice 10).

Confirms CWE-918 (Server-Side Request Forgery) by observing a genuine
server-side outbound request from the target application to a
WebGuard-controlled callback destination -- never by guessing at
response text, and never by pointing the probe at an internal address
(127.0.0.1, RFC1918, cloud metadata endpoints) to "prove" SSRF. The
only destination this module ever hands to a probe is a callback URL
this module itself issued.

This module defines the *interface* (`CallbackBroker`) the detector
depends on, plus a bounded, self-contained default implementation
(`InMemoryCallbackBroker`) usable standalone (no API-layer dependency,
same relationship this project already has between
`authentication.AuthenticationMaterial` and
`apps/api/authentication_contexts.AuthenticationContextRepository`).
The multi-tenant, RBAC/audit-relevant implementation used by the
loopback API service lives in `apps/api/webguard_api/callback_service.py`
and also satisfies this same `CallbackBroker` protocol -- the detector
never knows or cares which one it was given, which is exactly what
keeps this interface compatible with a later, separately-scalable
cloud callback service (see requirement 19/20 in the phase 10 audit
doc): swapping the broker implementation never requires touching the
detector.

Callback authenticity (requirement 7) is enforced structurally: a
token is generated only by a `register()` call using
`secrets.token_urlsafe` (never accepted as external input), is
scan-bound and candidate-bound at registration time, exists only until
`expires_at`, and accepts only a bounded number of observations. There
is no code path anywhere that lets a caller supply an arbitrary
callback ID and have it treated as proof.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol, Tuple


DEFAULT_CALLBACK_TOKEN_TTL_SECONDS = 300.0
DEFAULT_MAXIMUM_WAIT_SECONDS = 3.0
DEFAULT_GRACE_SECONDS = 2.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.05
DEFAULT_MAXIMUM_ACTIVE_REGISTRATIONS = 20
DEFAULT_MAXIMUM_OBSERVATIONS_PER_TOKEN = 5

MAXIMUM_CALLBACK_TOKEN_TTL_SECONDS = 3600.0
MAXIMUM_WAIT_SECONDS_CAP = 30.0


class CallbackBrokerError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class CallbackPolicy:
    """Explicit, bounded limits for callback registration and waiting
    (requirement 18) -- independent of the crawl/detection request
    budgets used elsewhere in this codebase."""

    maximum_wait_seconds: float = DEFAULT_MAXIMUM_WAIT_SECONDS
    grace_seconds: float = DEFAULT_GRACE_SECONDS
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS
    token_ttl_seconds: float = DEFAULT_CALLBACK_TOKEN_TTL_SECONDS
    maximum_active_registrations: int = DEFAULT_MAXIMUM_ACTIVE_REGISTRATIONS
    maximum_observations_per_token: int = DEFAULT_MAXIMUM_OBSERVATIONS_PER_TOKEN

    def __post_init__(self) -> None:
        if not (0.0 < self.maximum_wait_seconds <= MAXIMUM_WAIT_SECONDS_CAP):
            raise CallbackBrokerError(
                "callback_policy_wait_invalid",
                f"maximum_wait_seconds must be > 0 and <= {MAXIMUM_WAIT_SECONDS_CAP}.",
            )
        if not (0.0 <= self.grace_seconds <= MAXIMUM_WAIT_SECONDS_CAP):
            raise CallbackBrokerError(
                "callback_policy_grace_invalid",
                f"grace_seconds must be >= 0 and <= {MAXIMUM_WAIT_SECONDS_CAP}.",
            )
        if not (0.0 < self.poll_interval_seconds <= 5.0):
            raise CallbackBrokerError(
                "callback_policy_poll_interval_invalid",
                "poll_interval_seconds must be > 0 and <= 5.0.",
            )
        if not (0.0 < self.token_ttl_seconds <= MAXIMUM_CALLBACK_TOKEN_TTL_SECONDS):
            raise CallbackBrokerError(
                "callback_policy_ttl_invalid",
                f"token_ttl_seconds must be > 0 and <= {MAXIMUM_CALLBACK_TOKEN_TTL_SECONDS}.",
            )
        if not (1 <= self.maximum_active_registrations <= 200):
            raise CallbackBrokerError(
                "callback_policy_registrations_invalid",
                "maximum_active_registrations must be between 1 and 200.",
            )
        if not (1 <= self.maximum_observations_per_token <= 50):
            raise CallbackBrokerError(
                "callback_policy_observations_invalid",
                "maximum_observations_per_token must be between 1 and 50.",
            )


@dataclass(frozen=True, slots=True)
class CallbackToken:
    """An opaque, high-entropy, single-purpose correlation reference and
    the full callback URL a probe should embed. The detector never
    constructs a callback URL itself -- only a `CallbackBroker` does,
    so there is exactly one place a callback destination is ever
    produced."""

    value: str
    url: str
    scan_id: str
    candidate_fingerprint: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class CallbackObservation:
    """One bounded, sanitized record of an inbound request that
    presented a valid, unexpired, under-quota callback token. Never
    carries full headers, raw source IP, or a request body -- only what
    the confirmation logic in `ssrf_callback_detector.py` actually
    needs (requirement 10)."""

    token_value: str
    observed_at: datetime
    method: str
    source_class: str = "external"


class CallbackBroker(Protocol):
    """The interface `ssrf_callback_detector.py` depends on. Any
    implementation -- in-memory (this module), repository-backed
    (`apps/api`), or a future cloud callback service client -- must
    satisfy this exactly; the detector is written against this
    protocol only, never against a concrete class."""

    def register(
        self, *, scan_id: str, candidate_fingerprint: str
    ) -> CallbackToken: ...

    def wait_for_observation(
        self,
        token: CallbackToken,
        *,
        policy: CallbackPolicy,
        cancellation_check: Callable[[], bool] | None = None,
    ) -> Tuple[CallbackObservation | None, bool, bool]:
        """Returns ``(observation_or_none, within_primary_window,
        cancelled)``. ``within_primary_window`` is False when an
        observation was only found during the secondary grace period
        (see ``CallbackPolicy.grace_seconds``) -- callers use this to
        decide between CONFIRMED and PROBABLE without this protocol
        needing to know about detector-level classification at all.
        ``cancelled`` is True only when ``cancellation_check`` stopped
        the wait early -- distinct from a full wait that genuinely
        observed nothing, so a caller can tell "cancelled, unknown"
        apart from "waited it out, no callback"."""
        ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InMemoryCallbackBroker:
    """Bounded, self-contained, in-memory `CallbackBroker`. Requires no
    real network listener -- a caller (typically a test, or the
    standalone `webguard scan` CLI path) that wants genuine inbound
    HTTP callbacks must still run something that calls
    `record_observation` when a request actually arrives; this class
    only owns the correlation state, not a socket. See
    `apps/api/webguard_api/callback_server.py` for the real local HTTP
    receiver that calls into a broker exactly like this one."""

    def __init__(self, *, base_url: str = "http://127.0.0.1:0/") -> None:
        self._base_url = base_url if base_url.endswith("/") else base_url + "/"
        self._lock = threading.Lock()
        self._tokens: dict[str, CallbackToken] = {}
        self._observations: dict[str, list[CallbackObservation]] = {}

    def set_base_url(self, base_url: str) -> None:
        """Updates the URL prefix used for every *subsequent*
        `register()` call. See `CallbackRepository.set_base_url` for
        why this exists (a local-testing construction-order
        dependency, not a production pattern)."""

        with self._lock:
            self._base_url = base_url if base_url.endswith("/") else base_url + "/"

    def register(
        self,
        *,
        scan_id: str,
        candidate_fingerprint: str,
        policy: CallbackPolicy = CallbackPolicy(),
    ) -> CallbackToken:
        with self._lock:
            active = sum(
                1
                for existing in self._tokens.values()
                if existing.expires_at > _utc_now()
            )
            if active >= policy.maximum_active_registrations:
                raise CallbackBrokerError(
                    "callback_registration_limit_exceeded",
                    f"{active} active callback registrations already exist, "
                    f"at the {policy.maximum_active_registrations} limit.",
                )
            value = secrets.token_urlsafe(32)
            token = CallbackToken(
                value=value,
                url=f"{self._base_url}{scan_id}/{value}",
                scan_id=scan_id,
                candidate_fingerprint=candidate_fingerprint,
                expires_at=_utc_now() + timedelta(seconds=policy.token_ttl_seconds),
            )
            self._tokens[value] = token
            self._observations[value] = []
            return token

    def record_observation(
        self,
        token_value: str,
        *,
        method: str,
        source_class: str = "external",
        policy: CallbackPolicy = CallbackPolicy(),
        now: datetime | None = None,
    ) -> bool:
        """Called by a real HTTP receiver (or a test standing in for
        one) when an inbound request presents ``token_value``. Returns
        False -- silently, never raising -- for an unknown, expired, or
        over-quota token: an attacker who guesses or replays a callback
        path must never be able to trigger an exception an operator
        might mistake for something else, and must never be able to
        fabricate a confirmed finding merely by hitting an arbitrary
        path."""

        moment = now or _utc_now()
        with self._lock:
            token = self._tokens.get(token_value)
            if token is None or token.expires_at <= moment:
                return False
            observations = self._observations[token_value]
            if len(observations) >= policy.maximum_observations_per_token:
                return False
            observations.append(
                CallbackObservation(
                    token_value=token_value,
                    observed_at=moment,
                    method=method,
                    source_class=source_class,
                )
            )
            return True

    def wait_for_observation(
        self,
        token: CallbackToken,
        *,
        policy: CallbackPolicy = CallbackPolicy(),
        cancellation_check: Callable[[], bool] | None = None,
    ) -> Tuple[CallbackObservation | None, bool, bool]:
        deadline_primary = time.monotonic() + policy.maximum_wait_seconds
        deadline_grace = deadline_primary + policy.grace_seconds

        while True:
            if cancellation_check is not None and cancellation_check():
                return None, False, True
            with self._lock:
                observations = self._observations.get(token.value, ())
                if observations:
                    return observations[0], time.monotonic() <= deadline_primary, False
            if time.monotonic() >= deadline_grace:
                return None, False, False
            time.sleep(policy.poll_interval_seconds)


__all__ = [
    "DEFAULT_CALLBACK_TOKEN_TTL_SECONDS",
    "DEFAULT_GRACE_SECONDS",
    "DEFAULT_MAXIMUM_ACTIVE_REGISTRATIONS",
    "DEFAULT_MAXIMUM_OBSERVATIONS_PER_TOKEN",
    "DEFAULT_MAXIMUM_WAIT_SECONDS",
    "DEFAULT_POLL_INTERVAL_SECONDS",
    "MAXIMUM_CALLBACK_TOKEN_TTL_SECONDS",
    "MAXIMUM_WAIT_SECONDS_CAP",
    "CallbackBroker",
    "CallbackBrokerError",
    "CallbackObservation",
    "CallbackPolicy",
    "CallbackToken",
    "InMemoryCallbackBroker",
]
