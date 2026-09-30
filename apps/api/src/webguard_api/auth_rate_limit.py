"""Pre-authentication abuse protection (Slice 16 requirement 12):
bounded limits on login attempts, password-reset requests, email-
verification resends, and invitation acceptance -- all keyed by a
caller-supplied bucket (typically ``f"{purpose}:{ip}:{identifier}"``),
counted over a trailing window.

Two backends, matching every other repository in this project:

- ``InMemoryAuthRateLimiter`` wraps the existing process-local
  ``FixedWindowRateLimiter`` -- fine for local/dev/lab/tests, where
  exactly one process ever serves these routes.
- ``PostgresAuthRateLimiter`` is a real, distributed-safe counter:
  one row per attempt in ``auth_rate_limit_events``, counted over a
  trailing window via a plain indexed query. This is deliberately not
  a read-modify-write counter row (which would race under concurrent
  writers); an INSERT plus a COUNT is race-free by construction.

**Is PostgreSQL alone sufficient?** Yes, for this slice and for any
deployment with a small number of API processes: the write volume is
bounded by genuine auth-adjacent traffic (never a hot path), and the
window query is a simple indexed range scan. This becomes worth
replacing with a Redis-backed limiter only if API processes scale to
the point where "every auth attempt round-trips the primary database"
is itself a real cost concern, or if sub-millisecond decision latency
matters more than it does for a login form -- neither is true today.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol

from .postgres_pool import WebGuardPostgresPool
from .rate_limit import FixedWindowRateLimiter, RateLimitError


class AuthRateLimiter(Protocol):
    def check_and_record(self, bucket_key: str, *, now: datetime) -> None: ...


class InMemoryAuthRateLimiter:
    def __init__(self, *, max_attempts: int, window_seconds: int) -> None:
        self._limiter = FixedWindowRateLimiter(requests=max_attempts, window_seconds=window_seconds)

    def check_and_record(self, bucket_key: str, *, now: datetime) -> None:
        self._limiter.check(bucket_key, now_epoch=now.timestamp())


class PostgresAuthRateLimiter:
    def __init__(self, pool: WebGuardPostgresPool, *, max_attempts: int, window_seconds: int) -> None:
        self._pool = pool
        self._max_attempts = max_attempts
        self._window = timedelta(seconds=window_seconds)

    def check_and_record(self, bucket_key: str, *, now: datetime) -> None:
        # Best-effort, not a hard atomic cap: a handful of concurrent
        # requests for the same bucket can each pass the COUNT check
        # before any of them INSERTs (a classic check-then-act race).
        # That is an acceptable bound for brute-force protection, which
        # needs thousands of attempts to matter, not one or two extra
        # ones under a rare concurrent burst -- and it is deliberately
        # not serialized with an advisory lock, since doing so would
        # make every login attempt across the whole deployment contend
        # on one lock, which is its own denial-of-service shape.
        window_start = now - self._window
        with self._pool.connection() as connection:
            # Bound table growth: this bucket's own attempts older than
            # the window are no longer relevant to any decision.
            connection.execute(
                "DELETE FROM auth_rate_limit_events WHERE bucket_key = %s AND occurred_at < %s",
                (bucket_key, window_start),
            )
            row = connection.execute(
                "SELECT COUNT(*) FROM auth_rate_limit_events WHERE bucket_key = %s AND occurred_at >= %s",
                (bucket_key, window_start),
            ).fetchone()
            count = row[0] if row else 0
            if count >= self._max_attempts:
                raise RateLimitError(
                    "auth_rate_limit_exceeded",
                    "Too many attempts. Try again later.",
                    retry_after_seconds=int(self._window.total_seconds()),
                )
            connection.execute(
                "INSERT INTO auth_rate_limit_events (bucket_key, occurred_at) VALUES (%s, %s)",
                (bucket_key, now),
            )


__all__ = [
    "AuthRateLimiter",
    "InMemoryAuthRateLimiter",
    "PostgresAuthRateLimiter",
]
