"""Small in-memory fixed-window rate-limit foundation for the local API."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class RateLimitError(ValueError):
    def __init__(self, code: str, message: str, *, retry_after_seconds: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = 429
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    limit: int
    remaining: int
    reset_after_seconds: int


class FixedWindowRateLimiter:
    """Process-local per-token limiter; intentionally not a distributed quota."""

    def __init__(self, *, requests: int, window_seconds: int) -> None:
        if isinstance(requests, bool) or not isinstance(requests, int) or requests < 1:
            raise ValueError("requests must be a positive integer")
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or window_seconds < 1:
            raise ValueError("window_seconds must be a positive integer")
        self.requests = requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[int, int]] = {}

    def check(self, key: str, *, now_epoch: float) -> RateLimitDecision:
        window = int(now_epoch // self.window_seconds)
        with self._lock:
            current_window, count = self._windows.get(key, (window, 0))
            if current_window != window:
                current_window, count = window, 0
            if count >= self.requests:
                retry = max(1, int((window + 1) * self.window_seconds - now_epoch))
                raise RateLimitError(
                    "rate_limit_exceeded",
                    "The API token exceeded the local request limit.",
                    retry_after_seconds=retry,
                )
            count += 1
            self._windows[key] = (current_window, count)
            reset = max(1, int((window + 1) * self.window_seconds - now_epoch))
            return RateLimitDecision(
                limit=self.requests,
                remaining=self.requests - count,
                reset_after_seconds=reset,
            )


__all__ = [
    "FixedWindowRateLimiter",
    "RateLimitDecision",
    "RateLimitError",
]
