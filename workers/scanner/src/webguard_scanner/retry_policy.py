"""Bounded retry configuration for OpenHuntX WebGuard."""

from __future__ import annotations

import math
from dataclasses import dataclass


MAXIMUM_REQUEST_ATTEMPTS = 3
MAXIMUM_BACKOFF_SECONDS = 5.0
MAXIMUM_BACKOFF_MULTIPLIER = 4.0


def _finite_number(
    value: object,
    *,
    field_name: str,
) -> float:
    """Return a finite float while rejecting booleans and invalid types."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            f"{field_name} must be a finite number."
        )

    normalised = float(value)

    if not math.isfinite(normalised):
        raise ValueError(
            f"{field_name} must be a finite number."
        )

    return normalised


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Strict limits for retrying transient request failures.

    maximum_attempts counts the initial request. A value of one therefore
    disables retries, which is the default.
    """

    maximum_attempts: int = 1
    initial_backoff_seconds: float = 0.25
    backoff_multiplier: float = 2.0
    maximum_backoff_seconds: float = 2.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.maximum_attempts, bool)
            or not isinstance(self.maximum_attempts, int)
        ):
            raise ValueError(
                "maximum_attempts must be an integer."
            )

        if not (
            1
            <= self.maximum_attempts
            <= MAXIMUM_REQUEST_ATTEMPTS
        ):
            raise ValueError(
                "maximum_attempts must be between 1 and "
                f"{MAXIMUM_REQUEST_ATTEMPTS}."
            )

        initial = _finite_number(
            self.initial_backoff_seconds,
            field_name="initial_backoff_seconds",
        )
        multiplier = _finite_number(
            self.backoff_multiplier,
            field_name="backoff_multiplier",
        )
        maximum = _finite_number(
            self.maximum_backoff_seconds,
            field_name="maximum_backoff_seconds",
        )

        if initial < 0:
            raise ValueError(
                "initial_backoff_seconds cannot be negative."
            )

        if not (
            1.0
            <= multiplier
            <= MAXIMUM_BACKOFF_MULTIPLIER
        ):
            raise ValueError(
                "backoff_multiplier must be between 1.0 and "
                f"{MAXIMUM_BACKOFF_MULTIPLIER}."
            )

        if not (
            0
            <= maximum
            <= MAXIMUM_BACKOFF_SECONDS
        ):
            raise ValueError(
                "maximum_backoff_seconds must be between 0 and "
                f"{MAXIMUM_BACKOFF_SECONDS}."
            )

        if initial > maximum:
            raise ValueError(
                "initial_backoff_seconds cannot exceed "
                "maximum_backoff_seconds."
            )

        object.__setattr__(
            self,
            "initial_backoff_seconds",
            initial,
        )
        object.__setattr__(
            self,
            "backoff_multiplier",
            multiplier,
        )
        object.__setattr__(
            self,
            "maximum_backoff_seconds",
            maximum,
        )

    @property
    def retries_enabled(self) -> bool:
        """Return whether at least one retry can occur."""

        return self.maximum_attempts > 1

    def delay_after_failure(
        self,
        failed_attempt_number: int,
    ) -> float:
        """Return the capped delay before the next request attempt.

        failed_attempt_number is one-based. It must identify an attempt
        that has a following attempt under this policy.
        """

        if (
            isinstance(failed_attempt_number, bool)
            or not isinstance(failed_attempt_number, int)
            or failed_attempt_number < 1
            or failed_attempt_number >= self.maximum_attempts
        ):
            raise ValueError(
                "failed_attempt_number must identify an attempt "
                "that has a following attempt."
            )

        delay = (
            self.initial_backoff_seconds
            * (
                self.backoff_multiplier
                ** (failed_attempt_number - 1)
            )
        )

        return min(
            delay,
            self.maximum_backoff_seconds,
        )
