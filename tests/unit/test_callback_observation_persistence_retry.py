"""P1-12 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
fast, deterministic tests for `_record_observation_with_bounded_retry()`
in `callback_server.py` -- the bounded, `DatabaseError`-only retry that
sits between `CallbackHttpReceiver._handle()` and whatever
`_ObservationSink` it was constructed with. Mirrors worker.py's own
fast-unit-test pattern for its P1-10 retry helper: an injected fake
`sleep` (never a real one) and a fake sink scripted to raise a
controlled number of times, so exact attempt counts and backoff
durations are provable without any real timing dependency."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from webguard_api.callback_server import (
    DEFAULT_RECORD_OBSERVATION_MAXIMUM_ATTEMPTS,
    DEFAULT_RECORD_OBSERVATION_RETRY_BACKOFF_SECONDS,
    _record_observation_with_bounded_retry,
)
from webguard_api.db_errors import DatabaseUnavailableError
from webguard_api.store import JobStoreError

NOW = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)


class _FakeSink:
    """Scripted `_ObservationSink`: `fail_count` calls raise
    `DatabaseError`, then every subsequent call succeeds (or, if
    `always_fail`, every call raises). Records every call's exact
    arguments so a test can assert `now` was never recomputed between
    attempts."""

    def __init__(self, *, fail_count: int = 0, always_fail: bool = False, raise_instead: Exception | None = None) -> None:
        self.fail_count = fail_count
        self.always_fail = always_fail
        self.raise_instead = raise_instead
        self.calls: list[dict] = []

    def record_observation(self, token_value: str, *, method: str, now: datetime | None = None) -> bool:
        self.calls.append({"token_value": token_value, "method": method, "now": now})
        if self.raise_instead is not None and len(self.calls) == 1:
            raise self.raise_instead
        if self.always_fail or len(self.calls) <= self.fail_count:
            raise DatabaseUnavailableError("database_unavailable", "The database is currently unavailable.")
        return True


class _FakeSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class RecordObservationBoundedRetryTests(unittest.TestCase):
    def test_success_on_first_attempt_never_sleeps_and_makes_exactly_one_call(self) -> None:
        sink = _FakeSink(fail_count=0)
        sleep = _FakeSleep()
        _record_observation_with_bounded_retry(
            sink, "tok-1", method="GET", now=NOW,
            maximum_attempts=3, retry_backoff_seconds=0.1, sleep=sleep,
        )
        self.assertEqual(len(sink.calls), 1)
        self.assertEqual(sleep.calls, [])

    def test_one_transient_failure_then_success_retries_exactly_once(self) -> None:
        sink = _FakeSink(fail_count=1)
        sleep = _FakeSleep()
        _record_observation_with_bounded_retry(
            sink, "tok-1", method="GET", now=NOW,
            maximum_attempts=3, retry_backoff_seconds=0.1, sleep=sleep,
        )
        self.assertEqual(len(sink.calls), 2)
        self.assertEqual(sleep.calls, [0.1])

    def test_exhausting_every_attempt_gives_up_silently_no_exception_raised(self) -> None:
        sink = _FakeSink(always_fail=True)
        sleep = _FakeSleep()
        # Must not raise -- the caller (the HTTP handler) always reaches
        # the same uniform response regardless of persistence outcome.
        _record_observation_with_bounded_retry(
            sink, "tok-1", method="GET", now=NOW,
            maximum_attempts=2, retry_backoff_seconds=0.1, sleep=sleep,
        )
        self.assertEqual(len(sink.calls), 2, "must attempt exactly maximum_attempts times, never more")
        self.assertEqual(sleep.calls, [0.1], "must back off between attempts but never after the final one")

    def test_attempt_count_is_exactly_bounded_never_one_extra_or_one_short(self) -> None:
        for maximum_attempts in (1, 2, 5):
            with self.subTest(maximum_attempts=maximum_attempts):
                sink = _FakeSink(always_fail=True)
                sleep = _FakeSleep()
                _record_observation_with_bounded_retry(
                    sink, "tok-1", method="GET", now=NOW,
                    maximum_attempts=maximum_attempts, retry_backoff_seconds=0.05, sleep=sleep,
                )
                self.assertEqual(len(sink.calls), maximum_attempts)
                self.assertEqual(len(sleep.calls), maximum_attempts - 1)

    def test_default_constants_match_a_short_two_attempt_budget(self) -> None:
        # P1-12: deliberately much smaller than worker.py's P1-10
        # constants -- see callback_server.py's own module-level
        # comment for the full latency-budget justification.
        self.assertEqual(DEFAULT_RECORD_OBSERVATION_MAXIMUM_ATTEMPTS, 2)
        self.assertLess(DEFAULT_RECORD_OBSERVATION_RETRY_BACKOFF_SECONDS, 1.0)

    def test_semantic_job_store_error_is_never_retried(self) -> None:
        """A semantic failure (not a DatabaseError) must propagate
        immediately -- retrying it would be exactly the "blindly retry
        semantic errors" mistake P1-10/P1-11 were careful to avoid."""
        sink = _FakeSink(raise_instead=JobStoreError("some_semantic_code", "not an infrastructure failure"))
        sleep = _FakeSleep()
        with self.assertRaises(JobStoreError):
            _record_observation_with_bounded_retry(
                sink, "tok-1", method="GET", now=NOW,
                maximum_attempts=3, retry_backoff_seconds=0.1, sleep=sleep,
            )
        self.assertEqual(len(sink.calls), 1, "a semantic error must not be retried")
        self.assertEqual(sleep.calls, [])

    def test_unexpected_programming_error_is_never_retried_or_swallowed(self) -> None:
        sink = _FakeSink(raise_instead=TypeError("simulated unexpected programming error"))
        sleep = _FakeSleep()
        with self.assertRaises(TypeError):
            _record_observation_with_bounded_retry(
                sink, "tok-1", method="GET", now=NOW,
                maximum_attempts=3, retry_backoff_seconds=0.1, sleep=sleep,
            )
        self.assertEqual(len(sink.calls), 1)

    def test_now_is_never_recomputed_between_attempts(self) -> None:
        """P1-12 OBSERVED_AT SEMANTICS: the exact same `now` value must
        be passed on every attempt, whether the first fails or not --
        the persisted observed_at must reflect when the callback
        actually arrived, never when a retry happened to succeed."""
        sink = _FakeSink(fail_count=1)
        sleep = _FakeSleep()
        _record_observation_with_bounded_retry(
            sink, "tok-1", method="GET", now=NOW,
            maximum_attempts=3, retry_backoff_seconds=0.05, sleep=sleep,
        )
        self.assertEqual(len(sink.calls), 2)
        self.assertEqual(sink.calls[0]["now"], NOW)
        self.assertEqual(sink.calls[1]["now"], NOW)
        self.assertIs(sink.calls[0]["now"], sink.calls[1]["now"], "the exact same object, not merely an equal value")


if __name__ == "__main__":
    unittest.main()
