"""P1 Batch A1: tests for `PostgresCallbackBroker` -- the production
SSRF-callback adapter over durable PostgreSQL storage
(apps/api/src/webguard_api/postgres_callback_broker.py).

Reproduces, at a fast and deterministic unit-test level, the real
failure this batch fixed: a `DatabaseError` (Postgres unreachable)
occurring during `wait_for_observation()` -- at wait-start
(`get_registration`) or mid-poll (`_latest_observation`) -- must
translate to `CallbackServiceError`, exactly like `register()`'s own
pre-existing `DatabaseError` handling, never silently return "no
observation" (indistinguishable from a genuine NOT_VULNERABLE result)
and never leave a raw driver-shaped exception to escape uncaught. See
tests/unit/test_ssrf_callback_detector.py for the next layer up (this
translated all the way to a per-candidate INCONCLUSIVE outcome, not a
crashed detector run), and this session's own live reproduction against
a real, killed-and-restarted Postgres container for proof this is not
just a mocked-away assumption -- before the fix, the equivalent
uncaught `DatabaseUnavailableError` crashed the entire worker thread
(worker.py's own `_fail()` needing Postgres too, at a moment Postgres
was still down, is a second, adjacent, NOT-yet-fixed finding -- see
this batch's own remediation report).
"""

from __future__ import annotations

import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Callable

from webguard_api.callback_service import CallbackServiceError, ScopedCallbackRegistration
from webguard_api.db_errors import DatabaseError, DatabaseUnavailableError
from webguard_api.postgres_callback_broker import PostgresCallbackBroker
from webguard_scanner.callback_broker import CallbackPolicy

NOW = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
BASE_URL = "https://callback.example.test/"
ORG_ID = "org-1"


def _registration(*, token_value: str = "tok-1", expires_at: datetime | None = None, revoked_at: datetime | None = None) -> ScopedCallbackRegistration:
    return ScopedCallbackRegistration(
        token_value=token_value,
        scan_id="scan-1",
        organization_id=ORG_ID,
        target="https://target.example.test/",
        authorization_id="auth-1",
        candidate_fingerprint="url",
        created_at=NOW,
        expires_at=expires_at or (NOW + timedelta(minutes=5)),
        job_id="job-1",
    )


class _FakeRepository:
    """Mimics `PostgresCallbackRegistrationRepository`'s interface at
    the two call sites `PostgresCallbackBroker` uses. Each method can
    be scripted to raise or return a fixed value, or to call through a
    caller-supplied side effect (so a test can vary behavior call by
    call, e.g. "fails once, then succeeds")."""

    def __init__(self) -> None:
        self.register_effect: Callable[..., ScopedCallbackRegistration] | Exception | None = None
        self.get_registration_effect: Callable[..., ScopedCallbackRegistration] | Exception | None = None
        self.register_calls = 0
        self.get_registration_calls = 0

    def register(self, **kwargs) -> ScopedCallbackRegistration:
        self.register_calls += 1
        effect = self.register_effect
        if isinstance(effect, Exception):
            raise effect
        if callable(effect):
            return effect(**kwargs)
        return _registration()

    def get_registration(self, token_value: str, *, organization_id: str) -> ScopedCallbackRegistration:
        self.get_registration_calls += 1
        effect = self.get_registration_effect
        if isinstance(effect, Exception):
            raise effect
        if callable(effect):
            return effect(token_value, organization_id=organization_id)
        return _registration(token_value=token_value)


class _FakeConnection:
    def __init__(self, row: tuple | None) -> None:
        self._row = row

    def execute(self, *args, **kwargs) -> "_FakeConnection":
        return self

    def fetchone(self) -> tuple | None:
        return self._row


class _FakePool:
    """Mimics `WebGuardPostgresPool`'s `.connection()` context manager,
    the one direct dependency `_latest_observation()` has beyond the
    repository. `poll_effects` is consumed one entry per call to
    `.connection()` -- an `Exception` instance is raised, anything else
    is treated as the row `fetchone()` should return (`None` = no
    observation yet)."""

    def __init__(self, poll_effects: list) -> None:
        self._effects = list(poll_effects)
        self.calls = 0

    @contextmanager
    def connection(self):
        self.calls += 1
        effect = self._effects.pop(0) if self._effects else None
        if isinstance(effect, Exception):
            raise effect
        yield _FakeConnection(effect)


def _broker(repository: _FakeRepository, pool: _FakePool, *, policy: CallbackPolicy | None = None) -> PostgresCallbackBroker:
    return PostgresCallbackBroker(repository, pool, base_url=BASE_URL, policy=policy)


class RegisterDatabaseFailureTests(unittest.TestCase):
    """Scenario 1: DB unavailable during registration -- pre-existing
    behavior (register() already translated DatabaseError before this
    batch); recorded here as an explicit regression proof for A1's own
    test list, at the exact class this batch also touches."""

    def test_database_error_during_registration_becomes_callback_service_error(self) -> None:
        repository = _FakeRepository()
        repository.register_effect = DatabaseUnavailableError(
            "database_unavailable", "The database is currently unavailable."
        )
        broker = _broker(repository, _FakePool([]))

        with self.assertRaises(CallbackServiceError) as caught:
            broker.register(
                scan_id="scan-1", candidate_fingerprint="url", organization_id=ORG_ID,
                target="https://target.example.test/", authorization_id="auth-1",
            )
        self.assertEqual(caught.exception.code, "database_unavailable")


class WaitForObservationDatabaseFailureTests(unittest.TestCase):
    def _token(self):
        from webguard_scanner.callback_broker import CallbackToken

        return CallbackToken(
            value="tok-1", url=f"{BASE_URL}scan-1/tok-1", scan_id="scan-1",
            candidate_fingerprint="url", expires_at=NOW + timedelta(minutes=5),
        )

    def test_database_unavailable_at_wait_start_becomes_callback_service_error(self) -> None:
        """Scenario 2: DB unavailable during the first observation
        poll -- here, specifically the ownership check
        (`get_registration`) that runs before the poll loop even
        begins."""
        repository = _FakeRepository()
        repository.get_registration_effect = DatabaseUnavailableError(
            "database_unavailable", "The database is currently unavailable."
        )
        broker = _broker(repository, _FakePool([]))

        with self.assertRaises(CallbackServiceError) as caught:
            broker.wait_for_observation(self._token(), organization_id=ORG_ID, policy=CallbackPolicy())
        self.assertEqual(caught.exception.code, "database_unavailable")

    def test_database_fails_after_one_successful_empty_poll(self) -> None:
        """Scenario 3: DB fails after one successful empty poll -- the
        first `_latest_observation()` call succeeds (no observation
        yet), the second raises. Must still surface as
        CallbackServiceError, never as a silent "no observation"."""
        repository = _FakeRepository()
        pool = _FakePool([
            None,  # first poll: connects fine, no row yet
            DatabaseUnavailableError("database_unavailable", "The database is currently unavailable."),
        ])
        broker = _broker(repository, pool, policy=CallbackPolicy(
            maximum_wait_seconds=2.0, grace_seconds=2.0, poll_interval_seconds=0.02
        ))

        with self.assertRaises(CallbackServiceError) as caught:
            broker.wait_for_observation(self._token(), organization_id=ORG_ID, policy=CallbackPolicy(
                maximum_wait_seconds=2.0, grace_seconds=2.0, poll_interval_seconds=0.02
            ))
        self.assertEqual(caught.exception.code, "database_unavailable")
        self.assertGreaterEqual(pool.calls, 2)

    def test_never_returns_not_vulnerable_shape_on_database_failure(self) -> None:
        """Explicit contract check: a DB failure must raise, never
        return the same (None, False, False) tuple a genuine absent
        observation returns -- the two must never be indistinguishable
        to the caller."""
        repository = _FakeRepository()
        pool = _FakePool([DatabaseUnavailableError("database_unavailable", "unavailable")])
        broker = _broker(repository, pool)

        raised = False
        try:
            result = broker.wait_for_observation(self._token(), organization_id=ORG_ID, policy=CallbackPolicy())
            self.fail(f"expected CallbackServiceError, got a normal return: {result!r}")
        except CallbackServiceError:
            raised = True
        self.assertTrue(raised)

    def test_intermittent_empty_polls_before_a_real_observation_still_succeed(self) -> None:
        """Scenario 4 (DB recovers during bounded wait), expressed at
        this layer: a call that does NOT raise (an ordinary empty poll,
        the shape any brief, sub-pool-timeout blip already takes once
        it's below WebGuardPostgresPool's own connection-checkout
        retry) must not be affected by this fix at all -- polling
        continues normally and a later, genuine observation is still
        found. This batch adds no new retry logic of its own; the
        existing poll loop (unmodified) already provides this."""
        repository = _FakeRepository()
        observed_at = NOW + timedelta(seconds=1)
        pool = _FakePool([
            None, None,  # two ordinary empty polls
            ("GET", "external", observed_at),  # then a genuine observation
        ])
        broker = _broker(repository, pool, policy=CallbackPolicy(
            maximum_wait_seconds=2.0, grace_seconds=2.0, poll_interval_seconds=0.01
        ))

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID,
            policy=CallbackPolicy(maximum_wait_seconds=2.0, grace_seconds=2.0, poll_interval_seconds=0.01),
        )
        self.assertIsNotNone(observation)
        self.assertEqual(observation.token_value, "tok-1")
        self.assertTrue(within_primary)
        self.assertFalse(cancelled)

    def test_observation_genuinely_absent_times_out_cleanly(self) -> None:
        """Scenario 5: observation genuinely absent -- no DB failure
        anywhere, the wait simply times out. Must remain unaffected by
        this fix (no exception, ordinary (None, False, False))."""
        repository = _FakeRepository()
        pool = _FakePool([None] * 50)  # never a row, for the whole window
        broker = _broker(repository, pool, policy=CallbackPolicy(
            maximum_wait_seconds=0.1, grace_seconds=0.1, poll_interval_seconds=0.02
        ))

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID,
            policy=CallbackPolicy(maximum_wait_seconds=0.1, grace_seconds=0.1, poll_interval_seconds=0.02),
        )
        self.assertIsNone(observation)
        self.assertFalse(within_primary)
        self.assertFalse(cancelled)

    def test_observation_genuinely_present_is_returned(self) -> None:
        """Scenario 6: observation genuinely present -- must remain
        unaffected by this fix."""
        repository = _FakeRepository()
        observed_at = NOW
        pool = _FakePool([("GET", "external", observed_at)])
        broker = _broker(repository, pool, policy=CallbackPolicy(
            maximum_wait_seconds=1.0, grace_seconds=1.0, poll_interval_seconds=0.02
        ))

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID,
            policy=CallbackPolicy(maximum_wait_seconds=1.0, grace_seconds=1.0, poll_interval_seconds=0.02),
        )
        self.assertIsNotNone(observation)
        self.assertEqual(observation.method, "GET")
        self.assertTrue(within_primary)

    def test_expired_but_unrevoked_token_resolves_as_no_observation(self) -> None:
        """Scenario 7: expired token. `get_registration()` itself has
        no independent expiry check (expiry is enforced at
        `record_observation()` time -- an expired token simply never
        gets an observation recorded for it), so this resolves as an
        ordinary, clean timeout -- not an exception. Recorded here as
        an explicit regression proof, unaffected by this fix."""
        repository = _FakeRepository()
        repository.get_registration_effect = lambda token_value, *, organization_id: _registration(
            token_value=token_value, expires_at=NOW - timedelta(seconds=1)
        )
        pool = _FakePool([None] * 10)
        broker = _broker(repository, pool, policy=CallbackPolicy(
            maximum_wait_seconds=0.05, grace_seconds=0.05, poll_interval_seconds=0.01
        ))

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID,
            policy=CallbackPolicy(maximum_wait_seconds=0.05, grace_seconds=0.05, poll_interval_seconds=0.01),
        )
        self.assertIsNone(observation)
        self.assertFalse(cancelled)

    def test_revoked_token_becomes_callback_service_error_not_a_crash(self) -> None:
        """Scenario 8: revoked token. `get_registration()` already
        raised CallbackServiceError directly for this (pre-existing) --
        before this fix, nothing wrapped `wait_for_observation()` at
        any layer above this, so it would have propagated uncaught all
        the way to the worker. This test proves it still raises the
        identical, well-typed error this layer has always raised for
        this case (the *upper* layers' new handling of it is proven in
        test_ssrf_callback_detector.py and executor.py's own tests)."""
        repository = _FakeRepository()
        repository.get_registration_effect = lambda token_value, *, organization_id: (
            _ for _ in ()
        ).throw(CallbackServiceError("callback_registration_revoked", "This callback registration has been revoked."))
        broker = _broker(repository, _FakePool([]))

        with self.assertRaises(CallbackServiceError) as caught:
            broker.wait_for_observation(self._token(), organization_id=ORG_ID, policy=CallbackPolicy())
        self.assertEqual(caught.exception.code, "callback_registration_revoked")

    def test_wrong_organization_becomes_callback_service_error_not_a_crash(self) -> None:
        """Scenario 9: wrong organization. `get_registration()` scopes
        its lookup by (token_value, organization_id) -- a mismatch is
        indistinguishable from "not found" by design (never leaks
        another org's registration existence)."""
        repository = _FakeRepository()
        repository.get_registration_effect = lambda token_value, *, organization_id: (
            _ for _ in ()
        ).throw(CallbackServiceError("callback_registration_not_found", "No callback registration matches the requested token."))
        broker = _broker(repository, _FakePool([]))

        with self.assertRaises(CallbackServiceError) as caught:
            broker.wait_for_observation(self._token(), organization_id="a-different-org", policy=CallbackPolicy())
        self.assertEqual(caught.exception.code, "callback_registration_not_found")

    def test_raw_database_error_is_never_the_exception_type_that_escapes(self) -> None:
        """Explicit "do not leak raw database exceptions" check: the
        exception a caller actually catches must be CallbackServiceError
        (the scanner-facing type this package's error taxonomy defines),
        never the raw DatabaseError/DatabaseUnavailableError itself."""
        repository = _FakeRepository()
        pool = _FakePool([DatabaseUnavailableError("database_unavailable", "unavailable")])
        broker = _broker(repository, pool)

        try:
            broker.wait_for_observation(self._token(), organization_id=ORG_ID, policy=CallbackPolicy())
            self.fail("expected an exception")
        except CallbackServiceError:
            pass
        except DatabaseError:
            self.fail("a raw DatabaseError escaped instead of the translated CallbackServiceError")


if __name__ == "__main__":
    unittest.main()
