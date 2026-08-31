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


class EvidenceTimeClassificationTests(unittest.TestCase):
    """P1-12: `wait_for_observation()`'s CONFIRMED-vs-PROBABLE decision
    is based on `observation.observed_at` (when the callback actually
    arrived, timestamped by the callback-service process) compared
    against UTC deadlines anchored to this call's own start -- never on
    `time.monotonic()` at the moment this process's poll query happens
    to notice the row. `policy.maximum_wait_seconds`/`grace_seconds`
    are kept short (well under a second) purely so these tests run
    fast and deterministically; the boundary offsets below (0.5s
    margins) are chosen to be far larger than any realistic jitter
    between this test's own `datetime.now(timezone.utc)` capture and
    the method's internal one, so there is no flakiness risk."""

    POLICY = CallbackPolicy(maximum_wait_seconds=1.0, grace_seconds=1.0, poll_interval_seconds=0.01)

    def _token(self):
        from webguard_scanner.callback_broker import CallbackToken

        return CallbackToken(
            value="tok-1", url=f"{BASE_URL}scan-1/tok-1", scan_id="scan-1",
            candidate_fingerprint="url", expires_at=NOW + timedelta(minutes=5),
        )

    @staticmethod
    def _row(observed_at: datetime) -> tuple:
        return ("GET", "external", observed_at)

    def test_a_late_discovery_of_an_in_window_callback_is_still_confirmed(self) -> None:
        """Scenario A: the callback genuinely arrived well inside the
        primary window, but this process's poll was slow to notice it
        (simulated here as the first poll attempt finding nothing, the
        second finding the row) -- discovery latency must not affect
        the outcome. This is the exact regression P1-12 exists to fix:
        before this change, a delayed *discovery* (e.g. from a
        persistence retry) would have compared `time.monotonic()` at
        discovery time, not the event's own timestamp, and could wrongly
        demote this to PROBABLE."""
        started = datetime.now(timezone.utc)
        observed_at = started + timedelta(seconds=0.3)  # well inside the 1.0s primary window
        repository = _FakeRepository()
        pool = _FakePool([None, self._row(observed_at)])  # first poll: nothing yet; second: found
        broker = _broker(repository, pool, policy=self.POLICY)

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID, policy=self.POLICY
        )
        self.assertIsNotNone(observation)
        self.assertTrue(within_primary, "a persistence/discovery delay must not demote an in-window callback")
        self.assertFalse(cancelled)

    def test_b_genuine_grace_window_arrival_is_probable(self) -> None:
        """Scenario B: the callback itself genuinely arrived after the
        primary deadline but inside grace -- PROBABLE is the correct,
        honest outcome (weaker timing evidence), not an artifact to
        eliminate."""
        started = datetime.now(timezone.utc)
        observed_at = started + timedelta(seconds=1.5)  # past the 1.0s primary, inside the 1.0-2.0s grace band
        repository = _FakeRepository()
        pool = _FakePool([self._row(observed_at)])
        broker = _broker(repository, pool, policy=self.POLICY)

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID, policy=self.POLICY
        )
        self.assertIsNotNone(observation)
        self.assertFalse(within_primary)
        self.assertFalse(cancelled)

    def test_c_arrival_after_grace_is_never_confirmed_or_probable(self) -> None:
        """Scenario C: the callback's own timestamp is past the grace
        deadline, discovered while the poll loop is (by construction of
        this test) still running -- must be treated exactly like no
        observation at all (`observation is None`), never resurrected
        as PROBABLE just because the row happened to be visible."""
        started = datetime.now(timezone.utc)
        observed_at = started + timedelta(seconds=3.0)  # past the full 2.0s (primary+grace) window
        repository = _FakeRepository()
        pool = _FakePool([self._row(observed_at)])
        broker = _broker(repository, pool, policy=self.POLICY)

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID, policy=self.POLICY
        )
        self.assertIsNone(observation)
        self.assertFalse(within_primary)
        self.assertFalse(cancelled)

    def test_d_never_persisted_never_fabricated(self) -> None:
        """Scenario D: no row ever appears (persistence permanently
        failed) -- must time out to (None, False, False), identical to
        a genuine NOT_VULNERABLE result. Nothing here fabricates an
        observation that was never durably written."""
        repository = _FakeRepository()
        pool = _FakePool([None] * 500)  # every poll finds nothing, for the whole wait+grace window
        broker = _broker(repository, pool, policy=self.POLICY)

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID, policy=self.POLICY
        )
        self.assertIsNone(observation)
        self.assertFalse(within_primary)
        self.assertFalse(cancelled)

    def test_e_discovery_delay_alone_never_changes_the_outcome(self) -> None:
        """Scenario E: same in-window `observed_at` as scenario A, but
        with several extra empty polls first to simulate a longer
        discovery delay -- still CONFIRMED, as long as discovery occurs
        before the overall wait actually ends."""
        started = datetime.now(timezone.utc)
        observed_at = started + timedelta(seconds=0.2)
        repository = _FakeRepository()
        pool = _FakePool([None, None, None, self._row(observed_at)])
        broker = _broker(repository, pool, policy=self.POLICY)

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID, policy=self.POLICY
        )
        self.assertIsNotNone(observation)
        self.assertTrue(within_primary)
        self.assertFalse(cancelled)

    def test_f_observed_at_exactly_on_primary_boundary_is_confirmed(self) -> None:
        """Scenario F: deterministic, documented boundary semantics --
        the primary-window comparison is inclusive (`<=`), so an
        observation timestamped exactly at the primary deadline counts
        as CONFIRMED, not PROBABLE."""
        started = datetime.now(timezone.utc)
        observed_at = started + timedelta(seconds=self.POLICY.maximum_wait_seconds)
        repository = _FakeRepository()
        pool = _FakePool([self._row(observed_at)])
        broker = _broker(repository, pool, policy=self.POLICY)

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID, policy=self.POLICY
        )
        self.assertIsNotNone(observation)
        self.assertTrue(within_primary)

    def test_g_observed_at_exactly_on_grace_boundary_is_probable_not_dropped(self) -> None:
        """Scenario G: the grace-window comparison is also inclusive
        (`<=`) -- an observation timestamped exactly at the grace
        deadline still counts as PROBABLE, not silently dropped as
        "too late"."""
        started = datetime.now(timezone.utc)
        observed_at = started + timedelta(
            seconds=self.POLICY.maximum_wait_seconds + self.POLICY.grace_seconds
        )
        repository = _FakeRepository()
        pool = _FakePool([self._row(observed_at)])
        broker = _broker(repository, pool, policy=self.POLICY)

        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID, policy=self.POLICY
        )
        self.assertIsNotNone(observation)
        self.assertFalse(within_primary, "on the grace boundary this is PROBABLE, not CONFIRMED")

    def test_small_clock_offsets_do_not_change_classification_near_the_middle_of_a_window(self) -> None:
        """Synthetic clock-skew check (not a tolerance mechanism -- see
        the P1-12 design report's clock-skew analysis): small offsets
        (+-100ms, +-500ms) applied to an `observed_at` that sits well
        inside the primary window must not perturb the outcome, since
        none of these offsets approach either boundary. This documents
        the current, deliberately-untolerant behavior rather than
        introducing new slack."""
        started = datetime.now(timezone.utc)
        for offset_ms in (-500, -100, 0, 100, 500):
            with self.subTest(offset_ms=offset_ms):
                observed_at = started + timedelta(seconds=0.4) + timedelta(milliseconds=offset_ms)
                repository = _FakeRepository()
                pool = _FakePool([self._row(observed_at)])
                broker = _broker(repository, pool, policy=self.POLICY)

                observation, within_primary, _ = broker.wait_for_observation(
                    self._token(), organization_id=ORG_ID, policy=self.POLICY
                )
                self.assertIsNotNone(observation)
                self.assertTrue(within_primary)


class ClockSkewBoundaryCharacterizationTests(unittest.TestCase):
    """P1-12 follow-up: CHARACTERIZATION tests only. These prove, with
    concrete near-boundary numbers, exactly how the CURRENT
    implementation behaves under distributed clock skew between the
    callback-service host (which stamps `observed_at` at the moment a
    callback physically arrives) and the worker host (which computes
    the UTC evidence deadlines `observed_at` is compared against).
    Nothing here changes classification code and nothing here adds an
    application-level clock-skew tolerance -- none exists before or
    after this file, and this file's job is to make that fact
    concrete and testable, not to fix it.

    What these tests establish, explicitly:

    1. No application-level clock-skew tolerance exists. The
       comparison is a bare `<=`/`>` against a UTC deadline; there is
       no epsilon, grace band, or fuzz applied to absorb skew between
       hosts.
    2. Synchronized UTC clocks between the worker host and the
       callback-service host is an INFRASTRUCTURE assumption this code
       relies on (see the P1-12 design report's clock-skew analysis --
       the same assumption this codebase already makes for TrustScan
       permit validity windows), not something this code enforces,
       measures, or compensates for itself.
    3. Clock skew near an evidence boundary CAN change which bucket a
       genuine observation lands in -- tests 1 and 2 below demonstrate
       exactly that, with real numbers, in both directions.
    4. This does NOT alter WHETHER callback evidence exists. A real
       callback either arrived or it did not; skew can only move an
       arrival that genuinely happened across the CONFIRMED/PROBABLE
       line -- it can never fabricate an observation from nothing, and
       it can never make a genuine arrival vanish (see
       EvidenceTimeClassificationTests.test_d_never_persisted_never_fabricated
       for the "nothing ever arrived" case, which skew cannot affect
       since there is no observed_at to skew in the first place).
    5. It affects only the TIMING/CONFIDENCE category (CONFIRMED vs.
       PROBABLE), never whether a candidate is flagged as vulnerable
       at all -- NOT_VULNERABLE/INCONCLUSIVE classification is
       unrelated to this comparison.
    6. Monotonic time (`time.monotonic()`) remains solely responsible
       for wait-loop termination (when to stop polling) throughout --
       untouched by, and irrelevant to, every scenario below.

    Tests 3 and 4 show +-500ms surviving unperturbed ONLY because the
    chosen arrival times sit far enough from a boundary for that
    specific window (production defaults: 3.0s primary, 2.0s grace) --
    this is NOT a general "+-500ms is always safe" claim. Tests 1 and 2
    are the deliberate counter-examples: the identical +-100ms class of
    offset, placed near a boundary instead of mid-window, flips the
    outcome both ways.
    """

    POLICY = CallbackPolicy(maximum_wait_seconds=3.0, grace_seconds=2.0, poll_interval_seconds=0.01)

    def _token(self):
        from webguard_scanner.callback_broker import CallbackToken

        return CallbackToken(
            value="tok-1", url=f"{BASE_URL}scan-1/tok-1", scan_id="scan-1",
            candidate_fingerprint="url", expires_at=NOW + timedelta(minutes=5),
        )

    def _classify(self, observed_at: datetime) -> str:
        repository = _FakeRepository()
        pool = _FakePool([("GET", "external", observed_at)])
        broker = _broker(repository, pool, policy=self.POLICY)
        observation, within_primary, cancelled = broker.wait_for_observation(
            self._token(), organization_id=ORG_ID, policy=self.POLICY
        )
        self.assertIsNotNone(observation)
        self.assertFalse(cancelled)
        return "CONFIRMED" if within_primary else "PROBABLE"

    def test_1_true_arrival_just_before_primary_boundary_with_positive_skew_reads_probable(self) -> None:
        """TRUE arrival: primary_deadline - 50ms -- a genuinely
        in-window callback that, absent any skew, would be CONFIRMED.
        Callback-service clock is +100ms fast, so the value it stamps
        into `observed_at` reads as primary_deadline + 50ms -- past the
        boundary. Result: PROBABLE. The skew, not the target's actual
        timing, decided the bucket. Expected and unfixed by design --
        no tolerance exists to correct for this."""
        started = datetime.now(timezone.utc)
        primary_deadline = started + timedelta(seconds=self.POLICY.maximum_wait_seconds)
        true_arrival = primary_deadline - timedelta(milliseconds=50)
        callback_service_clock_offset = timedelta(milliseconds=100)
        stored_observed_at = true_arrival + callback_service_clock_offset
        self.assertEqual(self._classify(stored_observed_at), "PROBABLE")

    def test_2_true_arrival_just_after_primary_boundary_with_negative_skew_reads_confirmed(self) -> None:
        """Mirror of test 1: TRUE arrival is primary_deadline + 50ms --
        a genuinely late callback that, absent skew, would be PROBABLE.
        Callback-service clock is 100ms SLOW, so the stamped
        `observed_at` reads as primary_deadline - 50ms. Result:
        CONFIRMED -- a higher confidence bucket than the real event
        timing warrants, purely from clock skew, in the opposite
        direction from test 1. Both directions are possible; neither is
        corrected for."""
        started = datetime.now(timezone.utc)
        primary_deadline = started + timedelta(seconds=self.POLICY.maximum_wait_seconds)
        true_arrival = primary_deadline + timedelta(milliseconds=50)
        callback_service_clock_offset = timedelta(milliseconds=-100)
        stored_observed_at = true_arrival + callback_service_clock_offset
        self.assertEqual(self._classify(stored_observed_at), "CONFIRMED")

    def test_3_arrival_comfortably_inside_primary_survives_500ms_skew_either_direction(self) -> None:
        """NOT a claim that +-500ms is always safe -- see tests 1/2 for
        the near-boundary counter-example. Here the true arrival sits
        at the midpoint of a 3.0s primary window (1.5s from wait
        start), far enough from both the window start and the primary
        deadline that a +-500ms offset in either direction keeps the
        stamped `observed_at` inside primary."""
        started = datetime.now(timezone.utc)
        true_arrival = started + timedelta(seconds=1.5)  # midpoint of a 3.0s primary window
        for offset_ms in (-500, 500):
            with self.subTest(offset_ms=offset_ms):
                stored_observed_at = true_arrival + timedelta(milliseconds=offset_ms)
                self.assertEqual(self._classify(stored_observed_at), "CONFIRMED")

    def test_4_arrival_comfortably_inside_grace_survives_500ms_skew_either_direction(self) -> None:
        """Same caveat as test 3: safe here because of distance from
        the boundaries, not a general guarantee. True arrival at the
        midpoint of the grace band (4.0s from wait start, for a 3.0s
        primary + 2.0s grace = 3.0-5.0s band), +-500ms stays inside
        grace (3.5s-4.5s)."""
        started = datetime.now(timezone.utc)
        true_arrival = started + timedelta(seconds=4.0)  # midpoint of the 3.0-5.0s grace band
        for offset_ms in (-500, 500):
            with self.subTest(offset_ms=offset_ms):
                stored_observed_at = true_arrival + timedelta(milliseconds=offset_ms)
                self.assertEqual(self._classify(stored_observed_at), "PROBABLE")

    def test_5_observed_at_exactly_on_primary_deadline_is_confirmed(self) -> None:
        """Deterministic boundary semantics, restated here for this
        characterization suite's own completeness (also covered by
        EvidenceTimeClassificationTests.test_f): the primary comparison
        is inclusive (`<=`)."""
        started = datetime.now(timezone.utc)
        primary_deadline = started + timedelta(seconds=self.POLICY.maximum_wait_seconds)
        self.assertEqual(self._classify(primary_deadline), "CONFIRMED")

    def test_6_observed_at_exactly_on_grace_deadline_is_probable(self) -> None:
        """Deterministic boundary semantics, restated here for this
        characterization suite's own completeness (also covered by
        EvidenceTimeClassificationTests.test_g): the grace comparison
        is also inclusive (`<=`), so the exact boundary is PROBABLE,
        never silently dropped."""
        started = datetime.now(timezone.utc)
        grace_deadline = started + timedelta(
            seconds=self.POLICY.maximum_wait_seconds + self.POLICY.grace_seconds
        )
        self.assertEqual(self._classify(grace_deadline), "PROBABLE")


if __name__ == "__main__":
    unittest.main()
