"""Regression coverage for the result-polling cadence in
tests/integration/test_production_ssrf_callback_e2e.py's
`_run_job_and_get_findings`.

Root cause this guards against: that E2E test authenticates every
GET-result poll with the same bearer token used for permit and job
creation, and `build_production_components` wires a real
`FixedWindowRateLimiter(requests=120, window_seconds=60)` (see
production_startup.py) that every authenticated request is checked
against, keyed by token (http_api.py's `_authenticate`). A polling
loop too aggressive for that budget does not make the underlying job
run any slower -- it makes the *test* exhaust its own rate-limit quota
and then sit blocked on HTTP 429 responses until an unrelated
wall-clock 60-second window happens to roll over. That, not a slow
scan, is what produced the intermittent ~21s-60s runtimes traced for
`test_no_fabricated_confirmation_when_persistence_never_recovers`
before its polling interval was widened from 0.1s to 1.0s.

This exercises the real `FixedWindowRateLimiter` (not a mock) with the
same request shape that test produces, so a future change to either
the polling interval or the production rate-limit constants that
reintroduces the same exhaustion is caught here in milliseconds,
without needing real Postgres or network infrastructure.
"""

from __future__ import annotations

import unittest

from webguard_api import FixedWindowRateLimiter
from webguard_api.rate_limit import RateLimitError

from tests.integration.test_production_ssrf_callback_e2e import (
    RESULT_POLL_INTERVAL_SECONDS,
)

_RATE_LIMIT_REQUESTS = 120
_RATE_LIMIT_WINDOW_SECONDS = 60

# The longest completion_timeout_seconds any test in that module passes
# to _run_job_and_get_findings (test_no_fabricated_confirmation_when_
# persistence_never_recovers's own worst case).
_LONGEST_COMPLETION_TIMEOUT_SECONDS = 60

# Mirrors _run_job_and_get_findings's own non-polling calls on the same
# token: one permit creation, one job creation, one final findings read.
_NON_POLLING_REQUESTS = 3


def _poll_budget_holds(*, poll_interval_seconds: float, completion_timeout_seconds: float) -> bool:
    """True if a token issuing `_NON_POLLING_REQUESTS` one-off requests
    plus a GET-result poll every `poll_interval_seconds` for up to
    `completion_timeout_seconds` never gets rate-limited, in the worst
    case where the polling loop starts at the very beginning of a fresh
    60-second window (so nothing has decayed out of it yet)."""

    limiter = FixedWindowRateLimiter(
        requests=_RATE_LIMIT_REQUESTS, window_seconds=_RATE_LIMIT_WINDOW_SECONDS
    )
    now_epoch = 0.0
    try:
        for _ in range(_NON_POLLING_REQUESTS):
            limiter.check("token", now_epoch=now_epoch)
        elapsed = 0.0
        while elapsed < completion_timeout_seconds:
            limiter.check("token", now_epoch=now_epoch)
            elapsed += poll_interval_seconds
            now_epoch += poll_interval_seconds
    except RateLimitError:
        return False
    return True


class SsrfE2ePollingRateLimitBudgetTests(unittest.TestCase):
    def test_old_tenth_second_poll_interval_exceeds_the_token_rate_limit(self) -> None:
        """Documents the confirmed defect: polling every 0.1s for the
        60s completion_timeout_seconds
        test_no_fabricated_confirmation_when_persistence_never_recovers
        uses blows through the 120-request/60s budget well before that
        job can finish (it needs on the order of 20s in practice, but
        even the full 60s timeout is itself the polling loop's own
        window -- the budget is exhausted in about 12s of 0.1s polling
        regardless)."""

        self.assertFalse(
            _poll_budget_holds(
                poll_interval_seconds=0.1,
                completion_timeout_seconds=_LONGEST_COMPLETION_TIMEOUT_SECONDS,
            )
        )

    def test_current_poll_interval_stays_within_the_token_rate_limit(self) -> None:
        """The fix, checked against the actual constant
        _run_job_and_get_findings uses (not a hardcoded duplicate of
        it): polling at RESULT_POLL_INTERVAL_SECONDS for the longest
        completion_timeout_seconds any test in that module uses stays
        comfortably under the 120-request cap. If someone narrows
        RESULT_POLL_INTERVAL_SECONDS back toward 0.1s (or the module
        gains a test with a longer timeout) without checking this
        budget, this test starts failing again."""

        self.assertTrue(
            _poll_budget_holds(
                poll_interval_seconds=RESULT_POLL_INTERVAL_SECONDS,
                completion_timeout_seconds=_LONGEST_COMPLETION_TIMEOUT_SECONDS,
            )
        )


if __name__ == "__main__":
    unittest.main()
