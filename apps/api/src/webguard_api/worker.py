"""Lease-aware background worker for persistent WebGuard scan jobs.

P1-10 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md): a
transient PostgreSQL outage must never permanently kill this worker.
Three distinct places touch the database outside of the job-claim
happy path, and each needed its own resilience treatment against a
``DatabaseError`` (as opposed to a semantic ``JobStoreError`` like
``job_lease_lost``, which must keep failing immediately -- see
``_STALE_LEASE_CODES``):

1. Terminal-state persistence (``_finish_result``/``_fail``/``_cancel``)
   -- bounded retries (``_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS``,
   short backoff) via ``_persist_terminal_state``. If every retry is
   exhausted, the attempt is abandoned *without* raising and *without*
   pretending the write succeeded -- the job is left exactly where it
   durably already is (``RUNNING``, still leased) for the existing,
   already-proven ``recover_expired_leases()`` mechanism to reclaim
   once Postgres (and/or another worker) is available again. This is
   why ``run_once()`` no longer recursively calls ``_fail()`` after
   determining the store itself is unavailable -- that recursive
   attempt is exactly what previously escalated one outage into a
   dead worker thread.
2. The heartbeat/cancellation-check loop (``monitor_job``) -- a
   ``DatabaseError`` here no longer ends the thread; it skips that one
   cycle with a short backoff and keeps trying on its normal schedule.
   Genuine lease loss (``JobStoreError``) is unchanged: that still
   stops the monitor and cancels the in-flight scan, exactly as
   before. A prolonged outage does not need the monitor to declare the
   lease "uncertain" for correctness -- the durable
   ``lease_expires_at`` this worker already wrote at claim/last-renew
   time is what governs; if it lapses, ``recover_expired_leases()``
   reclaims the job to someone else, and this worker's own eventual
   terminal-persistence attempt is then correctly rejected by the
   existing revision/lease-token CAS (unchanged, see ``store.py``).
3. ``run_forever()``'s own loop boundary -- a ``DatabaseError`` from
   ``recover_expired_leases()``/``claim_next_leased()`` themselves
   (i.e. before any job is even claimed) no longer escapes the loop.
   It backs off (reusing ``poll_seconds``, responsive to
   ``stop_event`` so shutdown is never delayed) and the next iteration
   retries naturally -- no separate retry-of-retries logic needed
   here, since neither call holds any in-progress work that a retry
   could lose.

Nothing about lease ownership, lease-token/revision CAS, or
``FOR UPDATE SKIP LOCKED`` claim semantics changes -- see ``store.py``/
``postgres_jobs.py``, both untouched by this fix.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from webguard_scanner import CrawlCancellationToken

from .config import (
    DEFAULT_WORKER_HEARTBEAT_SECONDS,
    DEFAULT_WORKER_LEASE_SECONDS,
    DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
)
from .db_errors import DatabaseError
from .executor import JobExecutionError, ScanJobExecutor
from .repository_contracts import JobRepository
from .store import (
    JobStoreError,
    LeaseRecoverySummary,
    LeasedScanJob,
)

_STALE_LEASE_CODES = {
    "job_lease_expired",
    "job_lease_lost",
    "job_lease_required",
}

# Terminal-persistence retry budget: small and bounded -- the point is
# "absorb a brief blip," not "consume the whole lease window retrying
# one write." This is NOT a guarantee that a retry sequence always
# finishes before the lease it's trying to close out could expire:
# terminal persistence can begin late in an already-running lease
# interval (e.g. right before a heartbeat was due), and each attempt
# can itself take up to WebGuardPostgresPool's own 5s connection-
# checkout timeout before raising, so under a long enough outage the
# lease genuinely can lapse mid-retry. That is safe by construction,
# not by timing: retries never weaken the lease-token/revision CAS
# (_terminal_update() is unchanged). If the lease lapses and another
# worker reclaims the job before this retry sequence finishes, this
# worker's eventual write is rejected exactly as any other stale
# attempt already is (job_lease_lost, or job_state_transition_invalid
# if the job has already reached a terminal state by then) -- so
# correctness holds even when retry duration overlaps lease expiry.
# The cost of that overlap is a possible duplicate execution (see
# DUPLICATE-EXECUTION RISK in docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md),
# never a corrupted or double-persisted result: the CAS still
# guarantees at most one terminal write survives.
DEFAULT_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS = 3
DEFAULT_TERMINAL_PERSISTENCE_RETRY_BACKOFF_SECONDS = 1.0

# Heartbeat-renewal retry backoff: how long the monitor thread waits
# before its next attempt after a DatabaseError, distinct from (and
# shorter than) the full heartbeat_seconds interval a *successful*
# renewal schedules -- so a transient blip is retried promptly, not
# just on the next full heartbeat cycle, while still never busy-looping
# (bounded below by this constant, not by the 10ms floor the normal
# wait_seconds calculation would otherwise clamp to once next_heartbeat
# is in the past).
DEFAULT_HEARTBEAT_RETRY_BACKOFF_SECONDS = 1.0


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _default_worker_id() -> str:
    hostname = socket.gethostname().strip() or "localhost"
    safe_hostname = "".join(
        character if 33 <= ord(character) <= 126 else "-"
        for character in hostname
    )[:64]
    return f"{safe_hostname}:{os.getpid()}:{uuid4().hex[:12]}"


class ScanJobWorker:
    """Claim, heartbeat, execute, and safely recover leased scan jobs."""

    def __init__(
        self,
        *,
        store: JobRepository,
        executor: ScanJobExecutor,
        poll_seconds: float = 0.25,
        worker_id: str | None = None,
        lease_seconds: float = DEFAULT_WORKER_LEASE_SECONDS,
        heartbeat_seconds: float = DEFAULT_WORKER_HEARTBEAT_SECONDS,
        maximum_attempts: int = DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        terminal_persistence_maximum_attempts: int = DEFAULT_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS,
        terminal_persistence_retry_backoff_seconds: float = DEFAULT_TERMINAL_PERSISTENCE_RETRY_BACKOFF_SECONDS,
        heartbeat_retry_backoff_seconds: float = DEFAULT_HEARTBEAT_RETRY_BACKOFF_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.store = store
        self.executor = executor
        self.poll_seconds = float(poll_seconds)
        self.worker_id = _default_worker_id() if worker_id is None else worker_id
        self.lease_seconds = float(lease_seconds)
        self.heartbeat_seconds = float(heartbeat_seconds)
        self.maximum_attempts = maximum_attempts
        self.clock = clock
        self.monotonic = monotonic
        self.terminal_persistence_maximum_attempts = int(terminal_persistence_maximum_attempts)
        self.terminal_persistence_retry_backoff_seconds = float(terminal_persistence_retry_backoff_seconds)
        self.heartbeat_retry_backoff_seconds = float(heartbeat_retry_backoff_seconds)
        self._sleep = sleep
        self.last_recovery_summary = LeaseRecoverySummary()
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        if not 0.01 <= self.poll_seconds <= 5.0:
            raise ValueError("poll_seconds must be from 0.01 to 5 seconds.")
        # Reuse store validation so worker and persistence rules remain aligned.
        self.store._worker_id(self.worker_id)
        self.store._lease_seconds(self.lease_seconds)
        self.store._maximum_attempts(self.maximum_attempts)
        if not 0.05 <= self.heartbeat_seconds < self.lease_seconds:
            raise ValueError(
                "heartbeat_seconds must be at least 0.05 and less than lease_seconds."
            )
        if self.terminal_persistence_maximum_attempts < 1:
            raise ValueError("terminal_persistence_maximum_attempts must be at least 1.")
        if self.terminal_persistence_retry_backoff_seconds < 0:
            raise ValueError("terminal_persistence_retry_backoff_seconds must not be negative.")
        if self.heartbeat_retry_backoff_seconds < 0:
            raise ValueError("heartbeat_retry_backoff_seconds must not be negative.")

    @staticmethod
    def _is_stale_lease_error(error: JobStoreError) -> bool:
        return error.code in _STALE_LEASE_CODES

    def _persist_terminal_state(self, operation: Callable[[], None]) -> bool:
        """Runs one terminal-persistence write (finish/fail/cancel),
        retrying only genuine infrastructure failures (``DatabaseError``)
        with a short bounded backoff -- never a semantic ``JobStoreError``
        (``job_lease_lost`` and friends propagate immediately, unchanged,
        so the caller's existing stale-lease handling keeps working
        exactly as before). Returns ``True`` if the write succeeded,
        ``False`` if every retry was exhausted while the database
        remained unavailable -- the caller must treat ``False`` as
        "abandon this attempt," never as success or as a reason to
        raise or to try a *different* terminal write instead (that
        recursive pattern -- fail write fails, so try _fail() again --
        is exactly what previously turned one outage into a dead
        worker thread)."""

        for attempt in range(1, self.terminal_persistence_maximum_attempts + 1):
            try:
                operation()
                return True
            except DatabaseError:
                if attempt >= self.terminal_persistence_maximum_attempts:
                    return False
                self._sleep(self.terminal_persistence_retry_backoff_seconds)
        return False

    def _finish_result(self, lease: LeasedScanJob, outcome) -> bool:
        return self._persist_terminal_state(
            lambda: self.store.finish_result_leased(
                lease.record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                scan_id=outcome.report.scan_id,
                result_status=outcome.report.status,
                report_ref=outcome.report_ref,
                audit_ref=outcome.audit_ref,
                now=self.clock(),
                safety_receipt_ref=outcome.safety_receipt_ref,
                safety_receipt_sha256=outcome.safety_receipt_sha256,
            )
        )

    def _fail(
        self,
        lease: LeasedScanJob,
        *,
        code: str,
        message: str,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> bool:
        return self._persist_terminal_state(
            lambda: self.store.fail_leased(
                lease.record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                error_code=code,
                error_message=message,
                now=self.clock(),
                safety_receipt_ref=safety_receipt_ref,
                safety_receipt_sha256=safety_receipt_sha256,
            )
        )

    def _cancel(self, lease: LeasedScanJob) -> bool:
        return self._persist_terminal_state(
            lambda: self.store.cancel_running_leased(
                lease.record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                now=self.clock(),
            )
        )

    def run_once(self) -> bool:
        self.last_recovery_summary = self.store.recover_expired_leases(
            now=self.clock(),
            maximum_attempts=self.maximum_attempts,
        )
        lease = self.store.claim_next_leased(
            now=self.clock(),
            worker_id=self.worker_id,
            lease_seconds=self.lease_seconds,
        )
        if lease is None:
            return False

        record = lease.record
        token = CrawlCancellationToken()
        monitor_stop = threading.Event()
        lease_lost = threading.Event()
        next_heartbeat = self.monotonic() + self.heartbeat_seconds

        def monitor_job() -> None:
            nonlocal next_heartbeat
            while not monitor_stop.is_set():
                wait_seconds = min(
                    self.poll_seconds,
                    max(0.01, next_heartbeat - self.monotonic()),
                )
                if monitor_stop.wait(wait_seconds):
                    return
                try:
                    if self.store.is_cancellation_requested(record.job_id):
                        token.cancel()
                    if self.monotonic() >= next_heartbeat:
                        self.store.renew_lease(
                            record.job_id,
                            worker_id=lease.worker_id,
                            lease_token=lease.lease_token,
                            now=self.clock(),
                            lease_seconds=self.lease_seconds,
                        )
                        next_heartbeat = self.monotonic() + self.heartbeat_seconds
                except JobStoreError:
                    # Genuine, semantic lease loss (another worker
                    # already reclaimed this job, or it's otherwise no
                    # longer this worker's to renew) -- unchanged: stop
                    # monitoring and cancel the in-flight scan.
                    lease_lost.set()
                    token.cancel()
                    return
                except DatabaseError:
                    # Infrastructure hiccup, not lease loss -- P1-10:
                    # this must not end the thread. Skip this cycle,
                    # retry sooner than a full heartbeat interval (but
                    # never immediately -- avoids busy-looping while
                    # Postgres is down), and keep monitoring. The
                    # durable lease_expires_at this worker already
                    # wrote still governs correctness even if renewal
                    # keeps failing: if it lapses, recover_expired_leases()
                    # elsewhere reclaims the job, and this worker's own
                    # eventual terminal-persistence attempt is then
                    # correctly rejected by the unchanged CAS.
                    next_heartbeat = self.monotonic() + self.heartbeat_retry_backoff_seconds

        monitor = threading.Thread(
            target=monitor_job,
            name=f"webguard-lease-{record.job_id[:8]}",
            daemon=True,
        )
        monitor.start()

        def stop_monitor() -> None:
            monitor_stop.set()
            monitor.join(timeout=1.0)

        try:
            if record.cancellation_requested:
                token.cancel()
            outcome = self.executor.execute(
                record,
                cancellation_token=token,
            )
            stop_monitor()
            if lease_lost.is_set():
                return True
            try:
                # A False return means every retry was exhausted while
                # Postgres remained unavailable (see
                # _persist_terminal_state) -- the completed result is
                # deliberately NOT reported as persisted, and nothing
                # else is attempted: the job stays RUNNING, exactly as
                # durably recorded, for existing lease-expiry recovery
                # to reclaim. This is not an error to raise or a
                # reason to fall through to _fail() -- the scan
                # genuinely succeeded; only recording that fact failed.
                self._finish_result(lease, outcome)
            except JobStoreError as exc:
                if not self._is_stale_lease_error(exc):
                    raise
        except JobExecutionError as exc:
            stop_monitor()
            if lease_lost.is_set():
                return True
            try:
                if token.is_cancelled or exc.code == "job_cancelled_before_execution":
                    self._cancel(lease)
                else:
                    self._fail(
                        lease,
                        code=exc.code,
                        message=exc.message,
                        safety_receipt_ref=exc.safety_receipt_ref,
                        safety_receipt_sha256=exc.safety_receipt_sha256,
                    )
            except JobStoreError as store_error:
                if not self._is_stale_lease_error(store_error):
                    raise
        except JobStoreError:
            stop_monitor()
            raise
        except Exception:
            stop_monitor()
            if lease_lost.is_set():
                return True
            try:
                # Same rule as above: if this also cannot be persisted
                # because Postgres is unavailable, _fail() itself
                # returns False rather than raising -- there is no
                # second attempt, no recursive "try to record the
                # failure of recording the failure." The job is left
                # RUNNING for lease-expiry recovery, and this worker
                # moves on. This is the exact chain (executor raises ->
                # _fail() needs Postgres -> Postgres unavailable ->
                # _fail() itself throws -> worker dies) P1-10 closes.
                self._fail(
                    lease,
                    code="worker_internal_error",
                    message=(
                        "The scanner worker encountered an unexpected internal error."
                    ),
                )
            except JobStoreError as store_error:
                if not self._is_stale_lease_error(store_error):
                    raise
        finally:
            stop_monitor()
        return True

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                processed = self.run_once()
            except DatabaseError:
                # P1-10: recover_expired_leases()/claim_next_leased()
                # (run_once()'s own first two calls, before any job is
                # even claimed) are deliberately left unwrapped inside
                # run_once() itself -- neither holds any in-progress
                # work a retry could lose, so there is nothing to gain
                # from a separate retry-of-retries there. This boundary
                # is the single place that absorbs a DatabaseError from
                # either: back off (stop_event-responsive, so shutdown
                # is never delayed by an outage) and let the next loop
                # iteration retry naturally. Only DatabaseError is
                # caught here, deliberately -- an unexpected programming
                # error must keep its existing visibility, not be
                # silently absorbed by an infrastructure-outage handler.
                if stop_event.wait(self.poll_seconds):
                    return
                continue
            if not processed:
                stop_event.wait(self.poll_seconds)


__all__ = [
    "DEFAULT_HEARTBEAT_RETRY_BACKOFF_SECONDS",
    "DEFAULT_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS",
    "DEFAULT_TERMINAL_PERSISTENCE_RETRY_BACKOFF_SECONDS",
    "DEFAULT_WORKER_HEARTBEAT_SECONDS",
    "DEFAULT_WORKER_LEASE_SECONDS",
    "DEFAULT_WORKER_MAXIMUM_ATTEMPTS",
    "ScanJobWorker",
]
