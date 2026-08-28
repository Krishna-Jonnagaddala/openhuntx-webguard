"""Lease-aware background worker for persistent WebGuard scan jobs."""

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

    @staticmethod
    def _is_stale_lease_error(error: JobStoreError) -> bool:
        return error.code in _STALE_LEASE_CODES

    def _finish_result(self, lease: LeasedScanJob, outcome) -> None:
        self.store.finish_result_leased(
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

    def _fail(
        self,
        lease: LeasedScanJob,
        *,
        code: str,
        message: str,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> None:
        self.store.fail_leased(
            lease.record.job_id,
            worker_id=lease.worker_id,
            lease_token=lease.lease_token,
            error_code=code,
            error_message=message,
            now=self.clock(),
            safety_receipt_ref=safety_receipt_ref,
            safety_receipt_sha256=safety_receipt_sha256,
        )

    def _cancel(self, lease: LeasedScanJob) -> None:
        self.store.cancel_running_leased(
            lease.record.job_id,
            worker_id=lease.worker_id,
            lease_token=lease.lease_token,
            now=self.clock(),
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
                    lease_lost.set()
                    token.cancel()
                    return

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
            processed = self.run_once()
            if not processed:
                stop_event.wait(self.poll_seconds)


__all__ = [
    "DEFAULT_WORKER_HEARTBEAT_SECONDS",
    "DEFAULT_WORKER_LEASE_SECONDS",
    "DEFAULT_WORKER_MAXIMUM_ATTEMPTS",
    "ScanJobWorker",
]
