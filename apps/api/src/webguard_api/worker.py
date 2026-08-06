"""Background worker for persistent WebGuard scan jobs."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Callable

from webguard_scanner import CrawlCancellationToken

from .executor import JobExecutionError, ScanJobExecutor
from .store import JobStoreError, ScanJobStore


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanJobWorker:
    """Claim and execute queued jobs with cooperative cancellation polling."""

    def __init__(
        self,
        *,
        store: ScanJobStore,
        executor: ScanJobExecutor,
        poll_seconds: float = 0.25,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.store = store
        self.executor = executor
        self.poll_seconds = float(poll_seconds)
        self.clock = clock

    def run_once(self) -> bool:
        record = self.store.claim_next(now=self.clock())
        if record is None:
            return False

        token = CrawlCancellationToken()
        monitor_stop = threading.Event()

        def monitor_cancellation() -> None:
            while not monitor_stop.wait(min(self.poll_seconds, 0.1)):
                try:
                    if self.store.is_cancellation_requested(record.job_id):
                        token.cancel()
                        return
                except JobStoreError:
                    token.cancel()
                    return

        monitor = threading.Thread(
            target=monitor_cancellation,
            name=f"webguard-cancel-{record.job_id[:8]}",
            daemon=True,
        )
        monitor.start()
        try:
            if record.cancellation_requested:
                token.cancel()
            outcome = self.executor.execute(
                record,
                cancellation_token=token,
            )
            self.store.finish_result(
                record.job_id,
                scan_id=outcome.report.scan_id,
                result_status=outcome.report.status,
                report_ref=outcome.report_ref,
                audit_ref=outcome.audit_ref,
                now=self.clock(),
            )
        except JobExecutionError as exc:
            if token.is_cancelled or exc.code == "job_cancelled_before_execution":
                self.store.cancel_running(record.job_id, now=self.clock())
            else:
                self.store.fail(
                    record.job_id,
                    error_code=exc.code,
                    error_message=exc.message,
                    now=self.clock(),
                )
        except Exception:
            # Unexpected exceptions are intentionally not persisted verbatim.
            self.store.fail(
                record.job_id,
                error_code="worker_internal_error",
                error_message="The scanner worker encountered an unexpected internal error.",
                now=self.clock(),
            )
        finally:
            monitor_stop.set()
            monitor.join(timeout=1.0)
        return True

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            processed = self.run_once()
            if not processed:
                stop_event.wait(self.poll_seconds)


__all__ = ["ScanJobWorker"]
