"""Database-backed recurring scan-schedule coordinator."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .authorizations import AuthorizationRepository, AuthorizationRepositoryError
from .identity import IdentityStore
from .permits import TrustScanPermitError, TrustScanSigner, validate_permit_use
from .store import JobStoreError, ScanJobStore


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ScheduleRunSummary:
    """One scheduler pass summary."""

    inspected: int = 0
    enqueued: int = 0
    blocked: int = 0
    raced: int = 0


class ScanScheduleCoordinator:
    """Materialise due recurring schedules into tenant-scoped scan jobs."""

    def __init__(
        self,
        *,
        store: ScanJobStore,
        authorizations: AuthorizationRepository,
        identity: IdentityStore,
        trustscan_signer: TrustScanSigner,
        poll_seconds: float = 1.0,
        batch_size: int = 100,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.store = store
        self.authorizations = authorizations
        self.identity = identity
        self.trustscan_signer = trustscan_signer
        self.poll_seconds = float(poll_seconds)
        self.batch_size = batch_size
        self.clock = clock
        if not 0.1 <= self.poll_seconds <= 60.0:
            raise ValueError("poll_seconds must be from 0.1 to 60 seconds.")
        if isinstance(self.batch_size, bool) or not isinstance(self.batch_size, int):
            raise ValueError("batch_size must be an integer.")
        if not 1 <= self.batch_size <= 1000:
            raise ValueError("batch_size must be from 1 to 1000.")

    def _block(self, schedule, *, code: str, now: datetime) -> bool:
        return (
            self.store.block_due_schedule(
                schedule.schedule_id,
                expected_revision=schedule.revision,
                error_code=code,
                now=now,
            )
            is not None
        )

    def run_once(self) -> ScheduleRunSummary:
        now = self.clock()
        schedules = self.store.list_due_schedules(now=now, limit=self.batch_size)
        enqueued = blocked = raced = 0
        for schedule in schedules:
            if not self.identity.authorization_is_assigned(
                schedule.organization_id,
                schedule.authorization_id,
            ):
                blocked += int(
                    self._block(
                        schedule,
                        code="authorization_not_assigned",
                        now=now,
                    )
                )
                continue
            try:
                authorization = self.authorizations.get(schedule.authorization_id)
            except AuthorizationRepositoryError as exc:
                blocked += int(self._block(schedule, code=exc.code, now=now))
                continue
            if authorization.target != schedule.target:
                blocked += int(
                    self._block(
                        schedule,
                        code="authorization_target_mismatch",
                        now=now,
                    )
                )
                continue
            if not authorization.issued_at <= now < authorization.expires_at:
                blocked += int(
                    self._block(
                        schedule,
                        code="authorization_not_current",
                        now=now,
                    )
                )
                continue
            binding = self.store.get_schedule_permit_binding(schedule.schedule_id)
            if binding is None:
                blocked += int(
                    self._block(
                        schedule,
                        code="trustscan_permit_missing",
                        now=now,
                    )
                )
                continue
            try:
                permit = self.store.get_scan_permit_scoped(
                    binding[0], schedule.organization_id
                )
            except JobStoreError as exc:
                blocked += int(self._block(schedule, code=exc.code, now=now))
                continue
            if permit.permit.fingerprint != binding[1]:
                blocked += int(
                    self._block(
                        schedule,
                        code="trustscan_permit_binding_changed",
                        now=now,
                    )
                )
                continue
            try:
                validate_permit_use(
                    permit,
                    signer=self.trustscan_signer,
                    organization_id=schedule.organization_id,
                    authorization=authorization,
                    target=schedule.target,
                    mode=schedule.mode,
                    now=now,
                )
            except TrustScanPermitError as exc:
                blocked += int(self._block(schedule, code=exc.code, now=now))
                continue
            try:
                result = self.store.enqueue_due_schedule(
                    schedule.schedule_id,
                    expected_revision=schedule.revision,
                    authorization_sha256=authorization.fingerprint,
                    permit_id=permit.permit.claims.permit_id,
                    permit_sha256=permit.permit.fingerprint,
                    now=now,
                )
            except JobStoreError:
                raise
            if result is None:
                raced += 1
            else:
                enqueued += 1
        return ScheduleRunSummary(
            inspected=len(schedules),
            enqueued=enqueued,
            blocked=blocked,
            raced=raced,
        )

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            self.run_once()
            stop_event.wait(self.poll_seconds)


__all__ = ["ScanScheduleCoordinator", "ScheduleRunSummary"]
