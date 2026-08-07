from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import JobStoreError, ScanJobStore
from webguard_contracts import ScanJobMode, ScanJobState, ScanScheduleState

from tests.unit.service_test_support import (
    AUTH_ID, NOW, ORG_ID, OWNER_ID, TARGET, create_trustscan_permit
)

OTHER_ORG = "77777777-7777-4777-8777-777777777777"
SCHEDULE_ID = "66666666-6666-4666-8666-666666666666"


class ScheduleStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")
        self.permit = create_trustscan_permit(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self, **changes):
        values = dict(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name="Daily passive crawl",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256="a" * 64,
            mode=ScanJobMode.CRAWL,
            interval_seconds=86400,
            starts_at=NOW + timedelta(hours=1),
            now=NOW,
            schedule_id=SCHEDULE_ID,
        )
        values.update(changes)
        if values["organization_id"] == ORG_ID:
            values.setdefault("permit_id", self.permit.permit.claims.permit_id)
            values.setdefault("permit_sha256", self.permit.permit.fingerprint)
        return self.store.create_schedule(**values)

    def enqueue_due_schedule(self, schedule_id, **kwargs):
        kwargs.setdefault("permit_id", self.permit.permit.claims.permit_id)
        kwargs.setdefault("permit_sha256", self.permit.permit.fingerprint)
        return self.store.enqueue_due_schedule(schedule_id, **kwargs)

    def test_create_and_read_schedule(self) -> None:
        created = self.create()
        fetched = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertEqual(created, fetched)
        self.assertIs(fetched.state, ScanScheduleState.ACTIVE)

    def test_cross_tenant_read_returns_not_found(self) -> None:
        self.create()
        with self.assertRaises(JobStoreError) as context:
            self.store.get_schedule_scoped(SCHEDULE_ID, OTHER_ORG)
        self.assertEqual(context.exception.code, "schedule_not_found")

    def test_list_is_organization_scoped(self) -> None:
        self.create()
        self.create(
            schedule_id="88888888-8888-4888-8888-888888888888",
            organization_id=OTHER_ORG,
        )
        values = self.store.list_schedules_scoped(ORG_ID)
        self.assertEqual([item.schedule_id for item in values], [SCHEDULE_ID])

    def test_pause_and_resume_schedule(self) -> None:
        self.create()
        paused = self.store.pause_schedule_scoped(SCHEDULE_ID, ORG_ID, now=NOW)
        self.assertIs(paused.state, ScanScheduleState.PAUSED)
        resumed = self.store.resume_schedule_scoped(
            SCHEDULE_ID,
            ORG_ID,
            now=NOW + timedelta(minutes=5),
        )
        self.assertIs(resumed.state, ScanScheduleState.ACTIVE)
        self.assertEqual(
            resumed.next_run_at,
            NOW + timedelta(minutes=5, days=1),
        )

    def test_due_query_excludes_paused_schedule(self) -> None:
        self.create(starts_at=NOW)
        self.store.pause_schedule_scoped(SCHEDULE_ID, ORG_ID, now=NOW)
        self.assertEqual(self.store.list_due_schedules(now=NOW), ())

    def test_due_query_orders_by_next_run(self) -> None:
        later = self.create(
            starts_at=NOW + timedelta(hours=1),
            schedule_id="88888888-8888-4888-8888-888888888888",
        )
        earlier = self.create(starts_at=NOW)
        values = self.store.list_due_schedules(now=NOW + timedelta(hours=2))
        self.assertEqual(
            [item.schedule_id for item in values],
            [earlier.schedule_id, later.schedule_id],
        )

    def test_enqueue_due_schedule_creates_scoped_job(self) -> None:
        schedule = self.create(starts_at=NOW)
        result = self.enqueue_due_schedule(
            schedule.schedule_id,
            expected_revision=schedule.revision,
            authorization_sha256="b" * 64,
            now=NOW,
        )
        self.assertIsNotNone(result)
        assert result is not None
        updated, job = result
        self.assertIs(job.state, ScanJobState.QUEUED)
        self.assertEqual(self.store.get_scope(job.job_id), (ORG_ID, OWNER_ID))
        self.assertEqual(updated.last_job_id, job.job_id)
        self.assertEqual(updated.authorization_sha256, "b" * 64)
        self.assertEqual(updated.next_run_at, NOW + timedelta(days=1))

    def test_enqueue_due_schedule_skips_missed_intervals(self) -> None:
        schedule = self.create(
            starts_at=NOW,
            interval_seconds=3600,
        )
        result = self.enqueue_due_schedule(
            schedule.schedule_id,
            expected_revision=schedule.revision,
            authorization_sha256="a" * 64,
            now=NOW + timedelta(hours=5, minutes=30),
        )
        assert result is not None
        updated, _ = result
        self.assertEqual(updated.next_run_at, NOW + timedelta(hours=6))

    def test_stale_revision_cannot_enqueue_duplicate(self) -> None:
        schedule = self.create(starts_at=NOW)
        first = self.enqueue_due_schedule(
            schedule.schedule_id,
            expected_revision=0,
            authorization_sha256="a" * 64,
            now=NOW,
        )
        second = self.enqueue_due_schedule(
            schedule.schedule_id,
            expected_revision=0,
            authorization_sha256="a" * 64,
            now=NOW,
        )
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_not_due_schedule_is_not_enqueued(self) -> None:
        schedule = self.create(starts_at=NOW + timedelta(hours=1))
        self.assertIsNone(
            self.enqueue_due_schedule(
                schedule.schedule_id,
                expected_revision=schedule.revision,
                authorization_sha256="a" * 64,
                now=NOW,
            )
        )

    def test_block_due_schedule_pauses_and_records_error(self) -> None:
        schedule = self.create(starts_at=NOW)
        blocked = self.store.block_due_schedule(
            schedule.schedule_id,
            expected_revision=schedule.revision,
            error_code="authorization_not_current",
            now=NOW,
        )
        self.assertIsNotNone(blocked)
        assert blocked is not None
        self.assertIs(blocked.state, ScanScheduleState.PAUSED)
        self.assertEqual(blocked.last_error_code, "authorization_not_current")
        self.assertEqual(blocked.last_error_at, NOW)

    def test_stale_revision_cannot_block(self) -> None:
        self.create(starts_at=NOW)
        self.assertIsNone(
            self.store.block_due_schedule(
                SCHEDULE_ID,
                expected_revision=5,
                error_code="authorization_not_current",
                now=NOW,
            )
        )

    def test_list_limit_is_bounded(self) -> None:
        with self.assertRaises(JobStoreError):
            self.store.list_schedules_scoped(ORG_ID, limit=0)
        with self.assertRaises(JobStoreError):
            self.store.list_due_schedules(now=NOW, limit=1001)


if __name__ == "__main__":
    unittest.main()
