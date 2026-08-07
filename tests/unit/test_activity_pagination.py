from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import IdentityStore, ScanJobStore
from webguard_contracts import (
    AuditOutcome,
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    ScanScheduleState,
    SecurityAuditEvent,
)

from tests.unit.service_test_support import AUTH_ID, NOW, ORG_ID, OWNER_ID, TARGET


class JobAndSchedulePageStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def submit(self, index: int, *, mode=ScanJobMode.CRAWL):
        submitted_at = NOW + timedelta(seconds=index)
        request = ScanJobRequest(
            idempotency_key=f"pagination-job-{index}",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256="a" * 64,
            mode=mode,
            submitted_at=submitted_at,
        )
        job_id = f"00000000-0000-4000-8000-{index:012d}"
        record, created = self.store.submit(
            request,
            job_id=job_id,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
        )
        self.assertTrue(created)
        return record

    def test_job_pages_are_descending_stable_and_non_overlapping(self) -> None:
        records = [self.submit(index) for index in range(1, 6)]
        first, more = self.store.list_jobs_scoped_page(ORG_ID, limit=2)
        self.assertTrue(more)
        self.assertEqual([item.job_id for item in first], [records[4].job_id, records[3].job_id])
        last = first[-1]
        second, more = self.store.list_jobs_scoped_page(
            ORG_ID,
            limit=2,
            after=(
                last.request.submitted_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                last.job_id,
            ),
        )
        self.assertTrue(more)
        self.assertEqual([item.job_id for item in second], [records[2].job_id, records[1].job_id])
        last = second[-1]
        third, more = self.store.list_jobs_scoped_page(
            ORG_ID,
            limit=2,
            after=(
                last.request.submitted_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                last.job_id,
            ),
        )
        self.assertFalse(more)
        self.assertEqual([item.job_id for item in third], [records[0].job_id])

    def test_job_filters_apply_before_pagination(self) -> None:
        first = self.submit(1, mode=ScanJobMode.CRAWL)
        self.submit(2, mode=ScanJobMode.SINGLE_PAGE)
        crawl, more = self.store.list_jobs_scoped_page(
            ORG_ID,
            limit=10,
            state=ScanJobState.QUEUED,
            mode=ScanJobMode.CRAWL,
        )
        self.assertFalse(more)
        self.assertEqual([item.job_id for item in crawl], [first.job_id])

    def test_job_pages_are_organization_scoped(self) -> None:
        self.submit(1)
        records, more = self.store.list_jobs_scoped_page(
            "99999999-9999-4999-8999-999999999999",
            limit=10,
        )
        self.assertFalse(more)
        self.assertEqual(records, ())

    def create_schedule(self, index: int, *, state=ScanScheduleState.ACTIVE):
        record = self.store.create_schedule(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name=f"Schedule {index}",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256="a" * 64,
            mode=ScanJobMode.CRAWL,
            interval_seconds=3600,
            starts_at=NOW + timedelta(hours=1),
            now=NOW + timedelta(seconds=index),
            schedule_id=f"10000000-0000-4000-8000-{index:012d}",
        )
        if state is ScanScheduleState.PAUSED:
            record = self.store.pause_schedule_scoped(
                record.schedule_id,
                ORG_ID,
                now=NOW + timedelta(minutes=1),
            )
        return record

    def test_schedule_pages_and_state_filter(self) -> None:
        active = self.create_schedule(1)
        paused = self.create_schedule(2, state=ScanScheduleState.PAUSED)
        newest = self.create_schedule(3)
        page, more = self.store.list_schedules_scoped_page(ORG_ID, limit=2)
        self.assertTrue(more)
        self.assertEqual([item.schedule_id for item in page], [newest.schedule_id, paused.schedule_id])
        filtered, more = self.store.list_schedules_scoped_page(
            ORG_ID,
            limit=10,
            state=ScanScheduleState.ACTIVE,
        )
        self.assertFalse(more)
        self.assertEqual([item.schedule_id for item in filtered], [newest.schedule_id, active.schedule_id])

    def test_cursor_signing_key_is_stable_and_private_length(self) -> None:
        first = self.store.cursor_signing_key()
        second = ScanJobStore(self.store.path).cursor_signing_key()
        self.assertEqual(first, second)
        self.assertGreaterEqual(len(first), 32)


class AuditPageStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        path = Path(self.temporary.name) / "jobs.sqlite3"
        ScanJobStore(path)
        self.identity = IdentityStore(path)
        organization = self.identity.create_organization(
            "Example", now=NOW, organization_id=ORG_ID
        )
        from webguard_contracts import OrganizationRole, PrincipalType
        principal = self.identity.create_principal(
            organization.organization_id,
            "Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )
        issued = self.identity.create_token(
            principal.principal_id,
            label="audit-test",
            validity_days=30,
            now=NOW,
            token_id="44444444-4444-4444-8444-444444444444",
        )
        self.token_id = issued.metadata.token_id

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def event(self, index: int, outcome: AuditOutcome) -> SecurityAuditEvent:
        event = SecurityAuditEvent(
            event_id=f"20000000-0000-4000-8000-{index:012d}",
            request_id=f"30000000-0000-4000-8000-{index:012d}",
            organization_id=ORG_ID,
            principal_id=OWNER_ID,
            token_id=self.token_id,
            action="jobs.list",
            resource_type="organization",
            resource_id=ORG_ID,
            outcome=outcome,
            occurred_at=NOW + timedelta(seconds=index),
        )
        self.identity.record_audit_event(event)
        return event

    def test_audit_pages_and_outcome_filter(self) -> None:
        first = self.event(1, AuditOutcome.SUCCEEDED)
        denied = self.event(2, AuditOutcome.DENIED)
        newest = self.event(3, AuditOutcome.SUCCEEDED)
        page, more = self.identity.list_audit_events_page(ORG_ID, limit=2)
        self.assertTrue(more)
        self.assertEqual([item.event_id for item in page], [newest.event_id, denied.event_id])
        filtered, more = self.identity.list_audit_events_page(
            ORG_ID,
            limit=10,
            outcome=AuditOutcome.SUCCEEDED,
        )
        self.assertFalse(more)
        self.assertEqual([item.event_id for item in filtered], [newest.event_id, first.event_id])


if __name__ == "__main__":
    unittest.main()
