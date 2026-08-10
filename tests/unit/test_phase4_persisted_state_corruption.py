from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from webguard_api import JobStoreError, ScanJobStore
from webguard_contracts import (
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    create_trustscan_permit,
)


SCHEDULE_ID = "44444444-aaaa-4bbb-8ccc-444444444444"


def request(key: str) -> ScanJobRequest:
    auth = authorization()

    return ScanJobRequest(
        idempotency_key=key,
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256=auth.fingerprint,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


class Phase4PersistedStateCorruptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def update(
        self,
        sql: str,
        parameters: tuple[object, ...],
    ) -> None:
        connection = sqlite3.connect(self.path)

        try:
            connection.execute(sql, parameters)
            connection.commit()
        finally:
            connection.close()

    def create_schedule(self):
        permit = create_trustscan_permit(self.store)

        schedule = self.store.create_schedule(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name="Phase 4 corruption schedule",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL,
            interval_seconds=3600,
            starts_at=NOW,
            now=NOW,
            schedule_id=SCHEDULE_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )

        return schedule, permit

    def test_truncated_database_is_rejected_with_controlled_store_error(
        self,
    ) -> None:
        original = self.path.read_bytes()

        self.assertGreater(
            len(original),
            512,
        )

        self.path.write_bytes(
            original[: max(512, len(original) // 3)]
        )

        with self.assertRaises(JobStoreError):
            ScanJobStore(self.path)

    def test_malformed_job_state_is_controlled_on_read(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase4-malformed-job-state")
        )

        self.update(
            """
            UPDATE scan_jobs
            SET state = ?
            WHERE job_id = ?
            """,
            (
                "not-a-job-state",
                record.job_id,
            ),
        )

        with self.assertRaises(JobStoreError):
            self.store.get(record.job_id)

    def test_malformed_job_timestamp_is_controlled_on_read(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase4-malformed-job-time")
        )

        self.update(
            """
            UPDATE scan_jobs
            SET updated_at = ?
            WHERE job_id = ?
            """,
            (
                "not-a-timestamp",
                record.job_id,
            ),
        )

        with self.assertRaises(JobStoreError):
            self.store.get(record.job_id)

    def test_malformed_revision_cannot_cross_claim_boundary(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase4-malformed-revision")
        )

        self.update(
            """
            UPDATE scan_jobs
            SET revision = ?
            WHERE job_id = ?
            """,
            (
                "not-an-integer",
                record.job_id,
            ),
        )

        with self.assertRaises(JobStoreError):
            self.store.claim_next(
                now=NOW,
            )

        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT state
                FROM scan_jobs
                WHERE job_id = ?
                """,
                (record.job_id,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(row)
        self.assertEqual(
            row[0],
            ScanJobState.QUEUED.value,
            msg=(
                "Malformed persisted metadata must not "
                "cross the worker-claim boundary."
            ),
        )

    def test_malformed_schedule_state_is_controlled_on_read(
        self,
    ) -> None:
        schedule, _ = self.create_schedule()

        self.update(
            """
            UPDATE scan_schedules
            SET state = ?
            WHERE schedule_id = ?
            """,
            (
                "not-a-schedule-state",
                schedule.schedule_id,
            ),
        )

        with self.assertRaises(JobStoreError):
            self.store.get_schedule_scoped(
                schedule.schedule_id,
                ORG_ID,
            )

    def test_malformed_schedule_timestamp_is_controlled_on_read(
        self,
    ) -> None:
        schedule, _ = self.create_schedule()

        self.update(
            """
            UPDATE scan_schedules
            SET next_run_at = ?
            WHERE schedule_id = ?
            """,
            (
                "not-a-timestamp",
                schedule.schedule_id,
            ),
        )

        with self.assertRaises(JobStoreError):
            self.store.get_schedule_scoped(
                schedule.schedule_id,
                ORG_ID,
            )

    def test_malformed_permit_revocation_timestamp_is_controlled(
        self,
    ) -> None:
        permit = create_trustscan_permit(self.store)
        permit_id = permit.permit.claims.permit_id

        self.update(
            """
            UPDATE scan_permits
            SET revoked_at = ?
            WHERE permit_id = ?
            """,
            (
                "not-a-timestamp",
                permit_id,
            ),
        )

        with self.assertRaises(JobStoreError):
            self.store.get_scan_permit(
                permit_id
            )


if __name__ == "__main__":
    unittest.main()
