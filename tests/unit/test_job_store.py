from __future__ import annotations

import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_contracts import (
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    ScanStatus,
)
from webguard_api import JobStoreError, ScanJobStore


NOW = datetime(2026, 8, 6, 18, 0, tzinfo=timezone.utc)
AUTH_ID = "8ae6403f-7832-498c-b37e-c0c87be19ea1"
SCAN_ID = "b6a39765-16c6-42b4-91f0-998bf07f1912"


def request(key: str = "internstack-20260806", **changes) -> ScanJobRequest:
    values = dict(
        idempotency_key=key,
        target="https://internstack.in/",
        authorization_id=AUTH_ID,
        authorization_sha256="a" * 64,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )
    values.update(changes)
    return ScanJobRequest(**values)


class ScanJobStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "private" / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_database_is_owner_only(self) -> None:
        mode = stat.S_IMODE(self.path.stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_submit_creates_queued_record(self) -> None:
        record, created = self.store.submit(request())
        self.assertTrue(created)
        self.assertIs(record.state, ScanJobState.QUEUED)
        self.assertEqual(self.store.get(record.job_id), record)

    def test_idempotent_submit_returns_existing_record(self) -> None:
        first, created = self.store.submit(request())
        self.assertTrue(created)
        second, created = self.store.submit(
            request(submitted_at=NOW + timedelta(seconds=1))
        )
        self.assertFalse(created)
        self.assertEqual(second.job_id, first.job_id)
        self.assertEqual(second.request.submitted_at, first.request.submitted_at)

    def test_idempotency_key_conflict_is_rejected(self) -> None:
        self.store.submit(request())
        with self.assertRaisesRegex(JobStoreError, "different request"):
            self.store.submit(request(mode=ScanJobMode.SINGLE_PAGE))

    def test_get_unknown_job_is_controlled(self) -> None:
        with self.assertRaisesRegex(JobStoreError, "not found"):
            self.store.get(SCAN_ID)

    def test_claim_next_uses_submission_order(self) -> None:
        later, _ = self.store.submit(
            request("later-job", submitted_at=NOW + timedelta(seconds=1))
        )
        earlier, _ = self.store.submit(request("earlier-job"))
        claimed = self.store.claim_next(now=NOW + timedelta(seconds=2))
        assert claimed is not None
        self.assertEqual(claimed.job_id, earlier.job_id)
        self.assertIs(claimed.state, ScanJobState.RUNNING)
        self.assertEqual(claimed.revision, 1)
        self.assertEqual(self.store.get(later.job_id).state, ScanJobState.QUEUED)

    def test_claim_empty_queue_returns_none(self) -> None:
        self.assertIsNone(self.store.claim_next(now=NOW))

    def test_queued_cancellation_is_terminal(self) -> None:
        record, _ = self.store.submit(request())
        cancelled = self.store.request_cancellation(
            record.job_id,
            now=NOW + timedelta(seconds=1),
        )
        self.assertIs(cancelled.state, ScanJobState.CANCELLED)
        self.assertTrue(cancelled.cancellation_requested)
        self.assertIsNone(self.store.claim_next(now=NOW + timedelta(seconds=2)))

    def test_running_cancellation_sets_flag_without_terminal_transition(self) -> None:
        record, _ = self.store.submit(request())
        claimed = self.store.claim_next(now=NOW + timedelta(seconds=1))
        assert claimed is not None
        updated = self.store.request_cancellation(
            record.job_id,
            now=NOW + timedelta(seconds=2),
        )
        self.assertIs(updated.state, ScanJobState.RUNNING)
        self.assertTrue(updated.cancellation_requested)
        self.assertTrue(self.store.is_cancellation_requested(record.job_id))

    def test_terminal_cancellation_request_is_idempotent(self) -> None:
        record, _ = self.store.submit(request())
        first = self.store.request_cancellation(record.job_id, now=NOW)
        second = self.store.request_cancellation(
            record.job_id,
            now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(first, second)

    def test_finish_completed_result(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next(now=NOW)
        finished = self.store.finish_result(
            record.job_id,
            scan_id=SCAN_ID,
            result_status=ScanStatus.COMPLETED,
            report_ref=f"jobs/{record.job_id}/report.json",
            audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
            now=NOW + timedelta(seconds=1),
        )
        self.assertIs(finished.state, ScanJobState.COMPLETED)
        self.assertEqual(finished.scan_id, SCAN_ID)

    def test_finish_completed_with_errors_result(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next(now=NOW)
        finished = self.store.finish_result(
            record.job_id,
            scan_id=SCAN_ID,
            result_status=ScanStatus.COMPLETED_WITH_ERRORS,
            report_ref=f"jobs/{record.job_id}/report.json",
            audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
            now=NOW,
        )
        self.assertIs(finished.state, ScanJobState.COMPLETED_WITH_ERRORS)

    def test_finish_failed_scan_preserves_artifacts(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next(now=NOW)
        finished = self.store.finish_result(
            record.job_id,
            scan_id=SCAN_ID,
            result_status=ScanStatus.FAILED,
            report_ref=f"jobs/{record.job_id}/report.json",
            audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
            now=NOW,
        )
        self.assertIs(finished.state, ScanJobState.FAILED)
        self.assertIs(finished.result_status, ScanStatus.FAILED)

    def test_finish_cancelled_scan_preserves_partial_report(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next(now=NOW)
        finished = self.store.finish_result(
            record.job_id,
            scan_id=SCAN_ID,
            result_status=ScanStatus.CANCELLED,
            report_ref=f"jobs/{record.job_id}/report.json",
            audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
            now=NOW,
        )
        self.assertIs(finished.state, ScanJobState.CANCELLED)
        self.assertEqual(finished.report_ref, f"jobs/{record.job_id}/report.json")

    def test_service_failure_has_no_artifacts(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next(now=NOW)
        failed = self.store.fail(
            record.job_id,
            error_code="authorization_not_found",
            error_message="Authorization not found.",
            now=NOW,
        )
        self.assertIs(failed.state, ScanJobState.FAILED)
        self.assertIsNone(failed.report_ref)
        self.assertEqual(failed.error_code, "authorization_not_found")

    def test_running_job_can_be_cancelled_by_worker(self) -> None:
        record, _ = self.store.submit(request())
        self.store.claim_next(now=NOW)
        cancelled = self.store.cancel_running(record.job_id, now=NOW)
        self.assertIs(cancelled.state, ScanJobState.CANCELLED)

    def test_terminal_update_requires_running_state(self) -> None:
        record, _ = self.store.submit(request())
        with self.assertRaisesRegex(JobStoreError, "Only running"):
            self.store.fail(
                record.job_id,
                error_code="worker_error",
                error_message="Failed.",
                now=NOW,
            )

    def test_symlink_database_is_rejected(self) -> None:
        target = self.root / "target.sqlite3"
        target.write_text("x", encoding="utf-8")
        link = self.root / "link.sqlite3"
        link.symlink_to(target)
        with self.assertRaisesRegex(JobStoreError, "symbolic link"):
            ScanJobStore(link)

    def test_directory_database_path_is_rejected(self) -> None:
        directory = self.root / "database"
        directory.mkdir()
        with self.assertRaisesRegex(JobStoreError, "regular file"):
            ScanJobStore(directory)


if __name__ == "__main__":
    unittest.main()
