from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from webguard_contracts import (
    CURRENT_SCAN_JOB_SCHEMA_VERSION,
    SCAN_JOB_RECORD_TYPE,
    SCAN_JOB_REQUEST_TYPE,
    ScanJobLoadError,
    ScanJobMode,
    ScanJobRecord,
    ScanJobRequest,
    ScanJobState,
    ScanJobValidationError,
    ScanStatus,
    load_scan_job_record_json,
    load_scan_job_request_json,
    load_scan_job_submission_json,
)


NOW = datetime(2026, 8, 6, 18, 0, tzinfo=timezone.utc)
AUTH_ID = "8ae6403f-7832-498c-b37e-c0c87be19ea1"
JOB_ID = "b6a39765-16c6-42b4-91f0-998bf07f1912"
SCAN_ID = "a7a39765-16c6-42b4-91f0-998bf07f1912"
DIGEST = "a" * 64


def request(**changes) -> ScanJobRequest:
    values = dict(
        idempotency_key="internstack-20260806",
        target="https://example.com/",
        authorization_id=AUTH_ID,
        authorization_sha256=DIGEST,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )
    values.update(changes)
    return ScanJobRequest(**values)


def queued(**changes) -> ScanJobRecord:
    values = dict(
        job_id=JOB_ID,
        request=request(),
        state=ScanJobState.QUEUED,
        updated_at=NOW,
    )
    values.update(changes)
    return ScanJobRecord(**values)


class ScanJobSubmissionTests(unittest.TestCase):
    def valid_document(self) -> str:
        return json.dumps(
            {
                "target": "https://example.com/",
                "authorization_id": AUTH_ID,
                "confirm_authorization": AUTH_ID,
                "mode": "crawl",
            }
        )

    def test_loads_valid_submission(self) -> None:
        result = load_scan_job_submission_json(self.valid_document())
        self.assertEqual(result.target, "https://example.com/")
        self.assertIs(result.mode, ScanJobMode.CRAWL)

    def test_single_page_mode_is_supported(self) -> None:
        document = json.loads(self.valid_document())
        document["mode"] = "single_page"
        result = load_scan_job_submission_json(json.dumps(document))
        self.assertIs(result.mode, ScanJobMode.SINGLE_PAGE)

    def test_rejects_confirmation_mismatch(self) -> None:
        document = json.loads(self.valid_document())
        document["confirm_authorization"] = JOB_ID
        with self.assertRaisesRegex(ScanJobLoadError, "exactly match"):
            load_scan_job_submission_json(json.dumps(document))

    def test_rejects_http_target(self) -> None:
        document = json.loads(self.valid_document())
        document["target"] = "http://example.com/"
        with self.assertRaises(ScanJobLoadError):
            load_scan_job_submission_json(json.dumps(document))

    def test_rejects_unknown_field(self) -> None:
        document = json.loads(self.valid_document())
        document["active_scan"] = True
        with self.assertRaisesRegex(ScanJobLoadError, "unknown field"):
            load_scan_job_submission_json(json.dumps(document))

    def test_rejects_missing_field(self) -> None:
        document = json.loads(self.valid_document())
        del document["mode"]
        with self.assertRaisesRegex(ScanJobLoadError, "missing required"):
            load_scan_job_submission_json(json.dumps(document))

    def test_rejects_duplicate_json_key(self) -> None:
        document = (
            '{"target":"https://example.com/",'
            f'"authorization_id":"{AUTH_ID}",'
            f'"confirm_authorization":"{AUTH_ID}",'
            '"mode":"crawl","mode":"single_page"}'
        )
        with self.assertRaisesRegex(ScanJobLoadError, "duplicate key"):
            load_scan_job_submission_json(document)

    def test_rejects_invalid_mode(self) -> None:
        document = json.loads(self.valid_document())
        document["mode"] = "active"
        with self.assertRaisesRegex(ScanJobLoadError, "single_page"):
            load_scan_job_submission_json(json.dumps(document))

    def test_rejects_non_object_root(self) -> None:
        with self.assertRaisesRegex(ScanJobLoadError, "JSON object"):
            load_scan_job_submission_json("[]")

    def test_rejects_oversized_document(self) -> None:
        with self.assertRaisesRegex(ScanJobLoadError, "128 KiB"):
            load_scan_job_submission_json(b" " * (128 * 1024 + 1))


class ScanJobRequestTests(unittest.TestCase):
    def test_fingerprint_is_deterministic(self) -> None:
        first = request()
        second = request(submitted_at=NOW + timedelta(seconds=1))
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_fingerprint_changes_with_mode(self) -> None:
        self.assertNotEqual(
            request().fingerprint,
            request(mode=ScanJobMode.SINGLE_PAGE).fingerprint,
        )

    def test_to_dict_is_versioned(self) -> None:
        document = request().to_dict()
        self.assertEqual(document["type"], SCAN_JOB_REQUEST_TYPE)
        self.assertEqual(document["schema_version"], CURRENT_SCAN_JOB_SCHEMA_VERSION)

    def test_json_round_trip(self) -> None:
        original = request()
        loaded = load_scan_job_request_json(original.to_json())
        self.assertEqual(loaded, original)

    def test_rejects_short_idempotency_key(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "8 to 128"):
            request(idempotency_key="short")

    def test_rejects_invalid_idempotency_character(self) -> None:
        with self.assertRaises(ScanJobValidationError):
            request(idempotency_key="invalid key")

    def test_rejects_noncanonical_target(self) -> None:
        # Request construction canonicalizes the root path.
        self.assertEqual(request(target="https://example.com").target, "https://example.com/")

    def test_rejects_invalid_digest(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "SHA-256"):
            request(authorization_sha256="abc")

    def test_rejects_naive_timestamp(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "timezone-aware"):
            request(submitted_at=datetime(2026, 8, 6, 18, 0))

    def test_loader_rejects_changed_fingerprint(self) -> None:
        document = request().to_dict()
        document["fingerprint"] = "b" * 64
        with self.assertRaisesRegex(ScanJobLoadError, "fingerprint"):
            load_scan_job_request_json(json.dumps(document))


class ScanJobRecordTests(unittest.TestCase):
    def test_queued_round_trip(self) -> None:
        original = queued()
        loaded = load_scan_job_record_json(original.to_json())
        self.assertEqual(loaded, original)
        self.assertEqual(loaded.to_dict()["type"], SCAN_JOB_RECORD_TYPE)

    def test_running_requires_start_time(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "started_at"):
            queued(state=ScanJobState.RUNNING)

    def test_valid_running_record(self) -> None:
        result = queued(
            state=ScanJobState.RUNNING,
            started_at=NOW,
            updated_at=NOW,
        )
        self.assertIs(result.state, ScanJobState.RUNNING)

    def test_completed_requires_result_projection(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "result"):
            queued(
                state=ScanJobState.COMPLETED,
                started_at=NOW,
                completed_at=NOW,
            )

    def test_valid_completed_record(self) -> None:
        result = queued(
            state=ScanJobState.COMPLETED,
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=1),
            updated_at=NOW + timedelta(seconds=1),
            scan_id=SCAN_ID,
            result_status=ScanStatus.COMPLETED,
            report_ref=f"jobs/{JOB_ID}/report.json",
            audit_ref=f"jobs/{JOB_ID}/authorization-audit.json",
        )
        self.assertEqual(result.report_ref, f"jobs/{JOB_ID}/report.json")

    def test_valid_result_backed_failed_record(self) -> None:
        result = queued(
            state=ScanJobState.FAILED,
            started_at=NOW,
            completed_at=NOW,
            scan_id=SCAN_ID,
            result_status=ScanStatus.FAILED,
            report_ref=f"jobs/{JOB_ID}/report.json",
            audit_ref=f"jobs/{JOB_ID}/authorization-audit.json",
        )
        self.assertIs(result.result_status, ScanStatus.FAILED)

    def test_valid_service_failure(self) -> None:
        result = queued(
            state=ScanJobState.FAILED,
            started_at=NOW,
            completed_at=NOW,
            error_code="authorization_not_found",
            error_message="Authorization was not found.",
        )
        self.assertEqual(result.error_code, "authorization_not_found")

    def test_rejects_partial_service_error(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "both"):
            queued(
                state=ScanJobState.FAILED,
                started_at=NOW,
                completed_at=NOW,
                error_code="worker_error",
            )

    def test_queued_cancellation_is_valid(self) -> None:
        result = queued(
            state=ScanJobState.CANCELLED,
            cancellation_requested=True,
            completed_at=NOW,
        )
        self.assertIsNone(result.started_at)

    def test_rejects_absolute_artifact_reference(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "relative"):
            queued(
                state=ScanJobState.COMPLETED,
                started_at=NOW,
                completed_at=NOW,
                scan_id=SCAN_ID,
                result_status=ScanStatus.COMPLETED,
                report_ref="/tmp/report.json",
                audit_ref="jobs/audit.json",
            )

    def test_rejects_parent_traversal_reference(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "relative"):
            queued(
                state=ScanJobState.COMPLETED,
                started_at=NOW,
                completed_at=NOW,
                scan_id=SCAN_ID,
                result_status=ScanStatus.COMPLETED,
                report_ref="jobs/../report.json",
                audit_ref="jobs/audit.json",
            )

    def test_rejects_result_status_mismatch(self) -> None:
        with self.assertRaisesRegex(ScanJobValidationError, "do not match"):
            queued(
                state=ScanJobState.COMPLETED,
                started_at=NOW,
                completed_at=NOW,
                scan_id=SCAN_ID,
                result_status=ScanStatus.FAILED,
                report_ref="jobs/report.json",
                audit_ref="jobs/audit.json",
            )

    def test_public_projection_does_not_include_confirmation(self) -> None:
        document = queued().to_public_dict()
        serialized = json.dumps(document)
        self.assertNotIn("confirmation", serialized)
        self.assertNotIn("confirm_authorization", serialized)
        self.assertNotIn("authorization_sha256", serialized)
        self.assertNotIn("idempotency_key", serialized)
        self.assertNotIn("fingerprint", serialized)


if __name__ == "__main__":
    unittest.main()
