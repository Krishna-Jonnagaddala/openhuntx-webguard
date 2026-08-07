from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from webguard_contracts import (
    MAXIMUM_SCAN_SCHEDULE_DOCUMENT_BYTES,
    ScanJobMode,
    ScanScheduleLoadError,
    ScanScheduleRecord,
    ScanScheduleState,
    ScanScheduleSubmission,
    ScanScheduleValidationError,
    load_scan_schedule_submission_json,
)

NOW = datetime(2026, 8, 7, 0, 0, tzinfo=timezone.utc)
AUTH_ID = "8ae6403f-7832-498c-b37e-c0c87be19ea1"
ORG_ID = "11111111-1111-4111-8111-111111111111"
OWNER_ID = "22222222-2222-4222-8222-222222222222"
SCHEDULE_ID = "66666666-6666-4666-8666-666666666666"


def body(**changes) -> bytes:
    value = {
        "name": "Daily passive crawl",
        "target": "https://internstack.in/",
        "authorization_id": AUTH_ID,
        "confirm_authorization": AUTH_ID,
        "mode": "crawl",
        "interval_seconds": 86400,
        "starts_at": "2026-08-07T01:00:00.000000Z",
    }
    value.update(changes)
    return json.dumps(value).encode("utf-8")


class ScanScheduleContractTests(unittest.TestCase):
    def test_loads_valid_submission(self) -> None:
        value = load_scan_schedule_submission_json(body())
        self.assertEqual(value.mode, ScanJobMode.CRAWL)
        self.assertEqual(value.interval_seconds, 86400)
        self.assertEqual(value.starts_at, NOW + timedelta(hours=1))

    def test_rejects_confirmation_mismatch(self) -> None:
        with self.assertRaises(ScanScheduleLoadError) as context:
            load_scan_schedule_submission_json(
                body(confirm_authorization="77777777-7777-4777-8777-777777777777")
            )
        self.assertEqual(
            context.exception.code,
            "scan_schedule_authorization_confirmation_mismatch",
        )

    def test_rejects_interval_below_one_hour(self) -> None:
        with self.assertRaises(ScanScheduleLoadError) as context:
            load_scan_schedule_submission_json(body(interval_seconds=3599))
        self.assertEqual(context.exception.code, "scan_schedule_interval_invalid")

    def test_rejects_boolean_interval(self) -> None:
        with self.assertRaises(ScanScheduleLoadError):
            load_scan_schedule_submission_json(body(interval_seconds=True))

    def test_accepts_maximum_interval(self) -> None:
        value = load_scan_schedule_submission_json(body(interval_seconds=31536000))
        self.assertEqual(value.interval_seconds, 31536000)

    def test_rejects_interval_above_one_year(self) -> None:
        with self.assertRaises(ScanScheduleLoadError):
            load_scan_schedule_submission_json(body(interval_seconds=31536001))

    def test_rejects_noncanonical_timestamp(self) -> None:
        with self.assertRaises(ScanScheduleLoadError) as context:
            load_scan_schedule_submission_json(
                body(starts_at="2026-08-07T01:00:00+00:00")
            )
        self.assertIn("timestamp", context.exception.code)

    def test_rejects_unknown_field(self) -> None:
        with self.assertRaises(ScanScheduleLoadError) as context:
            load_scan_schedule_submission_json(body(extra=True))
        self.assertEqual(context.exception.code, "scan_schedule_field_unknown")

    def test_rejects_duplicate_json_key(self) -> None:
        raw = body()[:-1] + b',"name":"duplicate"}'
        with self.assertRaises(ScanScheduleLoadError) as context:
            load_scan_schedule_submission_json(raw)
        self.assertEqual(context.exception.code, "scan_schedule_duplicate_key")

    def test_rejects_oversized_document(self) -> None:
        with self.assertRaises(ScanScheduleLoadError) as context:
            load_scan_schedule_submission_json(
                b"{" + b" " * MAXIMUM_SCAN_SCHEDULE_DOCUMENT_BYTES + b"}"
            )
        self.assertEqual(context.exception.code, "scan_schedule_document_too_large")

    def test_rejects_invalid_mode(self) -> None:
        with self.assertRaises(ScanScheduleLoadError) as context:
            load_scan_schedule_submission_json(body(mode="active"))
        self.assertEqual(context.exception.code, "scan_schedule_mode_invalid")

    def test_rejects_control_character_in_name(self) -> None:
        with self.assertRaises(ScanScheduleLoadError):
            load_scan_schedule_submission_json(body(name="Daily\u0000scan"))

    def test_submission_requires_aware_datetime(self) -> None:
        with self.assertRaises(ScanScheduleValidationError):
            ScanScheduleSubmission(
                name="Daily",
                target="https://internstack.in/",
                authorization_id=AUTH_ID,
                confirmation=AUTH_ID,
                mode=ScanJobMode.CRAWL,
                interval_seconds=3600,
                starts_at=datetime(2026, 8, 7, 1, 0),
            )

    def test_record_public_projection_omits_authorization_fingerprint(self) -> None:
        value = ScanScheduleRecord(
            schedule_id=SCHEDULE_ID,
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name="Daily",
            target="https://internstack.in/",
            authorization_id=AUTH_ID,
            authorization_sha256="a" * 64,
            mode=ScanJobMode.CRAWL,
            interval_seconds=86400,
            state=ScanScheduleState.ACTIVE,
            created_at=NOW,
            updated_at=NOW,
            next_run_at=NOW + timedelta(hours=1),
        )
        payload = value.to_public_dict()
        self.assertNotIn("authorization_sha256", payload)
        self.assertEqual(payload["state"], "active")

    def test_record_rejects_partial_error_projection(self) -> None:
        with self.assertRaises(ScanScheduleValidationError) as context:
            ScanScheduleRecord(
                schedule_id=SCHEDULE_ID,
                organization_id=ORG_ID,
                created_by=OWNER_ID,
                name="Daily",
                target="https://internstack.in/",
                authorization_id=AUTH_ID,
                authorization_sha256="a" * 64,
                mode=ScanJobMode.CRAWL,
                interval_seconds=86400,
                state=ScanScheduleState.PAUSED,
                created_at=NOW,
                updated_at=NOW,
                next_run_at=NOW + timedelta(hours=1),
                last_error_code="authorization_not_current",
            )
        self.assertEqual(
            context.exception.code,
            "scan_schedule_error_projection_invalid",
        )


if __name__ == "__main__":
    unittest.main()
