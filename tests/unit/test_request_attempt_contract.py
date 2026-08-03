"""Tests for request-attempt audit records in ScanResult."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from webguard_contracts import (
    RequestAttempt,
    RequestAttemptOutcome,
    ScanContractValidationError,
    ScanCoverage,
    ScanError,
    ScanResult,
    ScanStatus,
)


STARTED_AT = datetime(
    2026,
    8,
    3,
    17,
    0,
    tzinfo=timezone.utc,
)
ATTEMPT_ONE_STARTED = STARTED_AT + timedelta(milliseconds=10)
ATTEMPT_ONE_COMPLETED = STARTED_AT + timedelta(milliseconds=60)
ATTEMPT_TWO_STARTED = STARTED_AT + timedelta(milliseconds=160)
ATTEMPT_TWO_COMPLETED = STARTED_AT + timedelta(milliseconds=200)
COMPLETED_AT = STARTED_AT + timedelta(seconds=1)


def successful_attempt(
    *,
    attempt_number: int = 1,
    started_at: datetime = ATTEMPT_ONE_STARTED,
    completed_at: datetime = ATTEMPT_ONE_COMPLETED,
) -> RequestAttempt:
    return RequestAttempt(
        attempt_number=attempt_number,
        started_at=started_at,
        completed_at=completed_at,
        outcome=RequestAttemptOutcome.SUCCEEDED,
        connected_address="203.0.113.10",
        http_status=200,
    )


def failed_attempt(
    *,
    attempt_number: int = 1,
    started_at: datetime = ATTEMPT_ONE_STARTED,
    completed_at: datetime = ATTEMPT_ONE_COMPLETED,
    retryable: bool = True,
    retry_scheduled: bool = False,
    backoff_seconds: float = 0.0,
) -> RequestAttempt:
    return RequestAttempt(
        attempt_number=attempt_number,
        started_at=started_at,
        completed_at=completed_at,
        outcome=RequestAttemptOutcome.FAILED,
        error_code="connection_timeout",
        retryable=retryable,
        retry_scheduled=retry_scheduled,
        backoff_seconds=backoff_seconds,
    )


def completed_result(
    *,
    coverage: ScanCoverage | None = None,
    request_attempts: tuple[RequestAttempt, ...] = (),
    connected_addresses: tuple[str, ...] = (),
    http_statuses: tuple[int, ...] = (),
) -> ScanResult:
    return ScanResult(
        scan_id=str(uuid4()),
        scan_type="passive-http-headers",
        status=ScanStatus.COMPLETED,
        target="https://example.com/",
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=STARTED_AT,
        completed_at=COMPLETED_AT,
        coverage=(
            coverage
            if coverage is not None
            else ScanCoverage(
                requests_attempted=len(request_attempts),
                requests_succeeded=sum(
                    item.outcome
                    is RequestAttemptOutcome.SUCCEEDED
                    for item in request_attempts
                ),
            )
        ),
        connected_addresses=connected_addresses,
        http_statuses=http_statuses,
        request_attempts=request_attempts,
    )


class RequestAttemptContractTests(unittest.TestCase):
    """Verify audit-trail validation and deterministic serialization."""

    def test_successful_attempt_normalises_and_serialises(self) -> None:
        attempt = RequestAttempt(
            attempt_number=1,
            started_at=ATTEMPT_ONE_STARTED,
            completed_at=ATTEMPT_ONE_COMPLETED,
            outcome=RequestAttemptOutcome.SUCCEEDED,
            connected_address="2001:0db8::1",
            http_status=204,
        )

        self.assertEqual(
            attempt.connected_address,
            "2001:db8::1",
        )
        self.assertEqual(attempt.duration_milliseconds, 50)
        self.assertEqual(
            attempt.to_dict(),
            {
                "attempt_number": 1,
                "started_at": "2026-08-03T17:00:00.010000Z",
                "completed_at": "2026-08-03T17:00:00.060000Z",
                "duration_milliseconds": 50,
                "outcome": "succeeded",
                "connected_address": "2001:db8::1",
                "http_status": 204,
                "error_code": None,
                "retryable": None,
                "retry_scheduled": False,
                "backoff_seconds": 0.0,
            },
        )

    def test_failed_attempt_records_retry_decision(self) -> None:
        attempt = failed_attempt(
            retry_scheduled=True,
            backoff_seconds=0.25,
        )

        self.assertEqual(attempt.error_code, "connection_timeout")
        self.assertTrue(attempt.retryable)
        self.assertTrue(attempt.retry_scheduled)
        self.assertEqual(attempt.backoff_seconds, 0.25)

    def test_rejects_naive_attempt_timestamp(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "timezone-aware",
        ):
            successful_attempt(
                started_at=ATTEMPT_ONE_STARTED.replace(tzinfo=None),
            )

    def test_success_requires_address_and_status(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "require an address and HTTP status",
        ):
            RequestAttempt(
                attempt_number=1,
                started_at=ATTEMPT_ONE_STARTED,
                completed_at=ATTEMPT_ONE_COMPLETED,
                outcome=RequestAttemptOutcome.SUCCEEDED,
            )

    def test_failure_requires_error_metadata(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "require error_code and retryable",
        ):
            RequestAttempt(
                attempt_number=1,
                started_at=ATTEMPT_ONE_STARTED,
                completed_at=ATTEMPT_ONE_COMPLETED,
                outcome=RequestAttemptOutcome.FAILED,
            )

    def test_non_retryable_failure_cannot_schedule_retry(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "cannot schedule a retry",
        ):
            failed_attempt(
                retryable=False,
                retry_scheduled=True,
            )

    def test_backoff_requires_scheduled_retry(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "must be zero",
        ):
            failed_attempt(
                retry_scheduled=False,
                backoff_seconds=0.25,
            )

    def test_scan_result_serialises_complete_attempt_history(self) -> None:
        first = failed_attempt(
            retry_scheduled=True,
            backoff_seconds=0.1,
        )
        second = successful_attempt(
            attempt_number=2,
            started_at=ATTEMPT_TWO_STARTED,
            completed_at=ATTEMPT_TWO_COMPLETED,
        )

        result = completed_result(
            request_attempts=(first, second),
            connected_addresses=("203.0.113.10",),
            http_statuses=(200,),
        )
        payload = result.to_dict()

        self.assertEqual(result.schema_version, "1.1")
        self.assertEqual(payload["request_attempt_count"], 2)
        self.assertEqual(
            [
                item["outcome"]
                for item in payload["request_attempts"]
            ],
            ["failed", "succeeded"],
        )

    def test_rejects_non_contiguous_attempt_numbers(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "numbered from one",
        ):
            completed_result(
                coverage=ScanCoverage(
                    requests_attempted=1,
                    requests_succeeded=1,
                ),
                request_attempts=(
                    successful_attempt(attempt_number=2),
                ),
                connected_addresses=("203.0.113.10",),
                http_statuses=(200,),
            )

    def test_rejects_attempt_count_mismatch(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "match requests_attempted",
        ):
            completed_result(
                coverage=ScanCoverage(
                    requests_attempted=2,
                    requests_succeeded=1,
                ),
                request_attempts=(successful_attempt(),),
                connected_addresses=("203.0.113.10",),
                http_statuses=(200,),
            )

    def test_rejects_success_count_mismatch(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "match requests_succeeded",
        ):
            completed_result(
                coverage=ScanCoverage(
                    requests_attempted=1,
                    requests_succeeded=0,
                ),
                request_attempts=(successful_attempt(),),
                connected_addresses=("203.0.113.10",),
                http_statuses=(200,),
            )

    def test_terminal_result_cannot_end_with_scheduled_retry(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "cannot end with a scheduled retry",
        ):
            ScanResult(
                scan_id=str(uuid4()),
                scan_type="passive-http-headers",
                status=ScanStatus.FAILED,
                target="https://example.com/",
                engine="webguard-native",
                engine_version="0.1.0",
                started_at=STARTED_AT,
                completed_at=COMPLETED_AT,
                coverage=ScanCoverage(
                    requests_attempted=1,
                    requests_succeeded=0,
                ),
                errors=(
                    ScanError(
                        code="connection_timeout",
                        message="The request timed out.",
                        stage="request",
                        retryable=True,
                    ),
                ),
                request_attempts=(
                    failed_attempt(
                        retry_scheduled=True,
                        backoff_seconds=0.1,
                    ),
                ),
            )

    def test_attempt_metadata_must_match_result_metadata(self) -> None:
        with self.assertRaisesRegex(
            ScanContractValidationError,
            "Attempt addresses must match",
        ):
            completed_result(
                request_attempts=(successful_attempt(),),
                connected_addresses=("203.0.113.11",),
                http_statuses=(200,),
            )

    def test_empty_history_preserves_legacy_constructor_compatibility(
        self,
    ) -> None:
        result = completed_result(
            coverage=ScanCoverage(
                requests_attempted=1,
                requests_succeeded=1,
            ),
        )

        self.assertEqual(result.request_attempts, ())
        self.assertEqual(result.to_dict()["request_attempts"], [])


if __name__ == "__main__":
    unittest.main()
