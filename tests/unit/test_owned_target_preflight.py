"""Tests for the external owned-target readiness gate."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from webguard_contracts import (
    OWNED_TARGET_STOP_CONDITIONS,
    OwnedTargetAuthorization,
    OwnedTargetLimits,
)
from webguard_scanner import (
    CrawlPolicy,
    FetchPolicy,
    OwnedTargetPreflightError,
    RetryPolicy,
    ValidatedTarget,
    validate_owned_target_preflight,
)


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
AUTHORIZATION_ID = "ae2d7d11-ad93-4f32-9203-1d81ffd0a170"
SCAN_ID = "9750faf2-1467-474c-853c-fc4a26c421a0"


def authorization(**overrides) -> OwnedTargetAuthorization:
    values = {
        "authorization_id": AUTHORIZATION_ID,
        "organization": "InternStack Private Limited",
        "authorized_by": "Krishna Jonnagaddala",
        "target": "https://internstack.in/",
        "allowed_hosts": ("internstack.in",),
        "issued_at": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(days=30),
        "purpose": "Controlled passive assessment of the owned website.",
        "limits": OwnedTargetLimits(),
    }
    values.update(overrides)
    return OwnedTargetAuthorization(**values)


def target(**overrides) -> ValidatedTarget:
    values = {
        "original_url": "https://internstack.in/",
        "normalised_url": "https://internstack.in/",
        "scheme": "https",
        "hostname": "internstack.in",
        "port": 443,
        "resolved_addresses": ("93.184.216.34",),
    }
    values.update(overrides)
    return ValidatedTarget(**values)


def fetch_policy(**overrides) -> FetchPolicy:
    values = {
        "timeout_seconds": 10,
        "maximum_body_bytes": 1_048_576,
        "maximum_header_bytes": 65_536,
        "maximum_header_count": 100,
    }
    values.update(overrides)
    return FetchPolicy(**values)


def retry_policy(**overrides) -> RetryPolicy:
    values = {"maximum_attempts": 1}
    values.update(overrides)
    return RetryPolicy(**values)


def crawl_policy(**overrides) -> CrawlPolicy:
    values = {
        "maximum_pages": 10,
        "maximum_depth": 1,
        "maximum_links_per_page": 50,
        "minimum_delay_seconds": 1,
        "maximum_execution_seconds": 60,
        "maximum_request_attempts": 15,
    }
    values.update(overrides)
    return CrawlPolicy(**values)


def preflight(**overrides):
    values = {
        "authorization": authorization(),
        "target": target(),
        "confirmation": AUTHORIZATION_ID,
        "scan_id": SCAN_ID,
        "fetch_policy": fetch_policy(),
        "retry_policy": retry_policy(),
        "crawl_policy": crawl_policy(),
        "now": NOW,
    }
    values.update(overrides)
    return validate_owned_target_preflight(**values)


class OwnedTargetPreflightTests(unittest.TestCase):
    def test_approved_crawl_builds_audit_record(self) -> None:
        result = preflight()
        self.assertEqual(result.authorization.authorization_id, AUTHORIZATION_ID)
        self.assertTrue(result.execution_policy.crawl_enabled)
        self.assertEqual(result.execution_policy.maximum_pages, 10)
        self.assertEqual(result.audit_record.scan_id, SCAN_ID)
        self.assertEqual(
            result.audit_record.stop_conditions,
            OWNED_TARGET_STOP_CONDITIONS,
        )
        self.assertEqual(
            result.audit_record.authorization_sha256,
            result.authorization_sha256,
        )

    def test_approved_single_page_policy_has_no_crawl_values(self) -> None:
        result = preflight(crawl_policy=None)
        self.assertFalse(result.execution_policy.crawl_enabled)
        self.assertIsNone(result.execution_policy.maximum_pages)
        self.assertIsNone(result.execution_policy.query_mode)

    def test_confirmation_must_match_authorization_id(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(confirmation="wrong")
        self.assertEqual(
            raised.exception.code,
            "owned_target_confirmation_mismatch",
        )

    def test_not_yet_valid_authorization_is_rejected(self) -> None:
        value = authorization(
            issued_at=NOW + timedelta(hours=1),
            expires_at=NOW + timedelta(days=1),
        )
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(authorization=value)
        self.assertEqual(
            raised.exception.code,
            "owned_target_authorization_not_yet_valid",
        )

    def test_expired_authorization_is_rejected(self) -> None:
        value = authorization(
            issued_at=NOW - timedelta(days=2),
            expires_at=NOW,
        )
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(authorization=value)
        self.assertEqual(
            raised.exception.code,
            "owned_target_authorization_expired",
        )

    def test_canonical_target_must_match_exactly(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(
                target=target(
                    original_url="https://internstack.in/app",
                    normalised_url="https://internstack.in/app",
                )
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_canonical_target_mismatch",
        )

    def test_https_is_required(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(
                target=target(
                    original_url="http://internstack.in/",
                    normalised_url="http://internstack.in/",
                    scheme="http",
                    port=80,
                )
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_https_required",
        )

    def test_private_resolution_is_rejected_defensively(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(target=target(resolved_addresses=("127.0.0.1",)))
        self.assertEqual(
            raised.exception.code,
            "owned_target_public_address_required",
        )

    def test_timeout_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(fetch_policy=fetch_policy(timeout_seconds=11))
        self.assertEqual(
            raised.exception.code,
            "owned_target_timeout_limit_exceeded",
        )

    def test_body_limit_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(
                fetch_policy=fetch_policy(maximum_body_bytes=1_048_577)
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_body_limit_exceeded",
        )

    def test_header_byte_limit_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(
                fetch_policy=fetch_policy(maximum_header_bytes=65_537)
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_header_bytes_limit_exceeded",
        )

    def test_header_count_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(fetch_policy=fetch_policy(maximum_header_count=101))
        self.assertEqual(
            raised.exception.code,
            "owned_target_header_count_limit_exceeded",
        )

    def test_retries_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(retry_policy=retry_policy(maximum_attempts=2))
        self.assertEqual(
            raised.exception.code,
            "owned_target_retry_limit_exceeded",
        )

    def test_page_limit_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(crawl_policy=crawl_policy(maximum_pages=11))
        self.assertEqual(
            raised.exception.code,
            "owned_target_page_limit_exceeded",
        )

    def test_depth_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(crawl_policy=crawl_policy(maximum_depth=2))
        self.assertEqual(
            raised.exception.code,
            "owned_target_depth_limit_exceeded",
        )

    def test_link_limit_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(
                crawl_policy=crawl_policy(maximum_links_per_page=51)
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_link_limit_exceeded",
        )

    def test_delay_cannot_be_below_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(crawl_policy=crawl_policy(minimum_delay_seconds=0.5))
        self.assertEqual(
            raised.exception.code,
            "owned_target_delay_below_minimum",
        )

    def test_execution_time_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(
                crawl_policy=crawl_policy(maximum_execution_seconds=61)
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_execution_limit_exceeded",
        )

    def test_request_budget_cannot_exceed_authorization(self) -> None:
        with self.assertRaises(OwnedTargetPreflightError) as raised:
            preflight(
                crawl_policy=crawl_policy(maximum_request_attempts=16)
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_request_budget_exceeded",
        )

    def test_lower_bounded_policy_is_accepted(self) -> None:
        result = preflight(
            fetch_policy=fetch_policy(
                timeout_seconds=5,
                maximum_body_bytes=500_000,
            ),
            crawl_policy=crawl_policy(
                maximum_pages=5,
                maximum_depth=0,
                maximum_links_per_page=25,
                minimum_delay_seconds=2,
                maximum_execution_seconds=30,
                maximum_request_attempts=7,
            ),
        )
        self.assertEqual(result.execution_policy.maximum_pages, 5)
        self.assertEqual(result.execution_policy.minimum_delay_seconds, 2)
        self.assertEqual(result.audit_record.resolved_addresses, ("93.184.216.34",))


if __name__ == "__main__":
    unittest.main()
