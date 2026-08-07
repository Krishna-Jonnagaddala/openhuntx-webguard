"""Contract tests for owned-target authorization and preflight audit records."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_contracts import (
    MAXIMUM_OWNED_TARGET_DOCUMENT_BYTES,
    OWNED_TARGET_STOP_CONDITIONS,
    OwnedTargetAuditRecord,
    OwnedTargetAuthorization,
    OwnedTargetExecutionPolicy,
    OwnedTargetLimits,
    OwnedTargetLoadError,
    OwnedTargetValidationError,
    canonicalize_owned_target_hostname,
    canonicalize_owned_target_url,
    load_owned_target_audit_file,
    load_owned_target_audit_json,
    load_owned_target_authorization_file,
    load_owned_target_authorization_json,
    write_owned_target_audit_file,
    write_owned_target_authorization_file,
)


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
AUTHORIZATION_ID = "0b0a01c4-b409-4d50-a62d-93b94f14fef5"
SCAN_ID = "fdaf890b-7b1e-4012-8b44-842bedb70a7a"


def authorization(**overrides) -> OwnedTargetAuthorization:
    values = {
        "authorization_id": AUTHORIZATION_ID,
        "organization": "InternStack Private Limited",
        "authorized_by": "Krishna Jonnagaddala",
        "target": "https://example.com/",
        "allowed_hosts": ("example.com", "www.example.com"),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(days=30),
        "purpose": "Passive security assessment of the owned production website.",
        "limits": OwnedTargetLimits(),
    }
    values.update(overrides)
    return OwnedTargetAuthorization(**values)


def execution_policy(*, crawl: bool = True) -> OwnedTargetExecutionPolicy:
    if not crawl:
        return OwnedTargetExecutionPolicy(
            timeout_seconds=10,
            maximum_body_bytes=1_048_576,
            maximum_header_bytes=65_536,
            maximum_header_count=100,
            maximum_attempts_per_request=1,
            crawl_enabled=False,
        )
    return OwnedTargetExecutionPolicy(
        timeout_seconds=10,
        maximum_body_bytes=1_048_576,
        maximum_header_bytes=65_536,
        maximum_header_count=100,
        maximum_attempts_per_request=1,
        crawl_enabled=True,
        maximum_pages=10,
        maximum_depth=1,
        maximum_links_per_page=50,
        minimum_delay_seconds=1,
        maximum_execution_seconds=60,
        maximum_request_attempts=15,
        query_mode="drop",
    )


def audit(**overrides) -> OwnedTargetAuditRecord:
    values = {
        "scan_id": SCAN_ID,
        "authorization_id": AUTHORIZATION_ID,
        "authorization_sha256": authorization().fingerprint,
        "organization": "InternStack Private Limited",
        "authorized_by": "Krishna Jonnagaddala",
        "target": "https://example.com/",
        "resolved_addresses": ("93.184.216.34",),
        "created_at": NOW,
        "execution_policy": execution_policy(),
    }
    values.update(overrides)
    return OwnedTargetAuditRecord(**values)


class OwnedTargetContractTests(unittest.TestCase):
    def test_authorization_round_trip_is_deterministic(self) -> None:
        value = authorization()
        loaded = load_owned_target_authorization_json(value.to_json())
        self.assertEqual(loaded, value)
        self.assertEqual(loaded.to_json(), value.to_json())

    def test_authorization_fingerprint_is_deterministic(self) -> None:
        first = authorization()
        second = load_owned_target_authorization_json(first.to_json())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(len(first.fingerprint), 64)

    def test_authorization_fingerprint_changes_with_limits(self) -> None:
        first = authorization()
        second = authorization(
            limits=OwnedTargetLimits(maximum_pages=9)
        )
        self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_url_canonicalizer_adds_root_path(self) -> None:
        self.assertEqual(
            canonicalize_owned_target_url("https://Example.COM"),
            "https://example.com/",
        )

    def test_hostname_canonicalizer_supports_idna(self) -> None:
        self.assertEqual(
            canonicalize_owned_target_hostname("BÜCHER.example"),
            "xn--bcher-kva.example",
        )

    def test_http_authorization_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            OwnedTargetValidationError,
            "HTTPS",
        ):
            authorization(target="http://example.com/")

    def test_ip_literal_authorization_is_rejected(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            authorization(
                target="https://93.184.216.34/",
                allowed_hosts=("93.184.216.34",),
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_hostname_ip_not_allowed",
        )

    def test_target_must_be_canonical(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            authorization(target="https://Example.COM")
        self.assertEqual(
            raised.exception.code,
            "owned_target_url_non_canonical",
        )

    def test_target_cannot_include_query_or_fragment(self) -> None:
        for value in (
            "https://example.com/?a=1",
            "https://example.com/#section",
        ):
            with self.subTest(value=value):
                with self.assertRaises(OwnedTargetValidationError):
                    authorization(target=value)

    def test_allowed_hosts_must_be_sorted_unique_canonical(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            authorization(
                allowed_hosts=(
                    "www.example.com",
                    "example.com",
                    "example.com",
                )
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_allowed_hosts_non_canonical",
        )

    def test_canonical_host_must_be_allowed(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            authorization(allowed_hosts=("www.example.com",))
        self.assertEqual(
            raised.exception.code,
            "owned_target_canonical_host_not_allowed",
        )

    def test_authorization_requires_passive_only(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            authorization(passive_only=False)
        self.assertEqual(
            raised.exception.code,
            "owned_target_passive_only_required",
        )

    def test_authorization_expiry_must_follow_issue_time(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            authorization(expires_at=NOW)
        self.assertEqual(
            raised.exception.code,
            "owned_target_authorization_window_invalid",
        )

    def test_authorization_validity_cannot_exceed_366_days(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            authorization(expires_at=NOW + timedelta(days=367))
        self.assertEqual(
            raised.exception.code,
            "owned_target_authorization_window_too_long",
        )

    def test_limits_require_safe_minimum_delay(self) -> None:
        with self.assertRaises(OwnedTargetValidationError):
            OwnedTargetLimits(minimum_delay_seconds=0.1)

    def test_limits_reject_excessive_page_count(self) -> None:
        with self.assertRaises(OwnedTargetValidationError):
            OwnedTargetLimits(maximum_pages=51)

    def test_loader_rejects_unknown_root_field(self) -> None:
        document = json.loads(authorization().to_json())
        document["unexpected"] = True
        with self.assertRaises(OwnedTargetLoadError) as raised:
            load_owned_target_authorization_json(json.dumps(document))
        self.assertEqual(raised.exception.code, "owned_target_fields_invalid")

    def test_loader_rejects_missing_root_field(self) -> None:
        document = json.loads(authorization().to_json())
        del document["purpose"]
        with self.assertRaises(OwnedTargetLoadError) as raised:
            load_owned_target_authorization_json(json.dumps(document))
        self.assertEqual(raised.exception.code, "owned_target_fields_invalid")

    def test_loader_rejects_duplicate_json_key(self) -> None:
        document = authorization().to_json()
        duplicate = document[:-1] + ',"purpose":"duplicate"}'
        with self.assertRaises(OwnedTargetLoadError) as raised:
            load_owned_target_authorization_json(duplicate)
        self.assertEqual(raised.exception.code, "owned_target_duplicate_key")

    def test_loader_rejects_noncanonical_timestamp(self) -> None:
        document = json.loads(authorization().to_json())
        document["issued_at"] = "2026-08-05T12:00:00Z"
        with self.assertRaises(OwnedTargetLoadError) as raised:
            load_owned_target_authorization_json(json.dumps(document))
        self.assertEqual(
            raised.exception.code,
            "owned_target_timestamp_non_canonical",
        )

    def test_loader_rejects_noncanonical_numeric_representation(self) -> None:
        document = json.loads(authorization().to_json())
        document["limits"]["timeout_seconds"] = 10
        with self.assertRaises(OwnedTargetLoadError) as raised:
            load_owned_target_authorization_json(json.dumps(document))
        self.assertEqual(
            raised.exception.code,
            "owned_target_limits_non_canonical",
        )

    def test_loader_rejects_invalid_utf8(self) -> None:
        with self.assertRaises(OwnedTargetLoadError) as raised:
            load_owned_target_authorization_json(b"\xff")
        self.assertEqual(raised.exception.code, "owned_target_encoding_invalid")

    def test_loader_rejects_oversized_document(self) -> None:
        document = b" " * (MAXIMUM_OWNED_TARGET_DOCUMENT_BYTES + 1)
        with self.assertRaises(OwnedTargetLoadError) as raised:
            load_owned_target_authorization_json(document)
        self.assertEqual(
            raised.exception.code,
            "owned_target_document_too_large",
        )

    def test_authorization_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            write_owned_target_authorization_file(authorization(), path)
            loaded = load_owned_target_authorization_file(path)
            self.assertEqual(loaded, authorization())
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_authorization_file_requires_explicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            write_owned_target_authorization_file(authorization(), path)
            with self.assertRaises(OwnedTargetLoadError) as raised:
                write_owned_target_authorization_file(authorization(), path)
            self.assertEqual(
                raised.exception.code,
                "owned_target_file_exists",
            )
            write_owned_target_authorization_file(
                authorization(),
                path,
                overwrite=True,
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_authorization_loader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real.json"
            link = Path(directory) / "link.json"
            real.write_text(authorization().to_json(), encoding="utf-8")
            link.symlink_to(real)
            with self.assertRaises(OwnedTargetLoadError) as raised:
                load_owned_target_authorization_file(link)
            self.assertEqual(
                raised.exception.code,
                "owned_target_symlink_not_allowed",
            )

    def test_single_page_execution_policy_rejects_crawl_values(self) -> None:
        with self.assertRaises(OwnedTargetValidationError):
            OwnedTargetExecutionPolicy(
                timeout_seconds=10,
                maximum_body_bytes=1_048_576,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
                maximum_attempts_per_request=1,
                crawl_enabled=False,
                maximum_pages=1,
            )

    def test_crawl_execution_policy_requires_every_crawl_value(self) -> None:
        with self.assertRaises(OwnedTargetValidationError):
            OwnedTargetExecutionPolicy(
                timeout_seconds=10,
                maximum_body_bytes=1_048_576,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
                maximum_attempts_per_request=1,
                crawl_enabled=True,
            )

    def test_audit_round_trip_is_deterministic(self) -> None:
        value = audit()
        loaded = load_owned_target_audit_json(value.to_json())
        self.assertEqual(loaded, value)
        self.assertEqual(loaded.to_json(), value.to_json())

    def test_audit_requires_sha256_fingerprint(self) -> None:
        with self.assertRaises(OwnedTargetValidationError):
            audit(authorization_sha256="not-a-digest")

    def test_audit_requires_fixed_stop_conditions(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            audit(stop_conditions=("operator_interrupt",))
        self.assertEqual(
            raised.exception.code,
            "owned_target_stop_conditions_invalid",
        )
        self.assertEqual(audit().stop_conditions, OWNED_TARGET_STOP_CONDITIONS)

    def test_audit_addresses_must_be_sorted_and_unique(self) -> None:
        with self.assertRaises(OwnedTargetValidationError) as raised:
            audit(
                resolved_addresses=(
                    "2001:4860:4860::8888",
                    "93.184.216.34",
                )
            )
        self.assertEqual(
            raised.exception.code,
            "owned_target_addresses_non_canonical",
        )

    def test_audit_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.json"
            write_owned_target_audit_file(audit(), path)
            self.assertEqual(load_owned_target_audit_file(path), audit())

    def test_audit_loader_rejects_changed_stop_conditions(self) -> None:
        document = json.loads(audit().to_json())
        document["stop_conditions"] = ["operator_interrupt"]
        with self.assertRaises(OwnedTargetLoadError) as raised:
            load_owned_target_audit_json(json.dumps(document))
        self.assertEqual(
            raised.exception.code,
            "owned_target_stop_conditions_invalid",
        )


if __name__ == "__main__":
    unittest.main()
