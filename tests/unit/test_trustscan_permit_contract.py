from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import timedelta

from webguard_contracts import (
    ScanJobMode,
    TRUSTSCAN_PROHIBITED_OPERATIONS,
    TrustScanPermitClaims,
    TrustScanPermitLoadError,
    TrustScanPermitValidationError,
    load_signed_trustscan_permit_json,
    load_trustscan_permit_submission_json,
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


def timestamp(value) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def submission(**changes) -> bytes:
    values = {
        "target": TARGET,
        "authorization_id": AUTH_ID,
        "confirm_authorization": AUTH_ID,
        "permitted_modes": ["crawl", "single_page"],
        "allowed_http_methods": ["GET", "HEAD"],
        "not_before": timestamp(NOW),
        "expires_at": timestamp(NOW + timedelta(days=7)),
        "maximum_request_attempts": 15,
        "maximum_requests_per_second": 1.0,
        "maximum_concurrency": 1,
        "active_checks": [],
    }
    values.update(changes)
    return json.dumps(values).encode("utf-8")


class TrustScanPermitContractTests(unittest.TestCase):
    def test_loads_valid_submission(self) -> None:
        value = load_trustscan_permit_submission_json(submission())
        self.assertEqual(value.target, TARGET)
        self.assertEqual(value.authorization_id, AUTH_ID)
        self.assertEqual(
            value.permitted_modes,
            (ScanJobMode.CRAWL, ScanJobMode.SINGLE_PAGE),
        )
        self.assertEqual(value.allowed_http_methods, ("GET", "HEAD"))
        self.assertEqual(value.maximum_concurrency, 1)

    def test_submission_rejects_noncanonical_modes(self) -> None:
        with self.assertRaises(TrustScanPermitLoadError) as caught:
            load_trustscan_permit_submission_json(
                submission(permitted_modes=["single_page", "crawl"])
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_modes_non_canonical")

    def test_submission_rejects_unsafe_http_method(self) -> None:
        with self.assertRaises(TrustScanPermitLoadError) as caught:
            load_trustscan_permit_submission_json(
                submission(allowed_http_methods=["GET", "POST"])
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_methods_invalid")

    def test_submission_rejects_validity_over_90_days(self) -> None:
        with self.assertRaises(TrustScanPermitLoadError) as caught:
            load_trustscan_permit_submission_json(
                submission(expires_at=timestamp(NOW + timedelta(days=91)))
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_window_too_long")

    def test_submission_rejects_concurrency_above_one(self) -> None:
        with self.assertRaises(TrustScanPermitLoadError) as caught:
            load_trustscan_permit_submission_json(submission(maximum_concurrency=2))
        self.assertEqual(caught.exception.code, "trustscan_permit_integer_invalid")

    def test_claims_require_mandatory_prohibited_operations(self) -> None:
        auth = authorization()
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            TrustScanPermitClaims(
                permit_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                organization_id=ORG_ID,
                authorization_id=AUTH_ID,
                authorization_sha256=auth.fingerprint,
                target=TARGET,
                issued_by=OWNER_ID,
                issued_at=NOW,
                not_before=NOW,
                expires_at=NOW + timedelta(days=7),
                permitted_modes=(ScanJobMode.CRAWL,),
                allowed_http_methods=("GET",),
                maximum_request_attempts=15,
                maximum_requests_per_second=1.0,
                prohibited_operations=TRUSTSCAN_PROHIBITED_OPERATIONS[:-1],
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_prohibited_operations_invalid",
        )

    def test_signed_permit_round_trip_is_canonical(self) -> None:
        import tempfile
        from pathlib import Path
        from webguard_api import ScanJobStore

        with tempfile.TemporaryDirectory() as directory:
            store = ScanJobStore(Path(directory) / "jobs.sqlite3")
            record = create_trustscan_permit(store)
            loaded = load_signed_trustscan_permit_json(record.permit.to_json())
            self.assertEqual(loaded, record.permit)
            self.assertEqual(loaded.to_json(), record.permit.to_json())

    def test_signed_document_rejects_fingerprint_tampering(self) -> None:
        import tempfile
        from pathlib import Path
        from webguard_api import ScanJobStore

        with tempfile.TemporaryDirectory() as directory:
            store = ScanJobStore(Path(directory) / "jobs.sqlite3")
            record = create_trustscan_permit(store)
            payload = record.permit.to_dict()
            payload["permit_sha256"] = "0" * 64
            with self.assertRaises(TrustScanPermitLoadError) as caught:
                load_signed_trustscan_permit_json(json.dumps(payload))
            self.assertEqual(
                caught.exception.code,
                "trustscan_permit_fingerprint_mismatch",
            )


if __name__ == "__main__":
    unittest.main()
