from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import timedelta

from webguard_contracts import (
    TrustScanSafetyReceiptClaims,
    TrustScanSafetyReceiptError,
    load_signed_trustscan_safety_receipt_json,
)

from tests.unit.service_test_support import NOW, ORG_ID, TARGET


RECEIPT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PERMIT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
JOB_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
SCAN_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"


def claims(**changes) -> TrustScanSafetyReceiptClaims:
    values = dict(
        receipt_id=RECEIPT_ID,
        permit_id=PERMIT_ID,
        permit_sha256="a" * 64,
        organization_id=ORG_ID,
        job_id=JOB_ID,
        scan_id=SCAN_ID,
        target=TARGET,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
        maximum_request_attempts=15,
        maximum_requests_per_second=1.0,
        maximum_concurrency=1,
        requests_attempted=2,
        requests_permitted=2,
        requests_blocked=0,
        responses_429=0,
        responses_5xx=0,
        request_errors=0,
        throttles=1,
        throttle_seconds=1.0,
        circuit_breaker_activations=0,
        scope_violations=0,
        permit_revalidations=3,
        peak_concurrency=1,
        termination_reason="completed",
        safety_policy_respected=True,
    )
    values.update(changes)
    return TrustScanSafetyReceiptClaims(**values)


class TrustScanSafetyReceiptContractTests(unittest.TestCase):
    def test_claims_json_is_deterministic(self) -> None:
        first = claims()
        second = claims()
        self.assertEqual(first.signing_bytes, second.signing_bytes)
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_rejects_permitted_count_above_attempted_count(self) -> None:
        with self.assertRaises(TrustScanSafetyReceiptError) as caught:
            claims(requests_attempted=1, requests_permitted=2)
        self.assertEqual(
            caught.exception.code,
            "trustscan_safety_receipt_request_counts_invalid",
        )

    def test_rejects_peak_concurrency_above_permit_limit(self) -> None:
        with self.assertRaises(TrustScanSafetyReceiptError) as caught:
            claims(peak_concurrency=2)
        self.assertEqual(
            caught.exception.code,
            "trustscan_safety_receipt_concurrency_invalid",
        )

    def test_rejects_noncanonical_timestamp_when_loading(self) -> None:
        from webguard_api import TrustScanSigner

        signer = TrustScanSigner(bytes(range(32)))
        receipt = signer.sign_safety_receipt(claims())
        document = json.loads(receipt.to_json())
        document["claims"]["started_at"] = "2026-08-06T18:00:00Z"
        with self.assertRaises(TrustScanSafetyReceiptError) as caught:
            load_signed_trustscan_safety_receipt_json(
                json.dumps(document, sort_keys=True, separators=(",", ":"))
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_safety_receipt_timestamp_non_canonical",
        )

    def test_signed_receipt_round_trip_is_strict_and_canonical(self) -> None:
        from webguard_api import TrustScanSigner

        signer = TrustScanSigner(bytes(range(32)))
        receipt = signer.sign_safety_receipt(claims())
        loaded = load_signed_trustscan_safety_receipt_json(receipt.to_json())
        self.assertEqual(loaded, receipt)
        signer.verify_safety_receipt(loaded)

    def test_changed_claims_fail_signature_verification(self) -> None:
        from webguard_api import TrustScanPermitError, TrustScanSigner

        signer = TrustScanSigner(bytes(range(32)))
        receipt = signer.sign_safety_receipt(claims())
        changed = replace(
            receipt,
            claims=replace(receipt.claims, requests_attempted=3),
        )
        with self.assertRaises(TrustScanPermitError) as caught:
            signer.verify_safety_receipt(changed)
        self.assertEqual(
            caught.exception.code,
            "trustscan_safety_receipt_signature_invalid",
        )


if __name__ == "__main__":
    unittest.main()
