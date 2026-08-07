from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webguard_api import (
    ScanJobStore,
    TrustScanRuntimeSafetyEngine,
    TrustScanRuntimeSafetyError,
)
from webguard_scanner import SafeHttpResponse, ValidatedTarget

from tests.unit.service_test_support import (
    NOW,
    ORG_ID,
    TARGET,
    create_trustscan_permit,
    trustscan_signer,
)


JOB_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SCAN_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def target(url: str = TARGET) -> ValidatedTarget:
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme=parsed.scheme,
        hostname=parsed.hostname or "",
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        resolved_addresses=("204.69.207.1",),
    )


def response(status: int = 200) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=status,
        reason="test",
        headers=(),
        body=b"",
        connected_address="204.69.207.1",
        elapsed_milliseconds=5,
    )


class TrustScanRuntimeSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ScanJobStore(Path(self.temporary.name) / "jobs.sqlite3")
        self.signer = trustscan_signer(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def engine(self, **permit_changes):
        permit = create_trustscan_permit(self.store, **permit_changes)
        revalidations: list[None] = []
        monotonic_values = iter([0.0, 2.0, 4.0, 6.0, 8.0, 10.0])
        engine = TrustScanRuntimeSafetyEngine(
            permit=permit,
            signer=self.signer,
            organization_id=ORG_ID,
            job_id=JOB_ID,
            scan_id=SCAN_ID,
            target=TARGET,
            revalidate=lambda: revalidations.append(None),
            clock=lambda: NOW,
            monotonic=lambda: next(monotonic_values),
            sleeper=lambda _seconds: None,
        )
        return engine, revalidations

    def test_request_is_revalidated_immediately_before_permission(self) -> None:
        engine, revalidations = self.engine()
        engine.before_request(target(), "GET")
        engine.after_request(target(), "GET", response(), None)
        self.assertEqual(len(revalidations), 1)
        self.assertEqual(engine.requests_attempted, 1)
        self.assertEqual(engine.requests_permitted, 1)
        self.assertEqual(engine.peak_concurrency, 1)

    def test_disallowed_method_is_blocked_before_revalidation(self) -> None:
        engine, revalidations = self.engine()
        with self.assertRaises(TrustScanRuntimeSafetyError) as caught:
            engine.before_request(target(), "POST")
        self.assertEqual(caught.exception.code, "trustscan_runtime_method_not_allowed")
        self.assertEqual(engine.requests_permitted, 0)
        self.assertEqual(engine.requests_blocked, 1)
        self.assertEqual(revalidations, [])

    def test_cross_origin_request_is_blocked_before_network(self) -> None:
        engine, _ = self.engine()
        with self.assertRaises(TrustScanRuntimeSafetyError) as caught:
            engine.before_request(target("https://other.example/"), "GET")
        self.assertEqual(caught.exception.code, "trustscan_runtime_scope_violation")
        self.assertEqual(engine.scope_violations, 1)
        self.assertEqual(engine.requests_permitted, 0)

    def test_rate_limit_throttles_and_revalidates_after_wait(self) -> None:
        permit = create_trustscan_permit(
            self.store,
            maximum_requests_per_second=1.0,
        )
        revalidations: list[None] = []
        sleeps: list[float] = []
        monotonic_values = iter([0.0, 0.25, 1.0])
        engine = TrustScanRuntimeSafetyEngine(
            permit=permit,
            signer=self.signer,
            organization_id=ORG_ID,
            job_id=JOB_ID,
            scan_id=SCAN_ID,
            target=TARGET,
            revalidate=lambda: revalidations.append(None),
            clock=lambda: NOW,
            monotonic=lambda: next(monotonic_values),
            sleeper=sleeps.append,
        )
        engine.before_request(target(), "GET")
        engine.after_request(target(), "GET", response(), None)
        engine.before_request(target(), "GET")
        self.assertEqual(sleeps, [0.75])
        self.assertEqual(len(revalidations), 3)
        self.assertEqual(engine.throttles, 1)
        self.assertAlmostEqual(engine.throttle_seconds, 0.75)

    def test_request_attempt_budget_is_enforced(self) -> None:
        engine, _ = self.engine(maximum_request_attempts=1)
        engine.before_request(target(), "GET")
        engine.after_request(target(), "GET", response(), None)
        with self.assertRaises(TrustScanRuntimeSafetyError) as caught:
            engine.before_request(target(), "GET")
        self.assertEqual(
            caught.exception.code,
            "trustscan_runtime_request_budget_exhausted",
        )
        self.assertEqual(engine.requests_permitted, 1)
        self.assertEqual(engine.requests_blocked, 1)

    def test_circuit_breaker_blocks_request_after_three_protective_events(self) -> None:
        engine, _ = self.engine()
        for _ in range(3):
            engine.before_request(target(), "GET")
            engine.after_request(target(), "GET", response(500), None)
        self.assertEqual(engine.responses_5xx, 3)
        self.assertEqual(engine.circuit_breaker_activations, 1)
        with self.assertRaises(TrustScanRuntimeSafetyError) as caught:
            engine.before_request(target(), "GET")
        self.assertEqual(caught.exception.code, "trustscan_runtime_circuit_open")
        self.assertEqual(engine.requests_blocked, 1)

    def test_signed_receipt_records_observed_runtime_facts(self) -> None:
        engine, _ = self.engine()
        engine.before_request(target(), "GET")
        engine.after_request(target(), "GET", response(429), None)
        receipt = engine.signed_receipt(termination_reason="completed")
        self.signer.verify_safety_receipt(receipt)
        claims = receipt.claims
        self.assertEqual(claims.requests_attempted, 1)
        self.assertEqual(claims.requests_permitted, 1)
        self.assertEqual(claims.responses_429, 1)
        self.assertEqual(claims.permit_revalidations, 1)
        self.assertTrue(claims.safety_policy_respected)


if __name__ == "__main__":
    unittest.main()
