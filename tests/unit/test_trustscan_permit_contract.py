from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import timedelta

from webguard_contracts import (
    MAXIMUM_MISSING_AUTHENTICATION_ENDPOINTS,
    MissingAuthenticationEndpoint,
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
        "authentication_context_id": None,
        "authorization_comparison_plan_id": None,
        "missing_authentication_endpoints": [],
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
        # POST is a permit-issuable method as of Slice 6 (request-template
        # and mutation-engine work) -- see TRUSTSCAN_ALLOWED_HTTP_METHODS
        # and docs/audit/active-detection-phase6-request-mutation.md. DELETE
        # remains outside the vocabulary entirely, so it still exercises
        # this rejection path.
        with self.assertRaises(TrustScanPermitLoadError) as caught:
            load_trustscan_permit_submission_json(
                submission(allowed_http_methods=["DELETE", "GET"])
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_methods_invalid")

    def test_submission_accepts_post_as_an_issuable_method(self) -> None:
        value = load_trustscan_permit_submission_json(
            submission(allowed_http_methods=["GET", "HEAD", "POST"])
        )
        self.assertEqual(value.allowed_http_methods, ("GET", "HEAD", "POST"))

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


def _claims(**overrides) -> TrustScanPermitClaims:
    auth = authorization()
    values = {
        "permit_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "organization_id": ORG_ID,
        "authorization_id": AUTH_ID,
        "authorization_sha256": auth.fingerprint,
        "target": TARGET,
        "issued_by": OWNER_ID,
        "issued_at": NOW,
        "not_before": NOW,
        "expires_at": NOW + timedelta(days=7),
        "permitted_modes": (ScanJobMode.SINGLE_PAGE,),
        "allowed_http_methods": ("GET",),
        "maximum_request_attempts": 15,
        "maximum_requests_per_second": 1.0,
    }
    values.update(overrides)
    return TrustScanPermitClaims(**values)


class MissingAuthenticationEndpointTests(unittest.TestCase):
    """Slice 17 (CWE-306): the MissingAuthenticationEndpoint claim entry
    itself, and the bidirectional rule binding it to active_checks and
    authentication_context_id."""

    def test_to_dict_from_dict_round_trip(self) -> None:
        entry = MissingAuthenticationEndpoint(
            endpoint="https://example.com/admin/dashboard",
            owner_marker="internal-only-marker",
        )
        restored = MissingAuthenticationEndpoint.from_dict(entry.to_dict())
        self.assertEqual(entry, restored)
        self.assertEqual(restored.method, "GET")

    def test_owner_marker_defaults_to_empty_string(self) -> None:
        entry = MissingAuthenticationEndpoint(endpoint="https://example.com/x")
        self.assertEqual(entry.owner_marker, "")

    def test_empty_endpoint_is_rejected(self) -> None:
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            MissingAuthenticationEndpoint(endpoint="   ")
        self.assertEqual(
            caught.exception.code, "trustscan_permit_missing_auth_endpoint_invalid"
        )

    def test_non_get_method_is_rejected(self) -> None:
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            MissingAuthenticationEndpoint(
                endpoint="https://example.com/x", method="POST"
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_missing_auth_endpoint_method_invalid",
        )

    def test_method_is_case_normalized_to_upper(self) -> None:
        entry = MissingAuthenticationEndpoint(
            endpoint="https://example.com/x", method="get"
        )
        self.assertEqual(entry.method, "GET")

    def test_from_dict_rejects_non_mapping(self) -> None:
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            MissingAuthenticationEndpoint.from_dict("not-a-mapping")
        self.assertEqual(
            caught.exception.code, "trustscan_permit_missing_auth_endpoint_invalid"
        )

    def test_from_dict_requires_endpoint_key(self) -> None:
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            MissingAuthenticationEndpoint.from_dict({"owner_marker": "x"})
        self.assertEqual(
            caught.exception.code, "trustscan_permit_missing_auth_endpoint_invalid"
        )

    def test_more_than_maximum_endpoints_is_rejected(self) -> None:
        endpoints = tuple(
            MissingAuthenticationEndpoint(endpoint=f"https://example.com/{i}")
            for i in range(MAXIMUM_MISSING_AUTHENTICATION_ENDPOINTS + 1)
        )
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            _claims(
                active_checks=("active.authentication.missing",),
                authentication_context_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                missing_authentication_endpoints=endpoints,
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_missing_auth_endpoints_too_many",
        )

    def test_exactly_maximum_endpoints_is_accepted(self) -> None:
        endpoints = tuple(
            MissingAuthenticationEndpoint(endpoint=f"https://example.com/{i}")
            for i in range(MAXIMUM_MISSING_AUTHENTICATION_ENDPOINTS)
        )
        claims = _claims(
            active_checks=("active.authentication.missing",),
            authentication_context_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            missing_authentication_endpoints=endpoints,
        )
        self.assertEqual(len(claims.missing_authentication_endpoints), 10)

    def test_endpoints_without_the_check_in_active_checks_is_rejected(self) -> None:
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            _claims(
                active_checks=(),
                authentication_context_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                missing_authentication_endpoints=(
                    MissingAuthenticationEndpoint(endpoint="https://example.com/x"),
                ),
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_missing_auth_endpoints_without_check",
        )

    def test_check_without_any_endpoints_is_rejected(self) -> None:
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            _claims(
                active_checks=("active.authentication.missing",),
                authentication_context_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                missing_authentication_endpoints=(),
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_missing_auth_check_without_endpoints",
        )

    def test_check_without_authentication_context_is_rejected(self) -> None:
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            _claims(
                active_checks=("active.authentication.missing",),
                authentication_context_id=None,
                missing_authentication_endpoints=(
                    MissingAuthenticationEndpoint(endpoint="https://example.com/x"),
                ),
            )
        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_missing_auth_check_without_context",
        )

    def test_valid_combination_is_accepted(self) -> None:
        claims = _claims(
            active_checks=("active.authentication.missing",),
            authentication_context_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            missing_authentication_endpoints=(
                MissingAuthenticationEndpoint(
                    endpoint="https://example.com/admin",
                    owner_marker="marker",
                ),
            ),
        )
        self.assertEqual(len(claims.missing_authentication_endpoints), 1)
        self.assertEqual(
            claims.missing_authentication_endpoints[0].endpoint,
            "https://example.com/admin",
        )

    def test_no_check_and_no_endpoints_is_accepted(self) -> None:
        claims = _claims()
        self.assertEqual(claims.missing_authentication_endpoints, ())

    def test_claims_to_dict_includes_missing_authentication_endpoints(self) -> None:
        claims = _claims(
            active_checks=("active.authentication.missing",),
            authentication_context_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            missing_authentication_endpoints=(
                MissingAuthenticationEndpoint(endpoint="https://example.com/admin"),
            ),
        )
        payload = claims.to_dict()
        self.assertEqual(
            payload["missing_authentication_endpoints"],
            [{"endpoint": "https://example.com/admin", "method": "GET", "owner_marker": ""}],
        )

    def test_submission_json_round_trips_missing_authentication_endpoints(self) -> None:
        value = load_trustscan_permit_submission_json(
            submission(
                active_checks=["active.authentication.missing"],
                authentication_context_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                missing_authentication_endpoints=[
                    {
                        "endpoint": "https://example.com/admin",
                        "method": "GET",
                        "owner_marker": "internal-marker",
                    }
                ],
            )
        )
        self.assertEqual(len(value.missing_authentication_endpoints), 1)
        entry = value.missing_authentication_endpoints[0]
        self.assertEqual(entry.endpoint, "https://example.com/admin")
        self.assertEqual(entry.owner_marker, "internal-marker")

    def test_a_fingerprint_changes_when_endpoints_change(self) -> None:
        base = _claims(
            active_checks=("active.authentication.missing",),
            authentication_context_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            missing_authentication_endpoints=(
                MissingAuthenticationEndpoint(endpoint="https://example.com/admin"),
            ),
        )
        tampered = replace(
            base,
            missing_authentication_endpoints=(
                MissingAuthenticationEndpoint(endpoint="https://example.com/other"),
            ),
        )
        self.assertNotEqual(base.fingerprint, tampered.fingerprint)


if __name__ == "__main__":
    unittest.main()
