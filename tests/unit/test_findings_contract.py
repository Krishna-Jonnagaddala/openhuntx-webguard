"""Tests for the shared normalized finding contract."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime

from webguard_contracts import (
    Confidence,
    ContractValidationError,
    Evidence,
    ExternalIdentifier,
    FindingIdentity,
    NormalizedFinding,
    Severity,
)


def make_finding(**changes) -> NormalizedFinding:
    """Create a valid finding that individual tests can modify."""

    values = {
        "identity": FindingIdentity(
            rule_id="web.headers.hsts.missing",
            asset="HTTPS://Example.COM.:443/",
            path="/login",
            method="get",
        ),
        "source": "webguard-passive",
        "source_rule_id": "HSTS-001",
        "title": "Strict-Transport-Security header missing",
        "description": (
            "The HTTPS response does not include the "
            "Strict-Transport-Security header."
        ),
        "severity": Severity.MEDIUM,
        "confidence": Confidence.CONFIRMED,
        "remediation": (
            "Add an appropriate Strict-Transport-Security header "
            "after confirming the entire site supports HTTPS."
        ),
        "identifiers": (
            ExternalIdentifier("CWE", "CWE-319"),
            ExternalIdentifier("CWE", "CWE-319"),
        ),
        "evidence": (
            Evidence(
                "Response headers did not contain "
                "Strict-Transport-Security."
            ),
        ),
        "references": (
            "https://owasp.org/",
            "https://owasp.org/",
        ),
        "tags": (
            "Headers",
            "headers",
            "transport-security",
        ),
    }

    values.update(changes)

    return NormalizedFinding(**values)


class FindingContractTests(unittest.TestCase):
    """Verify contract validation and deterministic identity."""

    def test_normalises_identity_and_collections(self) -> None:
        finding = make_finding()

        self.assertEqual(
            finding.identity.asset,
            "https://example.com",
        )
        self.assertEqual(
            finding.identity.method,
            "GET",
        )
        self.assertEqual(
            len(finding.identifiers),
            1,
        )
        self.assertEqual(
            finding.tags,
            (
                "headers",
                "transport-security",
            ),
        )
        self.assertEqual(
            finding.references,
            ("https://owasp.org/",),
        )

    def test_fingerprint_ignores_presentation_changes(self) -> None:
        first = make_finding()

        second = make_finding(
            title="Updated title",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=(
                Evidence("Different evidence summary."),
            ),
        )

        self.assertEqual(
            first.fingerprint,
            second.fingerprint,
        )

    def test_fingerprint_changes_with_location(self) -> None:
        first = make_finding()

        second = make_finding(
            identity=replace(
                first.identity,
                path="/admin",
            ),
        )

        self.assertNotEqual(
            first.fingerprint,
            second.fingerprint,
        )

    def test_fingerprint_is_sha256_hex(self) -> None:
        fingerprint = make_finding().fingerprint

        self.assertEqual(
            len(fingerprint),
            64,
        )

        self.assertTrue(
            all(
                character in "0123456789abcdef"
                for character in fingerprint
            )
        )

    def test_json_is_deterministic_and_parseable(self) -> None:
        finding = make_finding()

        first = finding.to_json()
        second = finding.to_json()
        decoded = json.loads(first)

        self.assertEqual(first, second)
        self.assertEqual(
            decoded["schema_version"],
            "1.0",
        )
        self.assertEqual(
            decoded["fingerprint"],
            finding.fingerprint,
        )
        self.assertEqual(
            decoded["severity"],
            "medium",
        )

    def test_rejects_naive_datetime(self) -> None:
        with self.assertRaises(
            ContractValidationError
        ) as context:
            make_finding(
                detected_at=datetime(
                    2026,
                    8,
                    3,
                    1,
                    0,
                    0,
                )
            )

        self.assertEqual(
            context.exception.code,
            "detected_at_invalid",
        )

    def test_rejects_asset_with_path(self) -> None:
        with self.assertRaises(
            ContractValidationError
        ) as context:
            FindingIdentity(
                rule_id="web.headers.test",
                asset="https://example.com/login",
            )

        self.assertEqual(
            context.exception.code,
            "asset_invalid",
        )

    def test_rejects_path_with_query(self) -> None:
        with self.assertRaises(
            ContractValidationError
        ) as context:
            FindingIdentity(
                rule_id="web.headers.test",
                asset="https://example.com",
                path="/login?next=/admin",
            )

        self.assertEqual(
            context.exception.code,
            "path_invalid",
        )

    def test_rejects_non_https_reference(self) -> None:
        with self.assertRaises(
            ContractValidationError
        ) as context:
            make_finding(
                references=(
                    "http://example.com/advisory",
                )
            )

        self.assertEqual(
            context.exception.code,
            "reference_invalid",
        )

    def test_rejects_invalid_rule_id(self) -> None:
        with self.assertRaises(
            ContractValidationError
        ) as context:
            FindingIdentity(
                rule_id="Missing HSTS!",
                asset="https://example.com",
            )

        self.assertEqual(
            context.exception.code,
            "rule_id_invalid",
        )


if __name__ == "__main__":
    unittest.main()
