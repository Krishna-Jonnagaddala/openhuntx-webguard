"""Tests for passive CORS response-header analysis."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from webguard_contracts import Confidence, Severity

from webguard_scanner import (
    CorsAnalysisError,
    SafeHttpResponse,
    ValidatedTarget,
    analyze_cors,
)


def target() -> ValidatedTarget:
    return ValidatedTarget(
        original_url="https://example.com/api",
        normalised_url="https://example.com/api",
        scheme="https",
        hostname="example.com",
        port=443,
        resolved_addresses=("93.184.216.34",),
    )


def response(*headers: tuple[str, str]) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=tuple(headers),
        body=b"{}",
        connected_address="93.184.216.34",
        elapsed_milliseconds=5,
    )


class CorsAnalyzerTests(unittest.TestCase):
    """Verify bounded passive CORS findings and limitations."""

    def test_no_cors_headers_produces_no_findings(self) -> None:
        self.assertEqual(analyze_cors(target(), response()), ())

    def test_wildcard_origin_is_reported(self) -> None:
        findings = analyze_cors(
            target(),
            response(("Access-Control-Allow-Origin", "*")),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cors.allow_origin.wildcard",
        )
        self.assertIs(findings[0].severity, Severity.LOW)

    def test_wildcard_with_credentials_is_reported_as_invalid(self) -> None:
        findings = analyze_cors(
            target(),
            response(
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ),
        )

        self.assertEqual(
            {item.identity.rule_id for item in findings},
            {"web.cors.credentials.wildcard_origin"},
        )
        self.assertIs(findings[0].severity, Severity.MEDIUM)

    def test_null_origin_is_reported(self) -> None:
        findings = analyze_cors(
            target(),
            response(("Access-Control-Allow-Origin", "null")),
        )

        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cors.allow_origin.null",
        )

    def test_credentialed_null_origin_is_reported(self) -> None:
        findings = analyze_cors(
            target(),
            response(
                ("Access-Control-Allow-Origin", "null"),
                ("Access-Control-Allow-Credentials", "true"),
            ),
        )

        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cors.credentials.null_origin",
        )
        self.assertIs(findings[0].severity, Severity.MEDIUM)

    def test_multiple_allow_origin_fields_are_invalid(self) -> None:
        findings = analyze_cors(
            target(),
            response(
                ("Access-Control-Allow-Origin", "https://one.example"),
                ("Access-Control-Allow-Origin", "https://two.example"),
            ),
        )

        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cors.allow_origin.invalid",
        )

    def test_comma_separated_allow_origin_is_invalid(self) -> None:
        findings = analyze_cors(
            target(),
            response(
                (
                    "Access-Control-Allow-Origin",
                    "https://one.example, https://two.example",
                ),
            ),
        )

        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cors.allow_origin.invalid",
        )

    def test_origin_with_path_is_invalid(self) -> None:
        findings = analyze_cors(
            target(),
            response(
                (
                    "Access-Control-Allow-Origin",
                    "https://trusted.example/path",
                ),
            ),
        )

        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cors.allow_origin.invalid",
        )

    def test_valid_static_origin_does_not_create_a_finding(self) -> None:
        findings = analyze_cors(
            target(),
            response(
                (
                    "Access-Control-Allow-Origin",
                    "https://trusted.example",
                ),
                ("Access-Control-Allow-Credentials", "true"),
            ),
        )

        self.assertEqual(findings, ())

    def test_invalid_credentials_value_is_reported(self) -> None:
        findings = analyze_cors(
            target(),
            response(
                (
                    "Access-Control-Allow-Origin",
                    "https://trusted.example",
                ),
                ("Access-Control-Allow-Credentials", "True"),
            ),
        )

        self.assertIn(
            "web.cors.credentials.invalid",
            {item.identity.rule_id for item in findings},
        )

    def test_credentials_without_origin_are_reported(self) -> None:
        findings = analyze_cors(
            target(),
            response(("Access-Control-Allow-Credentials", "true")),
        )

        self.assertEqual(
            {item.identity.rule_id for item in findings},
            {"web.cors.credentials.without_origin"},
        )

    def test_dynamic_origin_signal_requires_vary_origin(self) -> None:
        reflected_origin = "https://private-tenant.example"
        findings = analyze_cors(
            target(),
            response(
                ("Access-Control-Allow-Origin", reflected_origin),
                ("Vary", "Accept-Encoding, Origin"),
            ),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cors.dynamic_origin.observed",
        )
        self.assertIs(findings[0].confidence, Confidence.MEDIUM)
        serialized = json.dumps(findings[0].to_dict())
        self.assertNotIn(reflected_origin, serialized)

    def test_header_names_are_case_insensitive(self) -> None:
        findings = analyze_cors(
            target(),
            response(("aCcEsS-CoNtRoL-AlLoW-OrIgIn", "*")),
        )

        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cors.allow_origin.wildcard",
        )

    def test_rejects_inconsistent_target_fields(self) -> None:
        inconsistent = replace(target(), hostname="different.example")

        with self.assertRaises(CorsAnalysisError) as context:
            analyze_cors(inconsistent, response())

        self.assertEqual(
            context.exception.code,
            "validated_target_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
