"""Tests for passive information-disclosure header analysis."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from webguard_contracts import Severity

from webguard_scanner import (
    DisclosureAnalysisError,
    SafeHttpResponse,
    ValidatedTarget,
    analyze_information_disclosure,
)


def target() -> ValidatedTarget:
    return ValidatedTarget(
        original_url="https://example.com/",
        normalised_url="https://example.com/",
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
        body=b"",
        connected_address="93.184.216.34",
        elapsed_milliseconds=5,
    )


class DisclosureAnalyzerTests(unittest.TestCase):
    """Verify disclosure findings and value redaction."""

    def test_no_disclosure_headers_produces_no_findings(self) -> None:
        self.assertEqual(
            analyze_information_disclosure(target(), response()),
            (),
        )

    def test_server_version_is_reported(self) -> None:
        findings = analyze_information_disclosure(
            target(),
            response(("Server", "nginx/1.25.4")),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.disclosure.server.version",
        )
        self.assertIs(findings[0].severity, Severity.LOW)

    def test_generic_server_value_is_not_reported(self) -> None:
        findings = analyze_information_disclosure(
            target(),
            response(("Server", "webserver")),
        )

        self.assertEqual(findings, ())

    def test_powered_by_value_is_never_retained(self) -> None:
        secret_value = "InternalFramework/9.8.7 tenant-alpha"
        findings = analyze_information_disclosure(
            target(),
            response(("X-Powered-By", secret_value)),
        )

        self.assertEqual(
            findings[0].identity.rule_id,
            "web.disclosure.powered_by.present",
        )
        self.assertNotIn(
            secret_value,
            json.dumps(findings[0].to_dict()),
        )

    def test_aspnet_headers_produce_distinct_findings(self) -> None:
        findings = analyze_information_disclosure(
            target(),
            response(
                ("X-AspNet-Version", "4.0.30319"),
                ("X-AspNetMvc-Version", "5.2"),
            ),
        )

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {item.identity.parameter for item in findings},
            {
                "header:x-aspnet-version",
                "header:x-aspnetmvc-version",
            },
        )
        self.assertEqual(
            len({item.fingerprint for item in findings}),
            2,
        )

    def test_generator_and_via_headers_are_reported(self) -> None:
        findings = analyze_information_disclosure(
            target(),
            response(
                ("X-Generator", "ExampleCMS 4.2"),
                ("Via", "1.1 internal-proxy"),
            ),
        )

        self.assertEqual(
            {item.identity.rule_id for item in findings},
            {
                "web.disclosure.generator.present",
                "web.disclosure.via.present",
            },
        )

    def test_framework_header_value_is_not_retained(self) -> None:
        internal_value = "backend-07.private.example"
        findings = analyze_information_disclosure(
            target(),
            response(("X-Backend-Server", internal_value)),
        )

        self.assertEqual(
            findings[0].identity.rule_id,
            "web.disclosure.framework_header.present",
        )
        self.assertNotIn(
            internal_value,
            json.dumps(findings[0].to_dict()),
        )

    def test_header_names_are_case_insensitive(self) -> None:
        findings = analyze_information_disclosure(
            target(),
            response(("x-pOwErEd-bY", "Example/1.2")),
        )

        self.assertEqual(
            findings[0].identity.parameter,
            "header:x-powered-by",
        )

    def test_rejects_inconsistent_target_fields(self) -> None:
        inconsistent = replace(target(), hostname="different.example")

        with self.assertRaises(DisclosureAnalysisError) as context:
            analyze_information_disclosure(inconsistent, response())

        self.assertEqual(
            context.exception.code,
            "validated_target_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
