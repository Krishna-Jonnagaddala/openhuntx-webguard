"""Tests for passive Set-Cookie security analysis."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from webguard_contracts import Severity

from webguard_scanner import (
    CookieAnalysisError,
    SafeHttpResponse,
    ValidatedTarget,
    analyze_cookies,
)


def target(
    *,
    scheme: str = "https",
    url: str = "https://example.com/",
    hostname: str = "example.com",
    port: int = 443,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_addresses=("93.184.216.34",),
    )


def response(
    *headers: tuple[str, str],
) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=tuple(headers),
        body=b"<html></html>",
        connected_address="93.184.216.34",
        elapsed_milliseconds=5,
    )


def rules(findings) -> set[str]:
    return {
        item.identity.rule_id
        for item in findings
    }


SECURE_COOKIE = (
    "Set-Cookie",
    "session=secret; Secure; HttpOnly; SameSite=Lax; Path=/",
)


class CookieAnalyzerTests(unittest.TestCase):
    """Verify bounded cookie metadata analysis and value redaction."""

    def test_no_set_cookie_headers_produce_no_findings(self) -> None:
        self.assertEqual(
            analyze_cookies(target(), response()),
            (),
        )

    def test_well_configured_cookie_produces_no_findings(self) -> None:
        self.assertEqual(
            analyze_cookies(
                target(),
                response(SECURE_COOKIE),
            ),
            (),
        )

    def test_missing_secure_is_reported(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; HttpOnly; SameSite=Lax; Path=/",
                )
            ),
        )

        self.assertIn(
            "web.cookies.secure.missing",
            rules(findings),
        )
        secure = next(
            item
            for item in findings
            if item.identity.rule_id
            == "web.cookies.secure.missing"
        )
        self.assertIs(secure.severity, Severity.MEDIUM)

    def test_missing_httponly_is_reported(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; Secure; SameSite=Lax; Path=/",
                )
            ),
        )

        self.assertIn(
            "web.cookies.httponly.missing",
            rules(findings),
        )

    def test_missing_samesite_is_reported(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; Secure; HttpOnly; Path=/",
                )
            ),
        )

        self.assertIn(
            "web.cookies.samesite.missing",
            rules(findings),
        )

    def test_samesite_none_without_secure_is_reported(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; HttpOnly; SameSite=None; Path=/",
                )
            ),
        )

        self.assertIn(
            "web.cookies.secure.missing",
            rules(findings),
        )
        self.assertIn(
            "web.cookies.samesite.none_without_secure",
            rules(findings),
        )

    def test_invalid_samesite_is_reported(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; Secure; HttpOnly; "
                    "SameSite=Sometimes; Path=/",
                )
            ),
        )

        self.assertIn(
            "web.cookies.samesite.invalid",
            rules(findings),
        )

    def test_domain_attribute_broadens_scope(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; Secure; HttpOnly; SameSite=Lax; "
                    "Path=/; Domain=example.com",
                )
            ),
        )

        self.assertIn(
            "web.cookies.domain.broad",
            rules(findings),
        )

    def test_nonmatching_domain_is_reported_as_invalid(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; Secure; HttpOnly; SameSite=Lax; "
                    "Path=/; Domain=other.example",
                )
            ),
        )

        self.assertIn(
            "web.cookies.domain.invalid",
            rules(findings),
        )

    def test_missing_path_is_reported(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; Secure; HttpOnly; SameSite=Lax",
                )
            ),
        )

        self.assertIn(
            "web.cookies.path.missing",
            rules(findings),
        )

    def test_site_wide_path_from_narrow_path_is_reported(self) -> None:
        findings = analyze_cookies(
            target(
                url="https://example.com/account/login",
            ),
            response(SECURE_COOKIE),
        )

        self.assertIn(
            "web.cookies.path.broad",
            rules(findings),
        )

    def test_invalid_path_is_reported(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "session=secret; Secure; HttpOnly; SameSite=Lax; "
                    "Path=account",
                )
            ),
        )

        self.assertIn(
            "web.cookies.path.invalid",
            rules(findings),
        )

    def test_cookie_set_over_http_is_reported(self) -> None:
        findings = analyze_cookies(
            target(
                scheme="http",
                url="http://example.com/",
                port=80,
            ),
            response(SECURE_COOKIE),
        )

        self.assertIn(
            "web.cookies.transport.insecure",
            rules(findings),
        )

    def test_secure_prefix_requirements_are_enforced(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "__sEcUrE-session=secret; HttpOnly; "
                    "SameSite=Lax; Path=/",
                )
            ),
        )

        self.assertIn(
            "web.cookies.prefix_secure.invalid",
            rules(findings),
        )

    def test_host_prefix_requirements_are_enforced(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "__Host-session=secret; Secure; HttpOnly; "
                    "SameSite=Lax; Path=/; Domain=example.com",
                )
            ),
        )

        self.assertIn(
            "web.cookies.prefix_host.invalid",
            rules(findings),
        )

    def test_valid_host_prefixed_cookie_produces_no_findings(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    "__Host-session=secret; Secure; HttpOnly; "
                    "SameSite=Strict; Path=/",
                )
            ),
        )

        self.assertEqual(findings, ())

    def test_attribute_names_are_case_insensitive(self) -> None:
        findings = analyze_cookies(
            target(),
            response(
                (
                    "sEt-CoOkIe",
                    "session=secret; sEcUrE; hTtPoNlY; "
                    "sAmEsItE=Lax; pAtH=/",
                )
            ),
        )

        self.assertEqual(findings, ())

    def test_duplicate_cookie_findings_are_deduplicated(self) -> None:
        insecure = (
            "Set-Cookie",
            "session=one; SameSite=Lax; Path=/",
        )
        findings = analyze_cookies(
            target(),
            response(
                insecure,
                (
                    "Set-Cookie",
                    "session=two; SameSite=Lax; Path=/",
                ),
            ),
        )

        matching = [
            item
            for item in findings
            if item.identity.rule_id
            == "web.cookies.secure.missing"
        ]
        self.assertEqual(len(matching), 1)

    def test_cookie_values_are_never_retained(self) -> None:
        secret = "top-secret-value-123"
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    f"session={secret}; Path=/",
                )
            ),
        )

        serialized = json.dumps(
            [
                item.to_dict()
                for item in findings
            ],
            sort_keys=True,
        )

        self.assertNotIn(secret, serialized)
        self.assertTrue(
            all(
                item.identity.parameter == "cookie:session"
                for item in findings
            )
        )

    def test_malformed_header_is_reported_without_value(self) -> None:
        secret = "top-secret-value-456"
        findings = analyze_cookies(
            target(),
            response(
                (
                    "Set-Cookie",
                    f"not-a-cookie-{secret}",
                )
            ),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.cookies.syntax.malformed",
        )
        self.assertNotIn(
            secret,
            json.dumps(findings[0].to_dict()),
        )

    def test_rejects_inconsistent_target_fields(self) -> None:
        inconsistent = replace(
            target(),
            hostname="different.example",
        )

        with self.assertRaises(
            CookieAnalysisError
        ) as context:
            analyze_cookies(
                inconsistent,
                response(SECURE_COOKIE),
            )

        self.assertEqual(
            context.exception.code,
            "validated_target_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
