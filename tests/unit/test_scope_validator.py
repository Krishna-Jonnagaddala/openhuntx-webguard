"""Tests for the WebGuard target-scope validator."""

from __future__ import annotations

import unittest
from typing import Iterable

from webguard_scanner import (
    TargetValidationError,
    ValidationMode,
    ValidationPolicy,
    validate_target_url,
)


def resolver_returning(*addresses: str):
    """Create a deterministic DNS resolver for testing."""

    def resolver(_hostname: str, _port: int) -> Iterable[str]:
        return addresses

    return resolver


class ScopeValidatorTests(unittest.TestCase):
    """Test commercial and laboratory scope controls."""

    def setUp(self) -> None:
        self.commercial_policy = ValidationPolicy(
            mode=ValidationMode.COMMERCIAL,
        )

        self.lab_policy = ValidationPolicy(
            mode=ValidationMode.LAB,
            allowed_lab_hosts=frozenset(
                {
                    "127.0.0.1",
                    "localhost",
                    "juice-shop",
                }
            ),
        )

    def assert_validation_error(
        self,
        expected_code: str,
        url: str,
        policy: ValidationPolicy,
        *addresses: str,
    ) -> None:
        with self.assertRaises(TargetValidationError) as context:
            validate_target_url(
                url,
                policy,
                resolver=resolver_returning(*addresses),
            )

        self.assertEqual(context.exception.code, expected_code)

    def test_accepts_public_https_target(self) -> None:
        target = validate_target_url(
            "HTTPS://Example.COM.:443/application",
            self.commercial_policy,
            resolver=resolver_returning("93.184.216.34"),
        )

        self.assertEqual(
            target.normalised_url,
            "https://example.com/application",
        )
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.resolved_addresses, ("93.184.216.34",))

    def test_preserves_non_default_port(self) -> None:
        target = validate_target_url(
            "https://example.com:8443/",
            self.commercial_policy,
            resolver=resolver_returning("93.184.216.34"),
        )

        self.assertEqual(
            target.normalised_url,
            "https://example.com:8443/",
        )

    def test_rejects_loopback_in_commercial_mode(self) -> None:
        self.assert_validation_error(
            "non_public_address",
            "http://127.0.0.1:3000/",
            self.commercial_policy,
            "127.0.0.1",
        )

    def test_rejects_private_address_in_commercial_mode(self) -> None:
        self.assert_validation_error(
            "non_public_address",
            "https://internal.example/",
            self.commercial_policy,
            "10.20.30.40",
        )

    def test_rejects_cloud_metadata_address(self) -> None:
        self.assert_validation_error(
            "non_public_address",
            "http://metadata.example/",
            self.commercial_policy,
            "169.254.169.254",
        )

    def test_rejects_mixed_public_and_private_dns_results(self) -> None:
        self.assert_validation_error(
            "non_public_address",
            "https://mixed.example/",
            self.commercial_policy,
            "93.184.216.34",
            "192.168.1.20",
        )

    def test_rejects_ipv4_mapped_loopback(self) -> None:
        self.assert_validation_error(
            "non_public_address",
            "https://mapped.example/",
            self.commercial_policy,
            "::ffff:127.0.0.1",
        )

    def test_rejects_unsupported_scheme(self) -> None:
        self.assert_validation_error(
            "scheme_not_allowed",
            "ftp://example.com/",
            self.commercial_policy,
            "93.184.216.34",
        )

    def test_rejects_embedded_credentials(self) -> None:
        self.assert_validation_error(
            "credentials_not_allowed",
            "https://admin:password@example.com/",
            self.commercial_policy,
            "93.184.216.34",
        )

    def test_rejects_query_string(self) -> None:
        self.assert_validation_error(
            "query_not_allowed",
            "https://example.com/?user=1",
            self.commercial_policy,
            "93.184.216.34",
        )

    def test_rejects_fragment(self) -> None:
        self.assert_validation_error(
            "fragment_not_allowed",
            "https://example.com/#account",
            self.commercial_policy,
            "93.184.216.34",
        )

    def test_accepts_allowlisted_loopback_lab_target(self) -> None:
        target = validate_target_url(
            "http://127.0.0.1:3000/",
            self.lab_policy,
            resolver=resolver_returning("127.0.0.1"),
        )

        self.assertEqual(
            target.normalised_url,
            "http://127.0.0.1:3000/",
        )

    def test_accepts_allowlisted_private_docker_target(self) -> None:
        target = validate_target_url(
            "http://juice-shop:3000/",
            self.lab_policy,
            resolver=resolver_returning("172.20.0.3"),
        )

        self.assertEqual(target.hostname, "juice-shop")
        self.assertEqual(target.resolved_addresses, ("172.20.0.3",))

    def test_rejects_unallowlisted_lab_hostname(self) -> None:
        self.assert_validation_error(
            "lab_host_not_allowed",
            "http://unknown-service:3000/",
            self.lab_policy,
            "172.20.0.4",
        )

    def test_rejects_public_address_in_lab_mode(self) -> None:
        self.assert_validation_error(
            "public_lab_address",
            "http://juice-shop:3000/",
            self.lab_policy,
            "93.184.216.34",
        )

    def test_rejects_empty_lab_allowlist(self) -> None:
        policy = ValidationPolicy(mode=ValidationMode.LAB)

        self.assert_validation_error(
            "lab_allowlist_empty",
            "http://juice-shop:3000/",
            policy,
            "172.20.0.3",
        )

    def test_rejects_empty_dns_result(self) -> None:
        self.assert_validation_error(
            "dns_no_addresses",
            "https://example.com/",
            self.commercial_policy,
        )

    def test_rejects_invalid_port(self) -> None:
        self.assert_validation_error(
            "port_invalid",
            "https://example.com:99999/",
            self.commercial_policy,
            "93.184.216.34",
        )

    def test_rejects_backslash_ambiguity(self) -> None:
        self.assert_validation_error(
            "backslash_not_allowed",
            r"https:\\example.com\account",
            self.commercial_policy,
            "93.184.216.34",
        )


if __name__ == "__main__":
    unittest.main()
