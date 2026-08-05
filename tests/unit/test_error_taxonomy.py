"""Tests for the controlled scanner error taxonomy."""

from __future__ import annotations

import ast
import inspect
import unittest
from pathlib import Path

import webguard_scanner.header_analyzer as header_analyzer_module
import webguard_scanner.safe_http as safe_http_module
import webguard_scanner.tls_analyzer as tls_analyzer_module

from webguard_scanner import (
    ErrorCategory,
    classify_error,
    is_retryable_error,
    known_error_codes,
)


def _literal_error_codes(
    module: object,
    exception_name: str,
) -> set[str]:
    source_path = Path(
        inspect.getsourcefile(module) or ""
    )
    tree = ast.parse(
        source_path.read_text(encoding="utf-8")
    )

    codes: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == exception_name
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            continue

        codes.add(node.args[0].value)

    return codes


class ErrorTaxonomyTests(unittest.TestCase):
    """Verify reviewed retry classifications fail closed."""

    def test_transient_network_errors_are_retryable(
        self,
    ) -> None:
        for code in (
            "connection_timeout",
            "connection_refused",
            "connection_interrupted",
            "network_unreachable",
            "connection_failed",
        ):
            with self.subTest(code=code):
                policy = classify_error(
                    stage="request",
                    code=code,
                )

                self.assertIs(
                    policy.category,
                    ErrorCategory.NETWORK_TRANSIENT,
                )
                self.assertTrue(policy.retryable)

    def test_tls_errors_are_not_retryable(
        self,
    ) -> None:
        for code in (
            "tls_certificate_invalid",
            "tls_handshake_failed",
            "tls_context_insecure",
            "tls_metadata_unavailable",
            "tls_certificate_metadata_invalid",
            "tls_certificate_metadata_too_large",
        ):
            with self.subTest(code=code):
                policy = classify_error(
                    stage="request",
                    code=code,
                )

                self.assertIs(
                    policy.category,
                    ErrorCategory.TLS,
                )
                self.assertFalse(policy.retryable)

    def test_response_policy_and_limit_errors_are_not_retryable(
        self,
    ) -> None:
        expectations = {
            "redirect_blocked": ErrorCategory.RESPONSE_POLICY,
            "response_body_too_large": ErrorCategory.RESPONSE_LIMIT,
            "response_headers_too_many": ErrorCategory.RESPONSE_LIMIT,
            "response_headers_too_large": ErrorCategory.RESPONSE_LIMIT,
            "content_length_invalid": ErrorCategory.RESPONSE_FORMAT,
            "content_length_ambiguous": ErrorCategory.RESPONSE_FORMAT,
        }

        for code, category in expectations.items():
            with self.subTest(code=code):
                policy = classify_error(
                    stage="request",
                    code=code,
                )

                self.assertIs(policy.category, category)
                self.assertFalse(policy.retryable)

    def test_analysis_errors_are_not_retryable(
        self,
    ) -> None:
        policy = classify_error(
            stage="analysis",
            code="validated_target_mismatch",
        )

        self.assertIs(
            policy.category,
            ErrorCategory.ANALYSIS,
        )
        self.assertFalse(policy.retryable)

    def test_unknown_errors_fail_closed(
        self,
    ) -> None:
        policy = classify_error(
            stage="request",
            code="future_unreviewed_error",
        )

        self.assertIs(
            policy.category,
            ErrorCategory.UNKNOWN,
        )
        self.assertFalse(policy.retryable)
        self.assertFalse(
            is_retryable_error(
                stage="future-stage",
                code="connection_timeout",
            )
        )

    def test_all_literal_request_errors_have_reviewed_policy(
        self,
    ) -> None:
        emitted_codes = _literal_error_codes(
            safe_http_module,
            "SafeRequestError",
        )
        reviewed_codes = set(
            known_error_codes(stage="request")
        )

        self.assertEqual(
            emitted_codes - reviewed_codes,
            set(),
        )

    def test_all_literal_analysis_errors_have_reviewed_policy(
        self,
    ) -> None:
        emitted_codes = _literal_error_codes(
            header_analyzer_module,
            "HeaderAnalysisError",
        )
        reviewed_codes = set(
            known_error_codes(stage="analysis")
        )

        self.assertEqual(
            emitted_codes - reviewed_codes,
            set(),
        )
        tls_emitted_codes = _literal_error_codes(
            tls_analyzer_module,
            "TlsAnalysisError",
        )
        self.assertEqual(
            tls_emitted_codes - reviewed_codes,
            set(),
        )


if __name__ == "__main__":
    unittest.main()
