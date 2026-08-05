"""Tests for registered passive analyser execution."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from webguard_contracts import (
    Confidence,
    Evidence,
    FindingIdentity,
    NormalizedFinding,
    Severity,
    SkippedCheck,
)

from webguard_scanner import (
    AnalyzerOutputError,
    AnalyzerRegistryError,
    DEFAULT_PASSIVE_ANALYZERS,
    PASSIVE_CHECKS,
    PassiveAnalyzer,
    SafeHttpResponse,
    ValidatedTarget,
    execute_analyzers,
    registered_checks,
    validate_analyzer_registry,
)


NOW = datetime(2026, 8, 3, tzinfo=timezone.utc)


class ControlledAnalysisError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class InvalidControlledError(RuntimeError):
    pass


def target() -> ValidatedTarget:
    return ValidatedTarget(
        original_url="https://example.com/",
        normalised_url="https://example.com/",
        scheme="https",
        hostname="example.com",
        port=443,
        resolved_addresses=("93.184.216.34",),
    )


def response() -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(),
        body=b"",
        connected_address="93.184.216.34",
        elapsed_milliseconds=1,
    )


def finding(
    rule_id: str = "web.test.one.issue",
) -> NormalizedFinding:
    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule_id,
            asset="https://example.com",
            path="/",
            method="GET",
        ),
        source="webguard-passive",
        source_rule_id="TEST-001",
        title="Test finding",
        description="A deterministic test finding.",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        remediation="Apply the test remediation.",
        detected_at=NOW,
        evidence=(Evidence(summary="Test evidence."),),
        tags=("passive", "test"),
    )


def ok_analyzer(_target, _response):
    return ()


def analyzer(
    analyzer_id: str = "one",
    checks: tuple[str, ...] = ("web.test.one",),
    finding_namespace: str = "web.test",
    analyze=ok_analyzer,
    controlled_error: type[Exception] = ControlledAnalysisError,
) -> PassiveAnalyzer:
    return PassiveAnalyzer(
        analyzer_id=analyzer_id,
        checks=checks,
        finding_namespace=finding_namespace,
        analyze=analyze,
        controlled_error=controlled_error,
    )


class PassiveAnalyzerTests(unittest.TestCase):
    def test_canonicalizes_identifier_and_check_order(self) -> None:
        item = analyzer(
            analyzer_id="  One  ",
            checks=("web.test.two", "web.test.one"),
        )

        self.assertEqual(item.analyzer_id, "one")
        self.assertEqual(
            item.checks,
            ("web.test.one", "web.test.two"),
        )

    def test_rejects_invalid_analyzer_id(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            analyzer(analyzer_id="Invalid ID")

        self.assertEqual(
            context.exception.code,
            "analyzer_id_invalid",
        )

    def test_rejects_empty_checks(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            analyzer(checks=())

        self.assertEqual(
            context.exception.code,
            "analyzer_checks_invalid",
        )

    def test_rejects_check_outside_namespace(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            analyzer(checks=("web.other.check",))

        self.assertEqual(
            context.exception.code,
            "analyzer_check_namespace_mismatch",
        )

    def test_rejects_duplicate_checks(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            analyzer(
                checks=("web.test.one", "web.test.one"),
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_check_duplicate",
        )

    def test_rejects_overlapping_checks(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            analyzer(
                checks=("web.test.one", "web.test.one.child"),
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_check_overlap",
        )

    def test_rejects_non_callable_analyze_value(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            analyzer(analyze=None)

        self.assertEqual(
            context.exception.code,
            "analyzer_function_invalid",
        )

    def test_rejects_invalid_controlled_error_type(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            analyzer(controlled_error=str)

        self.assertEqual(
            context.exception.code,
            "analyzer_error_type_invalid",
        )


class AnalyzerRegistryTests(unittest.TestCase):
    def test_default_registry_has_stable_ids_and_complete_ownership(self) -> None:
        self.assertEqual(
            tuple(
                item.analyzer_id
                for item in DEFAULT_PASSIVE_ANALYZERS
            ),
            ("headers", "cookies", "cors", "disclosure", "html"),
        )
        self.assertEqual(
            registered_checks(DEFAULT_PASSIVE_ANALYZERS),
            PASSIVE_CHECKS,
        )
        self.assertEqual(len(PASSIVE_CHECKS), 33)

    def test_rejects_empty_registry(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            validate_analyzer_registry(())

        self.assertEqual(
            context.exception.code,
            "analyzer_registry_empty",
        )

    def test_rejects_duplicate_analyzer_ids(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            validate_analyzer_registry(
                (
                    analyzer("same", ("web.test.one",)),
                    analyzer("same", ("web.test.two",)),
                )
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_id_duplicate",
        )

    def test_rejects_duplicate_check_owners(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            validate_analyzer_registry(
                (
                    analyzer("one"),
                    analyzer("two"),
                )
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_check_owner_duplicate",
        )

    def test_rejects_overlapping_check_owners(self) -> None:
        with self.assertRaises(AnalyzerRegistryError) as context:
            validate_analyzer_registry(
                (
                    analyzer("one", ("web.test.one",)),
                    analyzer(
                        "two",
                        ("web.test.one.child",),
                    ),
                )
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_check_owner_overlap",
        )

    def test_registered_checks_are_canonical(self) -> None:
        checks = registered_checks(
            (
                analyzer("two", ("web.test.two",)),
                analyzer("one", ("web.test.one",)),
            )
        )

        self.assertEqual(
            checks,
            ("web.test.one", "web.test.two"),
        )


class AnalyzerExecutionTests(unittest.TestCase):
    def test_success_records_findings_and_executed_checks(self) -> None:
        item = analyzer(
            analyze=lambda _target, _response: (finding(),),
        )

        result = execute_analyzers(
            target(),
            response(),
            analyzers=(item,),
        )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.errors, ())
        self.assertEqual(
            result.executed_checks,
            ("web.test.one",),
        )
        self.assertEqual(result.skipped_checks, ())

    def test_pre_skipped_check_is_not_executed(self) -> None:
        item = analyzer(
            checks=("web.test.one", "web.test.two"),
        )

        result = execute_analyzers(
            target(),
            response(),
            analyzers=(item,),
            pre_skipped_checks=(
                SkippedCheck(
                    check_id="web.test.one",
                    reason="Not applicable to this target.",
                ),
            ),
        )

        self.assertEqual(
            result.executed_checks,
            ("web.test.two",),
        )
        self.assertEqual(
            tuple(
                skipped.check_id
                for skipped in result.skipped_checks
            ),
            ("web.test.one",),
        )

    def test_controlled_failure_is_isolated_and_pipeline_continues(self) -> None:
        calls: list[str] = []

        def fail(_target, _response):
            calls.append("failed")
            raise ControlledAnalysisError(
                "validated_target_mismatch",
                "Controlled failure.",
            )

        def succeed(_target, _response):
            calls.append("succeeded")
            return (finding("web.test.two.issue"),)

        result = execute_analyzers(
            target(),
            response(),
            analyzers=(
                analyzer("one", ("web.test.one",), analyze=fail),
                analyzer("two", ("web.test.two",), analyze=succeed),
            ),
        )

        self.assertEqual(calls, ["failed", "succeeded"])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].stage, "analysis.one")
        self.assertFalse(result.errors[0].retryable)
        self.assertEqual(
            result.executed_checks,
            ("web.test.two",),
        )
        self.assertEqual(
            tuple(
                skipped.check_id
                for skipped in result.skipped_checks
            ),
            ("web.test.one",),
        )

    def test_unexpected_exception_surfaces(self) -> None:
        def fail(_target, _response):
            raise RuntimeError("unexpected")

        with self.assertRaisesRegex(RuntimeError, "unexpected"):
            execute_analyzers(
                target(),
                response(),
                analyzers=(analyzer(analyze=fail),),
            )

    def test_rejects_non_tuple_output(self) -> None:
        item = analyzer(
            analyze=lambda _target, _response: [],
        )

        with self.assertRaises(AnalyzerOutputError) as context:
            execute_analyzers(
                target(),
                response(),
                analyzers=(item,),
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_findings_type_invalid",
        )

    def test_rejects_non_finding_output_item(self) -> None:
        item = analyzer(
            analyze=lambda _target, _response: ("invalid",),
        )

        with self.assertRaises(AnalyzerOutputError) as context:
            execute_analyzers(
                target(),
                response(),
                analyzers=(item,),
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_finding_type_invalid",
        )

    def test_rejects_finding_outside_registered_namespace(self) -> None:
        item = analyzer(
            analyze=lambda _target, _response: (
                finding("web.other.issue"),
            ),
        )

        with self.assertRaises(AnalyzerOutputError) as context:
            execute_analyzers(
                target(),
                response(),
                analyzers=(item,),
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_finding_unowned",
        )

    def test_rejects_finding_for_pre_skipped_check(self) -> None:
        item = analyzer(
            checks=("web.test.one", "web.test.two"),
            analyze=lambda _target, _response: (
                finding("web.test.one.issue"),
            ),
        )

        with self.assertRaises(AnalyzerOutputError) as context:
            execute_analyzers(
                target(),
                response(),
                analyzers=(item,),
                pre_skipped_checks=(
                    SkippedCheck(
                        check_id="web.test.one",
                        reason="Not applicable.",
                    ),
                ),
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_finding_for_skipped_check",
        )

    def test_rejects_duplicate_fingerprints_across_analyzers(self) -> None:
        duplicate = finding("web.test.shared.issue")

        with self.assertRaises(AnalyzerOutputError) as context:
            execute_analyzers(
                target(),
                response(),
                analyzers=(
                    analyzer(
                        "one",
                        ("web.test.one",),
                        analyze=lambda _target, _response: (duplicate,),
                    ),
                    analyzer(
                        "two",
                        ("web.test.two",),
                        analyze=lambda _target, _response: (duplicate,),
                    ),
                ),
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_finding_duplicate",
        )

    def test_rejects_controlled_error_without_metadata(self) -> None:
        def fail(_target, _response):
            raise InvalidControlledError("missing metadata")

        item = analyzer(
            analyze=fail,
            controlled_error=InvalidControlledError,
        )

        with self.assertRaises(AnalyzerOutputError) as context:
            execute_analyzers(
                target(),
                response(),
                analyzers=(item,),
            )

        self.assertEqual(
            context.exception.code,
            "analyzer_controlled_error_code_invalid",
        )


if __name__ == "__main__":
    unittest.main()
