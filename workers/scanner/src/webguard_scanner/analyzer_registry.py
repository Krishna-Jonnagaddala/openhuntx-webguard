"""Registered passive analyser execution for OpenHuntX WebGuard."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from webguard_contracts import (
    NormalizedFinding,
    ScanError,
    SkippedCheck,
)

from .error_taxonomy import is_retryable_error
from .safe_http import SafeHttpResponse
from .scope_validator import ValidatedTarget


AnalyzerFunction = Callable[
    [ValidatedTarget, SafeHttpResponse],
    tuple[NormalizedFinding, ...],
]

_IDENTIFIER = re.compile(r"[a-z][a-z0-9._-]*")
_MAXIMUM_ANALYZER_ID_LENGTH = 96
_MAXIMUM_CHECK_ID_LENGTH = 128


class AnalyzerRegistryError(ValueError):
    """Raised when an analyser registry is invalid."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AnalyzerOutputError(RuntimeError):
    """Raised when an analyser violates its registered output contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _identifier(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise AnalyzerRegistryError(
            f"{name}_invalid",
            f"{name} must be a string.",
        )

    cleaned = value.strip().lower()

    if (
        not cleaned
        or len(cleaned) > maximum
        or _IDENTIFIER.fullmatch(cleaned) is None
    ):
        raise AnalyzerRegistryError(
            f"{name}_invalid",
            f"{name} must use lowercase letters, digits, dots, "
            "underscores, or hyphens.",
        )

    return cleaned


@dataclass(frozen=True, slots=True)
class PassiveAnalyzer:
    """One registered passive analyser and the checks it owns."""

    analyzer_id: str
    checks: tuple[str, ...]
    finding_namespace: str
    analyze: AnalyzerFunction
    controlled_error: type[Exception]

    def __post_init__(self) -> None:
        analyzer_id = _identifier(
            self.analyzer_id,
            "analyzer_id",
            _MAXIMUM_ANALYZER_ID_LENGTH,
        )

        finding_namespace = _identifier(
            self.finding_namespace,
            "analyzer_finding_namespace",
            _MAXIMUM_CHECK_ID_LENGTH,
        )

        if not isinstance(self.checks, tuple) or not self.checks:
            raise AnalyzerRegistryError(
                "analyzer_checks_invalid",
                "checks must be a non-empty tuple.",
            )

        checks = tuple(
            _identifier(
                check_id,
                "analyzer_check_id",
                _MAXIMUM_CHECK_ID_LENGTH,
            )
            for check_id in self.checks
        )

        if any(
            not check_id.startswith(f"{finding_namespace}.")
            for check_id in checks
        ):
            raise AnalyzerRegistryError(
                "analyzer_check_namespace_mismatch",
                "Every owned check must be inside finding_namespace.",
            )

        if len(set(checks)) != len(checks):
            raise AnalyzerRegistryError(
                "analyzer_check_duplicate",
                "An analyser cannot own the same check more than once.",
            )

        for left_index, left in enumerate(checks):
            for right in checks[left_index + 1 :]:
                if (
                    left.startswith(f"{right}.")
                    or right.startswith(f"{left}.")
                ):
                    raise AnalyzerRegistryError(
                        "analyzer_check_overlap",
                        "An analyser cannot own overlapping check IDs.",
                    )

        if not callable(self.analyze):
            raise AnalyzerRegistryError(
                "analyzer_function_invalid",
                "analyze must be callable.",
            )

        if (
            not isinstance(self.controlled_error, type)
            or not issubclass(self.controlled_error, Exception)
        ):
            raise AnalyzerRegistryError(
                "analyzer_error_type_invalid",
                "controlled_error must be an Exception type.",
            )

        object.__setattr__(self, "analyzer_id", analyzer_id)
        object.__setattr__(self, "finding_namespace", finding_namespace)
        object.__setattr__(self, "checks", tuple(sorted(checks)))


@dataclass(frozen=True, slots=True)
class AnalyzerPipelineResult:
    """Validated aggregate produced by the passive analyser pipeline."""

    findings: tuple[NormalizedFinding, ...]
    errors: tuple[ScanError, ...]
    executed_checks: tuple[str, ...]
    skipped_checks: tuple[SkippedCheck, ...]


def validate_analyzer_registry(
    analyzers: Iterable[PassiveAnalyzer],
) -> tuple[PassiveAnalyzer, ...]:
    """Validate deterministic analyser and check ownership."""

    try:
        registry = tuple(analyzers)
    except TypeError as exc:
        raise AnalyzerRegistryError(
            "analyzer_registry_invalid",
            "The analyser registry must be iterable.",
        ) from exc

    if not registry:
        raise AnalyzerRegistryError(
            "analyzer_registry_empty",
            "At least one passive analyser must be registered.",
        )

    if any(
        not isinstance(analyzer, PassiveAnalyzer)
        for analyzer in registry
    ):
        raise AnalyzerRegistryError(
            "analyzer_registry_item_invalid",
            "The registry contains a non-PassiveAnalyzer value.",
        )

    analyzer_ids: set[str] = set()
    check_owners: dict[str, str] = {}

    for analyzer in registry:
        if analyzer.analyzer_id in analyzer_ids:
            raise AnalyzerRegistryError(
                "analyzer_id_duplicate",
                "Analyser IDs must be unique.",
            )

        analyzer_ids.add(analyzer.analyzer_id)

        for check_id in analyzer.checks:
            if check_id in check_owners:
                raise AnalyzerRegistryError(
                    "analyzer_check_owner_duplicate",
                    f"Check {check_id!r} is owned by more than one analyser.",
                )

            for owned_check in check_owners:
                if (
                    check_id.startswith(f"{owned_check}.")
                    or owned_check.startswith(f"{check_id}.")
                ):
                    raise AnalyzerRegistryError(
                        "analyzer_check_owner_overlap",
                        "Registered analysers cannot own overlapping check IDs.",
                    )

            check_owners[check_id] = analyzer.analyzer_id

    return registry


def registered_checks(
    analyzers: Iterable[PassiveAnalyzer],
) -> tuple[str, ...]:
    """Return all uniquely owned check IDs in canonical order."""

    registry = validate_analyzer_registry(analyzers)

    return tuple(
        sorted(
            check_id
            for analyzer in registry
            for check_id in analyzer.checks
        )
    )


def _validate_finding_ownership(
    analyzer: PassiveAnalyzer,
    finding: NormalizedFinding,
    skipped_check_ids: set[str],
) -> None:
    rule_id = finding.identity.rule_id

    if not (
        rule_id == analyzer.finding_namespace
        or rule_id.startswith(f"{analyzer.finding_namespace}.")
    ):
        raise AnalyzerOutputError(
            "analyzer_finding_unowned",
            f"Analyser {analyzer.analyzer_id!r} returned a finding "
            "outside its registered namespace.",
        )

    if any(
        rule_id == check_id
        or rule_id.startswith(f"{check_id}.")
        for check_id in skipped_check_ids
    ):
        raise AnalyzerOutputError(
            "analyzer_finding_for_skipped_check",
            f"Analyser {analyzer.analyzer_id!r} returned a finding "
            "for a skipped check.",
        )


def _controlled_error_metadata(
    analyzer: PassiveAnalyzer,
    exc: Exception,
) -> tuple[str, str]:
    code = getattr(exc, "code", None)
    message = getattr(exc, "message", None)

    if not isinstance(code, str) or not code.strip():
        raise AnalyzerOutputError(
            "analyzer_controlled_error_code_invalid",
            f"Analyser {analyzer.analyzer_id!r} raised a controlled "
            "error without a usable code.",
        ) from exc

    if not isinstance(message, str) or not message.strip():
        raise AnalyzerOutputError(
            "analyzer_controlled_error_message_invalid",
            f"Analyser {analyzer.analyzer_id!r} raised a controlled "
            "error without a usable message.",
        ) from exc

    return code, message


def execute_analyzers(
    target: ValidatedTarget,
    response: SafeHttpResponse,
    *,
    analyzers: Iterable[PassiveAnalyzer],
    pre_skipped_checks: tuple[SkippedCheck, ...] = (),
) -> AnalyzerPipelineResult:
    """Execute registered analysers with controlled failure isolation.

    Only each analyser's declared controlled error type is isolated. Any
    unexpected exception or output-contract violation is allowed to surface.
    """

    registry = validate_analyzer_registry(analyzers)
    all_checks = set(registered_checks(registry))

    if any(
        not isinstance(item, SkippedCheck)
        for item in pre_skipped_checks
    ):
        raise AnalyzerRegistryError(
            "analyzer_pre_skips_invalid",
            "pre_skipped_checks contains an invalid value.",
        )

    pre_skipped_by_id: dict[str, SkippedCheck] = {}

    for item in pre_skipped_checks:
        if item.check_id not in all_checks:
            raise AnalyzerRegistryError(
                "analyzer_pre_skip_unregistered",
                "Every pre-skipped check must be registered.",
            )

        if item.check_id in pre_skipped_by_id:
            raise AnalyzerRegistryError(
                "analyzer_pre_skip_duplicate",
                "A check cannot be pre-skipped more than once.",
            )

        pre_skipped_by_id[item.check_id] = item

    findings: list[NormalizedFinding] = []
    errors: list[ScanError] = []
    executed_checks: set[str] = set()
    skipped_by_id = dict(pre_skipped_by_id)
    fingerprints: set[str] = set()

    for analyzer in registry:
        active_checks = tuple(
            check_id
            for check_id in analyzer.checks
            if check_id not in skipped_by_id
        )

        if not active_checks:
            continue

        controlled_error = analyzer.controlled_error

        try:
            analyzer_findings = analyzer.analyze(target, response)
        except controlled_error as exc:
            code, message = _controlled_error_metadata(analyzer, exc)
            retryable = is_retryable_error(
                stage="analysis",
                code=code,
            )

            errors.append(
                ScanError(
                    code=code,
                    message=message,
                    stage=f"analysis.{analyzer.analyzer_id}",
                    retryable=retryable,
                )
            )

            reason = (
                f"Analyser {analyzer.analyzer_id!r} did not complete "
                f"because controlled error {code!r} occurred."
            )

            for check_id in active_checks:
                skipped_by_id[check_id] = SkippedCheck(
                    check_id=check_id,
                    reason=reason,
                )

            continue

        if not isinstance(analyzer_findings, tuple):
            raise AnalyzerOutputError(
                "analyzer_findings_type_invalid",
                f"Analyser {analyzer.analyzer_id!r} must return a tuple.",
            )

        for finding in analyzer_findings:
            if not isinstance(finding, NormalizedFinding):
                raise AnalyzerOutputError(
                    "analyzer_finding_type_invalid",
                    f"Analyser {analyzer.analyzer_id!r} returned an "
                    "invalid finding value.",
                )

            _validate_finding_ownership(
                analyzer,
                finding,
                set(skipped_by_id),
            )

            if finding.fingerprint in fingerprints:
                raise AnalyzerOutputError(
                    "analyzer_finding_duplicate",
                    "The analyser pipeline produced a duplicate finding "
                    "fingerprint.",
                )

            fingerprints.add(finding.fingerprint)
            findings.append(finding)

        executed_checks.update(active_checks)

    return AnalyzerPipelineResult(
        findings=tuple(
            sorted(
                findings,
                key=lambda item: item.fingerprint,
            )
        ),
        errors=tuple(sorted(set(errors))),
        executed_checks=tuple(sorted(executed_checks)),
        skipped_checks=tuple(
            sorted(
                skipped_by_id.values(),
                key=lambda item: item.check_id,
            )
        ),
    )
