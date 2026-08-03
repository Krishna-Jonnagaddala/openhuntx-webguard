"""Strict loading and compatibility handling for saved scan reports."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .findings import (
    Confidence,
    ContractValidationError,
    Evidence,
    ExternalIdentifier,
    FindingIdentity,
    NormalizedFinding,
    Severity,
)
from .crawl_scans import (
    CrawlLinkSkip,
    CrawlPageScanResult,
    CrawlScanPolicy,
    CrawlScanResult,
)
from .scans import (
    RequestAttempt,
    RequestAttemptOutcome,
    ScanContractValidationError,
    ScanCoverage,
    ScanError,
    ScanResult,
    ScanStatus,
    SkippedCheck,
)


CURRENT_SCAN_SCHEMA_VERSION = "1.1"
SUPPORTED_SCAN_SCHEMA_VERSIONS = ("1.0", "1.1")
MAXIMUM_SCAN_REPORT_BYTES = 16 * 1024 * 1024


class ScanReportLoadError(ValueError):
    """Base class for controlled scan-report loading failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class UnsupportedSchemaVersionError(ScanReportLoadError):
    """Raised when a report uses an unsupported schema version."""

    def __init__(self, schema_version: object) -> None:
        super().__init__(
            "scan_schema_version_unsupported",
            "Unsupported scan report schema_version "
            f"{schema_version!r}. Supported versions are "
            + ", ".join(SUPPORTED_SCAN_SCHEMA_VERSIONS)
            + ".",
        )
        self.schema_version = schema_version


class MalformedScanReportError(ScanReportLoadError):
    """Raised when a report is malformed, inconsistent, or non-canonical."""


class _DuplicateJsonKeyError(ValueError):
    pass


_ROOT_FIELDS_1_0 = frozenset(
    {
        "schema_version",
        "scan_id",
        "scan_type",
        "status",
        "target",
        "engine",
        "engine_version",
        "started_at",
        "completed_at",
        "coverage",
        "finding_count",
        "findings",
        "error_count",
        "errors",
        "connected_addresses",
        "http_statuses",
    }
)

_ROOT_FIELDS_1_1 = frozenset(
    {
        *_ROOT_FIELDS_1_0,
        "request_attempt_count",
        "request_attempts",
    }
)

_COVERAGE_FIELDS = frozenset(
    {
        "planned_checks",
        "executed_checks",
        "skipped_checks",
        "unaccounted_checks",
        "completion_percent",
        "requests_attempted",
        "requests_succeeded",
    }
)

_SKIPPED_CHECK_FIELDS = frozenset({"check_id", "reason"})
_SCAN_ERROR_FIELDS = frozenset({"code", "message", "stage", "retryable"})
_ATTEMPT_FIELDS = frozenset(
    {
        "attempt_number",
        "started_at",
        "completed_at",
        "duration_milliseconds",
        "outcome",
        "connected_address",
        "http_status",
        "error_code",
        "retryable",
        "retry_scheduled",
        "backoff_seconds",
    }
)
_FINDING_FIELDS = frozenset(
    {
        "schema_version",
        "fingerprint",
        "identity",
        "source",
        "source_rule_id",
        "title",
        "description",
        "severity",
        "confidence",
        "remediation",
        "detected_at",
        "identifiers",
        "evidence",
        "references",
        "tags",
    }
)
_IDENTITY_FIELDS = frozenset(
    {"rule_id", "asset", "path", "method", "parameter"}
)
_IDENTIFIER_FIELDS = frozenset({"namespace", "value"})
_EVIDENCE_FIELDS = frozenset({"summary", "artifact_reference"})


def _malformed(code: str, message: str) -> MalformedScanReportError:
    return MalformedScanReportError(code, message)


def _object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _malformed(
            "scan_report_object_required",
            f"{path} must be a JSON object.",
        )

    result = dict(value)

    if any(not isinstance(key, str) for key in result):
        raise _malformed(
            "scan_report_key_invalid",
            f"{path} contains a non-text object key.",
        )

    return result


def _strict_object(
    value: object,
    path: str,
    expected_fields: frozenset[str],
) -> dict[str, Any]:
    result = _object(value, path)
    actual_fields = set(result)
    missing = sorted(expected_fields - actual_fields)
    unexpected = sorted(actual_fields - expected_fields)

    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise _malformed(
            "scan_report_fields_invalid",
            f"{path} has invalid fields ({'; '.join(details)}).",
        )

    return result


def _list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise _malformed(
            "scan_report_list_required",
            f"{path} must be a JSON array.",
        )
    return value


def _text(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise _malformed(
            "scan_report_text_required",
            f"{path} must be text.",
        )
    return value


def _optional_text(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _text(value, path)


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _malformed(
            "scan_report_integer_required",
            f"{path} must be an integer.",
        )
    return value


def _optional_integer(value: object, path: str) -> int | None:
    if value is None:
        return None
    return _integer(value, path)


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise _malformed(
            "scan_report_boolean_required",
            f"{path} must be boolean.",
        )
    return value


def _optional_boolean(value: object, path: str) -> bool | None:
    if value is None:
        return None
    return _boolean(value, path)


def _number(value: object, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _malformed(
            "scan_report_number_required",
            f"{path} must be a number.",
        )
    return float(value)


def _timestamp(value: object, path: str) -> datetime:
    timestamp_text = _text(value, path)
    try:
        parsed = datetime.fromisoformat(
            timestamp_text.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise _malformed(
            "scan_report_timestamp_invalid",
            f"{path} must be a valid ISO 8601 timestamp.",
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _malformed(
            "scan_report_timestamp_invalid",
            f"{path} must include a timezone offset.",
        )

    return parsed


def _optional_timestamp(value: object, path: str) -> datetime | None:
    if value is None:
        return None
    return _timestamp(value, path)


def _enum(enum_type: type[Any], value: object, path: str) -> Any:
    enum_text = _text(value, path)
    try:
        return enum_type(enum_text)
    except ValueError as exc:
        raise _malformed(
            "scan_report_enum_invalid",
            f"{path} contains unsupported value {enum_text!r}.",
        ) from exc


def _text_list(value: object, path: str) -> tuple[str, ...]:
    return tuple(
        _text(item, f"{path}[{index}]")
        for index, item in enumerate(_list(value, path))
    )


def _integer_list(value: object, path: str) -> tuple[int, ...]:
    return tuple(
        _integer(item, f"{path}[{index}]")
        for index, item in enumerate(_list(value, path))
    )


def _load_coverage(value: object) -> ScanCoverage:
    data = _strict_object(value, "coverage", _COVERAGE_FIELDS)
    skipped_checks: list[SkippedCheck] = []

    for index, item in enumerate(_list(data["skipped_checks"], "coverage.skipped_checks")):
        item_data = _strict_object(
            item,
            f"coverage.skipped_checks[{index}]",
            _SKIPPED_CHECK_FIELDS,
        )
        skipped_checks.append(
            SkippedCheck(
                check_id=_text(
                    item_data["check_id"],
                    f"coverage.skipped_checks[{index}].check_id",
                ),
                reason=_text(
                    item_data["reason"],
                    f"coverage.skipped_checks[{index}].reason",
                ),
            )
        )

    coverage = ScanCoverage(
        planned_checks=_text_list(
            data["planned_checks"], "coverage.planned_checks"
        ),
        executed_checks=_text_list(
            data["executed_checks"], "coverage.executed_checks"
        ),
        skipped_checks=tuple(skipped_checks),
        requests_attempted=_integer(
            data["requests_attempted"], "coverage.requests_attempted"
        ),
        requests_succeeded=_integer(
            data["requests_succeeded"], "coverage.requests_succeeded"
        ),
    )

    if coverage.to_dict() != data:
        raise _malformed(
            "scan_report_coverage_inconsistent",
            "coverage contains incorrect derived values or non-canonical ordering.",
        )

    return coverage


def _load_finding(value: object, index: int) -> NormalizedFinding:
    path = f"findings[{index}]"
    data = _strict_object(value, path, _FINDING_FIELDS)

    if _text(data["schema_version"], f"{path}.schema_version") != "1.0":
        raise _malformed(
            "finding_schema_version_unsupported",
            f"{path}.schema_version must be '1.0'.",
        )

    identity_data = _strict_object(
        data["identity"], f"{path}.identity", _IDENTITY_FIELDS
    )

    identifiers: list[ExternalIdentifier] = []
    for item_index, item in enumerate(_list(data["identifiers"], f"{path}.identifiers")):
        item_path = f"{path}.identifiers[{item_index}]"
        item_data = _strict_object(item, item_path, _IDENTIFIER_FIELDS)
        identifiers.append(
            ExternalIdentifier(
                namespace=_text(item_data["namespace"], f"{item_path}.namespace"),
                value=_text(item_data["value"], f"{item_path}.value"),
            )
        )

    evidence: list[Evidence] = []
    for item_index, item in enumerate(_list(data["evidence"], f"{path}.evidence")):
        item_path = f"{path}.evidence[{item_index}]"
        item_data = _strict_object(item, item_path, _EVIDENCE_FIELDS)
        evidence.append(
            Evidence(
                summary=_text(item_data["summary"], f"{item_path}.summary"),
                artifact_reference=_optional_text(
                    item_data["artifact_reference"],
                    f"{item_path}.artifact_reference",
                ),
            )
        )

    finding = NormalizedFinding(
        identity=FindingIdentity(
            rule_id=_text(identity_data["rule_id"], f"{path}.identity.rule_id"),
            asset=_text(identity_data["asset"], f"{path}.identity.asset"),
            path=_text(identity_data["path"], f"{path}.identity.path"),
            method=_text(identity_data["method"], f"{path}.identity.method"),
            parameter=_optional_text(
                identity_data["parameter"], f"{path}.identity.parameter"
            ),
        ),
        source=_text(data["source"], f"{path}.source"),
        source_rule_id=_optional_text(
            data["source_rule_id"], f"{path}.source_rule_id"
        ),
        title=_text(data["title"], f"{path}.title"),
        description=_text(data["description"], f"{path}.description"),
        severity=_enum(Severity, data["severity"], f"{path}.severity"),
        confidence=_enum(Confidence, data["confidence"], f"{path}.confidence"),
        remediation=_text(data["remediation"], f"{path}.remediation"),
        detected_at=_timestamp(data["detected_at"], f"{path}.detected_at"),
        identifiers=tuple(identifiers),
        evidence=tuple(evidence),
        references=_text_list(data["references"], f"{path}.references"),
        tags=_text_list(data["tags"], f"{path}.tags"),
    )

    if finding.to_dict() != data:
        raise _malformed(
            "scan_report_finding_inconsistent",
            f"{path} contains an invalid fingerprint, derived field, or non-canonical value.",
        )

    return finding


def _load_error(value: object, index: int) -> ScanError:
    path = f"errors[{index}]"
    data = _strict_object(value, path, _SCAN_ERROR_FIELDS)
    return ScanError(
        code=_text(data["code"], f"{path}.code"),
        message=_text(data["message"], f"{path}.message"),
        stage=_text(data["stage"], f"{path}.stage"),
        retryable=_boolean(data["retryable"], f"{path}.retryable"),
    )


def _load_attempt(value: object, index: int) -> RequestAttempt:
    path = f"request_attempts[{index}]"
    data = _strict_object(value, path, _ATTEMPT_FIELDS)
    attempt = RequestAttempt(
        attempt_number=_integer(data["attempt_number"], f"{path}.attempt_number"),
        started_at=_timestamp(data["started_at"], f"{path}.started_at"),
        completed_at=_timestamp(data["completed_at"], f"{path}.completed_at"),
        outcome=_enum(RequestAttemptOutcome, data["outcome"], f"{path}.outcome"),
        connected_address=_optional_text(
            data["connected_address"], f"{path}.connected_address"
        ),
        http_status=_optional_integer(data["http_status"], f"{path}.http_status"),
        error_code=_optional_text(data["error_code"], f"{path}.error_code"),
        retryable=_optional_boolean(data["retryable"], f"{path}.retryable"),
        retry_scheduled=_boolean(
            data["retry_scheduled"], f"{path}.retry_scheduled"
        ),
        backoff_seconds=_number(
            data["backoff_seconds"], f"{path}.backoff_seconds"
        ),
    )

    if attempt.to_dict() != data:
        raise _malformed(
            "scan_report_attempt_inconsistent",
            f"{path} contains an incorrect duration or non-canonical value.",
        )

    return attempt


def _legacy_projection(result: ScanResult) -> dict[str, Any]:
    data = result.to_dict()
    data["schema_version"] = "1.0"
    data.pop("request_attempt_count")
    data.pop("request_attempts")
    return data


def load_scan_result(data: Mapping[str, Any]) -> ScanResult:
    """Load, validate, and migrate one JSON-compatible scan report object."""

    try:
        root = _object(data, "report")
        schema_version = _text(root.get("schema_version"), "schema_version")

        if schema_version not in SUPPORTED_SCAN_SCHEMA_VERSIONS:
            raise UnsupportedSchemaVersionError(schema_version)

        expected_fields = (
            _ROOT_FIELDS_1_1
            if schema_version == CURRENT_SCAN_SCHEMA_VERSION
            else _ROOT_FIELDS_1_0
        )
        root = _strict_object(root, "report", expected_fields)

        findings = tuple(
            _load_finding(item, index)
            for index, item in enumerate(_list(root["findings"], "findings"))
        )
        errors = tuple(
            _load_error(item, index)
            for index, item in enumerate(_list(root["errors"], "errors"))
        )
        attempts = (
            tuple(
                _load_attempt(item, index)
                for index, item in enumerate(
                    _list(root["request_attempts"], "request_attempts")
                )
            )
            if schema_version == CURRENT_SCAN_SCHEMA_VERSION
            else ()
        )

        if _integer(root["finding_count"], "finding_count") != len(findings):
            raise _malformed(
                "scan_report_finding_count_mismatch",
                "finding_count does not match findings.",
            )

        if _integer(root["error_count"], "error_count") != len(errors):
            raise _malformed(
                "scan_report_error_count_mismatch",
                "error_count does not match errors.",
            )

        if schema_version == CURRENT_SCAN_SCHEMA_VERSION and _integer(
            root["request_attempt_count"], "request_attempt_count"
        ) != len(attempts):
            raise _malformed(
                "scan_report_attempt_count_mismatch",
                "request_attempt_count does not match request_attempts.",
            )

        result = ScanResult(
            scan_id=_text(root["scan_id"], "scan_id"),
            scan_type=_text(root["scan_type"], "scan_type"),
            status=_enum(ScanStatus, root["status"], "status"),
            target=_text(root["target"], "target"),
            engine=_text(root["engine"], "engine"),
            engine_version=_text(root["engine_version"], "engine_version"),
            started_at=_timestamp(root["started_at"], "started_at"),
            completed_at=_optional_timestamp(root["completed_at"], "completed_at"),
            coverage=_load_coverage(root["coverage"]),
            findings=findings,
            errors=errors,
            connected_addresses=_text_list(
                root["connected_addresses"], "connected_addresses"
            ),
            http_statuses=_integer_list(root["http_statuses"], "http_statuses"),
            request_attempts=attempts,
        )

        canonical = (
            result.to_dict()
            if schema_version == CURRENT_SCAN_SCHEMA_VERSION
            else _legacy_projection(result)
        )

        if canonical != root:
            raise _malformed(
                "scan_report_non_canonical",
                "The scan report contains inconsistent derived values or non-canonical ordering.",
            )

        return result

    except (UnsupportedSchemaVersionError, MalformedScanReportError):
        raise
    except (ContractValidationError, ScanContractValidationError) as exc:
        raise _malformed(
            "scan_report_contract_invalid",
            f"The scan report violates the contract: {exc}",
        ) from exc
    except (TypeError, ValueError, KeyError) as exc:
        raise _malformed(
            "scan_report_malformed",
            f"The scan report is malformed: {exc}",
        ) from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON numeric constant {value}.")


def load_scan_result_json(document: str | bytes | bytearray) -> ScanResult:
    """Parse and load one bounded JSON scan report document."""

    if isinstance(document, str):
        try:
            encoded_size = len(document.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise _malformed(
                "scan_report_encoding_invalid",
                "The scan report must be valid UTF-8.",
            ) from exc
        text = document
    elif isinstance(document, (bytes, bytearray)):
        encoded_size = len(document)
        try:
            text = bytes(document).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _malformed(
                "scan_report_encoding_invalid",
                "The scan report must be valid UTF-8.",
            ) from exc
    else:
        raise _malformed(
            "scan_report_document_invalid",
            "The scan report document must be text or UTF-8 bytes.",
        )

    if encoded_size > MAXIMUM_SCAN_REPORT_BYTES:
        raise _malformed(
            "scan_report_too_large",
            "The scan report exceeds the maximum permitted size.",
        )

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKeyError as exc:
        raise _malformed(
            "scan_report_duplicate_key",
            f"The scan report contains duplicate JSON key {exc.args[0]!r}.",
        ) from exc
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise _malformed(
            "scan_report_json_invalid",
            "The scan report is not valid strict JSON.",
        ) from exc

    return load_scan_result(_object(parsed, "report"))


def load_scan_result_file(path: str | Path) -> ScanResult:
    """Read and load one bounded UTF-8 JSON scan report file."""

    try:
        report_path = Path(path)
    except (TypeError, ValueError) as exc:
        raise _malformed(
            "scan_report_path_invalid",
            "The scan report path is invalid.",
        ) from exc

    try:
        size = report_path.stat().st_size
        if size > MAXIMUM_SCAN_REPORT_BYTES:
            raise _malformed(
                "scan_report_too_large",
                "The scan report exceeds the maximum permitted size.",
            )
        document = report_path.read_bytes()
    except MalformedScanReportError:
        raise
    except OSError as exc:
        raise _malformed(
            "scan_report_file_read_failed",
            f"Unable to read scan report file {report_path}.",
        ) from exc

    return load_scan_result_json(document)


CURRENT_CRAWL_SCAN_SCHEMA_VERSION = "1.0"
SUPPORTED_CRAWL_SCAN_SCHEMA_VERSIONS = ("1.0",)

_CRAWL_ROOT_FIELDS = frozenset(
    {
        "report_type",
        "schema_version",
        "scan_id",
        "scan_type",
        "status",
        "target",
        "engine",
        "engine_version",
        "started_at",
        "completed_at",
        "policy",
        "coverage",
        "page_count",
        "pages",
        "skipped_links",
        "finding_count",
        "error_count",
        "connected_addresses",
        "http_statuses",
        "request_attempt_count",
        "request_attempts",
    }
)
_CRAWL_POLICY_FIELDS = frozenset(
    {
        "maximum_pages",
        "maximum_depth",
        "maximum_links_per_page",
        "maximum_url_length",
        "minimum_delay_seconds",
        "query_mode",
        "allowed_content_types",
        "blocked_path_segments",
    }
)
_CRAWL_COVERAGE_FIELDS = frozenset(
    {
        "pages_attempted",
        "pages_succeeded",
        "pages_completed_with_errors",
        "pages_failed",
        "requests_attempted",
        "requests_succeeded",
        "check_executions_planned",
        "check_executions_executed",
        "check_executions_skipped",
        "unaccounted_check_executions",
        "completion_percent",
    }
)
_CRAWL_PAGE_FIELDS = frozenset(
    {
        "url",
        "depth",
        "parent_url",
        "status",
        "started_at",
        "completed_at",
        "content_type",
        "connected_address",
        "http_status",
        "discovered_links",
        "queued_links",
        "coverage",
        "finding_count",
        "findings",
        "error_count",
        "errors",
        "request_attempt_count",
        "request_attempts",
    }
)
_CRAWL_SKIP_FIELDS = frozenset({"reason", "count"})
_CRAWL_COMBINED_ATTEMPT_FIELDS = frozenset(
    {
        "sequence",
        "page_url",
        "page_attempt_number",
        "started_at",
        "completed_at",
        "duration_milliseconds",
        "outcome",
        "connected_address",
        "http_status",
        "error_code",
        "retryable",
        "retry_scheduled",
        "backoff_seconds",
    }
)


class UnsupportedCrawlSchemaVersionError(ScanReportLoadError):
    """Raised when a crawl report uses an unsupported schema version."""

    def __init__(self, schema_version: object) -> None:
        super().__init__(
            "crawl_scan_schema_version_unsupported",
            "Unsupported crawl scan report schema_version "
            f"{schema_version!r}. Supported versions are "
            + ", ".join(SUPPORTED_CRAWL_SCAN_SCHEMA_VERSIONS)
            + ".",
        )
        self.schema_version = schema_version


def _load_crawl_policy(value: object) -> CrawlScanPolicy:
    data = _strict_object(value, "policy", _CRAWL_POLICY_FIELDS)
    policy = CrawlScanPolicy(
        maximum_pages=_integer(data["maximum_pages"], "policy.maximum_pages"),
        maximum_depth=_integer(data["maximum_depth"], "policy.maximum_depth"),
        maximum_links_per_page=_integer(
            data["maximum_links_per_page"],
            "policy.maximum_links_per_page",
        ),
        maximum_url_length=_integer(
            data["maximum_url_length"],
            "policy.maximum_url_length",
        ),
        minimum_delay_seconds=_number(
            data["minimum_delay_seconds"],
            "policy.minimum_delay_seconds",
        ),
        query_mode=_text(data["query_mode"], "policy.query_mode"),
        allowed_content_types=_text_list(
            data["allowed_content_types"],
            "policy.allowed_content_types",
        ),
        blocked_path_segments=_text_list(
            data["blocked_path_segments"],
            "policy.blocked_path_segments",
        ),
    )
    if policy.to_dict() != data:
        raise _malformed(
            "crawl_scan_policy_inconsistent",
            "policy contains non-canonical values or ordering.",
        )
    return policy


def _load_crawl_page(value: object, index: int) -> CrawlPageScanResult:
    path = f"pages[{index}]"
    data = _strict_object(value, path, _CRAWL_PAGE_FIELDS)
    findings = tuple(
        _load_finding(item, finding_index)
        for finding_index, item in enumerate(
            _list(data["findings"], f"{path}.findings")
        )
    )
    errors = tuple(
        _load_error(item, error_index)
        for error_index, item in enumerate(
            _list(data["errors"], f"{path}.errors")
        )
    )
    attempts = tuple(
        _load_attempt(item, attempt_index)
        for attempt_index, item in enumerate(
            _list(data["request_attempts"], f"{path}.request_attempts")
        )
    )

    if _integer(data["finding_count"], f"{path}.finding_count") != len(findings):
        raise _malformed(
            "crawl_page_finding_count_mismatch",
            f"{path}.finding_count does not match findings.",
        )
    if _integer(data["error_count"], f"{path}.error_count") != len(errors):
        raise _malformed(
            "crawl_page_error_count_mismatch",
            f"{path}.error_count does not match errors.",
        )
    if _integer(
        data["request_attempt_count"],
        f"{path}.request_attempt_count",
    ) != len(attempts):
        raise _malformed(
            "crawl_page_attempt_count_mismatch",
            f"{path}.request_attempt_count does not match request_attempts.",
        )

    _timestamp(data["started_at"], f"{path}.started_at")
    _timestamp(data["completed_at"], f"{path}.completed_at")

    page = CrawlPageScanResult(
        url=_text(data["url"], f"{path}.url"),
        depth=_integer(data["depth"], f"{path}.depth"),
        parent_url=_optional_text(data["parent_url"], f"{path}.parent_url"),
        status=_enum(ScanStatus, data["status"], f"{path}.status"),
        coverage=_load_coverage(data["coverage"]),
        request_attempts=attempts,
        findings=findings,
        errors=errors,
        content_type=_optional_text(
            data["content_type"],
            f"{path}.content_type",
        ),
        connected_address=_optional_text(
            data["connected_address"],
            f"{path}.connected_address",
        ),
        http_status=_optional_integer(
            data["http_status"],
            f"{path}.http_status",
        ),
        discovered_links=_integer(
            data["discovered_links"],
            f"{path}.discovered_links",
        ),
        queued_links=_integer(
            data["queued_links"],
            f"{path}.queued_links",
        ),
    )
    if page.to_dict() != data:
        raise _malformed(
            "crawl_page_inconsistent",
            f"{path} contains incorrect derived values or non-canonical ordering.",
        )
    return page


def _load_crawl_skip(value: object, index: int) -> CrawlLinkSkip:
    path = f"skipped_links[{index}]"
    data = _strict_object(value, path, _CRAWL_SKIP_FIELDS)
    skip = CrawlLinkSkip(
        reason=_text(data["reason"], f"{path}.reason"),
        count=_integer(data["count"], f"{path}.count"),
    )
    if skip.to_dict() != data:
        raise _malformed(
            "crawl_skip_inconsistent",
            f"{path} contains non-canonical values.",
        )
    return skip


def _validate_crawl_projection(root: dict[str, Any]) -> None:
    _strict_object(root["coverage"], "coverage", _CRAWL_COVERAGE_FIELDS)
    for index, item in enumerate(
        _list(root["request_attempts"], "request_attempts")
    ):
        data = _strict_object(
            item,
            f"request_attempts[{index}]",
            _CRAWL_COMBINED_ATTEMPT_FIELDS,
        )
        _integer(data["sequence"], f"request_attempts[{index}].sequence")
        _text(data["page_url"], f"request_attempts[{index}].page_url")
        _integer(
            data["page_attempt_number"],
            f"request_attempts[{index}].page_attempt_number",
        )


def load_crawl_scan_result(data: Mapping[str, Any]) -> CrawlScanResult:
    """Load and strictly validate one page-aware crawl scan report."""

    try:
        root = _strict_object(data, "report", _CRAWL_ROOT_FIELDS)
        report_type = _text(root["report_type"], "report_type")
        if report_type != "crawl_scan":
            raise _malformed(
                "crawl_scan_report_type_invalid",
                "report_type must be 'crawl_scan'.",
            )
        schema_version = _text(root["schema_version"], "schema_version")
        if schema_version not in SUPPORTED_CRAWL_SCAN_SCHEMA_VERSIONS:
            raise UnsupportedCrawlSchemaVersionError(schema_version)

        pages = tuple(
            _load_crawl_page(item, index)
            for index, item in enumerate(_list(root["pages"], "pages"))
        )
        skipped_links = tuple(
            _load_crawl_skip(item, index)
            for index, item in enumerate(
                _list(root["skipped_links"], "skipped_links")
            )
        )
        _validate_crawl_projection(root)

        result = CrawlScanResult(
            scan_id=_text(root["scan_id"], "scan_id"),
            scan_type=_text(root["scan_type"], "scan_type"),
            status=_enum(ScanStatus, root["status"], "status"),
            target=_text(root["target"], "target"),
            engine=_text(root["engine"], "engine"),
            engine_version=_text(root["engine_version"], "engine_version"),
            started_at=_timestamp(root["started_at"], "started_at"),
            completed_at=_timestamp(root["completed_at"], "completed_at"),
            policy=_load_crawl_policy(root["policy"]),
            pages=pages,
            skipped_links=skipped_links,
        )

        if _integer(root["page_count"], "page_count") != len(result.pages):
            raise _malformed(
                "crawl_scan_page_count_mismatch",
                "page_count does not match pages.",
            )
        if _integer(root["finding_count"], "finding_count") != len(result.findings):
            raise _malformed(
                "crawl_scan_finding_count_mismatch",
                "finding_count does not match page findings.",
            )
        if _integer(root["error_count"], "error_count") != len(result.errors):
            raise _malformed(
                "crawl_scan_error_count_mismatch",
                "error_count does not match page errors.",
            )
        if _integer(
            root["request_attempt_count"],
            "request_attempt_count",
        ) != result.request_attempt_count:
            raise _malformed(
                "crawl_scan_attempt_count_mismatch",
                "request_attempt_count does not match page attempts.",
            )

        if result.to_dict() != root:
            raise _malformed(
                "crawl_scan_report_non_canonical",
                "The crawl scan report contains inconsistent derived values or non-canonical ordering.",
            )
        return result

    except (
        UnsupportedCrawlSchemaVersionError,
        MalformedScanReportError,
    ):
        raise
    except (ContractValidationError, ScanContractValidationError) as exc:
        raise _malformed(
            "crawl_scan_report_contract_invalid",
            f"The crawl scan report violates the contract: {exc}",
        ) from exc
    except (TypeError, ValueError, KeyError) as exc:
        raise _malformed(
            "crawl_scan_report_malformed",
            f"The crawl scan report is malformed: {exc}",
        ) from exc


def _parse_report_document(document: str | bytes | bytearray) -> dict[str, Any]:
    if isinstance(document, str):
        try:
            encoded_size = len(document.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise _malformed(
                "scan_report_encoding_invalid",
                "The scan report must be valid UTF-8.",
            ) from exc
        text = document
    elif isinstance(document, (bytes, bytearray)):
        encoded_size = len(document)
        try:
            text = bytes(document).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _malformed(
                "scan_report_encoding_invalid",
                "The scan report must be valid UTF-8.",
            ) from exc
    else:
        raise _malformed(
            "scan_report_document_invalid",
            "The scan report document must be text or UTF-8 bytes.",
        )

    if encoded_size > MAXIMUM_SCAN_REPORT_BYTES:
        raise _malformed(
            "scan_report_too_large",
            "The scan report exceeds the maximum permitted size.",
        )

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKeyError as exc:
        raise _malformed(
            "scan_report_duplicate_key",
            f"The scan report contains duplicate JSON key {exc.args[0]!r}.",
        ) from exc
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise _malformed(
            "scan_report_json_invalid",
            "The scan report is not valid strict JSON.",
        ) from exc

    return _object(parsed, "report")


def _read_report_document(path: str | Path) -> bytes:
    try:
        report_path = Path(path)
    except (TypeError, ValueError) as exc:
        raise _malformed(
            "scan_report_path_invalid",
            "The scan report path is invalid.",
        ) from exc
    try:
        size = report_path.stat().st_size
        if size > MAXIMUM_SCAN_REPORT_BYTES:
            raise _malformed(
                "scan_report_too_large",
                "The scan report exceeds the maximum permitted size.",
            )
        return report_path.read_bytes()
    except MalformedScanReportError:
        raise
    except OSError as exc:
        raise _malformed(
            "scan_report_file_read_failed",
            f"Unable to read scan report file {report_path}.",
        ) from exc


def load_crawl_scan_result_json(
    document: str | bytes | bytearray,
) -> CrawlScanResult:
    return load_crawl_scan_result(_parse_report_document(document))


def load_crawl_scan_result_file(path: str | Path) -> CrawlScanResult:
    return load_crawl_scan_result_json(_read_report_document(path))


WebGuardReport = ScanResult | CrawlScanResult


def load_webguard_report(data: Mapping[str, Any]) -> WebGuardReport:
    """Load either a legacy single-page report or a crawl scan report."""

    root = _object(data, "report")
    if "report_type" not in root:
        return load_scan_result(root)
    report_type = _text(root["report_type"], "report_type")
    if report_type == "crawl_scan":
        return load_crawl_scan_result(root)
    raise _malformed(
        "scan_report_type_unsupported",
        f"Unsupported report_type {report_type!r}.",
    )


def load_webguard_report_json(
    document: str | bytes | bytearray,
) -> WebGuardReport:
    return load_webguard_report(_parse_report_document(document))


def load_webguard_report_file(path: str | Path) -> WebGuardReport:
    return load_webguard_report_json(_read_report_document(path))
