"""Page-aware crawl scan contracts for OpenHuntX WebGuard."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Tuple
from urllib.parse import urlsplit

from .findings import NormalizedFinding
from .scans import (
    RequestAttempt,
    RequestAttemptOutcome,
    ScanContractValidationError,
    ScanCoverage,
    ScanError,
    ScanStatus,
    _aware_utc,
    _canonical_target,
    _identifier,
    _required_text,
    _target_origin,
    _timestamp,
)


MAXIMUM_CRAWL_REPORT_PAGES = 50
MAXIMUM_CRAWL_REPORT_DEPTH = 3
MAXIMUM_CRAWL_REPORT_LINKS_PER_PAGE = 500
MAXIMUM_CRAWL_REPORT_URL_LENGTH = 2048
MAXIMUM_CRAWL_REPORT_DELAY_SECONDS = 5.0
MAXIMUM_CRAWL_REPORT_EXECUTION_SECONDS = 3600.0
MAXIMUM_CRAWL_REPORT_REQUEST_ATTEMPTS = 150
DEFAULT_CRAWL_REPORT_EXECUTION_SECONDS = 300.0
DEFAULT_CRAWL_REPORT_REQUEST_ATTEMPTS = 150

_MEDIA_TYPE = re.compile(
    r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$"
)


class CrawlTerminationReason(str, Enum):
    """Why a bounded crawl stopped accepting new requests."""

    COMPLETED = "completed"
    PAGE_LIMIT_REACHED = "page_limit_reached"
    ROOT_REQUEST_FAILED = "root_request_failed"
    TIME_LIMIT_REACHED = "time_limit_reached"
    REQUEST_ATTEMPT_LIMIT_REACHED = "request_attempt_limit_reached"
    CANCELLED = "cancelled"


_TERMINATION_ERRORS: dict[CrawlTerminationReason, tuple[str, str]] = {
    CrawlTerminationReason.TIME_LIMIT_REACHED: (
        "crawl_time_limit_reached",
        "The crawl stopped after reaching its execution time limit.",
    ),
    CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED: (
        "crawl_request_attempt_limit_reached",
        "The crawl stopped after reaching its total request-attempt limit.",
    ),
    CrawlTerminationReason.CANCELLED: (
        "crawl_cancelled",
        "The crawl was cancelled before another request was started.",
    ),
}


@dataclass(frozen=True, slots=True)
class CrawlScanTermination:
    """Canonical crawl termination metadata."""

    reason: CrawlTerminationReason = CrawlTerminationReason.COMPLETED
    pages_pending: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.reason, CrawlTerminationReason):
            raise ScanContractValidationError(
                "crawl_termination_reason_invalid",
                "reason must be a CrawlTerminationReason value.",
            )

        _bounded_integer(
            self.pages_pending,
            "crawl_termination_pages_pending",
            0,
            MAXIMUM_CRAWL_REPORT_PAGES,
        )

        if (
            self.reason
            in {
                CrawlTerminationReason.COMPLETED,
                CrawlTerminationReason.ROOT_REQUEST_FAILED,
            }
            and self.pages_pending != 0
        ):
            raise ScanContractValidationError(
                "crawl_termination_pending_pages_invalid",
                "This termination reason cannot retain pending pages.",
            )

    @property
    def error(self) -> ScanError | None:
        metadata = _TERMINATION_ERRORS.get(self.reason)
        if metadata is None:
            return None

        code, message = metadata
        return ScanError(
            code=code,
            message=message,
            stage="crawl",
            retryable=False,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason.value,
            "pages_pending": self.pages_pending,
        }


@dataclass(frozen=True, slots=True)
class CrawlScanPolicy:
    """Canonical snapshot of the bounded crawler configuration."""

    maximum_pages: int
    maximum_depth: int
    maximum_links_per_page: int
    maximum_url_length: int
    minimum_delay_seconds: float
    query_mode: str
    allowed_content_types: Tuple[str, ...]
    blocked_path_segments: Tuple[str, ...]
    maximum_execution_seconds: float = (
        DEFAULT_CRAWL_REPORT_EXECUTION_SECONDS
    )
    maximum_request_attempts: int = (
        DEFAULT_CRAWL_REPORT_REQUEST_ATTEMPTS
    )

    def __post_init__(self) -> None:
        _bounded_integer(
            self.maximum_pages,
            "crawl_policy_maximum_pages",
            1,
            MAXIMUM_CRAWL_REPORT_PAGES,
        )
        _bounded_integer(
            self.maximum_depth,
            "crawl_policy_maximum_depth",
            0,
            MAXIMUM_CRAWL_REPORT_DEPTH,
        )
        _bounded_integer(
            self.maximum_links_per_page,
            "crawl_policy_maximum_links_per_page",
            1,
            MAXIMUM_CRAWL_REPORT_LINKS_PER_PAGE,
        )
        _bounded_integer(
            self.maximum_url_length,
            "crawl_policy_maximum_url_length",
            128,
            MAXIMUM_CRAWL_REPORT_URL_LENGTH,
        )
        _bounded_integer(
            self.maximum_request_attempts,
            "crawl_policy_maximum_request_attempts",
            1,
            MAXIMUM_CRAWL_REPORT_REQUEST_ATTEMPTS,
        )

        if (
            isinstance(self.maximum_execution_seconds, bool)
            or not isinstance(
                self.maximum_execution_seconds,
                (int, float),
            )
        ):
            raise ScanContractValidationError(
                "crawl_policy_execution_time_invalid",
                "maximum_execution_seconds must be a finite positive number.",
            )

        execution_seconds = float(self.maximum_execution_seconds)
        if (
            not math.isfinite(execution_seconds)
            or not 0 < execution_seconds
            <= MAXIMUM_CRAWL_REPORT_EXECUTION_SECONDS
        ):
            raise ScanContractValidationError(
                "crawl_policy_execution_time_invalid",
                "maximum_execution_seconds must be greater than zero and "
                "no more than 3600 seconds.",
            )

        if (
            isinstance(self.minimum_delay_seconds, bool)
            or not isinstance(self.minimum_delay_seconds, (int, float))
        ):
            raise ScanContractValidationError(
                "crawl_policy_delay_invalid",
                "minimum_delay_seconds must be a finite non-negative number.",
            )

        delay = float(self.minimum_delay_seconds)
        if (
            not math.isfinite(delay)
            or not 0 <= delay <= MAXIMUM_CRAWL_REPORT_DELAY_SECONDS
        ):
            raise ScanContractValidationError(
                "crawl_policy_delay_invalid",
                "minimum_delay_seconds must be between zero and five seconds.",
            )

        query_mode = _identifier(
            self.query_mode,
            "crawl_policy_query_mode",
        )
        if query_mode not in {"drop", "reject"}:
            raise ScanContractValidationError(
                "crawl_policy_query_mode_invalid",
                "query_mode must be 'drop' or 'reject'.",
            )

        allowed_types = _canonical_text_tuple(
            self.allowed_content_types,
            field_name="crawl_policy_allowed_content_type",
            normalizer=_media_type,
        )
        blocked_segments = _canonical_text_tuple(
            self.blocked_path_segments,
            field_name="crawl_policy_blocked_path_segment",
            normalizer=_path_segment,
        )

        if not allowed_types:
            raise ScanContractValidationError(
                "crawl_policy_allowed_content_types_invalid",
                "allowed_content_types cannot be empty.",
            )
        if not blocked_segments:
            raise ScanContractValidationError(
                "crawl_policy_blocked_path_segments_invalid",
                "blocked_path_segments cannot be empty.",
            )

        object.__setattr__(
            self,
            "maximum_execution_seconds",
            execution_seconds,
        )
        object.__setattr__(self, "minimum_delay_seconds", delay)
        object.__setattr__(self, "query_mode", query_mode)
        object.__setattr__(self, "allowed_content_types", allowed_types)
        object.__setattr__(self, "blocked_path_segments", blocked_segments)

    def to_dict(self) -> dict[str, Any]:
        return {
            "maximum_pages": self.maximum_pages,
            "maximum_depth": self.maximum_depth,
            "maximum_links_per_page": self.maximum_links_per_page,
            "maximum_url_length": self.maximum_url_length,
            "minimum_delay_seconds": self.minimum_delay_seconds,
            "maximum_execution_seconds": self.maximum_execution_seconds,
            "maximum_request_attempts": self.maximum_request_attempts,
            "query_mode": self.query_mode,
            "allowed_content_types": list(self.allowed_content_types),
            "blocked_path_segments": list(self.blocked_path_segments),
        }


@dataclass(frozen=True, slots=True, order=True)
class CrawlLinkSkip:
    """Aggregate count for one crawler link-exclusion reason."""

    reason: str
    count: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reason",
            _identifier(self.reason, "crawl_skip_reason"),
        )
        _bounded_integer(
            self.count,
            "crawl_skip_count",
            1,
            2_147_483_647,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "count": self.count,
        }


@dataclass(frozen=True, slots=True)
class CrawlPageScanResult:
    """Validated passive-analysis result for one crawled page."""

    url: str
    depth: int
    parent_url: str | None
    status: ScanStatus
    coverage: ScanCoverage
    request_attempts: Tuple[RequestAttempt, ...]

    findings: Tuple[NormalizedFinding, ...] = ()
    errors: Tuple[ScanError, ...] = ()
    content_type: str | None = None
    connected_address: str | None = None
    http_status: int | None = None
    discovered_links: int = 0
    queued_links: int = 0

    def __post_init__(self) -> None:
        url = _canonical_target(self.url)
        parent_url = (
            None
            if self.parent_url is None
            else _canonical_target(self.parent_url)
        )

        _bounded_integer(
            self.depth,
            "crawl_page_depth",
            0,
            MAXIMUM_CRAWL_REPORT_DEPTH,
        )

        if self.depth == 0 and parent_url is not None:
            raise ScanContractValidationError(
                "crawl_page_root_parent_invalid",
                "A depth-zero crawl page cannot have a parent URL.",
            )
        if self.depth > 0 and parent_url is None:
            raise ScanContractValidationError(
                "crawl_page_parent_required",
                "A non-root crawl page requires a parent URL.",
            )

        if self.status not in {
            ScanStatus.COMPLETED,
            ScanStatus.COMPLETED_WITH_ERRORS,
            ScanStatus.FAILED,
        }:
            raise ScanContractValidationError(
                "crawl_page_status_invalid",
                "Crawl page status must be completed, completed_with_errors, or failed.",
            )

        if not isinstance(self.coverage, ScanCoverage):
            raise ScanContractValidationError(
                "crawl_page_coverage_invalid",
                "coverage must be a ScanCoverage value.",
            )

        if (
            not isinstance(self.request_attempts, tuple)
            or not self.request_attempts
            or any(
                not isinstance(item, RequestAttempt)
                for item in self.request_attempts
            )
        ):
            raise ScanContractValidationError(
                "crawl_page_attempts_invalid",
                "request_attempts must contain at least one RequestAttempt.",
            )

        attempts = tuple(
            sorted(
                self.request_attempts,
                key=lambda item: item.attempt_number,
            )
        )
        expected_numbers = tuple(range(1, len(attempts) + 1))
        actual_numbers = tuple(item.attempt_number for item in attempts)
        if actual_numbers != expected_numbers:
            raise ScanContractValidationError(
                "crawl_page_attempt_sequence_invalid",
                "Page request attempts must be numbered consecutively from one.",
            )

        if self.coverage.requests_attempted != len(attempts):
            raise ScanContractValidationError(
                "crawl_page_attempt_count_mismatch",
                "Page coverage requests_attempted must match request_attempts.",
            )
        successful_attempts = tuple(
            item
            for item in attempts
            if item.outcome is RequestAttemptOutcome.SUCCEEDED
        )
        if self.coverage.requests_succeeded != len(successful_attempts):
            raise ScanContractValidationError(
                "crawl_page_attempt_success_mismatch",
                "Page coverage requests_succeeded must match request_attempts.",
            )

        if any(
            not isinstance(item, NormalizedFinding)
            for item in self.findings
        ):
            raise ScanContractValidationError(
                "crawl_page_findings_invalid",
                "findings contains an invalid value.",
            )

        page_origin = _target_origin(url)
        page_path = urlsplit(url).path or "/"
        findings_by_fingerprint: dict[str, NormalizedFinding] = {}
        for finding in self.findings:
            if (
                finding.identity.asset != page_origin
                or finding.identity.path != page_path
                or finding.identity.method != "GET"
            ):
                raise ScanContractValidationError(
                    "crawl_page_finding_ownership_invalid",
                    "Every finding must belong to the crawled page URL.",
                )
            if finding.fingerprint in findings_by_fingerprint:
                raise ScanContractValidationError(
                    "crawl_page_finding_duplicate",
                    "A crawl page cannot contain duplicate finding fingerprints.",
                )
            findings_by_fingerprint[finding.fingerprint] = finding

        if any(not isinstance(item, ScanError) for item in self.errors):
            raise ScanContractValidationError(
                "crawl_page_errors_invalid",
                "errors contains an invalid value.",
            )
        errors = tuple(sorted(set(self.errors)))

        content_type = (
            None
            if self.content_type is None
            else _media_type(self.content_type, "crawl_page_content_type")
        )

        address: str | None = None
        if self.connected_address is not None:
            try:
                address = ipaddress.ip_address(
                    _required_text(
                        self.connected_address,
                        "crawl_page_connected_address",
                        128,
                    )
                ).compressed
            except ValueError as exc:
                raise ScanContractValidationError(
                    "crawl_page_connected_address_invalid",
                    "connected_address must be a valid IP address.",
                ) from exc

        if self.http_status is not None and (
            not isinstance(self.http_status, int)
            or isinstance(self.http_status, bool)
            or not 100 <= self.http_status <= 599
        ):
            raise ScanContractValidationError(
                "crawl_page_http_status_invalid",
                "http_status must be an integer from 100 to 599.",
            )

        _bounded_integer(
            self.discovered_links,
            "crawl_page_discovered_links",
            0,
            MAXIMUM_CRAWL_REPORT_LINKS_PER_PAGE,
        )
        _bounded_integer(
            self.queued_links,
            "crawl_page_queued_links",
            0,
            MAXIMUM_CRAWL_REPORT_LINKS_PER_PAGE,
        )
        if self.queued_links > self.discovered_links:
            raise ScanContractValidationError(
                "crawl_page_queued_links_invalid",
                "queued_links cannot exceed discovered_links.",
            )

        final_attempt = attempts[-1]
        if self.status is ScanStatus.FAILED:
            if (
                final_attempt.outcome is not RequestAttemptOutcome.FAILED
                or self.coverage.requests_succeeded != 0
                or address is not None
                or self.http_status is not None
                or content_type is not None
                or findings_by_fingerprint
                or self.discovered_links != 0
                or self.queued_links != 0
            ):
                raise ScanContractValidationError(
                    "crawl_page_failure_metadata_invalid",
                    "Failed crawl pages cannot contain successful response metadata or findings.",
                )
            if not errors:
                raise ScanContractValidationError(
                    "crawl_page_failure_error_required",
                    "Failed crawl pages require at least one error.",
                )
        else:
            if (
                final_attempt.outcome is not RequestAttemptOutcome.SUCCEEDED
                or self.coverage.requests_succeeded != 1
                or address is None
                or self.http_status is None
                or final_attempt.connected_address != address
                or final_attempt.http_status != self.http_status
            ):
                raise ScanContractValidationError(
                    "crawl_page_success_metadata_invalid",
                    "Completed crawl pages require successful response metadata.",
                )
            if self.coverage.unaccounted_checks:
                raise ScanContractValidationError(
                    "crawl_page_coverage_incomplete",
                    "Completed crawl pages must account for every planned check.",
                )

        if self.status is ScanStatus.COMPLETED and errors:
            raise ScanContractValidationError(
                "crawl_page_completed_has_errors",
                "A completed crawl page cannot contain errors.",
            )
        if self.status is ScanStatus.COMPLETED_WITH_ERRORS and not errors:
            raise ScanContractValidationError(
                "crawl_page_errors_required",
                "A completed_with_errors crawl page requires at least one error.",
            )

        object.__setattr__(self, "url", url)
        object.__setattr__(self, "parent_url", parent_url)
        object.__setattr__(self, "request_attempts", attempts)
        object.__setattr__(
            self,
            "findings",
            tuple(
                sorted(
                    findings_by_fingerprint.values(),
                    key=lambda item: item.fingerprint,
                )
            ),
        )
        object.__setattr__(self, "errors", errors)
        object.__setattr__(self, "content_type", content_type)
        object.__setattr__(self, "connected_address", address)

    @property
    def started_at(self) -> datetime:
        return self.request_attempts[0].started_at

    @property
    def completed_at(self) -> datetime:
        return self.request_attempts[-1].completed_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "depth": self.depth,
            "parent_url": self.parent_url,
            "status": self.status.value,
            "started_at": _timestamp(self.started_at),
            "completed_at": _timestamp(self.completed_at),
            "content_type": self.content_type,
            "connected_address": self.connected_address,
            "http_status": self.http_status,
            "discovered_links": self.discovered_links,
            "queued_links": self.queued_links,
            "coverage": self.coverage.to_dict(),
            "finding_count": len(self.findings),
            "findings": [item.to_dict() for item in self.findings],
            "error_count": len(self.errors),
            "errors": [
                {
                    "code": item.code,
                    "message": item.message,
                    "stage": item.stage,
                    "retryable": item.retryable,
                }
                for item in self.errors
            ],
            "request_attempt_count": len(self.request_attempts),
            "request_attempts": [
                item.to_dict()
                for item in self.request_attempts
            ],
        }


@dataclass(frozen=True, slots=True)
class CrawlScanCoverage:
    """Aggregate page, request, and check-execution coverage."""

    pages_attempted: int
    pages_succeeded: int
    pages_completed_with_errors: int
    pages_failed: int
    pages_pending: int
    requests_attempted: int
    requests_succeeded: int
    check_executions_planned: int
    check_executions_executed: int
    check_executions_skipped: int

    def __post_init__(self) -> None:
        values = (
            ("crawl_pages_attempted", self.pages_attempted),
            ("crawl_pages_succeeded", self.pages_succeeded),
            (
                "crawl_pages_completed_with_errors",
                self.pages_completed_with_errors,
            ),
            ("crawl_pages_failed", self.pages_failed),
            ("crawl_pages_pending", self.pages_pending),
            ("crawl_requests_attempted", self.requests_attempted),
            ("crawl_requests_succeeded", self.requests_succeeded),
            (
                "crawl_check_executions_planned",
                self.check_executions_planned,
            ),
            (
                "crawl_check_executions_executed",
                self.check_executions_executed,
            ),
            (
                "crawl_check_executions_skipped",
                self.check_executions_skipped,
            ),
        )
        for name, value in values:
            _bounded_integer(value, name, 0, 2_147_483_647)

        if self.pages_succeeded + self.pages_failed != self.pages_attempted:
            raise ScanContractValidationError(
                "crawl_page_counts_invalid",
                "pages_succeeded plus pages_failed must equal pages_attempted.",
            )
        if self.pages_completed_with_errors > self.pages_succeeded:
            raise ScanContractValidationError(
                "crawl_partial_page_count_invalid",
                "pages_completed_with_errors cannot exceed pages_succeeded.",
            )
        if self.requests_succeeded > self.requests_attempted:
            raise ScanContractValidationError(
                "crawl_request_counts_invalid",
                "requests_succeeded cannot exceed requests_attempted.",
            )
        if (
            self.check_executions_executed
            + self.check_executions_skipped
            > self.check_executions_planned
        ):
            raise ScanContractValidationError(
                "crawl_check_counts_invalid",
                "Executed and skipped checks cannot exceed planned checks.",
            )

    @classmethod
    def from_pages(
        cls,
        pages: Tuple[CrawlPageScanResult, ...],
        *,
        pages_pending: int = 0,
    ) -> "CrawlScanCoverage":
        succeeded = tuple(
            page
            for page in pages
            if page.status is not ScanStatus.FAILED
        )
        return cls(
            pages_attempted=len(pages),
            pages_succeeded=len(succeeded),
            pages_completed_with_errors=sum(
                page.status is ScanStatus.COMPLETED_WITH_ERRORS
                for page in pages
            ),
            pages_failed=sum(
                page.status is ScanStatus.FAILED
                for page in pages
            ),
            pages_pending=pages_pending,
            requests_attempted=sum(
                page.coverage.requests_attempted
                for page in pages
            ),
            requests_succeeded=sum(
                page.coverage.requests_succeeded
                for page in pages
            ),
            check_executions_planned=sum(
                len(page.coverage.planned_checks)
                for page in pages
            ),
            check_executions_executed=sum(
                len(page.coverage.executed_checks)
                for page in pages
            ),
            check_executions_skipped=sum(
                len(page.coverage.skipped_checks)
                for page in pages
            ),
        )

    @property
    def unaccounted_check_executions(self) -> int:
        return (
            self.check_executions_planned
            - self.check_executions_executed
            - self.check_executions_skipped
        )

    @property
    def completion_percent(self) -> float | None:
        if self.check_executions_planned == 0:
            return None
        return round(
            self.check_executions_executed
            / self.check_executions_planned
            * 100,
            2,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "pages_attempted": self.pages_attempted,
            "pages_succeeded": self.pages_succeeded,
            "pages_completed_with_errors": self.pages_completed_with_errors,
            "pages_failed": self.pages_failed,
            "pages_pending": self.pages_pending,
            "requests_attempted": self.requests_attempted,
            "requests_succeeded": self.requests_succeeded,
            "check_executions_planned": self.check_executions_planned,
            "check_executions_executed": self.check_executions_executed,
            "check_executions_skipped": self.check_executions_skipped,
            "unaccounted_check_executions": self.unaccounted_check_executions,
            "completion_percent": self.completion_percent,
        }


@dataclass(frozen=True, slots=True)
class CrawlScanResult:
    """Versioned multi-page crawl scan report."""

    scan_id: str
    scan_type: str
    status: ScanStatus
    target: str
    engine: str
    engine_version: str
    started_at: datetime
    completed_at: datetime
    policy: CrawlScanPolicy
    pages: Tuple[CrawlPageScanResult, ...]
    skipped_links: Tuple[CrawlLinkSkip, ...] = ()
    termination: CrawlScanTermination = field(
        default_factory=CrawlScanTermination
    )

    report_type: str = field(default="crawl_scan", init=False)
    schema_version: str = field(default="1.1", init=False)

    def __post_init__(self) -> None:
        try:
            scan_id = str(
                uuid.UUID(
                    _required_text(self.scan_id, "scan_id", 64)
                )
            )
        except (ValueError, AttributeError) as exc:
            raise ScanContractValidationError(
                "scan_id_invalid",
                "scan_id must be a valid UUID.",
            ) from exc

        if self.status not in {
            ScanStatus.COMPLETED,
            ScanStatus.COMPLETED_WITH_ERRORS,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        }:
            raise ScanContractValidationError(
                "crawl_scan_status_invalid",
                "Crawl scan status must be terminal.",
            )

        target = _canonical_target(self.target)
        started_at = _aware_utc(self.started_at, "started_at")
        completed_at = _aware_utc(self.completed_at, "completed_at")
        if completed_at < started_at:
            raise ScanContractValidationError(
                "completed_at_before_started_at",
                "completed_at cannot be earlier than started_at.",
            )

        if not isinstance(self.policy, CrawlScanPolicy):
            raise ScanContractValidationError(
                "crawl_scan_policy_invalid",
                "policy must be a CrawlScanPolicy value.",
            )
        if (
            not isinstance(self.pages, tuple)
            or any(
                not isinstance(item, CrawlPageScanResult)
                for item in self.pages
            )
        ):
            raise ScanContractValidationError(
                "crawl_scan_pages_invalid",
                "pages must be a tuple of CrawlPageScanResult values.",
            )
        if not isinstance(self.termination, CrawlScanTermination):
            raise ScanContractValidationError(
                "crawl_scan_termination_invalid",
                "termination must be a CrawlScanTermination value.",
            )
        if (
            not self.pages
            and self.termination.reason
            not in {
                CrawlTerminationReason.TIME_LIMIT_REACHED,
                CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
                CrawlTerminationReason.CANCELLED,
            }
        ):
            raise ScanContractValidationError(
                "crawl_scan_empty_pages_invalid",
                "Only an early budget stop or cancellation may produce "
                "a crawl report without attempted pages.",
            )
        if len(self.pages) > self.policy.maximum_pages:
            raise ScanContractValidationError(
                "crawl_scan_page_limit_exceeded",
                "The report contains more pages than the policy permits.",
            )
        if self.pages and (
            self.pages[0].url != target
            or self.pages[0].depth != 0
        ):
            raise ScanContractValidationError(
                "crawl_scan_root_page_mismatch",
                "The first page must be the depth-zero crawl target.",
            )
        if (
            len(self.pages)
            + self.termination.pages_pending
            > self.policy.maximum_pages
        ):
            raise ScanContractValidationError(
                "crawl_scan_pending_page_limit_exceeded",
                "Attempted and pending pages exceed the configured page limit.",
            )

        target_origin = _target_origin(target)
        seen_pages: dict[str, CrawlPageScanResult] = {}
        fingerprints: set[str] = set()
        planned_checks = (
            ()
            if not self.pages
            else self.pages[0].coverage.planned_checks
        )
        previous_depth = -1
        previous_completed_at = started_at

        for page_index, page in enumerate(self.pages):
            if _target_origin(page.url) != target_origin:
                raise ScanContractValidationError(
                    "crawl_scan_page_origin_mismatch",
                    "Every crawl page must use the target origin.",
                )
            if page.url in seen_pages:
                raise ScanContractValidationError(
                    "crawl_scan_page_duplicate",
                    "A crawl scan cannot contain the same page twice.",
                )
            if page_index > 0 and page.depth == 0:
                raise ScanContractValidationError(
                    "crawl_scan_multiple_roots",
                    "Only the first crawl page may have depth zero.",
                )
            if page.depth < previous_depth:
                raise ScanContractValidationError(
                    "crawl_scan_page_order_invalid",
                    "Crawl pages must remain in breadth-first depth order.",
                )
            if page.depth > self.policy.maximum_depth:
                raise ScanContractValidationError(
                    "crawl_scan_depth_limit_exceeded",
                    "A crawl page exceeds the configured maximum depth.",
                )
            if page.parent_url is not None:
                parent = seen_pages.get(page.parent_url)
                if parent is None or page.depth != parent.depth + 1:
                    raise ScanContractValidationError(
                        "crawl_scan_parent_invalid",
                        "Every non-root page must reference an earlier parent at the preceding depth.",
                    )
            if page.started_at < previous_completed_at:
                raise ScanContractValidationError(
                    "crawl_scan_page_attempt_order_invalid",
                    "Crawl page attempts cannot overlap or move backwards in time.",
                )
            if page.coverage.planned_checks != planned_checks:
                raise ScanContractValidationError(
                    "crawl_scan_check_plan_mismatch",
                    "Every crawl page must use the same planned check set.",
                )
            if page.started_at < started_at or page.completed_at > completed_at:
                raise ScanContractValidationError(
                    "crawl_scan_page_time_invalid",
                    "Page request attempts must fall within the scan time window.",
                )
            for finding in page.findings:
                if finding.fingerprint in fingerprints:
                    raise ScanContractValidationError(
                        "crawl_scan_finding_duplicate",
                        "A crawl scan cannot contain duplicate finding fingerprints.",
                    )
                fingerprints.add(finding.fingerprint)
            seen_pages[page.url] = page
            previous_depth = page.depth
            previous_completed_at = page.completed_at

        if (
            not isinstance(self.skipped_links, tuple)
            or any(
                not isinstance(item, CrawlLinkSkip)
                for item in self.skipped_links
            )
        ):
            raise ScanContractValidationError(
                "crawl_scan_skipped_links_invalid",
                "skipped_links contains an invalid value.",
            )
        skipped_by_reason: dict[str, CrawlLinkSkip] = {}
        for item in self.skipped_links:
            if item.reason in skipped_by_reason:
                raise ScanContractValidationError(
                    "crawl_scan_skip_duplicate",
                    "A crawl skip reason can appear only once.",
                )
            skipped_by_reason[item.reason] = item

        if (
            self.pages
            and self.pages[0].status is ScanStatus.FAILED
            and len(self.pages) != 1
        ):
            raise ScanContractValidationError(
                "crawl_scan_pages_after_root_failure",
                "A crawl cannot contain child pages after the root request failed.",
            )

        if (
            self.termination.reason
            is CrawlTerminationReason.ROOT_REQUEST_FAILED
            and (
                not self.pages
                or self.pages[0].status is not ScanStatus.FAILED
            )
        ):
            raise ScanContractValidationError(
                "crawl_scan_root_failure_termination_invalid",
                "root_request_failed requires one failed root page.",
            )

        if (
            self.pages
            and self.pages[0].status is ScanStatus.FAILED
            and self.termination.reason
            not in {
                CrawlTerminationReason.ROOT_REQUEST_FAILED,
                CrawlTerminationReason.TIME_LIMIT_REACHED,
                CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
                CrawlTerminationReason.CANCELLED,
            }
        ):
            raise ScanContractValidationError(
                "crawl_scan_root_failure_termination_missing",
                "A failed root page requires an explicit root or budget "
                "termination reason.",
            )

        if (
            self.termination.reason
            is CrawlTerminationReason.CANCELLED
        ):
            expected_status = ScanStatus.CANCELLED
        elif self.termination.reason in {
            CrawlTerminationReason.TIME_LIMIT_REACHED,
            CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
        }:
            expected_status = ScanStatus.COMPLETED_WITH_ERRORS
        elif (
            self.pages
            and self.pages[0].status is ScanStatus.FAILED
        ):
            expected_status = ScanStatus.FAILED
        elif any(
            page.status is not ScanStatus.COMPLETED
            for page in self.pages
        ):
            expected_status = ScanStatus.COMPLETED_WITH_ERRORS
        else:
            expected_status = ScanStatus.COMPLETED
        if self.status is not expected_status:
            raise ScanContractValidationError(
                "crawl_scan_status_inconsistent",
                "Crawl scan status is inconsistent with page outcomes.",
            )

        object.__setattr__(self, "scan_id", scan_id)
        object.__setattr__(
            self,
            "scan_type",
            _identifier(self.scan_type, "scan_type"),
        )
        object.__setattr__(self, "target", target)
        object.__setattr__(
            self,
            "engine",
            _identifier(self.engine, "engine"),
        )
        object.__setattr__(
            self,
            "engine_version",
            _required_text(self.engine_version, "engine_version", 64),
        )
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "completed_at", completed_at)
        object.__setattr__(
            self,
            "skipped_links",
            tuple(sorted(skipped_by_reason.values())),
        )

    @property
    def coverage(self) -> CrawlScanCoverage:
        return CrawlScanCoverage.from_pages(
            self.pages,
            pages_pending=self.termination.pages_pending,
        )

    @property
    def findings(self) -> Tuple[NormalizedFinding, ...]:
        return tuple(
            sorted(
                (
                    finding
                    for page in self.pages
                    for finding in page.findings
                ),
                key=lambda item: item.fingerprint,
            )
        )

    @property
    def errors(self) -> Tuple[ScanError, ...]:
        page_errors = tuple(
            error
            for page in self.pages
            for error in page.errors
        )
        termination_error = self.termination.error
        if termination_error is None:
            return page_errors
        return (*page_errors, termination_error)

    @property
    def connected_addresses(self) -> Tuple[str, ...]:
        addresses = {
            page.connected_address
            for page in self.pages
            if page.connected_address is not None
        }
        return tuple(
            sorted(
                addresses,
                key=lambda value: (
                    ipaddress.ip_address(value).version,
                    int(ipaddress.ip_address(value)),
                ),
            )
        )

    @property
    def http_statuses(self) -> Tuple[int, ...]:
        return tuple(
            sorted(
                {
                    page.http_status
                    for page in self.pages
                    if page.http_status is not None
                }
            )
        )

    @property
    def request_attempt_count(self) -> int:
        return sum(len(page.request_attempts) for page in self.pages)

    def _combined_attempts(self) -> list[dict[str, Any]]:
        combined: list[dict[str, Any]] = []
        sequence = 0
        for page in self.pages:
            for attempt in page.request_attempts:
                sequence += 1
                data = attempt.to_dict()
                local_number = data.pop("attempt_number")
                combined.append(
                    {
                        "sequence": sequence,
                        "page_url": page.url,
                        "page_attempt_number": local_number,
                        **data,
                    }
                )
        return combined

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_type": self.report_type,
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "status": self.status.value,
            "target": self.target,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "started_at": _timestamp(self.started_at),
            "completed_at": _timestamp(self.completed_at),
            "policy": self.policy.to_dict(),
            "termination": self.termination.to_dict(),
            "coverage": self.coverage.to_dict(),
            "page_count": len(self.pages),
            "pages": [page.to_dict() for page in self.pages],
            "skipped_links": [item.to_dict() for item in self.skipped_links],
            "finding_count": len(self.findings),
            "error_count": len(self.errors),
            "connected_addresses": list(self.connected_addresses),
            "http_statuses": list(self.http_statuses),
            "request_attempt_count": self.request_attempt_count,
            "request_attempts": self._combined_attempts(),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


def _bounded_integer(
    value: object,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise ScanContractValidationError(
            f"{name}_invalid",
            f"{name} must be an integer from {minimum} to {maximum}.",
        )
    return value


def _media_type(value: object, field_name: str) -> str:
    cleaned = _required_text(value, field_name, 255).lower()
    if _MEDIA_TYPE.fullmatch(cleaned) is None:
        raise ScanContractValidationError(
            f"{field_name}_invalid",
            f"{field_name} must be a valid media type.",
        )
    return cleaned


def _path_segment(value: object, field_name: str) -> str:
    cleaned = _required_text(value, field_name, 64).lower()
    if "/" in cleaned or "\\" in cleaned or any(ord(char) < 33 for char in cleaned):
        raise ScanContractValidationError(
            f"{field_name}_invalid",
            f"{field_name} must be one bounded path segment.",
        )
    return cleaned


def _canonical_text_tuple(
    values: object,
    *,
    field_name: str,
    normalizer,
) -> Tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ScanContractValidationError(
            f"{field_name}s_invalid",
            f"{field_name}s must be a tuple.",
        )
    normalized = tuple(
        sorted(
            {
                normalizer(value, field_name)
                for value in values
            }
        )
    )
    if len(normalized) != len(values):
        raise ScanContractValidationError(
            f"{field_name}s_duplicate",
            f"{field_name}s cannot contain duplicates.",
        )
    return normalized


__all__ = [
    "CrawlLinkSkip",
    "CrawlPageScanResult",
    "CrawlScanCoverage",
    "CrawlScanPolicy",
    "CrawlScanResult",
    "MAXIMUM_CRAWL_REPORT_DELAY_SECONDS",
    "MAXIMUM_CRAWL_REPORT_DEPTH",
    "MAXIMUM_CRAWL_REPORT_LINKS_PER_PAGE",
    "MAXIMUM_CRAWL_REPORT_PAGES",
    "MAXIMUM_CRAWL_REPORT_URL_LENGTH",
]
