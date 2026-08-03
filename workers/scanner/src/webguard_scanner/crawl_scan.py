"""Page-aware passive crawl scan orchestration for OpenHuntX WebGuard."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from webguard_contracts import (
    CrawlLinkSkip,
    CrawlPageScanResult,
    CrawlScanPolicy,
    CrawlScanResult,
    CrawlScanTermination,
    CrawlTerminationReason,
    ScanCoverage,
    ScanError,
    ScanStatus,
    SkippedCheck,
)

from .analyzer_registry import (
    AnalyzerPipelineResult,
    PassiveAnalyzer,
    execute_analyzers,
    registered_checks,
    validate_analyzer_registry,
)
from .crawler import (
    CrawlCancellationToken,
    CrawlPageOutcome,
    CrawlPolicy,
    CrawlQueryMode,
    crawl_same_origin,
)
from .passive_scan import (
    DEFAULT_PASSIVE_ANALYZERS,
    ENGINE_NAME,
    ENGINE_VERSION,
)
from .retry_policy import RetryPolicy
from .safe_http import FetchPolicy
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _skipped_checks_for_target(
    target: ValidatedTarget,
    planned_checks: tuple[str, ...],
) -> tuple[SkippedCheck, ...]:
    if (
        target.scheme == "https"
        or "web.headers.hsts" not in planned_checks
    ):
        return ()

    return (
        SkippedCheck(
            check_id="web.headers.hsts",
            reason=(
                "HSTS applies only to HTTPS responses and was not "
                "evaluated for this HTTP target."
            ),
        ),
    )


def _policy_snapshot(policy: CrawlPolicy) -> CrawlScanPolicy:
    return CrawlScanPolicy(
        maximum_pages=policy.maximum_pages,
        maximum_depth=policy.maximum_depth,
        maximum_links_per_page=policy.maximum_links_per_page,
        maximum_url_length=policy.maximum_url_length,
        minimum_delay_seconds=policy.minimum_delay_seconds,
        maximum_execution_seconds=policy.maximum_execution_seconds,
        maximum_request_attempts=policy.maximum_request_attempts,
        query_mode=policy.query_mode.value,
        allowed_content_types=tuple(sorted(policy.allowed_content_types)),
        blocked_path_segments=tuple(sorted(policy.blocked_path_segments)),
    )


def _failed_page_coverage(
    target: ValidatedTarget,
    planned_checks: tuple[str, ...],
    requests_attempted: int,
) -> ScanCoverage:
    return ScanCoverage(
        planned_checks=planned_checks,
        executed_checks=(),
        skipped_checks=_skipped_checks_for_target(
            target,
            planned_checks,
        ),
        requests_attempted=requests_attempted,
        requests_succeeded=0,
    )


def _successful_page_coverage(
    pipeline: AnalyzerPipelineResult,
    *,
    planned_checks: tuple[str, ...],
    requests_attempted: int,
) -> ScanCoverage:
    return ScanCoverage(
        planned_checks=planned_checks,
        executed_checks=pipeline.executed_checks,
        skipped_checks=pipeline.skipped_checks,
        requests_attempted=requests_attempted,
        requests_succeeded=1,
    )


def run_passive_crawl_scan(
    root_target: ValidatedTarget,
    *,
    crawl_policy: CrawlPolicy = CrawlPolicy(),
    fetch_policy: FetchPolicy = FetchPolicy(),
    retry_policy: RetryPolicy = RetryPolicy(),
    analyzers: tuple[PassiveAnalyzer, ...] = DEFAULT_PASSIVE_ANALYZERS,
    scan_id: str | None = None,
    started_at: datetime | None = None,
    cancellation_token: CrawlCancellationToken | None = None,
) -> CrawlScanResult:
    """Crawl and passively analyse bounded same-origin HTML pages.

    Each successful response is analysed synchronously by the registered
    passive analyser pipeline. No additional analysis request is sent. A
    failed child page or controlled analyser failure is isolated to that page;
    an unexpected exception or analyser output-contract violation surfaces.
    """

    registry = validate_analyzer_registry(analyzers)
    planned_checks = registered_checks(registry)
    effective_scan_id = scan_id or str(uuid4())
    effective_started_at = started_at or _utc_now()
    analysis_by_url: dict[str, AnalyzerPipelineResult] = {}

    def analyze_page(
        page_target,
        response,
        _depth,
        _parent_url,
    ) -> None:
        analysis_by_url[page_target.normalised_url] = execute_analyzers(
            page_target,
            response,
            analyzers=registry,
            pre_skipped_checks=_skipped_checks_for_target(
                page_target,
                planned_checks,
            ),
        )

    execution = crawl_same_origin(
        root_target,
        crawl_policy=crawl_policy,
        fetch_policy=fetch_policy,
        retry_policy=retry_policy,
        on_page=analyze_page,
        cancellation_token=cancellation_token,
    )

    pages: list[CrawlPageScanResult] = []

    for page in execution.pages:
        page_target = ValidatedTarget(
            original_url=page.url,
            normalised_url=page.url,
            scheme=root_target.scheme,
            hostname=root_target.hostname,
            port=root_target.port,
            resolved_addresses=root_target.resolved_addresses,
        )

        if page.outcome is CrawlPageOutcome.FAILED:
            error_code = page.error_code or "request_failed"
            retryable = bool(page.retryable)
            pages.append(
                CrawlPageScanResult(
                    url=page.url,
                    depth=page.depth,
                    parent_url=page.parent_url,
                    status=ScanStatus.FAILED,
                    coverage=_failed_page_coverage(
                        page_target,
                        planned_checks,
                        len(page.attempts),
                    ),
                    request_attempts=page.attempts,
                    errors=(
                        ScanError(
                            code=error_code,
                            message=(
                                "The page request ended with controlled "
                                f"error {error_code!r}."
                            ),
                            stage="request",
                            retryable=retryable,
                        ),
                    ),
                )
            )
            continue

        pipeline = analysis_by_url.get(page.url)
        if pipeline is None:
            raise RuntimeError(
                "A successful crawl page is missing analyser output."
            )

        pages.append(
            CrawlPageScanResult(
                url=page.url,
                depth=page.depth,
                parent_url=page.parent_url,
                status=(
                    ScanStatus.COMPLETED_WITH_ERRORS
                    if pipeline.errors
                    else ScanStatus.COMPLETED
                ),
                coverage=_successful_page_coverage(
                    pipeline,
                    planned_checks=planned_checks,
                    requests_attempted=len(page.attempts),
                ),
                request_attempts=page.attempts,
                findings=pipeline.findings,
                errors=pipeline.errors,
                content_type=page.content_type,
                connected_address=page.connected_address,
                http_status=page.http_status,
                discovered_links=page.discovered_links,
                queued_links=page.queued_links,
            )
        )

    termination = CrawlScanTermination(
        reason=execution.termination_reason,
        pages_pending=execution.pages_pending,
    )

    if (
        execution.termination_reason
        is CrawlTerminationReason.CANCELLED
    ):
        status = ScanStatus.CANCELLED
    elif execution.termination_reason in {
        CrawlTerminationReason.TIME_LIMIT_REACHED,
        CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
    }:
        status = ScanStatus.COMPLETED_WITH_ERRORS
    elif (
        pages
        and pages[0].status is ScanStatus.FAILED
    ):
        status = ScanStatus.FAILED
    elif any(
        page.status is not ScanStatus.COMPLETED
        for page in pages
    ):
        status = ScanStatus.COMPLETED_WITH_ERRORS
    else:
        status = ScanStatus.COMPLETED

    return CrawlScanResult(
        scan_id=effective_scan_id,
        scan_type="passive-http-crawl",
        status=status,
        target=execution.root_url,
        engine=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        started_at=effective_started_at,
        completed_at=_utc_now(),
        policy=_policy_snapshot(crawl_policy),
        pages=tuple(pages),
        skipped_links=tuple(
            CrawlLinkSkip(
                reason=item.reason.value,
                count=item.count,
            )
            for item in execution.skipped_links
        ),
        termination=termination,
    )


__all__ = ["run_passive_crawl_scan"]
