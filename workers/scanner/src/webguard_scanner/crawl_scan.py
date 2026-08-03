
"""Page-aware passive crawl scan orchestration for OpenHuntX WebGuard."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from webguard_contracts import (
    CrawlCheckpoint,
    CrawlCheckpointFetchPolicy,
    CrawlCheckpointPendingPage,
    CrawlCheckpointRetryPolicy,
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
    validate_crawl_checkpoint_resume,
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
    CrawlPageRecord,
    CrawlPendingPage,
    CrawlPolicy,
    CrawlQueryMode,
    CrawlResumeState,
    CrawlSkipReason,
    CrawlSkipSummary,
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


CheckpointCallback = Callable[[CrawlCheckpoint], None]


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


def _fetch_policy_snapshot(
    policy: FetchPolicy,
) -> CrawlCheckpointFetchPolicy:
    return CrawlCheckpointFetchPolicy(
        timeout_seconds=policy.timeout_seconds,
        maximum_body_bytes=policy.maximum_body_bytes,
        maximum_header_bytes=policy.maximum_header_bytes,
        maximum_header_count=policy.maximum_header_count,
    )


def _retry_policy_snapshot(
    policy: RetryPolicy,
) -> CrawlCheckpointRetryPolicy:
    return CrawlCheckpointRetryPolicy(
        maximum_attempts=policy.maximum_attempts,
        initial_backoff_seconds=policy.initial_backoff_seconds,
        backoff_multiplier=policy.backoff_multiplier,
        maximum_backoff_seconds=policy.maximum_backoff_seconds,
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


def _target_for_page(
    root_target: ValidatedTarget,
    url: str,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme=root_target.scheme,
        hostname=root_target.hostname,
        port=root_target.port,
        resolved_addresses=root_target.resolved_addresses,
    )


def _failed_page_result(
    root_target: ValidatedTarget,
    page: CrawlPageRecord,
    planned_checks: tuple[str, ...],
) -> CrawlPageScanResult:
    page_target = _target_for_page(root_target, page.url)
    error_code = page.error_code or "request_failed"
    retryable = bool(page.retryable)
    return CrawlPageScanResult(
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


def _successful_page_result(
    root_target: ValidatedTarget,
    page: CrawlPageRecord,
    pipeline: AnalyzerPipelineResult,
    planned_checks: tuple[str, ...],
) -> CrawlPageScanResult:
    return CrawlPageScanResult(
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


def _page_record_from_checkpoint(
    page: CrawlPageScanResult,
) -> CrawlPageRecord:
    if page.status is ScanStatus.FAILED:
        request_errors = tuple(
            item
            for item in page.errors
            if item.stage == "request"
        )
        if not request_errors:
            raise ValueError(
                "A failed checkpoint page is missing its request error."
            )
        error = request_errors[0]
        return CrawlPageRecord(
            url=page.url,
            depth=page.depth,
            parent_url=page.parent_url,
            outcome=CrawlPageOutcome.FAILED,
            attempts=page.request_attempts,
            error_code=error.code,
            retryable=error.retryable,
        )

    return CrawlPageRecord(
        url=page.url,
        depth=page.depth,
        parent_url=page.parent_url,
        outcome=CrawlPageOutcome.SUCCEEDED,
        attempts=page.request_attempts,
        content_type=page.content_type,
        connected_address=page.connected_address,
        http_status=page.http_status,
        discovered_links=page.discovered_links,
        queued_links=page.queued_links,
    )


def _resume_state_from_checkpoint(
    checkpoint: CrawlCheckpoint,
) -> CrawlResumeState:
    return CrawlResumeState(
        root_url=checkpoint.target,
        pages=tuple(
            _page_record_from_checkpoint(page)
            for page in checkpoint.pages
        ),
        pending_pages=tuple(
            CrawlPendingPage(
                url=page.url,
                depth=page.depth,
                parent_url=page.parent_url,
            )
            for page in checkpoint.pending_pages
        ),
        visited_urls=checkpoint.visited_urls,
        skipped_links=tuple(
            CrawlSkipSummary(
                reason=CrawlSkipReason(item.reason),
                count=item.count,
            )
            for item in checkpoint.skipped_links
        ),
        elapsed_execution_seconds=(
            checkpoint.elapsed_execution_seconds
        ),
        attempts_used=checkpoint.attempts_used,
    )


def _materialize_page_results(
    *,
    root_target: ValidatedTarget,
    state: CrawlResumeState,
    existing_pages: dict[str, CrawlPageScanResult],
    analysis_by_url: dict[str, AnalyzerPipelineResult],
    planned_checks: tuple[str, ...],
) -> tuple[CrawlPageScanResult, ...]:
    results: list[CrawlPageScanResult] = []

    for page in state.pages:
        existing = existing_pages.get(page.url)
        if existing is not None:
            results.append(existing)
            continue

        if page.outcome is CrawlPageOutcome.FAILED:
            result = _failed_page_result(
                root_target,
                page,
                planned_checks,
            )
        else:
            pipeline = analysis_by_url.get(page.url)
            if pipeline is None:
                raise RuntimeError(
                    "A successful crawl page is missing analyser output."
                )
            result = _successful_page_result(
                root_target,
                page,
                pipeline,
                planned_checks,
            )

        existing_pages[page.url] = result
        results.append(result)

    return tuple(results)


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
    resume_checkpoint: CrawlCheckpoint | None = None,
    checkpoint_callback: CheckpointCallback | None = None,
) -> CrawlScanResult:
    """Crawl, analyse, checkpoint, or safely resume same-origin pages.

    Checkpoints contain only validated audit state and analyser results. HTTP
    response bodies, cookie values, and arbitrary response headers are never
    persisted. A resumed crawl reuses the original scan ID, start time, policy,
    visited-page set, pending breadth-first queue, elapsed time, and consumed
    request-attempt budget.
    """

    registry = validate_analyzer_registry(analyzers)
    planned_checks = registered_checks(registry)
    policy_snapshot = _policy_snapshot(crawl_policy)
    fetch_snapshot = _fetch_policy_snapshot(fetch_policy)
    retry_snapshot = _retry_policy_snapshot(retry_policy)

    existing_pages: dict[str, CrawlPageScanResult] = {}
    resume_state: CrawlResumeState | None = None

    if resume_checkpoint is None:
        effective_scan_id = scan_id or str(uuid4())
        effective_started_at = started_at or _utc_now()
    else:
        if scan_id is not None and scan_id != resume_checkpoint.scan_id:
            raise ValueError(
                "scan_id cannot differ from the resume checkpoint."
            )
        if (
            started_at is not None
            and started_at.astimezone(timezone.utc)
            != resume_checkpoint.started_at
        ):
            raise ValueError(
                "started_at cannot differ from the resume checkpoint."
            )

        validate_crawl_checkpoint_resume(
            resume_checkpoint,
            target=root_target.normalised_url,
            resolved_addresses=root_target.resolved_addresses,
            policy=policy_snapshot,
            fetch_policy=fetch_snapshot,
            retry_policy=retry_snapshot,
            engine=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
        )
        effective_scan_id = resume_checkpoint.scan_id
        effective_started_at = resume_checkpoint.started_at
        existing_pages = {
            page.url: page
            for page in resume_checkpoint.pages
        }
        resume_state = _resume_state_from_checkpoint(
            resume_checkpoint
        )

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

    def checkpoint_state(state: CrawlResumeState) -> None:
        if checkpoint_callback is None:
            return

        pages = _materialize_page_results(
            root_target=root_target,
            state=state,
            existing_pages=existing_pages,
            analysis_by_url=analysis_by_url,
            planned_checks=planned_checks,
        )
        checkpoint_callback(
            CrawlCheckpoint(
                scan_id=effective_scan_id,
                target=state.root_url,
                resolved_addresses=(
                    root_target.resolved_addresses
                ),
                engine=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                started_at=effective_started_at,
                updated_at=_utc_now(),
                policy=policy_snapshot,
                fetch_policy=fetch_snapshot,
                retry_policy=retry_snapshot,
                pages=pages,
                pending_pages=tuple(
                    CrawlCheckpointPendingPage(
                        url=item.url,
                        depth=item.depth,
                        parent_url=item.parent_url,
                    )
                    for item in state.pending_pages
                ),
                visited_urls=state.visited_urls,
                skipped_links=tuple(
                    CrawlLinkSkip(
                        reason=item.reason.value,
                        count=item.count,
                    )
                    for item in state.skipped_links
                ),
                elapsed_execution_seconds=(
                    state.elapsed_execution_seconds
                ),
                attempts_used=state.attempts_used,
            )
        )

    execution = crawl_same_origin(
        root_target,
        crawl_policy=crawl_policy,
        fetch_policy=fetch_policy,
        retry_policy=retry_policy,
        on_page=analyze_page,
        cancellation_token=cancellation_token,
        resume_state=resume_state,
        on_checkpoint=checkpoint_state,
    )

    # Avoid reconstructing a pending queue from a count. The checkpoint callback
    # has already persisted it; the report needs only completed page results.
    pages: list[CrawlPageScanResult] = []
    for page in execution.pages:
        existing = existing_pages.get(page.url)
        if existing is not None:
            pages.append(existing)
            continue

        if page.outcome is CrawlPageOutcome.FAILED:
            result = _failed_page_result(
                root_target,
                page,
                planned_checks,
            )
        else:
            pipeline = analysis_by_url.get(page.url)
            if pipeline is None:
                raise RuntimeError(
                    "A successful crawl page is missing analyser output."
                )
            result = _successful_page_result(
                root_target,
                page,
                pipeline,
                planned_checks,
            )
        existing_pages[page.url] = result
        pages.append(result)

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
        policy=policy_snapshot,
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


__all__ = [
    "CheckpointCallback",
    "run_passive_crawl_scan",
]
