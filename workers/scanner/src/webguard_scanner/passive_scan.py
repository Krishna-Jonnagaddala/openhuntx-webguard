"""Passive HTTP response scan orchestration for OpenHuntX WebGuard."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from uuid import uuid4

from webguard_contracts import (
    RequestAttempt,
    RequestAttemptOutcome,
    ScanCoverage,
    ScanError,
    ScanResult,
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
from .cookie_analyzer import (
    COOKIE_CHECKS,
    CookieAnalysisError,
    analyze_cookies,
)
from .cors_analyzer import (
    CORS_CHECKS,
    CorsAnalysisError,
    analyze_cors,
)
from .disclosure_analyzer import (
    DISCLOSURE_CHECKS,
    DisclosureAnalysisError,
    analyze_information_disclosure,
)
from .error_taxonomy import is_retryable_error
from .header_analyzer import (
    HeaderAnalysisError,
    analyze_security_headers,
)
from .html_analyzer import (
    HTML_CHECKS,
    HtmlAnalysisError,
    analyze_html_security,
)
from .tls_analyzer import (
    TLS_CHECKS,
    TlsAnalysisError,
    analyze_tls_security,
)
from .retry_policy import RetryPolicy
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .safe_http import (
    FetchPolicy,
    SafeRequestError,
    fetch_once,
)
from .scope_validator import ValidatedTarget


ENGINE_NAME = "webguard-native"
ENGINE_VERSION = "0.1.0"

PASSIVE_HEADER_CHECKS = (
    "web.headers.csp",
    "web.headers.frame_protection",
    "web.headers.hsts",
    "web.headers.referrer_policy",
    "web.headers.x_content_type_options",
)

PASSIVE_COOKIE_CHECKS = COOKIE_CHECKS
PASSIVE_CORS_CHECKS = CORS_CHECKS
PASSIVE_DISCLOSURE_CHECKS = DISCLOSURE_CHECKS
PASSIVE_HTML_CHECKS = HTML_CHECKS
PASSIVE_TLS_CHECKS = TLS_CHECKS


def _run_header_analyzer(target, response):
    return analyze_security_headers(target, response)


def _run_cookie_analyzer(target, response):
    return analyze_cookies(target, response)


def _run_cors_analyzer(target, response):
    return analyze_cors(target, response)


def _run_disclosure_analyzer(target, response):
    return analyze_information_disclosure(target, response)


def _run_html_analyzer(target, response):
    return analyze_html_security(target, response)


def _run_tls_analyzer(target, response):
    return analyze_tls_security(target, response)


DEFAULT_PASSIVE_ANALYZERS = validate_analyzer_registry(
    (
        PassiveAnalyzer(
            analyzer_id="headers",
            checks=PASSIVE_HEADER_CHECKS,
            finding_namespace="web.headers",
            analyze=_run_header_analyzer,
            controlled_error=HeaderAnalysisError,
        ),
        PassiveAnalyzer(
            analyzer_id="cookies",
            checks=PASSIVE_COOKIE_CHECKS,
            finding_namespace="web.cookies",
            analyze=_run_cookie_analyzer,
            controlled_error=CookieAnalysisError,
        ),
        PassiveAnalyzer(
            analyzer_id="cors",
            checks=PASSIVE_CORS_CHECKS,
            finding_namespace="web.cors",
            analyze=_run_cors_analyzer,
            controlled_error=CorsAnalysisError,
        ),
        PassiveAnalyzer(
            analyzer_id="disclosure",
            checks=PASSIVE_DISCLOSURE_CHECKS,
            finding_namespace="web.disclosure",
            analyze=_run_disclosure_analyzer,
            controlled_error=DisclosureAnalysisError,
        ),
        PassiveAnalyzer(
            analyzer_id="html",
            checks=PASSIVE_HTML_CHECKS,
            finding_namespace="web.html",
            analyze=_run_html_analyzer,
            controlled_error=HtmlAnalysisError,
        ),
        PassiveAnalyzer(
            analyzer_id="tls",
            checks=PASSIVE_TLS_CHECKS,
            finding_namespace="web.tls",
            analyze=_run_tls_analyzer,
            controlled_error=TlsAnalysisError,
        ),
    )
)

PASSIVE_CHECKS = registered_checks(DEFAULT_PASSIVE_ANALYZERS)


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def _skipped_checks_for_target(
    target: ValidatedTarget,
    planned_checks: tuple[str, ...],
) -> tuple[SkippedCheck, ...]:
    """Return registered checks that do not apply to the target."""

    if target.scheme == "https":
        return ()

    skipped: list[SkippedCheck] = []

    if "web.headers.hsts" in planned_checks:
        skipped.append(
            SkippedCheck(
                check_id="web.headers.hsts",
                reason=(
                    "HSTS applies only to HTTPS responses and was not "
                    "evaluated for this HTTP target."
                ),
            )
        )

    for check_id in PASSIVE_TLS_CHECKS:
        if check_id in planned_checks:
            skipped.append(
                SkippedCheck(
                    check_id=check_id,
                    reason=(
                        "TLS connection and certificate analysis applies only "
                        "to HTTPS targets."
                    ),
                )
            )

    return tuple(sorted(skipped, key=lambda item: item.check_id))


def _request_failure_coverage(
    target: ValidatedTarget,
    *,
    planned_checks: tuple[str, ...],
    requests_attempted: int,
) -> ScanCoverage:
    """Build coverage for a request that never produced a response."""

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


def _analysis_coverage(
    pipeline: AnalyzerPipelineResult,
    *,
    planned_checks: tuple[str, ...],
    requests_attempted: int,
) -> ScanCoverage:
    """Build exact coverage from the registered analyser pipeline."""

    return ScanCoverage(
        planned_checks=planned_checks,
        executed_checks=pipeline.executed_checks,
        skipped_checks=pipeline.skipped_checks,
        requests_attempted=requests_attempted,
        requests_succeeded=1,
    )


def _request_failed_result(
    *,
    scan_id: str,
    target: ValidatedTarget,
    started_at: datetime,
    error: ScanError,
    planned_checks: tuple[str, ...],
    request_attempts: tuple[RequestAttempt, ...],
) -> ScanResult:
    """Create a validated failed result for request-stage failure."""

    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-headers",
        status=ScanStatus.FAILED,
        target=target.normalised_url,
        engine=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        started_at=started_at,
        completed_at=_utc_now(),
        coverage=_request_failure_coverage(
            target,
            planned_checks=planned_checks,
            requests_attempted=len(request_attempts),
        ),
        errors=(error,),
        request_attempts=request_attempts,
    )


def run_passive_header_scan(
    target: ValidatedTarget,
    *,
    fetch_policy: FetchPolicy = FetchPolicy(),
    retry_policy: RetryPolicy = RetryPolicy(),
    analyzers: tuple[PassiveAnalyzer, ...] = DEFAULT_PASSIVE_ANALYZERS,
    scan_id: str | None = None,
    started_at: datetime | None = None,
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
) -> ScanResult:
    """Run one bounded passive HTTP response scan.

    The target must already have passed scope validation. One GET request is
    made unless explicitly configured transient retries are required. The
    response is then passed through the registered passive analyser pipeline.

    Controlled analyser failures are isolated, their checks are accounted as
    skipped, successful findings are preserved, and the result becomes
    ``completed_with_errors``. Unexpected exceptions and output-contract
    violations deliberately surface.
    """

    registry = validate_analyzer_registry(analyzers)
    planned_checks = registered_checks(registry)
    if before_request is not None and not callable(before_request):
        raise TypeError("before_request must be callable or null.")
    if after_request is not None and not callable(after_request):
        raise TypeError("after_request must be callable or null.")

    effective_scan_id = scan_id or str(uuid4())
    effective_started_at = started_at or _utc_now()
    request_attempts: list[RequestAttempt] = []

    while True:
        attempt_number = len(request_attempts) + 1
        attempt_started_at = _utc_now()

        if before_request is not None:
            before_request(target, "GET")

        try:
            response = fetch_once(
                target,
                method="GET",
                policy=fetch_policy,
            )
        except SafeRequestError as exc:
            attempt_completed_at = _utc_now()
            if after_request is not None:
                after_request(target, "GET", None, exc.code)
            retryable = is_retryable_error(
                stage="request",
                code=exc.code,
            )

            attempts_exhausted = (
                attempt_number
                >= retry_policy.maximum_attempts
            )
            retry_scheduled = (
                retryable
                and not attempts_exhausted
            )
            delay = (
                retry_policy.delay_after_failure(
                    attempt_number
                )
                if retry_scheduled
                else 0.0
            )

            request_attempts.append(
                RequestAttempt(
                    attempt_number=attempt_number,
                    started_at=attempt_started_at,
                    completed_at=attempt_completed_at,
                    outcome=RequestAttemptOutcome.FAILED,
                    error_code=exc.code,
                    retryable=retryable,
                    retry_scheduled=retry_scheduled,
                    backoff_seconds=delay,
                )
            )

            if not retry_scheduled:
                return _request_failed_result(
                    scan_id=effective_scan_id,
                    target=target,
                    started_at=effective_started_at,
                    error=ScanError(
                        code=exc.code,
                        message=exc.message,
                        stage="request",
                        retryable=retryable,
                    ),
                    planned_checks=planned_checks,
                    request_attempts=tuple(request_attempts),
                )

            if delay > 0:
                time.sleep(delay)

            continue

        attempt_completed_at = _utc_now()
        if after_request is not None:
            after_request(target, "GET", response, None)
        request_attempts.append(
            RequestAttempt(
                attempt_number=attempt_number,
                started_at=attempt_started_at,
                completed_at=attempt_completed_at,
                outcome=RequestAttemptOutcome.SUCCEEDED,
                connected_address=response.connected_address,
                http_status=response.status,
            )
        )
        break

    pipeline = execute_analyzers(
        target,
        response,
        analyzers=registry,
        pre_skipped_checks=_skipped_checks_for_target(
            target,
            planned_checks,
        ),
    )

    status = (
        ScanStatus.COMPLETED_WITH_ERRORS
        if pipeline.errors
        else ScanStatus.COMPLETED
    )

    return ScanResult(
        scan_id=effective_scan_id,
        scan_type="passive-http-headers",
        status=status,
        target=target.normalised_url,
        engine=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        started_at=effective_started_at,
        completed_at=_utc_now(),
        coverage=_analysis_coverage(
            pipeline,
            planned_checks=planned_checks,
            requests_attempted=len(request_attempts),
        ),
        findings=pipeline.findings,
        errors=pipeline.errors,
        connected_addresses=(response.connected_address,),
        http_statuses=(response.status,),
        request_attempts=tuple(request_attempts),
    )
