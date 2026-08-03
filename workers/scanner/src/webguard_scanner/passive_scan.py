"""Passive HTTP header scan orchestration for OpenHuntX WebGuard."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from uuid import uuid4

from webguard_contracts import (
    ScanCoverage,
    ScanError,
    ScanResult,
    ScanStatus,
    SkippedCheck,
)

from .error_taxonomy import is_retryable_error
from .header_analyzer import (
    HeaderAnalysisError,
    analyze_security_headers,
)
from .retry_policy import RetryPolicy
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


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def _skipped_checks_for_target(
    target: ValidatedTarget,
) -> tuple[SkippedCheck, ...]:
    """Return checks that do not apply to the validated target."""

    if target.scheme == "https":
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


def _successful_coverage(
    target: ValidatedTarget,
    *,
    requests_attempted: int,
) -> ScanCoverage:
    """Build coverage for a completed passive scan."""

    skipped_checks = _skipped_checks_for_target(target)
    skipped_ids = {
        skipped.check_id
        for skipped in skipped_checks
    }

    executed_checks = tuple(
        check_id
        for check_id in PASSIVE_HEADER_CHECKS
        if check_id not in skipped_ids
    )

    return ScanCoverage(
        planned_checks=PASSIVE_HEADER_CHECKS,
        executed_checks=executed_checks,
        skipped_checks=skipped_checks,
        requests_attempted=requests_attempted,
        requests_succeeded=1,
    )


def _failed_coverage(
    target: ValidatedTarget,
    *,
    requests_attempted: int,
    request_succeeded: bool,
) -> ScanCoverage:
    """Build partial coverage for a controlled scan failure."""

    return ScanCoverage(
        planned_checks=PASSIVE_HEADER_CHECKS,
        executed_checks=(),
        skipped_checks=_skipped_checks_for_target(target),
        requests_attempted=requests_attempted,
        requests_succeeded=int(request_succeeded),
    )


def _failed_result(
    *,
    scan_id: str,
    target: ValidatedTarget,
    started_at: datetime,
    error: ScanError,
    requests_attempted: int,
    request_succeeded: bool,
    connected_addresses: tuple[str, ...] = (),
    http_statuses: tuple[int, ...] = (),
) -> ScanResult:
    """Create a validated failed ScanResult."""

    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-headers",
        status=ScanStatus.FAILED,
        target=target.normalised_url,
        engine=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        started_at=started_at,
        completed_at=_utc_now(),
        coverage=_failed_coverage(
            target,
            requests_attempted=requests_attempted,
            request_succeeded=request_succeeded,
        ),
        errors=(error,),
        connected_addresses=connected_addresses,
        http_statuses=http_statuses,
    )


def run_passive_header_scan(
    target: ValidatedTarget,
    *,
    fetch_policy: FetchPolicy = FetchPolicy(),
    retry_policy: RetryPolicy = RetryPolicy(),
    scan_id: str | None = None,
    started_at: datetime | None = None,
) -> ScanResult:
    """Run one bounded passive header scan and return a ScanResult.

    The target must already have passed the appropriate scope-validation
    policy. This function sends GET requests only, does not run active
    payloads, and does not follow redirects.

    Retries are disabled by default. When explicitly configured, only
    taxonomy-approved request errors can be retried. Analysis failures
    and unexpected exceptions are never retried.
    """

    effective_scan_id = scan_id or str(uuid4())
    effective_started_at = started_at or _utc_now()
    requests_attempted = 0

    while True:
        requests_attempted += 1

        try:
            response = fetch_once(
                target,
                method="GET",
                policy=fetch_policy,
            )
        except SafeRequestError as exc:
            retryable = is_retryable_error(
                stage="request",
                code=exc.code,
            )

            attempts_exhausted = (
                requests_attempted
                >= retry_policy.maximum_attempts
            )

            if not retryable or attempts_exhausted:
                return _failed_result(
                    scan_id=effective_scan_id,
                    target=target,
                    started_at=effective_started_at,
                    error=ScanError(
                        code=exc.code,
                        message=exc.message,
                        stage="request",
                        retryable=retryable,
                    ),
                    requests_attempted=requests_attempted,
                    request_succeeded=False,
                )

            delay = retry_policy.delay_after_failure(
                requests_attempted
            )

            if delay > 0:
                time.sleep(delay)

            continue

        break

    try:
        findings = analyze_security_headers(
            target,
            response,
        )
    except HeaderAnalysisError as exc:
        return _failed_result(
            scan_id=effective_scan_id,
            target=target,
            started_at=effective_started_at,
            error=ScanError(
                code=exc.code,
                message=exc.message,
                stage="analysis",
                retryable=is_retryable_error(
                    stage="analysis",
                    code=exc.code,
                ),
            ),
            requests_attempted=requests_attempted,
            request_succeeded=True,
            connected_addresses=(
                response.connected_address,
            ),
            http_statuses=(
                response.status,
            ),
        )

    return ScanResult(
        scan_id=effective_scan_id,
        scan_type="passive-http-headers",
        status=ScanStatus.COMPLETED,
        target=target.normalised_url,
        engine=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        started_at=effective_started_at,
        completed_at=_utc_now(),
        coverage=_successful_coverage(
            target,
            requests_attempted=requests_attempted,
        ),
        findings=findings,
        connected_addresses=(
            response.connected_address,
        ),
        http_statuses=(
            response.status,
        ),
    )
