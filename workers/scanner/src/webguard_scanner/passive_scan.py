"""Passive HTTP header scan orchestration for OpenHuntX WebGuard."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from webguard_contracts import (
    ScanCoverage,
    ScanError,
    ScanResult,
    ScanStatus,
    SkippedCheck,
)

from .header_analyzer import (
    HeaderAnalysisError,
    analyze_security_headers,
)
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
        requests_attempted=1,
        requests_succeeded=1,
    )


def _failed_coverage(
    target: ValidatedTarget,
    *,
    request_succeeded: bool,
) -> ScanCoverage:
    """Build partial coverage for a controlled scan failure."""

    return ScanCoverage(
        planned_checks=PASSIVE_HEADER_CHECKS,
        executed_checks=(),
        skipped_checks=_skipped_checks_for_target(target),
        requests_attempted=1,
        requests_succeeded=int(request_succeeded),
    )


def _failed_result(
    *,
    scan_id: str,
    target: ValidatedTarget,
    started_at: datetime,
    error: ScanError,
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
    scan_id: str | None = None,
    started_at: datetime | None = None,
) -> ScanResult:
    """Run one bounded passive header scan and return a ScanResult.

    The target must already have passed the appropriate scope-validation
    policy. This function sends one GET request and does not run active
    payloads or follow redirects.

    Controlled request and analysis failures are returned as validated
    failed ScanResult objects. Unexpected exceptions are intentionally
    not suppressed.
    """

    effective_scan_id = scan_id or str(uuid4())
    effective_started_at = started_at or _utc_now()

    try:
        response = fetch_once(
            target,
            method="GET",
            policy=fetch_policy,
        )
    except SafeRequestError as exc:
        return _failed_result(
            scan_id=effective_scan_id,
            target=target,
            started_at=effective_started_at,
            error=ScanError(
                code=exc.code,
                message=exc.message,
                stage="request",
                retryable=False,
            ),
            request_succeeded=False,
        )

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
                retryable=False,
            ),
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
        coverage=_successful_coverage(target),
        findings=findings,
        connected_addresses=(
            response.connected_address,
        ),
        http_statuses=(
            response.status,
        ),
    )
