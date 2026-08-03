"""Passive HTTP header scan orchestration for OpenHuntX WebGuard."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from webguard_contracts import (
    ScanCoverage,
    ScanResult,
    ScanStatus,
    SkippedCheck,
)

from .header_analyzer import analyze_security_headers
from .safe_http import FetchPolicy, fetch_once
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


def _coverage_for_target(
    target: ValidatedTarget,
) -> ScanCoverage:
    """Build explicit passive-check coverage for the target scheme."""

    if target.scheme == "https":
        executed_checks = PASSIVE_HEADER_CHECKS
        skipped_checks: tuple[SkippedCheck, ...] = ()
    else:
        executed_checks = tuple(
            check_id
            for check_id in PASSIVE_HEADER_CHECKS
            if check_id != "web.headers.hsts"
        )
        skipped_checks = (
            SkippedCheck(
                check_id="web.headers.hsts",
                reason=(
                    "HSTS applies only to HTTPS responses and was not "
                    "evaluated for this HTTP target."
                ),
            ),
        )

    return ScanCoverage(
        planned_checks=PASSIVE_HEADER_CHECKS,
        executed_checks=executed_checks,
        skipped_checks=skipped_checks,
        requests_attempted=1,
        requests_succeeded=1,
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
    """

    effective_scan_id = scan_id or str(uuid4())
    effective_started_at = started_at or _utc_now()

    response = fetch_once(
        target,
        method="GET",
        policy=fetch_policy,
    )

    findings = analyze_security_headers(
        target,
        response,
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
        coverage=_coverage_for_target(target),
        findings=findings,
        connected_addresses=(
            response.connected_address,
        ),
        http_statuses=(
            response.status,
        ),
    )
