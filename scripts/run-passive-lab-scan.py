#!/usr/bin/env python3
"""Run an authorised passive header scan against a local lab target."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from webguard_contracts import ScanStatus

from webguard_scanner import (
    FetchPolicy,
    RetryPolicy,
    TargetValidationError,
    ValidationMode,
    ValidationPolicy,
    run_passive_header_scan,
    validate_target_url,
)


DEFAULT_TARGET = "http://127.0.0.1:3000/"
DEFAULT_OUTPUT = "scan-results/passive-header-lab.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a passive HTTP security-header assessment against an "
            "explicitly authorised local laboratory target."
        )
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Lab target URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"JSON output path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        dest="allowed_hosts",
        default=[],
        help=(
            "Explicitly allow an authorised lab hostname. May be repeated."
        ),
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=1,
        help=(
            "Maximum total request attempts. The default of 1 disables "
            "retries; the enforced maximum is 3."
        ),
    )
    return parser.parse_args()


def build_allowed_hosts(
    target_url: str,
    configured: list[str],
) -> frozenset[str]:
    """Build a restrictive lab allowlist."""

    parsed = urlsplit(target_url)

    if parsed.hostname is None:
        raise ValueError(
            "The target URL does not contain a hostname."
        )

    allowed_hosts = frozenset(
        {
            "127.0.0.1",
            "localhost",
            *configured,
        }
    )

    if parsed.hostname not in allowed_hosts:
        raise ValueError(
            "The target hostname is not allowlisted. "
            "Use --allow-host only for an authorised lab hostname."
        )

    return allowed_hosts


def _display_values(
    values: tuple[object, ...],
) -> str:
    """Render result metadata without assuming a value is present."""

    if not values:
        return "none"

    return ", ".join(
        str(value)
        for value in values
    )


def main() -> int:
    args = parse_args()

    try:
        allowed_hosts = build_allowed_hosts(
            args.target,
            args.allowed_hosts,
        )

        target = validate_target_url(
            args.target,
            ValidationPolicy(
                mode=ValidationMode.LAB,
                allowed_lab_hosts=allowed_hosts,
            ),
        )

        retry_policy = RetryPolicy(
            maximum_attempts=args.max_attempts,
        )
    except (
        TargetValidationError,
        ValueError,
    ) as exc:
        error_code = getattr(
            exc,
            "code",
            "lab_preflight_failed",
        )

        print(
            json.dumps(
                {
                    "status": "rejected",
                    "error_code": error_code,
                    "message": str(exc),
                    "stage": "preflight",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    result = run_passive_header_scan(
        target,
        fetch_policy=FetchPolicy(
            timeout_seconds=5,
            maximum_body_bytes=2_097_152,
            maximum_header_bytes=65_536,
            maximum_header_count=100,
        ),
        retry_policy=retry_policy,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    output_path.write_text(
        json.dumps(
            result.to_dict(),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Scan ID: {result.scan_id}")
    print(f"Status: {result.status.value}")
    print(f"Target: {result.target}")
    print(
        "Connected address: "
        f"{_display_values(result.connected_addresses)}"
    )
    print(
        "HTTP status: "
        f"{_display_values(result.http_statuses)}"
    )
    print(
        "Requests: "
        f"{result.coverage.requests_attempted} attempted, "
        f"{result.coverage.requests_succeeded} succeeded"
    )
    print(
        "Coverage: "
        f"{result.coverage.completion_percent}% executed"
    )
    print(f"Findings: {len(result.findings)}")

    for finding in result.findings:
        print(
            f"- [{finding.severity.value.upper()}] "
            f"{finding.title} "
            f"({finding.identity.rule_id})"
        )

    for skipped in result.coverage.skipped_checks:
        print(
            f"- [SKIPPED] {skipped.check_id}: "
            f"{skipped.reason}"
        )

    for error in result.errors:
        print(
            f"- [ERROR] {error.stage}/{error.code}: "
            f"{error.message} "
            f"(retryable: {'yes' if error.retryable else 'no'})"
        )

    print(f"Saved report: {output_path}")

    if result.status is ScanStatus.FAILED:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
