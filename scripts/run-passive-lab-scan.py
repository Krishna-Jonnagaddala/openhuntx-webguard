#!/usr/bin/env python3
"""Run an authorised passive header scan against a local lab target."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from webguard_scanner import (
    FetchPolicy,
    SafeRequestError,
    TargetValidationError,
    ValidationMode,
    ValidationPolicy,
    analyze_security_headers,
    fetch_once,
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
            "Explicitly allow a lab hostname. May be repeated. "
            "The target hostname is included automatically."
        ),
    )
    return parser.parse_args()


def build_allowed_hosts(target_url: str, configured: list[str]) -> frozenset[str]:
    parsed = urlsplit(target_url)

    if parsed.hostname is None:
        raise ValueError("The target URL does not contain a hostname.")

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

        response = fetch_once(
            target,
            method="GET",
            policy=FetchPolicy(
                timeout_seconds=5,
                maximum_body_bytes=2_097_152,
                maximum_header_bytes=65_536,
                maximum_header_count=100,
            ),
        )

        findings = analyze_security_headers(
            target,
            response,
        )

    except (
        TargetValidationError,
        SafeRequestError,
        ValueError,
    ) as exc:
        error_code = getattr(
            exc,
            "code",
            "lab_scan_failed",
        )
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_code": error_code,
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    document = {
        "scan_schema_version": "0.1",
        "scan_type": "passive-http-headers",
        "generated_at": (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "target": target.normalised_url,
        "connected_address": response.connected_address,
        "http_status": response.status,
        "elapsed_milliseconds": response.elapsed_milliseconds,
        "finding_count": len(findings),
        "findings": [
            finding.to_dict()
            for finding in findings
        ],
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    output_path.write_text(
        json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Target: {document['target']}")
    print(
        "Connected address: "
        f"{document['connected_address']}"
    )
    print(f"HTTP status: {document['http_status']}")
    print(f"Findings: {document['finding_count']}")

    for finding in findings:
        print(
            f"- [{finding.severity.value.upper()}] "
            f"{finding.title} "
            f"({finding.identity.rule_id})"
        )

    print(f"Saved report: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
