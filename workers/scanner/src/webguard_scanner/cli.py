"""Command-line interface for OpenHuntX WebGuard."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import sys
from pathlib import Path
from typing import Sequence, TextIO
from uuid import uuid4

from webguard_contracts import (
    ScanReportLoadError,
    ScanResult,
    ScanStatus,
    load_scan_result_file,
)

from .passive_scan import ENGINE_VERSION, run_passive_header_scan
from .retry_policy import RetryPolicy
from .safe_http import FetchPolicy
from .scope_validator import (
    TargetValidationError,
    ValidationMode,
    ValidationPolicy,
    validate_target_url,
)


EXIT_SUCCESS = 0
EXIT_SCAN_FAILED = 1
EXIT_USAGE = 2
EXIT_PREFLIGHT_FAILED = 3
EXIT_REPORT_INVALID = 4
EXIT_OUTPUT_FAILED = 5

DEFAULT_OUTPUT_DIRECTORY = Path("scan-results")
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAXIMUM_BODY_BYTES = 1_048_576
DEFAULT_MAXIMUM_HEADER_BYTES = 65_536
DEFAULT_MAXIMUM_HEADER_COUNT = 100

MAXIMUM_CLI_TIMEOUT_SECONDS = 60.0
MAXIMUM_CLI_BODY_BYTES = 16 * 1024 * 1024
MAXIMUM_CLI_HEADER_BYTES = 1024 * 1024
MAXIMUM_CLI_HEADER_COUNT = 1000


class CliControlledError(ValueError):
    """A bounded user-facing CLI failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def _positive_bounded_float(
    value: object,
    *,
    name: str,
    maximum: float,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
    ):
        raise CliControlledError(
            f"{name}_invalid",
            f"{name.replace('_', ' ')} must be a number.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    number = float(value)

    if not math.isfinite(number) or not 0 < number <= maximum:
        raise CliControlledError(
            f"{name}_invalid",
            f"{name.replace('_', ' ')} must be greater than zero and "
            f"no more than {maximum:g}.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    return number


def _positive_bounded_integer(
    value: object,
    *,
    name: str,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise CliControlledError(
            f"{name}_invalid",
            f"{name.replace('_', ' ')} must be an integer from 1 to "
            f"{maximum}.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    return value


def _build_fetch_policy(args: argparse.Namespace) -> FetchPolicy:
    return FetchPolicy(
        timeout_seconds=_positive_bounded_float(
            args.timeout_seconds,
            name="timeout_seconds",
            maximum=MAXIMUM_CLI_TIMEOUT_SECONDS,
        ),
        maximum_body_bytes=_positive_bounded_integer(
            args.maximum_body_bytes,
            name="maximum_body_bytes",
            maximum=MAXIMUM_CLI_BODY_BYTES,
        ),
        maximum_header_bytes=_positive_bounded_integer(
            args.maximum_header_bytes,
            name="maximum_header_bytes",
            maximum=MAXIMUM_CLI_HEADER_BYTES,
        ),
        maximum_header_count=_positive_bounded_integer(
            args.maximum_header_count,
            name="maximum_header_count",
            maximum=MAXIMUM_CLI_HEADER_COUNT,
        ),
    )


def _build_retry_policy(args: argparse.Namespace) -> RetryPolicy:
    try:
        return RetryPolicy(
            maximum_attempts=args.maximum_attempts,
            initial_backoff_seconds=args.initial_backoff_seconds,
            backoff_multiplier=args.backoff_multiplier,
            maximum_backoff_seconds=args.maximum_backoff_seconds,
        )
    except ValueError as exc:
        raise CliControlledError(
            "retry_policy_invalid",
            str(exc),
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc


def _build_validation_policy(args: argparse.Namespace) -> ValidationPolicy:
    allowed_hosts = frozenset(args.allowed_hosts)

    if args.lab:
        if not allowed_hosts:
            raise CliControlledError(
                "lab_allowlist_required",
                "Laboratory mode requires at least one explicit "
                "--allow-host value.",
                exit_code=EXIT_PREFLIGHT_FAILED,
            )

        return ValidationPolicy(
            mode=ValidationMode.LAB,
            allowed_lab_hosts=allowed_hosts,
        )

    if allowed_hosts:
        raise CliControlledError(
            "allow_host_requires_lab_mode",
            "--allow-host can only be used together with --lab.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    return ValidationPolicy(mode=ValidationMode.COMMERCIAL)


def _normalise_output_path(
    configured_path: Path | None,
    *,
    scan_id: str,
) -> Path:
    if configured_path is None:
        return DEFAULT_OUTPUT_DIRECTORY / f"{scan_id}.json"

    try:
        return configured_path.expanduser()
    except (RuntimeError, ValueError) as exc:
        raise CliControlledError(
            "output_path_invalid",
            "The output path is invalid.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc


def _check_output_path(path: Path, *, overwrite: bool) -> None:
    try:
        exists = os.path.lexists(path)
    except (OSError, TypeError, ValueError) as exc:
        raise CliControlledError(
            "output_path_invalid",
            f"Unable to inspect output path {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    if not exists:
        return

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CliControlledError(
            "output_path_inspection_failed",
            f"Unable to inspect output path {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise CliControlledError(
            "output_symlink_not_allowed",
            f"Refusing to write a scan report through symbolic link {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        )

    if not stat.S_ISREG(metadata.st_mode):
        raise CliControlledError(
            "output_not_regular_file",
            f"Output path {path} is not a regular file.",
            exit_code=EXIT_OUTPUT_FAILED,
        )

    if not overwrite:
        raise CliControlledError(
            "output_exists",
            f"Output file {path} already exists. Use --overwrite to "
            "replace it explicitly.",
            exit_code=EXIT_OUTPUT_FAILED,
        )


def _write_report(
    result: ScanResult,
    path: Path,
    *,
    overwrite: bool,
) -> None:
    _check_output_path(path, overwrite=overwrite)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CliControlledError(
            "output_directory_create_failed",
            f"Unable to create output directory {path.parent}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if overwrite else os.O_EXCL

    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    file_descriptor: int | None = None

    try:
        file_descriptor = os.open(path, flags, 0o600)
        with os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output_file:
            file_descriptor = None
            output_file.write(result.to_json())
            output_file.write("\n")
    except FileExistsError as exc:
        raise CliControlledError(
            "output_exists",
            f"Output file {path} already exists.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc
    except OSError as exc:
        raise CliControlledError(
            "output_write_failed",
            f"Unable to write scan report {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)


def _display_values(values: tuple[object, ...]) -> str:
    if not values:
        return "none"
    return ", ".join(str(value) for value in values)


def _render_scan_result(
    result: ScanResult,
    *,
    stream: TextIO,
    output_path: Path | None = None,
) -> None:
    completion = result.coverage.completion_percent
    completion_text = "not applicable" if completion is None else f"{completion}%"

    print(f"Scan ID: {result.scan_id}", file=stream)
    print(f"Status: {result.status.value}", file=stream)
    print(f"Target: {result.target}", file=stream)
    print(f"Engine: {result.engine} {result.engine_version}", file=stream)
    print(
        "Connected addresses: "
        f"{_display_values(result.connected_addresses)}",
        file=stream,
    )
    print(
        f"HTTP statuses: {_display_values(result.http_statuses)}",
        file=stream,
    )
    print(
        "Requests: "
        f"{result.coverage.requests_attempted} attempted, "
        f"{result.coverage.requests_succeeded} succeeded",
        file=stream,
    )
    print(f"Coverage: {completion_text}", file=stream)
    print(f"Findings: {len(result.findings)}", file=stream)
    print(f"Errors: {len(result.errors)}", file=stream)

    for finding in result.findings:
        print(
            f"- [{finding.severity.value.upper()}] "
            f"{finding.title} ({finding.identity.rule_id})",
            file=stream,
        )

    for skipped in result.coverage.skipped_checks:
        print(
            f"- [SKIPPED] {skipped.check_id}: {skipped.reason}",
            file=stream,
        )

    for error in result.errors:
        print(
            f"- [ERROR] {error.stage}/{error.code}: {error.message} "
            f"(retryable: {'yes' if error.retryable else 'no'})",
            file=stream,
        )

    for attempt in result.request_attempts:
        if attempt.outcome.value == "succeeded":
            print(
                f"- [ATTEMPT {attempt.attempt_number}] succeeded: "
                f"{attempt.connected_address}, HTTP {attempt.http_status}, "
                f"{attempt.duration_milliseconds} ms",
                file=stream,
            )
        else:
            print(
                f"- [ATTEMPT {attempt.attempt_number}] failed: "
                f"{attempt.error_code}; retry scheduled: "
                f"{'yes' if attempt.retry_scheduled else 'no'}; "
                f"backoff: {attempt.backoff_seconds} s",
                file=stream,
            )

    if output_path is not None:
        print(f"Saved report: {output_path}", file=stream)


def _scan_command(args: argparse.Namespace) -> int:
    scan_id = str(uuid4())
    output_path = _normalise_output_path(args.output, scan_id=scan_id)

    _check_output_path(output_path, overwrite=args.overwrite)

    validation_policy = _build_validation_policy(args)
    fetch_policy = _build_fetch_policy(args)
    retry_policy = _build_retry_policy(args)

    try:
        target = validate_target_url(
            args.target,
            validation_policy,
        )
    except TargetValidationError as exc:
        raise CliControlledError(
            getattr(exc, "code", "target_validation_failed"),
            str(exc),
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc

    result = run_passive_header_scan(
        target,
        fetch_policy=fetch_policy,
        retry_policy=retry_policy,
        scan_id=scan_id,
    )

    _write_report(
        result,
        output_path,
        overwrite=args.overwrite,
    )
    _render_scan_result(
        result,
        stream=sys.stdout,
        output_path=output_path,
    )

    if result.status is ScanStatus.COMPLETED:
        return EXIT_SUCCESS

    return EXIT_SCAN_FAILED


def _load_report(path: Path) -> ScanResult:
    try:
        return load_scan_result_file(path)
    except ScanReportLoadError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_REPORT_INVALID,
        ) from exc


def _report_validate_command(args: argparse.Namespace) -> int:
    result = _load_report(args.report)

    print(f"Valid report: {args.report}")
    print(f"Normalized schema: {result.schema_version}")
    print(f"Scan ID: {result.scan_id}")
    print(f"Status: {result.status.value}")

    return EXIT_SUCCESS


def _report_inspect_command(args: argparse.Namespace) -> int:
    result = _load_report(args.report)

    if args.json_output:
        print(result.to_json())
    else:
        print(f"Report: {args.report}")
        _render_scan_result(result, stream=sys.stdout)

    return EXIT_SUCCESS


def build_parser() -> argparse.ArgumentParser:
    """Build the public WebGuard argument parser."""

    parser = argparse.ArgumentParser(
        prog="webguard",
        description=(
            "Run passive OpenHuntX WebGuard scans only against targets "
            "you are authorised to assess."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {ENGINE_VERSION}",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    scan = commands.add_parser(
        "scan",
        help="Run a passive HTTP security-header scan.",
    )
    scan.add_argument("target", help="Authorised HTTP or HTTPS target URL.")
    scan.add_argument(
        "-o",
        "--output",
        type=Path,
        help=(
            "Report path. Defaults to scan-results/<scan-id>.json."
        ),
    )
    scan.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace an existing regular report file.",
    )
    scan.add_argument(
        "--lab",
        action="store_true",
        help=(
            "Enable laboratory scope rules. Requires at least one "
            "--allow-host value."
        ),
    )
    scan.add_argument(
        "--allow-host",
        action="append",
        dest="allowed_hosts",
        default=[],
        metavar="HOST",
        help=(
            "Explicitly allow an authorised laboratory hostname. "
            "May be repeated and is valid only with --lab."
        ),
    )
    scan.add_argument(
        "--timeout",
        dest="timeout_seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=(
            "Per-request timeout in seconds (default: 10; maximum: 60)."
        ),
    )
    scan.add_argument(
        "--max-body-bytes",
        dest="maximum_body_bytes",
        type=int,
        default=DEFAULT_MAXIMUM_BODY_BYTES,
        metavar="BYTES",
        help=(
            "Maximum response body bytes (default: 1048576; "
            "maximum: 16777216)."
        ),
    )
    scan.add_argument(
        "--max-header-bytes",
        dest="maximum_header_bytes",
        type=int,
        default=DEFAULT_MAXIMUM_HEADER_BYTES,
        metavar="BYTES",
        help=(
            "Maximum response header bytes (default: 65536; "
            "maximum: 1048576)."
        ),
    )
    scan.add_argument(
        "--max-header-count",
        dest="maximum_header_count",
        type=int,
        default=DEFAULT_MAXIMUM_HEADER_COUNT,
        metavar="COUNT",
        help=(
            "Maximum response header count (default: 100; maximum: 1000)."
        ),
    )
    scan.add_argument(
        "--max-attempts",
        dest="maximum_attempts",
        type=int,
        default=1,
        metavar="COUNT",
        help=(
            "Maximum total request attempts. The default of 1 disables "
            "retries; the enforced maximum is 3."
        ),
    )
    scan.add_argument(
        "--initial-backoff",
        dest="initial_backoff_seconds",
        type=float,
        default=0.25,
        metavar="SECONDS",
        help="Initial retry backoff (default: 0.25).",
    )
    scan.add_argument(
        "--backoff-multiplier",
        type=float,
        default=2.0,
        metavar="MULTIPLIER",
        help="Retry backoff multiplier (default: 2).",
    )
    scan.add_argument(
        "--max-backoff",
        dest="maximum_backoff_seconds",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Maximum retry backoff per failure (default: 2).",
    )
    scan.set_defaults(handler=_scan_command)

    report = commands.add_parser(
        "report",
        help="Validate or inspect a saved scan report.",
    )
    report_commands = report.add_subparsers(
        dest="report_command",
        required=True,
    )

    validate = report_commands.add_parser(
        "validate",
        help="Strictly validate and normalize a scan report.",
    )
    validate.add_argument("report", type=Path)
    validate.set_defaults(handler=_report_validate_command)

    inspect = report_commands.add_parser(
        "inspect",
        help="Display a validated scan report.",
    )
    inspect.add_argument("report", type=Path)
    inspect.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print canonical normalized JSON instead of a human summary.",
    )
    inspect.set_defaults(handler=_report_inspect_command)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the WebGuard CLI and return a deterministic process status."""

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.handler(args))
    except CliControlledError as exc:
        print(
            f"webguard: [{exc.code}] {exc.message}",
            file=sys.stderr,
        )
        return exc.exit_code


__all__ = [
    "EXIT_OUTPUT_FAILED",
    "EXIT_PREFLIGHT_FAILED",
    "EXIT_REPORT_INVALID",
    "EXIT_SCAN_FAILED",
    "EXIT_SUCCESS",
    "EXIT_USAGE",
    "build_parser",
    "main",
]
