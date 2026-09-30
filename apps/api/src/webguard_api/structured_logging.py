"""P1-B1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
structured, JSON-lines operational telemetry for WebGuard's own
service processes -- distinct from, and never a replacement for,
`SecurityAuditEvent` (the durable, authoritative record of security-
sensitive actions; see that class's own module for what belongs
there instead). This module is for operators watching a live process
-- "is the worker looping," "did this request fail," "is the
callback receiver's database write path healthy" -- not for the kind
of "who did what, when" record a compliance or incident review needs
to survive independently of stdout.

Built on Python's standard `logging` machinery (`logging.Logger`,
`logging.StreamHandler`, a custom `logging.Formatter`), not a bespoke
stdout writer -- `StreamHandler.emit()` already serializes concurrent
callers through its own lock, which is what makes this module safe to
call from worker/scheduler background threads and per-connection HTTP
handler threads at the same time without interleaved or corrupted
output lines. One dedicated logger (`propagate=False`) is used so
nothing else in this process's logging configuration -- in particular
`mail.py`'s and `service.py`'s own, pre-existing `logging.getLogger(...)`
loggers -- can end up routed through this module's strict JSON
formatter by accident; see those modules' own comments for exactly
which of their log calls were converted to `log_event()` here and
which were deliberately left alone (`DevelopmentMailProvider` logs a
real verification/reset link to the console by design, for local-dev
convenience -- that is data this module's allowlist exists to keep
out, so it is not routed through here at all).

Every field a caller passes is either a member of the closed allowlist
below (name AND shape both checked) or it is silently dropped -- never
raised, since a bug in what gets logged about a failure must never
become a second, unrelated failure in the code path being logged. This
also means bypassing the allowlist requires editing this module
itself, not just being careful at a call site.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
from datetime import datetime, timezone
from typing import Any

_STRUCTURED_LOGGER_NAME = "webguard.structured"

SERVICES = frozenset({"api", "worker", "scheduler", "callback-service", "signing-service"})
LEVELS = frozenset({"info", "warning", "error"})
_LEVEL_MAP = {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# -- allowlist ---------------------------------------------------------
# Conservative "safe token" shape: letters, digits, and a small set of
# punctuation that legitimate IDs/route-templates/module-dotted-names
# actually need (`-`, `_`, `:`, `.`, `/`, `{`, `}`). No whitespace, no
# control characters -- deliberately excluded even though JSON encoding
# alone would already escape them, as defense in depth against a field
# being used to smuggle an oversized or unexpected-shaped value.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_:./{}\-]{1,200}$")
# Stricter shape for source_module/source_function/exception_type
# specifically: must look like a Python dotted module name, a class
# name, or a function name -- never a filesystem path. This is
# enforced primarily by WHICH attribute the exception helper below
# reads (a frame's `__name__`, never `co_filename`), and re-checked
# here as defense in depth. `_FUNCTION_NAME` additionally permits
# Python's own synthetic frame names (`<module>`, `<lambda>`,
# `<listcomp>`, ...) -- legitimate, common `co_name` values with no
# path or request-data content, not the same risk category as an
# arbitrary string.
_DOTTED_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_FUNCTION_NAME = re.compile(r"^(<[a-z]+>|[A-Za-z_][A-Za-z0-9_]*)$")

_STRING_FIELDS = frozenset(
    {
        "request_id", "organization_id", "principal_id", "scan_id", "job_id",
        "schedule_id", "finding_id", "worker_id", "key_id",
        "route_name", "reason_code", "error_code",
    }
)
_IDENTIFIER_FIELDS = frozenset({"exception_type", "source_module"})
_INT_FIELDS = {
    "status_code": (100, 599),
    "attempt": (1, 50),
    "source_line": (1, 10_000_000),
}
_NUMERIC_FIELDS = {"duration_ms": (0, 24 * 60 * 60 * 1000)}  # bounded to one day, generously

_service_lock = threading.Lock()
_configured_service: str | None = None


def _utc_timestamp(epoch_seconds: float | None = None) -> str:
    when = datetime.now(timezone.utc) if epoch_seconds is None else datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    return when.isoformat(timespec="microseconds").replace("+00:00", "Z")


class _JsonLineFormatter(logging.Formatter):
    """Formats a log record into one JSON object per line -- and is
    itself the output boundary's enforcement point, not just a
    convenience for `log_event`'s own already-validated payloads.
    `log_event` is the intended, convenient entry point and validates
    its inputs up front (raising on a clearly-broken `event`/`level` so
    a bug at a call site is caught immediately during development), but
    nothing stops other code in this process from bypassing it entirely
    -- `logging.getLogger("webguard.structured").info({...})` reaches
    this same formatter directly. So every field here is re-validated
    against the SAME central allowlist (`_validate_field`), independent
    of whatever already happened upstream. `timestamp` and `level` are
    always derived from the `LogRecord` itself (`record.created`,
    `record.levelname`), never trusted from the payload, so a bypass
    caller cannot forge either. A record that isn't a dict, or is
    missing/has an invalid `service`/`event`/level, is dropped --
    `format()` returns `None`, which the handler below treats as "write
    nothing" -- rather than falling back to `str()`/`repr()` on
    whatever was passed, which could itself leak secret-shaped content
    via a custom `__str__`. No `default=str` and no other automatic
    stringification of arbitrary objects appears anywhere in this
    module."""

    def format(self, record: logging.LogRecord) -> str | None:
        raw = record.msg
        if not isinstance(raw, dict):
            return None

        level = record.levelname.lower()
        if level not in LEVELS:
            return None

        service = raw.get("service")
        if service not in SERVICES:
            return None

        event = raw.get("event")
        if not isinstance(event, str) or not _SAFE_TOKEN.match(event):
            return None

        payload: dict[str, Any] = {
            "timestamp": _utc_timestamp(record.created),
            "level": level,
            "service": service,
            "event": event,
        }
        for key, value in raw.items():
            if key in ("timestamp", "level", "service", "event"):
                continue
            validated = _validate_field(key, value)
            if validated is not None:
                payload[key] = validated
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True)


class _StructuredStreamHandler(logging.StreamHandler):
    """A record whose formatter returned `None` (malformed, or a
    bypass of `log_event()` that failed the output boundary's own
    revalidation) is dropped: no blank line, no fallback
    stringification. A formatting or write failure is never allowed to
    propagate -- a bug in what gets logged about a failure must never
    become a second, unrelated failure in the code path being
    logged."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
        except Exception:
            return
        if line is None:
            return
        try:
            self.stream.write(line + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


def configure_structured_logging(*, service: str, stream=None) -> None:
    """Configures the one dedicated structured-logging logger for this
    process. Idempotent (re-calling replaces the previous handler
    rather than accumulating duplicates, so tests and any future re-
    exec path stay clean). Must be called once, before the service's
    runtime loop starts. `service` is this process's default/primary
    role, used whenever a `log_event()` call doesn't specify its own
    `service=` -- `log_event()` is a silent no-op if this has not run
    yet in this process."""

    if service not in SERVICES:
        raise ValueError(f"unknown service: {service!r}; must be one of {sorted(SERVICES)}")
    global _configured_service
    with _service_lock:
        _configured_service = service
        logger = logging.getLogger(_STRUCTURED_LOGGER_NAME)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        handler = _StructuredStreamHandler(stream=stream or sys.stdout)
        handler.setFormatter(_JsonLineFormatter())
        logger.addHandler(handler)


def is_configured() -> bool:
    return _configured_service is not None


def _validate_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if not _SAFE_TOKEN.match(value):
        return None
    return value


def _validate_identifier(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if not _DOTTED_IDENTIFIER.match(value) or len(value) > 200:
        return None
    return value


def _validate_bounded_int(value: Any, bounds: tuple[int, int]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    low, high = bounds
    if not (low <= value <= high):
        return None
    return value


def _validate_bounded_number(value: Any, bounds: tuple[float, float]) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    low, high = bounds
    if not (low <= value <= high):
        return None
    return value


def _validate_field(key: str, value: Any) -> Any:
    """Returns the validated value, or `None` if the field must be
    dropped -- either because `key` is not on the allowlist at all, or
    because `value` does not have the shape that field requires."""

    if key in _STRING_FIELDS:
        return _validate_string(value)
    if key in _IDENTIFIER_FIELDS:
        return _validate_identifier(value)
    if key == "source_function":
        if not isinstance(value, str) or not _FUNCTION_NAME.match(value) or len(value) > 200:
            return None
        return value
    if key == "http_method":
        return value if value in HTTP_METHODS else None
    if key in _INT_FIELDS:
        return _validate_bounded_int(value, _INT_FIELDS[key])
    if key in _NUMERIC_FIELDS:
        return _validate_bounded_number(value, _NUMERIC_FIELDS[key])
    return None  # not an allowlisted field name at all -- dropped


def log_event(*, event: str, level: str = "info", service: str | None = None, **fields: Any) -> None:
    """Emits one structured JSON log line. `event` and `level` are
    required and validated against closed sets; every entry in
    `fields` is independently name-and-value validated against the
    central allowlist and silently dropped if it fails either check --
    this function never raises over a caller's field *values*, since a
    logging-call mistake must never become a new failure in the code
    path being logged. (It does raise on a clearly-broken `event`,
    `level`, or explicit `service` -- those indicate a bug in this
    module's own trusted call sites, worth catching immediately during
    development; see `_JsonLineFormatter` for the independent
    revalidation that protects the actual output even if a caller
    bypasses this function entirely.)

    `service` identifies which logical component produced this event
    -- e.g. `"worker"` for an embedded worker thread inside a combined
    `serve` process that itself configured logging as `service="api"`.
    Defaults to whatever `configure_structured_logging()` was given,
    which is correct for a call site whose service identity always
    matches the process it runs in (mail.py, service.py); a call site
    that can run *embedded* in a different process's identity
    (worker.py, scheduler.py, callback_server.py, signing_service.py,
    http_api.py) always passes its own `service=` explicitly instead of
    relying on this default, so an event never gets mislabeled just
    because it happened to run inside the combined `serve` process.

    A silent no-op if `configure_structured_logging()` has not run yet
    in this process -- deliberately, not an error: every call site
    this module is wired into (worker.py, scheduler.py, ...) is
    exercised directly by a large, pre-existing test suite that
    constructs those classes without ever going through the CLI's own
    `configure_structured_logging()` call. Logging must never become a
    new precondition for code that worked before this module existed;
    only the *service-mode* CLI commands (`serve`/`worker`/`scheduler`/
    `callback-service`/`signing-service`) call `configure_structured_logging()`,
    and only those processes' output is expected to be structured."""

    if _configured_service is None:
        return
    if level not in LEVELS:
        raise ValueError(f"invalid level: {level!r}; must be one of {sorted(LEVELS)}")
    if not isinstance(event, str) or not _SAFE_TOKEN.match(event):
        raise ValueError(f"invalid event name: {event!r}")
    resolved_service = _configured_service if service is None else service
    if resolved_service not in SERVICES:
        raise ValueError(f"unknown service: {resolved_service!r}; must be one of {sorted(SERVICES)}")

    payload: dict[str, Any] = {
        "timestamp": _utc_timestamp(),
        "level": level,
        "service": resolved_service,
        "event": event,
    }
    for key, value in fields.items():
        validated = _validate_field(key, value)
        if validated is not None:
            payload[key] = validated

    logger = logging.getLogger(_STRUCTURED_LOGGER_NAME)
    logger.log(_LEVEL_MAP[level], payload)


def exception_fields(exc: BaseException) -> dict[str, Any]:
    """Safely extracts diagnostic metadata from an exception's
    traceback -- `exception_type` (the class name only), and, from the
    innermost (raising) frame, `source_module` (the frame's own
    `__name__`, e.g. `"webguard_api.worker"` -- never
    `frame.f_code.co_filename`, which would be an absolute filesystem
    path), `source_function`, and `source_line`. Never `str(exc)`,
    `repr(exc)`, or `traceback.format_exc()` -- an exception message
    can accidentally embed request data, SQL fragments, or file paths;
    the class name and raise-site location carry real diagnostic value
    (enough to find the historical P0-1-class `AttributeError` this
    was modeled on) without that risk. Intended to be splatted directly
    into a `log_event(..., **exception_fields(exc))` call; every value
    still passes through `log_event`'s own field validation."""

    fields: dict[str, Any] = {"exception_type": type(exc).__name__}
    frame = exc.__traceback__
    last = None
    while frame is not None:
        last = frame
        frame = frame.tb_next
    if last is not None:
        code_frame = last.tb_frame
        module_name = code_frame.f_globals.get("__name__")
        if isinstance(module_name, str) and module_name:
            fields["source_module"] = module_name
        fields["source_function"] = code_frame.f_code.co_name
        fields["source_line"] = last.tb_lineno
    return fields


__all__ = [
    "HTTP_METHODS",
    "LEVELS",
    "SERVICES",
    "configure_structured_logging",
    "exception_fields",
    "is_configured",
    "log_event",
]
