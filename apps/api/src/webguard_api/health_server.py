"""P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md): a
small, internal-only HTTP health listener -- liveness (``/healthz``)
and readiness (``/ready``) only -- reused identically by the worker,
scheduler, callback-service, and signing-service standalone processes.
Deliberately a SEPARATE listener from any service's own public/
protocol surface (``callback_server.py``'s public callback listener,
``signing_service.py``'s bearer-protected ``/v1/sign`` listener) --
see the binding discipline below and each call site's own docstring
for why a shared listener there was rejected.

Built on the same ``ThreadingHTTPServer`` + explicit ``start()``/
``stop()`` daemon-thread idiom already used identically by
``http_api.py``'s ``create_server``, ``callback_server.py``'s
``CallbackHttpReceiver``, and ``signing_service.py``'s
``SigningServiceServer`` -- not a new pattern, the same one reused a
fourth time.

Hardcoded to bind ``127.0.0.1`` only -- deliberately no host parameter
is exposed to environment configuration anywhere in this module or its
callers (see ``cli.py``). This listener answers with no authentication
at all, because its response bodies never carry anything worth
protecting (a fixed boolean-shaped status and a fixed reason token,
nothing else) -- those two properties are a deliberate pair, not
independent choices, and is exactly why it must never be reachable
from anywhere but the same host.

Response bodies are a closed, fixed shape (see ``_make_handler``): no
stack trace, hostname, DSN, port topology, provider detail, or
exception message ever appears in one. A ``liveness_check``/
``readiness_check`` callable that raises unexpectedly is caught here
and reported to the caller as the fixed reason ``health_check_failed``
-- never propagated, never a 500, never a traceback on the wire.

Reuses P1-B1's ``structured_logging`` module directly for the
``readiness_failed``/``readiness_recovered`` transition events -- no
second logging mechanism. Edge-triggered: exactly one
``readiness_failed`` when ``/ready`` transitions healthy-to-unhealthy,
exactly one ``readiness_recovered`` on the reverse transition, nothing
for repeated probes of an unchanged state. ``/healthz`` deliberately
does not participate in that transition log -- see ``HealthServer``'s
own docstring for why.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .structured_logging import exception_fields, log_event

_STATUS_OK_BODY = b'{"status":"ok"}'
_NOT_FOUND_BODY = b'{"status":"not_found"}'
_METHOD_NOT_ALLOWED_BODY = b'{"status":"method_not_allowed"}'


def _not_ready_body(reason: str) -> bytes:
    # `reason` always comes from this codebase's own fixed reason-code
    # vocabulary (never a caller-supplied or exception-derived string),
    # so simple string formatting -- not json.dumps -- is safe and
    # matches this module's own "closed, fixed shape" response
    # contract; see structured_logging.py's allowlist for the same
    # reasoning applied to log fields.
    return f'{{"status":"not_ready","reason":"{reason}"}}'.encode("ascii")


def _safe_check(
    check: Callable[[], tuple[bool, str]],
    *,
    service: str,
    on_exception_event: str | None,
) -> tuple[bool, str]:
    """Runs a liveness/readiness callback with the same discipline
    P1-B1 already established for exception diagnostics: never
    ``str(exc)``/``repr(exc)``, never a traceback -- only the safe,
    already-reviewed ``exception_fields`` shape, and only into the
    structured log, never into the HTTP response. A callback that
    raises is treated as ``(False, "health_check_failed")``, exactly
    as if it had returned that tuple itself."""

    try:
        ready, reason = check()
        return bool(ready), reason
    except Exception as exc:  # noqa: BLE001 - a health-check callback must never crash this listener
        if on_exception_event is not None:
            log_event(
                service=service, event=on_exception_event, level="error",
                reason_code="health_check_failed", **exception_fields(exc),
            )
        return False, "health_check_failed"


def _make_handler(
    *,
    service: str,
    liveness_check: Callable[[], tuple[bool, str]],
    readiness_check: Callable[[], tuple[bool, str]],
    transition_state: dict[str, bool],
    transition_lock: threading.Lock,
) -> type[BaseHTTPRequestHandler]:
    class _HealthHandler(BaseHTTPRequestHandler):
        server_version = "WebGuardHealth/1"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
            # Never write a request line (path/query included) to
            # stderr -- matches this module's own "no arbitrary path
            # echo" contract.
            return

        def _write(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _record_transition(self, ready: bool, reason: str) -> None:
            with transition_lock:
                was_ready = transition_state["ready"]
                if ready and not was_ready:
                    transition_state["ready"] = True
                    log_event(service=service, event="readiness_recovered", level="info")
                elif not ready and was_ready:
                    transition_state["ready"] = False
                    log_event(service=service, event="readiness_failed", level="error", reason_code=reason)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                # Deliberately no readiness_failed/_recovered-shaped
                # edge-trigger log here -- liveness_check() is a pure,
                # local, non-raising computation for every call site
                # this module has today (progress_healthy() compares
                # two floats; the callback/signing "always alive"
                # checks are constant), so this path exists as
                # defense-in-depth against a future callback that
                # isn't, not because a transition log is meaningful
                # for it now. See HEALTH TRANSITION LOGGING in the
                # P1-B2 report for the explicit scope decision.
                alive, reason = _safe_check(liveness_check, service=service, on_exception_event=None)
                self._write(200 if alive else 503, _STATUS_OK_BODY if alive else _not_ready_body(reason))
                return
            if path == "/ready":
                ready, reason = _safe_check(readiness_check, service=service, on_exception_event="readiness_failed")
                self._record_transition(ready, reason)
                self._write(200 if ready else 503, _STATUS_OK_BODY if ready else _not_ready_body(reason))
                return
            self._write(404, _NOT_FOUND_BODY)

        def _reject_write(self) -> None:
            self._write(405, _METHOD_NOT_ALLOWED_BODY)

        do_POST = _reject_write
        do_PUT = _reject_write
        do_PATCH = _reject_write
        do_DELETE = _reject_write

    return _HealthHandler


class HealthServer:
    """One internal-only ``/healthz``+``/ready`` listener -- see this
    module's own docstring for the binding and redaction discipline.
    ``liveness_check``/``readiness_check`` each return ``(healthy,
    reason_code)``; ``reason_code`` is only ever read out of this
    codebase's own fixed vocabulary (see ``docs/audit/
    WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md``'s P1-B2 section), so
    every call site is required to pass one of those, never a raw
    message."""

    def __init__(
        self,
        *,
        service: str,
        liveness_check: Callable[[], tuple[bool, str]],
        readiness_check: Callable[[], tuple[bool, str]],
        port: int,
        host: str = "127.0.0.1",
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("HealthServer only ever binds 127.0.0.1 -- there is no host override.")
        transition_state: dict[str, bool] = {"ready": True}
        transition_lock = threading.Lock()
        handler = _make_handler(
            service=service,
            liveness_check=liveness_check,
            readiness_check=readiness_check,
            transition_state=transition_state,
            transition_lock=transition_lock,
        )
        self._server = ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/"

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def validate_health_port(raw: str, *, env_var_name: str) -> int:
    """Parses and bounds-checks a health-port environment variable --
    ``1..65535`` only, matching TCP's own valid port range. Rejects
    anything else (non-numeric, 0, negative, out of range) with a
    clear, specific error rather than a confusing bind failure later,
    or silently falling back to an unreviewed default port."""

    try:
        port = int(raw)
    except ValueError:
        raise ValueError(f"{env_var_name} must be an integer, got {raw!r}.") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{env_var_name} must be from 1 to 65535, got {port}.")
    return port


_MAXIMUM_STALE_SECONDS = 3600.0


def validate_stale_seconds(raw: str, *, env_var_name: str) -> float:
    """Parses and bounds-checks a progress-staleness override (e.g.
    ``WEBGUARD_WORKER_HEALTH_STALE_SECONDS``). Rejects 0, negative,
    NaN, infinity, and anything absurdly large (capped at one hour --
    a readiness threshold longer than that stops being a readiness
    threshold) rather than letting a malformed value silently produce
    a health check that can never fail."""

    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{env_var_name} must be a number, got {raw!r}.") from None
    if value != value or value in (float("inf"), float("-inf")):  # NaN/inf check without importing math
        raise ValueError(f"{env_var_name} must be a finite number, got {raw!r}.")
    if not 0 < value <= _MAXIMUM_STALE_SECONDS:
        raise ValueError(f"{env_var_name} must be greater than 0 and at most {_MAXIMUM_STALE_SECONDS:g}, got {value!r}.")
    return value


_MINIMUM_HEALTH_DB_TIMEOUT_SECONDS = 0.1
_MAXIMUM_HEALTH_DB_TIMEOUT_SECONDS = 5.0
DEFAULT_HEALTH_DB_TIMEOUT_SECONDS = 1.0


def validate_health_db_timeout(raw: str, *, env_var_name: str) -> float:
    """P1-B2 pre-commit correction (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
    parses and bounds-checks ``WEBGUARD_HEALTH_DB_CHECKOUT_TIMEOUT_SECONDS``
    -- the short, per-call Postgres checkout timeout a health/readiness
    probe passes to ``WebGuardPostgresPool.check_connectivity()``,
    deliberately much shorter than the normal ~5s application checkout
    timeout so one probe during a real outage cannot occupy a request
    thread for anywhere near that long. Bounded ``0.1..5.0`` seconds --
    below 0.1s a probe would spuriously fail under completely normal
    pool contention; above 5.0s it stops being meaningfully shorter
    than the default it exists to bound. Rejects 0, negative, NaN,
    infinity, and out-of-range values rather than letting a malformed
    override silently reproduce the original 5-second-block problem."""

    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{env_var_name} must be a number, got {raw!r}.") from None
    if value != value or value in (float("inf"), float("-inf")):  # NaN/inf check without importing math
        raise ValueError(f"{env_var_name} must be a finite number, got {raw!r}.")
    if not _MINIMUM_HEALTH_DB_TIMEOUT_SECONDS <= value <= _MAXIMUM_HEALTH_DB_TIMEOUT_SECONDS:
        raise ValueError(
            f"{env_var_name} must be from {_MINIMUM_HEALTH_DB_TIMEOUT_SECONDS:g} to "
            f"{_MAXIMUM_HEALTH_DB_TIMEOUT_SECONDS:g}, got {value!r}."
        )
    return value


__all__ = [
    "DEFAULT_HEALTH_DB_TIMEOUT_SECONDS",
    "HealthServer",
    "validate_health_db_timeout",
    "validate_health_port",
    "validate_stale_seconds",
]
