"""Loopback HTTP/JSON transport with bearer authentication and RBAC."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Type
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from .auth import ApiTokenAuthenticator, AuthContext, AuthenticationError
from .identity import TOKEN_PREFIX
from .pagination import PaginationError, parse_page_request
from .rate_limit import FixedWindowRateLimiter, RateLimitDecision, RateLimitError
from .service import ApiServiceError, WebGuardJobService


_JOB_PATH = re.compile(r"^/v1/jobs/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_JOB_CANCEL_PATH = re.compile(r"^/v1/jobs/([0-9a-f-]{36})/cancel$")
_JOB_RESULT_PATH = re.compile(r"^/v1/jobs/([0-9a-f-]{36})/result$")
_SCHEDULE_PATH = re.compile(r"^/v1/schedules/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_SCHEDULE_PAUSE_PATH = re.compile(r"^/v1/schedules/([0-9a-f-]{36})/pause$")
_SCHEDULE_RESUME_PATH = re.compile(r"^/v1/schedules/([0-9a-f-]{36})/resume$")
_PERMIT_PATH = re.compile(r"^/v1/permits/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_FINDING_PATH = re.compile(r"^/v1/findings/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_FINDING_STATUS_PATH = re.compile(r"^/v1/findings/([0-9a-f-]{36})/status$")
_FINDING_EVENTS_PATH = re.compile(r"^/v1/findings/([0-9a-f-]{36})/events$")
_REPORT_PATH = re.compile(r"^/v1/reports/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_SCAN_PATH = re.compile(r"^/v1/scans/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_PERMIT_REVOKE_PATH = re.compile(r"^/v1/permits/([0-9a-f-]{36})/revoke$")
_AUTHENTICATION_CONTEXT_REVOKE_PATH = re.compile(
    r"^/v1/authentication-contexts/([0-9a-f-]{36})/revoke$"
)
_AUTHORIZATION_COMPARISON_REVOKE_PATH = re.compile(
    r"^/v1/authorization-comparisons/([0-9a-f-]{36})/revoke$"
)


class ApiTransportError(ValueError):
    """Controlled HTTP transport validation failure."""

    def __init__(self, code: str, message: str, *, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def build_handler(
    service: WebGuardJobService,
    *,
    authenticator: ApiTokenAuthenticator,
    rate_limiter: FixedWindowRateLimiter,
    maximum_request_bytes: int,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    epoch_clock: Callable[[], float] = time.time,
) -> Type[BaseHTTPRequestHandler]:
    """Create a request handler bound to authenticated service dependencies."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "OpenHuntX-WebGuard-API"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _send_json(
            self,
            status: int,
            payload: object,
            *,
            request_id: str,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Request-ID", request_id)
            if extra_headers:
                for name, value in extra_headers.items():
                    self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _error(
            self,
            exc: ApiTransportError | ApiServiceError | AuthenticationError | RateLimitError,
            *,
            request_id: str,
        ) -> None:
            headers: dict[str, str] = {}
            if isinstance(exc, AuthenticationError) and exc.status == 401:
                headers["WWW-Authenticate"] = 'Bearer realm="webguard-api"'
            if isinstance(exc, RateLimitError):
                headers["Retry-After"] = str(exc.retry_after_seconds)
            self._send_json(
                exc.status,
                {
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                        "request_id": request_id,
                    }
                },
                request_id=request_id,
                extra_headers=headers,
            )

        def _request_target(self) -> tuple[str, dict[str, tuple[str, ...]]]:
            parsed = urlsplit(self.path)
            if parsed.fragment:
                raise ApiTransportError(
                    "request_target_invalid",
                    "API request targets cannot contain fragments.",
                    status=400,
                )
            try:
                parsed_query = parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                    strict_parsing=True,
                )
            except ValueError as exc:
                raise ApiTransportError(
                    "request_query_invalid",
                    "API query string is malformed.",
                    status=400,
                ) from exc
            query = {key: tuple(values) for key, values in parsed_query.items()}
            return parsed.path, query

        @staticmethod
        def _require_empty_query(query: dict[str, tuple[str, ...]]) -> None:
            if query:
                raise ApiTransportError(
                    "request_query_not_allowed",
                    "This API route does not accept query parameters.",
                    status=400,
                )

        @staticmethod
        def _page_request(
            query: dict[str, tuple[str, ...]],
            *,
            filters: dict[str, frozenset[str]],
            free_form_filters: frozenset[str] = frozenset(),
        ):
            try:
                return parse_page_request(
                    query, allowed_filters=filters, free_form_filters=free_form_filters
                )
            except PaginationError as exc:
                raise ApiTransportError(exc.code, exc.message, status=400) from exc

        def _read_json_body(self) -> bytes:
            transfer_values = self.headers.get_all("Transfer-Encoding") or []
            if transfer_values:
                raise ApiTransportError(
                    "transfer_encoding_not_allowed",
                    "Transfer-Encoding is not accepted by this local API.",
                    status=400,
                )
            content_types = self.headers.get_all("Content-Type") or []
            if len(content_types) != 1:
                raise ApiTransportError(
                    "content_type_required",
                    "Exactly one Content-Type header is required.",
                    status=415,
                )
            media_type = content_types[0].split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                raise ApiTransportError(
                    "content_type_invalid",
                    "Content-Type must be application/json.",
                    status=415,
                )
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1:
                raise ApiTransportError(
                    "content_length_required",
                    "Exactly one Content-Length header is required.",
                    status=411,
                )
            try:
                length = int(lengths[0])
            except ValueError as exc:
                raise ApiTransportError(
                    "content_length_invalid",
                    "Content-Length must be a non-negative integer.",
                    status=400,
                ) from exc
            if length < 0:
                raise ApiTransportError(
                    "content_length_invalid",
                    "Content-Length must be a non-negative integer.",
                    status=400,
                )
            if length > maximum_request_bytes:
                raise ApiTransportError(
                    "request_body_too_large",
                    "Request body exceeds the configured API limit.",
                    status=413,
                )
            body = self.rfile.read(length)
            if len(body) != length:
                raise ApiTransportError(
                    "request_body_incomplete",
                    "Request body ended before Content-Length bytes were received.",
                    status=400,
                )
            return body

        def _trustscan_permit_header(self) -> str:
            values = self.headers.get_all("TrustScan-Permit") or []
            if len(values) != 1 or not values[0] or values[0].strip() != values[0]:
                raise ApiTransportError(
                    "trustscan_permit_required",
                    "Exactly one canonical TrustScan-Permit header is required.",
                    status=400,
                )
            value = values[0]
            try:
                canonical = str(UUID(value))
            except (ValueError, AttributeError) as exc:
                raise ApiTransportError(
                    "trustscan_permit_invalid",
                    "TrustScan-Permit must be a canonical lower-case UUID.",
                    status=400,
                ) from exc
            if canonical != value:
                raise ApiTransportError(
                    "trustscan_permit_invalid",
                    "TrustScan-Permit must be a canonical lower-case UUID.",
                    status=400,
                )
            return canonical

        def _authentication_failure_key(
            self,
            authorization_headers: list[str],
        ) -> str:
            """Derive a secret-free bucket for failed authentication."""
            if len(authorization_headers) == 1:
                value = authorization_headers[0]
                scheme, separator, token = value.partition(" ")

                if (
                    separator == " "
                    and scheme.lower() == "bearer"
                    and token
                    and token.strip() == token
                ):
                    parts = token.split("_", 2)

                    if (
                        len(parts) == 3
                        and parts[0] == TOKEN_PREFIX
                        and parts[2]
                    ):
                        try:
                            canonical = str(UUID(parts[1]))
                        except (ValueError, AttributeError):
                            pass
                        else:
                            if canonical == parts[1]:
                                return (
                                    "auth-failure-token:"
                                    f"{canonical}"
                                )

            return (
                "auth-failure-peer:"
                f"{self.client_address[0]}"
            )

        def _authenticate(self) -> tuple[AuthContext, RateLimitDecision]:
            authorization_headers = (
                self.headers.get_all("Authorization") or []
            )
            now_epoch = epoch_clock()

            failure_key = self._authentication_failure_key(
                authorization_headers
            )

            # Atomically reserve pre-authentication capacity before any
            # token-secret verification. Failed authentication leaves this
            # reservation consumed.
            rate_limiter.check(
                failure_key,
                now_epoch=now_epoch,
            )

            try:
                context = authenticator.authenticate(
                    authorization_headers,
                    now=clock(),
                )
            except AuthenticationError:
                # The reservation remains consumed and therefore records
                # this failed authentication attempt.
                raise

            # Refund only this successful request's reservation.
            # Concurrent authentication failures remain counted.
            rate_limiter.release(
                failure_key,
                now_epoch=now_epoch,
            )

            # Preserve the existing authenticated per-token quota.
            decision = rate_limiter.check(
                context.token_id,
                now_epoch=now_epoch,
            )
            return context, decision

        @staticmethod
        def _rate_headers(decision: RateLimitDecision) -> dict[str, str]:
            return {
                "RateLimit-Limit": str(decision.limit),
                "RateLimit-Remaining": str(decision.remaining),
                "RateLimit-Reset": str(decision.reset_after_seconds),
            }

        def do_GET(self) -> None:  # noqa: N802
            request_id = str(uuid4())
            try:
                path, query = self._request_target()
                if path in ("/healthz", "/health"):
                    # Liveness only (requirement 14): must not fail
                    # merely because a transient dependency (database,
                    # signing provider) is unavailable -- that is
                    # exactly what `/ready` is for. This process being
                    # able to answer at all is the only thing checked
                    # here, by design. `/healthz` is kept for existing
                    # callers; `/health` is the Slice 12 requirement's
                    # own name for the identical check.
                    self._require_empty_query(query)
                    self._send_json(200, {"status": "ok"}, request_id=request_id)
                    return
                if path == "/ready":
                    # Safe-to-serve (requirement 14): actually checks
                    # the configured persistence dependency. Reports
                    # only a boolean and a fixed reason code -- never a
                    # host, port, connection string, or schema detail.
                    self._require_empty_query(query)
                    ready, reason = service.readiness()
                    self._send_json(
                        200 if ready else 503,
                        {"status": "ready" if ready else "not_ready", "reason": reason},
                        request_id=request_id,
                    )
                    return
                if path == "/v1/trustscan/verification-key":
                    self._require_empty_query(query)
                    self._send_json(
                        200,
                        service.trustscan_verification_key(),
                        request_id=request_id,
                    )
                    return
                context, decision = self._authenticate()
                if path == "/v1/me":
                    self._require_empty_query(query)
                    payload = service.me(context, request_id=request_id)
                elif path == "/v1/jobs":
                    page = self._page_request(
                        query,
                        filters={
                            "state": frozenset(
                                {
                                    "queued",
                                    "running",
                                    "completed",
                                    "completed_with_errors",
                                    "failed",
                                    "cancelled",
                                }
                            ),
                            "mode": frozenset({"single_page", "crawl"}),
                        },
                    )
                    payload = service.list_jobs(
                        context, page, request_id=request_id
                    )
                elif path == "/v1/audit-events":
                    page = self._page_request(
                        query,
                        filters={
                            "outcome": frozenset(
                                {"succeeded", "failed", "denied"}
                            )
                        },
                    )
                    payload = service.audit_events(
                        context, page, request_id=request_id
                    )
                elif path == "/v1/schedules":
                    page = self._page_request(
                        query,
                        filters={"state": frozenset({"active", "paused"})},
                        free_form_filters=frozenset({"target"}),
                    )
                    payload = service.list_schedules(
                        context, page, request_id=request_id
                    )
                elif path == "/v1/findings":
                    page = self._page_request(
                        query,
                        filters={
                            "status": frozenset(
                                {
                                    "open",
                                    "confirmed",
                                    "false_positive",
                                    "accepted_risk",
                                    "resolved",
                                    "reopened",
                                }
                            ),
                            "severity": frozenset(
                                {"informational", "low", "medium", "high", "critical"}
                            ),
                        },
                        free_form_filters=frozenset({"scan_id", "cwe_id", "asset"}),
                    )
                    payload = service.list_findings(
                        context, page, request_id=request_id
                    )
                elif path == "/v1/reports":
                    page = self._page_request(query, filters={}, free_form_filters=frozenset({"scan_id"}))
                    payload = service.list_reports(
                        context, page, request_id=request_id
                    )
                elif path == "/v1/scans":
                    page = self._page_request(
                        query,
                        filters={
                            "status": frozenset(
                                {
                                    "queued",
                                    "running",
                                    "completed",
                                    "completed_with_errors",
                                    "failed",
                                    "cancelled",
                                }
                            ),
                        },
                        free_form_filters=frozenset({"target"}),
                    )
                    payload = service.list_scans(
                        context, page, request_id=request_id
                    )
                else:
                    self._require_empty_query(query)
                    finding_events_match = _FINDING_EVENTS_PATH.fullmatch(path)
                    finding_match = _FINDING_PATH.fullmatch(path)
                    report_match = _REPORT_PATH.fullmatch(path)
                    scan_match = _SCAN_PATH.fullmatch(path)
                    if finding_events_match:
                        payload = service.list_finding_events(
                            context, finding_events_match.group(1), request_id=request_id
                        )
                    elif finding_match:
                        payload = service.get_finding(
                            context, finding_match.group(1), request_id=request_id
                        )
                    elif report_match:
                        payload = service.get_report(
                            context, report_match.group(1), request_id=request_id
                        )
                    elif scan_match:
                        payload = service.get_scan(
                            context, scan_match.group(1), request_id=request_id
                        )
                    else:
                        permit_match = _PERMIT_PATH.fullmatch(path)
                        if permit_match:
                            payload = service.get_permit(
                                context, permit_match.group(1), request_id=request_id
                            )
                        else:
                            schedule_match = _SCHEDULE_PATH.fullmatch(path)
                            if schedule_match:
                                payload = service.get_schedule(
                                    context, schedule_match.group(1), request_id=request_id
                                )
                            else:
                                match = _JOB_PATH.fullmatch(path)
                                if match:
                                    payload = service.get(
                                        context, match.group(1), request_id=request_id
                                    )
                                else:
                                    match = _JOB_RESULT_PATH.fullmatch(path)
                                    if match:
                                        payload = service.result(
                                            context, match.group(1), request_id=request_id
                                        )
                                    else:
                                        raise ApiTransportError(
                                            "route_not_found",
                                            "API route was not found.",
                                            status=404,
                                        )
                self._send_json(
                    200,
                    payload,
                    request_id=request_id,
                    extra_headers=self._rate_headers(decision),
                )
            except (
                ApiTransportError,
                ApiServiceError,
                AuthenticationError,
                RateLimitError,
            ) as exc:
                self._error(exc, request_id=request_id)

        def do_POST(self) -> None:  # noqa: N802
            request_id = str(uuid4())
            try:
                path, query = self._request_target()
                self._require_empty_query(query)
                context, decision = self._authenticate()
                if path == "/v1/permits":
                    payload = service.issue_permit(
                        context,
                        self._read_json_body(),
                        request_id=request_id,
                    )
                    self._send_json(
                        201,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                if path == "/v1/reports":
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "report_body_invalid", "Request body must be valid JSON.", status=400
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "report_body_invalid", "Request body must be a JSON object.", status=400
                        )
                    payload = service.create_report(context, body, request_id=request_id)
                    self._send_json(
                        201, payload, request_id=request_id, extra_headers=self._rate_headers(decision),
                    )
                    return
                finding_status_match = _FINDING_STATUS_PATH.fullmatch(path)
                if finding_status_match:
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "finding_status_body_invalid", "Request body must be valid JSON.", status=400
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "finding_status_body_invalid", "Request body must be a JSON object.", status=400
                        )
                    payload = service.update_finding_status(
                        context, finding_status_match.group(1), body, request_id=request_id
                    )
                    self._send_json(
                        200, payload, request_id=request_id, extra_headers=self._rate_headers(decision),
                    )
                    return
                if path == "/v1/authentication-contexts":
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "authentication_context_body_invalid",
                            "Request body must be valid JSON.",
                            status=400,
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "authentication_context_body_invalid",
                            "Request body must be a JSON object.",
                            status=400,
                        )
                    payload = service.register_authentication_context(
                        context, body, request_id=request_id
                    )
                    self._send_json(
                        201,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                authentication_context_revoke_match = (
                    _AUTHENTICATION_CONTEXT_REVOKE_PATH.fullmatch(path)
                )
                if authentication_context_revoke_match:
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "authentication_context_body_not_allowed",
                            "Authentication-context revocation requests cannot "
                            "contain a body.",
                            status=400,
                        )
                    payload = service.revoke_authentication_context(
                        context,
                        authentication_context_revoke_match.group(1),
                        request_id=request_id,
                    )
                    self._send_json(
                        200,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                if path == "/v1/authorization-comparisons":
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "authorization_comparison_body_invalid",
                            "Request body must be valid JSON.",
                            status=400,
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "authorization_comparison_body_invalid",
                            "Request body must be a JSON object.",
                            status=400,
                        )
                    payload = service.register_authorization_comparison_plan(
                        context, body, request_id=request_id
                    )
                    self._send_json(
                        201,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                authorization_comparison_revoke_match = (
                    _AUTHORIZATION_COMPARISON_REVOKE_PATH.fullmatch(path)
                )
                if authorization_comparison_revoke_match:
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "authorization_comparison_body_not_allowed",
                            "Authorization-comparison revocation requests cannot "
                            "contain a body.",
                            status=400,
                        )
                    payload = service.revoke_authorization_comparison_plan(
                        context,
                        authorization_comparison_revoke_match.group(1),
                        request_id=request_id,
                    )
                    self._send_json(
                        200,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                if path == "/v1/schedules":
                    payload = service.create_schedule(
                        context,
                        self._read_json_body(),
                        permit_id=self._trustscan_permit_header(),
                        request_id=request_id,
                    )
                    self._send_json(
                        201,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                if path == "/v1/jobs":
                    keys = self.headers.get_all("Idempotency-Key") or []
                    if len(keys) != 1:
                        raise ApiTransportError(
                            "idempotency_key_required",
                            "Exactly one Idempotency-Key header is required.",
                            status=400,
                        )
                    payload, created = service.submit(
                        context,
                        self._read_json_body(),
                        idempotency_key=keys[0],
                        permit_id=self._trustscan_permit_header(),
                        request_id=request_id,
                    )
                    self._send_json(
                        201 if created else 200,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                permit_match = _PERMIT_REVOKE_PATH.fullmatch(path)
                if permit_match:
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "permit_body_not_allowed",
                            "TrustScan permit revocation requests cannot contain a body.",
                            status=400,
                        )
                    payload = service.revoke_permit(
                        context, permit_match.group(1), request_id=request_id
                    )
                    self._send_json(
                        200,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                schedule_match = _SCHEDULE_PAUSE_PATH.fullmatch(path)
                if schedule_match:
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "schedule_body_not_allowed",
                            "Schedule state requests cannot contain a body.",
                            status=400,
                        )
                    payload = service.pause_schedule(
                        context, schedule_match.group(1), request_id=request_id
                    )
                    self._send_json(
                        200, payload, request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                schedule_match = _SCHEDULE_RESUME_PATH.fullmatch(path)
                if schedule_match:
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "schedule_body_not_allowed",
                            "Schedule state requests cannot contain a body.",
                            status=400,
                        )
                    payload = service.resume_schedule(
                        context, schedule_match.group(1), request_id=request_id
                    )
                    self._send_json(
                        200, payload, request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                match = _JOB_CANCEL_PATH.fullmatch(path)
                if match:
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "cancel_body_not_allowed",
                            "Cancellation requests cannot contain a body.",
                            status=400,
                        )
                    payload = service.cancel(context, match.group(1), request_id=request_id)
                    self._send_json(
                        200,
                        payload,
                        request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                raise ApiTransportError("route_not_found", "API route was not found.", status=404)
            except (ApiTransportError, ApiServiceError, AuthenticationError, RateLimitError) as exc:
                self._error(exc, request_id=request_id)

        def do_PUT(self) -> None:  # noqa: N802
            request_id = str(uuid4())
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": {"code": "method_not_allowed", "message": "Method not allowed.", "request_id": request_id}},
                request_id=request_id,
            )

        do_DELETE = do_PUT
        do_PATCH = do_PUT

    return Handler


def create_server(
    host: str,
    port: int,
    service: WebGuardJobService,
    *,
    authenticator: ApiTokenAuthenticator,
    rate_limiter: FixedWindowRateLimiter,
    maximum_request_bytes: int,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    epoch_clock: Callable[[], float] = time.time,
) -> ThreadingHTTPServer:
    """Bind the authenticated local HTTP transport."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ApiTransportError(
            "service_host_invalid", "API host must be a loopback IP literal.", status=500
        ) from exc
    if not address.is_loopback:
        raise ApiTransportError(
            "service_non_loopback_binding_rejected",
            "WebGuard API binding is restricted to loopback addresses.",
            status=500,
        )
    handler = build_handler(
        service,
        authenticator=authenticator,
        rate_limiter=rate_limiter,
        maximum_request_bytes=maximum_request_bytes,
        clock=clock,
        epoch_clock=epoch_clock,
    )
    server = ThreadingHTTPServer((address.compressed, port), handler)
    server.daemon_threads = True
    return server


__all__ = ["ApiTransportError", "build_handler", "create_server"]
