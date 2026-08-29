"""Loopback HTTP/JSON transport with bearer authentication and RBAC."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Type
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from .auth import ApiTokenAuthenticator, AuthContext, AuthenticationError, BrowserSessionAuthenticator
from .identity import TOKEN_PREFIX
from .pagination import PaginationError, parse_page_request
from .rate_limit import FixedWindowRateLimiter, RateLimitDecision, RateLimitError
from .service import ApiServiceError, WebGuardJobService

SESSION_COOKIE_NAME = "wg_session"  # noqa: S105
CSRF_COOKIE_NAME = "wg_csrf"  # noqa: S105
CSRF_HEADER_NAME = "X-CSRF-Token"  # noqa: S105


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
_REPORT_DOWNLOAD_PATH = re.compile(r"^/v1/reports/([0-9a-f-]{36})/download$")
_SCAN_PATH = re.compile(r"^/v1/scans/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_ASSET_PATH = re.compile(r"^/v1/assets/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_ASSET_VERIFICATION_START_PATH = re.compile(r"^/v1/assets/([0-9a-f-]{36})/verification$")
_ASSET_VERIFICATION_CHECK_PATH = re.compile(r"^/v1/assets/([0-9a-f-]{36})/verification/check$")
_TEAM_MEMBER_PATH = re.compile(r"^/v1/team/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_API_KEY_PATH = re.compile(r"^/v1/api-keys/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
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


_CORS_ALLOWED_METHODS = "GET, POST, PATCH, DELETE, OPTIONS"
_CORS_ALLOWED_HEADERS = "Authorization, Content-Type, Idempotency-Key, TrustScan-Permit, X-CSRF-Token"


def build_handler(
    service: WebGuardJobService,
    *,
    authenticator: ApiTokenAuthenticator,
    rate_limiter: FixedWindowRateLimiter,
    maximum_request_bytes: int,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    epoch_clock: Callable[[], float] = time.time,
    allowed_origins: frozenset[str] = frozenset(),
    session_authenticator: BrowserSessionAuthenticator | None = None,
    secure_cookies: bool = True,
    hsts_enabled: bool = False,
) -> Type[BaseHTTPRequestHandler]:
    """Create a request handler bound to authenticated service dependencies.

    ``allowed_origins`` is an explicit allowlist for browser CORS
    (Slice 15: the WebGuard web app is a pure SPA calling this API
    directly from the browser, so cross-origin requests are now a
    real, not hypothetical, transport concern). Empty by default --
    an operator must opt a specific origin in; there is no wildcard
    support, since credentials-bearing requests (the ``Authorization``
    bearer header) must never be paired with ``Access-Control-Allow-
    Origin: *``.

    ``session_authenticator`` (Slice 16) enables cookie-based browser
    sessions alongside the existing Bearer API tokens -- ``None``
    (the default) preserves every pre-Slice-16 caller's behavior
    exactly, since no code path can present a session cookie this
    handler will accept. ``secure_cookies`` should be true whenever
    the API is reachable over HTTPS (directly or through a reverse
    proxy) and false only for plain-HTTP local/dev use, where a
    browser will not store or return a ``Secure`` cookie at all --
    getting this wrong in dev doesn't fail insecurely, it just breaks
    login. ``hsts_enabled`` is readiness, not enforcement: this
    process itself only ever binds to loopback (see ``create_server``),
    so a real deployment's TLS-terminating reverse proxy is expected
    to set `Strict-Transport-Security` too; this lets it be present
    end-to-end once that proxy exists.
    """

    class Handler(BaseHTTPRequestHandler):
        server_version = "OpenHuntX-WebGuard-API"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _cors_headers(self) -> dict[str, str]:
            origin = self.headers.get("Origin")
            if not origin or origin not in allowed_origins:
                return {}
            # Credentialed (cookie-carrying) cross-origin requests
            # require this alongside a specific, non-wildcard Allow-
            # Origin -- both are already true here, since
            # `allowed_origins` never contains "*" (see build_handler's
            # docstring) and this only ever echoes a matched origin.
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }

        def _security_headers(self) -> dict[str, str]:
            headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                # A JSON/bytes-only API: it never needs to load a
                # script, style, image, or frame from anywhere,
                # including itself -- 'none' is not an approximation
                # of the right policy here, it is the right policy.
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                "Permissions-Policy": (
                    "geolocation=(), camera=(), microphone=(), payment=(), usb=(), "
                    "interest-cohort=()"
                ),
            }
            if hsts_enabled:
                headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
            return headers

        def _parse_cookies(self) -> SimpleCookie:
            jar: SimpleCookie = SimpleCookie()
            header_values = self.headers.get_all("Cookie") or []
            for value in header_values:
                try:
                    jar.load(value)
                except Exception:  # noqa: BLE001, S112 - a malformed cookie header must fail closed, not crash
                    continue
            return jar

        def _session_cookie_value(self) -> str | None:
            jar = self._parse_cookies()
            morsel = jar.get(SESSION_COOKIE_NAME)
            return morsel.value if morsel is not None else None

        def _csrf_header_value(self) -> str | None:
            values = self.headers.get_all(CSRF_HEADER_NAME) or []
            return values[0] if len(values) == 1 and values[0] else None

        def _set_cookie(
            self, name: str, value: str, *, http_only: bool, max_age_seconds: int
        ) -> str:
            attributes = [f"{name}={value}", "Path=/", f"Max-Age={max_age_seconds}", "SameSite=Lax"]
            if http_only:
                attributes.append("HttpOnly")
            if secure_cookies:
                attributes.append("Secure")
            return "; ".join(attributes)

        def _session_set_cookies(self, issued) -> list[str]:
            max_age = int((issued.record.absolute_expires_at - issued.record.issued_at).total_seconds())
            return [
                self._set_cookie(SESSION_COOKIE_NAME, issued.session_token, http_only=True, max_age_seconds=max_age),
                self._set_cookie(CSRF_COOKIE_NAME, issued.csrf_token, http_only=False, max_age_seconds=max_age),
            ]

        def _clear_session_cookies(self) -> list[str]:
            return [
                self._set_cookie(SESSION_COOKIE_NAME, "", http_only=True, max_age_seconds=0),
                self._set_cookie(CSRF_COOKIE_NAME, "", http_only=False, max_age_seconds=0),
            ]

        def _send_json(
            self,
            status: int,
            payload: object,
            *,
            request_id: str,
            extra_headers: dict[str, str] | None = None,
            set_cookies: list[str] | None = None,
        ) -> None:
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in self._security_headers().items():
                self.send_header(name, value)
            self.send_header("X-Request-ID", request_id)
            for name, value in self._cors_headers().items():
                self.send_header(name, value)
            if extra_headers:
                for name, value in extra_headers.items():
                    self.send_header(name, value)
            if set_cookies:
                for cookie in set_cookies:
                    self.send_header("Set-Cookie", cookie)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_OPTIONS(self) -> None:  # noqa: N802
            origin = self.headers.get("Origin")
            self.send_response(204)
            if origin and origin in allowed_origins:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Methods", _CORS_ALLOWED_METHODS)
                self.send_header("Access-Control-Allow-Headers", _CORS_ALLOWED_HEADERS)
                self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
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

        def _authenticate(self, *, require_csrf: bool = False) -> tuple[AuthContext, RateLimitDecision]:
            now_epoch = epoch_clock()
            session_token = (
                self._session_cookie_value() if session_authenticator is not None else None
            )

            if session_token is not None:
                # A distinct failure bucket from the Bearer-token one
                # below -- a browser session cookie and an API token
                # are different credential spaces and must not share
                # (or let one exhaust) the other's quota.
                failure_key = f"auth-failure-session-peer:{self.client_address[0]}"
                rate_limiter.check(failure_key, now_epoch=now_epoch)
                try:
                    context = session_authenticator.authenticate(
                        session_token,
                        now=clock(),
                        csrf_header=self._csrf_header_value(),
                        require_csrf=require_csrf,
                    )
                except AuthenticationError:
                    raise
                rate_limiter.release(failure_key, now_epoch=now_epoch)
                decision = rate_limiter.check(context.token_id, now_epoch=now_epoch)
                return context, decision

            authorization_headers = (
                self.headers.get_all("Authorization") or []
            )

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
            # require_csrf is a no-op for this path by design
            # (requirement 7): a request authenticated with an
            # Authorization header is never subject to browser CSRF
            # semantics -- it carries no ambient credential a
            # cross-site request could ride along with.
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
                download_match = _REPORT_DOWNLOAD_PATH.fullmatch(path)
                if download_match:
                    # Requirement 7: never exposes a filesystem path --
                    # a raw byte stream, tenant-checked, resolved through
                    # ArtifactStore. Not sent through _send_json, which
                    # always wraps a JSON body.
                    self._require_empty_query(query)
                    content, content_type, filename = service.download_report(
                        context, download_match.group(1), request_id=request_id
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(content)))
                    self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                    self.send_header("Cache-Control", "no-store")
                    for name, value in self._security_headers().items():
                        self.send_header(name, value)
                    self.send_header("X-Request-ID", request_id)
                    for name, value in self._cors_headers().items():
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(content)
                    return
                if path == "/v1/auth/session":
                    self._require_empty_query(query)
                    payload = service.get_session_info(context, request_id=request_id)
                    self._send_json(200, payload, request_id=request_id, extra_headers=self._rate_headers(decision))
                    return
                if path == "/v1/dashboard/summary":
                    self._require_empty_query(query)
                    payload = service.dashboard_summary(context, request_id=request_id)
                    self._send_json(200, payload, request_id=request_id, extra_headers=self._rate_headers(decision))
                    return
                if path == "/v1/team":
                    self._require_empty_query(query)
                    payload = service.list_team(context, request_id=request_id)
                    self._send_json(200, payload, request_id=request_id, extra_headers=self._rate_headers(decision))
                    return
                if path == "/v1/api-keys":
                    self._require_empty_query(query)
                    payload = service.list_api_keys(context, request_id=request_id)
                    self._send_json(200, payload, request_id=request_id, extra_headers=self._rate_headers(decision))
                    return
                if path == "/v1/settings":
                    self._require_empty_query(query)
                    payload = service.get_settings(context, request_id=request_id)
                    self._send_json(200, payload, request_id=request_id, extra_headers=self._rate_headers(decision))
                    return
                if path == "/v1/assets":
                    page = self._page_request(query, filters={})
                    payload = service.list_assets(context, page, request_id=request_id)
                    self._send_json(200, payload, request_id=request_id, extra_headers=self._rate_headers(decision))
                    return
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
                    asset_match = _ASSET_PATH.fullmatch(path)
                    if asset_match:
                        payload = service.get_asset(
                            context, asset_match.group(1), request_id=request_id
                        )
                    elif finding_events_match:
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

        def _unauthenticated_json_body(self, error_code: str) -> dict:
            raw_body = self._read_json_body()
            try:
                body = json.loads(raw_body)
            except json.JSONDecodeError as exc:
                raise ApiTransportError(error_code, "Request body must be valid JSON.", status=400) from exc
            if not isinstance(body, dict):
                raise ApiTransportError(error_code, "Request body must be a JSON object.", status=400)
            return body

        def _user_agent(self) -> str | None:
            values = self.headers.get_all("User-Agent") or []
            return values[0][:512] if values else None

        def do_POST(self) -> None:  # noqa: N802
            request_id = str(uuid4())
            try:
                path, query = self._request_target()
                self._require_empty_query(query)

                # -- unauthenticated browser-auth routes (Slice 16): the
                # request body's own token/credential is the authority
                # here, not a prior session or API token. Each is its
                # own IP-scoped rate-limit bucket inside service.py. --
                if path == "/v1/auth/register":
                    body = self._unauthenticated_json_body("register_body_invalid")
                    context, issued = service.register_account(
                        body, request_id=request_id, user_agent=self._user_agent(),
                        ip_address=self.client_address[0],
                    )
                    self._send_json(
                        201, context.to_public_dict(), request_id=request_id,
                        set_cookies=self._session_set_cookies(issued),
                    )
                    return
                if path == "/v1/auth/login":
                    body = self._unauthenticated_json_body("login_body_invalid")
                    context, issued = service.login(
                        body, request_id=request_id, user_agent=self._user_agent(),
                        ip_address=self.client_address[0],
                    )
                    self._send_json(
                        200, context.to_public_dict(), request_id=request_id,
                        set_cookies=self._session_set_cookies(issued),
                    )
                    return
                if path == "/v1/auth/password/reset/request":
                    body = self._unauthenticated_json_body("password_reset_body_invalid")
                    payload = service.request_password_reset(
                        body, request_id=request_id, ip_address=self.client_address[0]
                    )
                    self._send_json(200, payload, request_id=request_id)
                    return
                if path == "/v1/auth/password/reset/confirm":
                    body = self._unauthenticated_json_body("password_reset_confirm_body_invalid")
                    payload = service.confirm_password_reset(
                        body, request_id=request_id, ip_address=self.client_address[0]
                    )
                    self._send_json(200, payload, request_id=request_id)
                    return
                if path == "/v1/auth/email/verify/confirm":
                    body = self._unauthenticated_json_body("email_verification_body_invalid")
                    payload = service.confirm_email_verification(
                        body, request_id=request_id, ip_address=self.client_address[0]
                    )
                    self._send_json(200, payload, request_id=request_id)
                    return
                if path == "/v1/auth/invitations/accept":
                    body = self._unauthenticated_json_body("invitation_accept_body_invalid")
                    context, issued = service.accept_invitation(
                        body, request_id=request_id, user_agent=self._user_agent(),
                        ip_address=self.client_address[0],
                    )
                    self._send_json(
                        200, context.to_public_dict(), request_id=request_id,
                        set_cookies=self._session_set_cookies(issued),
                    )
                    return

                context, decision = self._authenticate(require_csrf=True)

                # -- authenticated browser-auth routes --
                if path == "/v1/auth/logout":
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError("logout_body_not_allowed", "Logout cannot contain a body.", status=400)
                    service.logout(context, request_id=request_id)
                    self._send_json(
                        200, {"status": "signed_out"}, request_id=request_id,
                        extra_headers=self._rate_headers(decision), set_cookies=self._clear_session_cookies(),
                    )
                    return
                if path == "/v1/auth/logout-all":
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "logout_all_body_not_allowed", "Logout-all cannot contain a body.", status=400
                        )
                    payload = service.logout_all_sessions(context, request_id=request_id)
                    self._send_json(
                        200, payload, request_id=request_id, extra_headers=self._rate_headers(decision),
                        set_cookies=self._clear_session_cookies(),
                    )
                    return
                if path == "/v1/auth/password/change":
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "password_change_body_invalid", "Request body must be valid JSON.", status=400
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "password_change_body_invalid", "Request body must be a JSON object.", status=400
                        )
                    service.change_password(context, body, request_id=request_id)
                    self._send_json(
                        200, {"status": "password_changed"}, request_id=request_id,
                        extra_headers=self._rate_headers(decision),
                    )
                    return
                if path == "/v1/auth/email/verify/request":
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "email_verify_request_body_not_allowed",
                            "This route cannot contain a body.", status=400,
                        )
                    payload = service.request_email_verification(context, request_id=request_id)
                    self._send_json(200, payload, request_id=request_id, extra_headers=self._rate_headers(decision))
                    return

                if path == "/v1/assets":
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "asset_body_invalid", "Request body must be valid JSON.", status=400
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "asset_body_invalid", "Request body must be a JSON object.", status=400
                        )
                    payload = service.create_asset(context, body, request_id=request_id)
                    self._send_json(
                        201, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
                asset_verification_start_match = _ASSET_VERIFICATION_START_PATH.fullmatch(path)
                if asset_verification_start_match:
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "asset_verification_body_not_allowed",
                            "Verification-start requests cannot contain a body.",
                            status=400,
                        )
                    payload = service.start_asset_verification(
                        context, asset_verification_start_match.group(1), request_id=request_id
                    )
                    self._send_json(
                        201, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
                asset_verification_check_match = _ASSET_VERIFICATION_CHECK_PATH.fullmatch(path)
                if asset_verification_check_match:
                    lengths = self.headers.get_all("Content-Length") or []
                    if lengths and any(value != "0" for value in lengths):
                        raise ApiTransportError(
                            "asset_verification_body_not_allowed",
                            "Verification-check requests cannot contain a body.",
                            status=400,
                        )
                    payload = service.check_asset_verification(
                        context, asset_verification_check_match.group(1), request_id=request_id
                    )
                    self._send_json(
                        200, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
                if path == "/v1/team/invitations":
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "team_invite_body_invalid", "Request body must be valid JSON.", status=400
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "team_invite_body_invalid", "Request body must be a JSON object.", status=400
                        )
                    payload = service.invite_team_member(context, body, request_id=request_id)
                    self._send_json(
                        201, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
                if path == "/v1/api-keys":
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "api_key_body_invalid", "Request body must be valid JSON.", status=400
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "api_key_body_invalid", "Request body must be a JSON object.", status=400
                        )
                    payload = service.create_api_key(context, body, request_id=request_id)
                    self._send_json(
                        201, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
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

        def do_PATCH(self) -> None:  # noqa: N802
            request_id = str(uuid4())
            try:
                path, query = self._request_target()
                self._require_empty_query(query)
                context, decision = self._authenticate(require_csrf=True)
                asset_match = _ASSET_PATH.fullmatch(path)
                if asset_match:
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "asset_body_invalid", "Request body must be valid JSON.", status=400
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "asset_body_invalid", "Request body must be a JSON object.", status=400
                        )
                    payload = service.update_asset(context, asset_match.group(1), body, request_id=request_id)
                    self._send_json(
                        200, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
                team_match = _TEAM_MEMBER_PATH.fullmatch(path)
                if team_match:
                    raw_body = self._read_json_body()
                    try:
                        body = json.loads(raw_body)
                    except json.JSONDecodeError as exc:
                        raise ApiTransportError(
                            "team_update_body_invalid", "Request body must be valid JSON.", status=400
                        ) from exc
                    if not isinstance(body, dict):
                        raise ApiTransportError(
                            "team_update_body_invalid", "Request body must be a JSON object.", status=400
                        )
                    payload = service.update_team_member(context, team_match.group(1), body, request_id=request_id)
                    self._send_json(
                        200, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
                raise ApiTransportError("route_not_found", "API route was not found.", status=404)
            except (ApiTransportError, ApiServiceError, AuthenticationError, RateLimitError) as exc:
                self._error(exc, request_id=request_id)

        def do_DELETE(self) -> None:  # noqa: N802
            request_id = str(uuid4())
            try:
                path, query = self._request_target()
                self._require_empty_query(query)
                context, decision = self._authenticate(require_csrf=True)
                lengths = self.headers.get_all("Content-Length") or []
                if lengths and any(value != "0" for value in lengths):
                    raise ApiTransportError(
                        "delete_body_not_allowed", "Delete requests cannot contain a body.", status=400
                    )
                team_match = _TEAM_MEMBER_PATH.fullmatch(path)
                if team_match:
                    payload = service.remove_team_member(context, team_match.group(1), request_id=request_id)
                    self._send_json(
                        200, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
                api_key_match = _API_KEY_PATH.fullmatch(path)
                if api_key_match:
                    payload = service.revoke_api_key(context, api_key_match.group(1), request_id=request_id)
                    self._send_json(
                        200, payload, request_id=request_id, extra_headers=self._rate_headers(decision)
                    )
                    return
                raise ApiTransportError("route_not_found", "API route was not found.", status=404)
            except (ApiTransportError, ApiServiceError, AuthenticationError, RateLimitError) as exc:
                self._error(exc, request_id=request_id)

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
    allowed_origins: frozenset[str] = frozenset(),
    session_authenticator: BrowserSessionAuthenticator | None = None,
    secure_cookies: bool = True,
    hsts_enabled: bool = False,
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
        allowed_origins=allowed_origins,
        session_authenticator=session_authenticator,
        secure_cookies=secure_cookies,
        hsts_enabled=hsts_enabled,
    )
    server = ThreadingHTTPServer((address.compressed, port), handler)
    server.daemon_threads = True
    return server


__all__ = ["ApiTransportError", "build_handler", "create_server"]
