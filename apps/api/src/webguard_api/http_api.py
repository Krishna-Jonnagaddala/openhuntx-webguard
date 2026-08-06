"""Local-only HTTP/JSON transport for the WebGuard job service."""

from __future__ import annotations

import ipaddress
import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Type
from urllib.parse import urlsplit

from .service import ApiServiceError, WebGuardJobService


_JOB_PATH = re.compile(r"^/v1/jobs/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_JOB_CANCEL_PATH = re.compile(r"^/v1/jobs/([0-9a-f-]{36})/cancel$")
_JOB_RESULT_PATH = re.compile(r"^/v1/jobs/([0-9a-f-]{36})/result$")


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
    maximum_request_bytes: int,
) -> Type[BaseHTTPRequestHandler]:
    """Create a request handler bound to one application service instance."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "OpenHuntX-WebGuard-API"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _send_json(self, status: int, payload: object) -> None:
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _error(self, exc: ApiTransportError | ApiServiceError) -> None:
            self._send_json(
                exc.status,
                {"error": {"code": exc.code, "message": exc.message}},
            )

        def _path(self) -> str:
            parsed = urlsplit(self.path)
            if parsed.query or parsed.fragment:
                raise ApiTransportError(
                    "request_target_invalid",
                    "API request targets cannot contain query strings or fragments.",
                    status=400,
                )
            return parsed.path

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

        def do_GET(self) -> None:  # noqa: N802
            try:
                path = self._path()
                if path == "/healthz":
                    self._send_json(200, {"status": "ok"})
                    return
                match = _JOB_PATH.fullmatch(path)
                if match:
                    self._send_json(200, service.get(match.group(1)))
                    return
                match = _JOB_RESULT_PATH.fullmatch(path)
                if match:
                    self._send_json(200, service.result(match.group(1)))
                    return
                raise ApiTransportError(
                    "route_not_found",
                    "API route was not found.",
                    status=404,
                )
            except (ApiTransportError, ApiServiceError) as exc:
                self._error(exc)

        def do_POST(self) -> None:  # noqa: N802
            try:
                path = self._path()
                if path == "/v1/jobs":
                    keys = self.headers.get_all("Idempotency-Key") or []
                    if len(keys) != 1:
                        raise ApiTransportError(
                            "idempotency_key_required",
                            "Exactly one Idempotency-Key header is required.",
                            status=400,
                        )
                    payload, created = service.submit(
                        self._read_json_body(),
                        idempotency_key=keys[0],
                    )
                    self._send_json(201 if created else 200, payload)
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
                    self._send_json(200, service.cancel(match.group(1)))
                    return
                raise ApiTransportError(
                    "route_not_found",
                    "API route was not found.",
                    status=404,
                )
            except (ApiTransportError, ApiServiceError) as exc:
                self._error(exc)

        def do_PUT(self) -> None:  # noqa: N802
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": {"code": "method_not_allowed", "message": "Method not allowed."}},
            )

        do_DELETE = do_PUT
        do_PATCH = do_PUT

    return Handler


def create_server(
    host: str,
    port: int,
    service: WebGuardJobService,
    *,
    maximum_request_bytes: int,
) -> ThreadingHTTPServer:
    """Bind the local HTTP transport. Host validation occurs in ServiceConfig."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ApiTransportError(
            "service_host_invalid",
            "API host must be a loopback IP literal.",
            status=500,
        ) from exc
    if not address.is_loopback:
        raise ApiTransportError(
            "service_non_loopback_binding_rejected",
            "Milestone 1.26 permits loopback API binding only.",
            status=500,
        )
    handler = build_handler(
        service,
        maximum_request_bytes=maximum_request_bytes,
    )
    server = ThreadingHTTPServer((address.compressed, port), handler)
    server.daemon_threads = True
    return server


__all__ = ["ApiTransportError", "build_handler", "create_server"]
