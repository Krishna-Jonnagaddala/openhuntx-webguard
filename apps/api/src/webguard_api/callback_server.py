"""Real local HTTP callback receiver for SSRF detection (Slice 10).

A genuine, runnable `ThreadingHTTPServer`-based listener -- not a test
mock -- that accepts an inbound request at ``/<scan_id>/<token>`` and
records it as a `CallbackObservation` via the injected observation
sink (normally a `CallbackRepository`). This is what a target
application's own server-side outbound request actually connects to
when it is vulnerable to SSRF.

This is deliberately a *separate* component from the detector
(requirement 19): the detector only ever talks to a `CallbackBroker`
protocol, never to this class or to a socket directly. That separation
is what makes a later, separately-scalable cloud callback service
(``callback.openhuntx.com`` -- see the phase 10 audit doc's
documented, not-yet-built production requirements) a drop-in
replacement rather than a rewrite.

Correlation is based **only** on the token presented in the path,
never on the source address or the Host header the request arrived
with -- this is what makes correlation robust to DNS rebinding or
callback-host spoofing (requirement 9): even if a hostname resolves
somewhere unexpected, or a request arrives claiming a different Host,
it is still only ever accepted as evidence for the exact token it
carries.

Every accepted or rejected request receives a bounded, generic
response (default `204 No Content`) -- this receiver never redirects,
executes, or reflects anything from the request back to the caller by
default. A test-only, explicit `respond_with_redirect` flag exists
solely to prove that a target application's own downstream redirect
handling (or lack of it) has no bearing on whether WebGuard already
recorded the observation -- confirmation happens the moment the
request arrives, never after any further round trip.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol


class _ObservationSink(Protocol):
    """What the receiver actually needs -- satisfied by both
    `CallbackRepository` (the normal, tenancy-aware case) and a bare
    `webguard_scanner.callback_broker.InMemoryCallbackBroker` (used
    directly by detector-level live-fixture tests that have no
    tenancy concept at all)."""

    def record_observation(
        self, token_value: str, *, method: str, now: datetime | None = None
    ) -> bool: ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_handler(
    repository: _ObservationSink, *, respond_with_redirect: bool
) -> type[BaseHTTPRequestHandler]:
    class _CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:  # noqa: D401
            return None

        def _handle(self) -> None:
            # Path shape: /<scan_id>/<token>. Only the trailing segment
            # (the token) is ever used for correlation -- scan_id is
            # accepted for a readable path structure and future
            # logging, never trusted as an authority signal by itself.
            segments = [segment for segment in self.path.split("/") if segment]
            token_value = segments[-1] if segments else ""
            repository.record_observation(
                token_value, method=self.command, now=_utc_now()
            )
            if respond_with_redirect:
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self._handle()

        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            if content_length:
                self.rfile.read(content_length)
            self._handle()

        def do_HEAD(self) -> None:  # noqa: N802
            self._handle()

    return _CallbackHandler


class CallbackHttpReceiver:
    """A real, bindable local HTTP server implementing the receiver
    role of the callback architecture. Not started automatically as
    part of ``webguard-api serve`` this slice -- an operator (or a
    test) constructs and starts one explicitly, mirroring how the
    worker and scheduler are already independently-run components in
    this architecture."""

    def __init__(
        self,
        repository: _ObservationSink,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        respond_with_redirect: bool = False,
    ) -> None:
        handler = _make_handler(repository, respond_with_redirect=respond_with_redirect)
        self._server = ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


__all__ = ["CallbackHttpReceiver"]
