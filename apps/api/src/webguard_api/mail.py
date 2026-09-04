"""Mail provider abstraction (Slice 16 requirement 26; production
delivery completed in Slice 17 requirement 1).

Defines the narrow interface identity-domain code (``service.py``)
depends on -- ``send(to, subject, body, category)`` and nothing else --
plus four backends:

- ``DevelopmentMailProvider`` (renamed from Slice 16's
  ``LoggingMailProvider``) -- local/dev default only; a real production
  deployment must configure ``ProductionMailProvider`` explicitly
  (``production_config.py`` fails closed otherwise). P1-B1 removed its
  original behavior of writing the full message body -- including the
  one-time token embedded in a verification/reset/invitation link -- to
  the application log: the redaction boundary that keeps that kind of
  value out of every other log path must not depend on what level a
  given process happens to have its logging configured at, and a
  local/dev console is reachable by exactly the same stdlib logging
  machinery as anything else in this process. It is now a documented
  no-op; see its own class docstring for how to actually inspect a
  message sent during local development.
- ``InMemoryMailProvider`` -- test-only sink, unchanged from Slice 16.
- ``ProductionMailProvider`` -- real transactional delivery via
  Postmark (``docs/production/PROVIDER_EVALUATION.md``'s own
  recommendation), through an injected ``PostmarkClientProtocol``
  rather than a vendor SDK import -- mirroring ``secret_provider.py``'s
  and ``signing.py``'s established duck-typed-client pattern exactly,
  so ``service.py`` never couples to Postmark (or any vendor) directly.
  Logs only non-sensitive delivery metadata (category, recipient,
  provider message ID, outcome) -- **never** the message body or its
  embedded one-time token (requirement 3's "ensure logs never contain
  those tokens").
- ``PostmarkHttpClient`` -- the real HTTPS transport, using only the
  standard library (``http.client``/``json``), matching this
  codebase's established outbound-HTTP convention (see
  ``workers/scanner/src/webguard_scanner/safe_http.py``) rather than
  adding a new SDK dependency for a single POST-JSON exchange.

Failure classification (requirement 6): every delivery failure is a
``MailDeliveryError`` carrying a ``category`` -- ``"temporary"``,
``"permanent"``, ``"configuration"``, ``"rate_limited"``, or
``"timeout"`` -- classified primarily from the HTTP status code (the
part of the contract this module trusts completely) and secondarily
from a small, well-documented set of stable Postmark ``ErrorCode``
values, never from free-text vendor messages. ``ProductionMailProvider``
retries exactly once, and only for a ``temporary``/``timeout``
classification, reusing the identical already-built payload -- the
one-time token was already embedded in it before this class ever sees
it, so a transport retry never causes a caller to mint a second one
(requirement 6's "one-time tokens must not accidentally be regenerated
on every transport retry"). A vendor's raw response text is logged internally for operator debugging only; it never becomes part of a
``MailDeliveryError``'s own ``message`` (requirement 20 -- no vendor
leakage to the customer-facing surface).
"""

from __future__ import annotations

import http.client
import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from .structured_logging import log_event

# P1-B1: this module previously kept one plain, unconverted stdlib
# logger (`_logger = logging.getLogger("webguard_api.mail")`) for
# `DevelopmentMailProvider.send()`, on the reasoning that a local/dev
# console logging the full message body -- including a real one-time
# verification/reset/invitation token -- for operator convenience was
# an acceptable, deliberately-out-of-scope exception to the structured-
# logging allowlist. A pre-commit review correctly rejected that: the
# redaction boundary must not depend on which level a process's root
# logger happens to be configured at (this codebase never calls
# `logging.basicConfig()`, so that line was, in the current state of
# the code, already silently inert -- but relying on that as a safety
# property is exactly the "current configuration happens to suppress
# it" trap the reviewer flagged, not a real guarantee). The logger and
# the call are removed entirely rather than reduced in level or
# partially redacted; see `DevelopmentMailProvider`'s own docstring.
# `ProductionMailProvider`'s calls below (already safe -- category/
# error-code-shaped values only, per this module's own pre-existing
# "no vendor leakage" discipline) remain converted to `log_event()`.


@dataclass(frozen=True, slots=True)
class MailMessage:
    to: str
    subject: str
    body: str
    category: str
    sent_at: datetime


class MailProvider(Protocol):
    def send(self, *, to: str, subject: str, body: str, category: str) -> None: ...


class MailDeliveryError(RuntimeError):
    """A controlled, sanitized mail-delivery failure. ``category`` is
    one of ``"temporary"``, ``"permanent"``, ``"configuration"``,
    ``"rate_limited"``, ``"timeout"`` -- callers use it to decide
    whether the failure is worth surfacing distinctly (e.g. to an
    admin inviting a teammate) or must be swallowed uniformly (e.g.
    the anti-enumeration password-reset-request response, which must
    look identical to callers regardless of whether delivery
    succeeded)."""

    def __init__(self, code: str, message: str, *, category: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.category = category


class DevelopmentMailProvider:
    """Local/dev default when no mail provider is explicitly configured
    and production config hasn't been validated -- `production_startup.py`
    substitutes `ProductionMailProvider` once it has. Deliberately does
    not log the message anywhere, through stdlib logging or structured
    logging: a verification/reset/invitation link embeds a real
    one-time token, and nothing about "this is only a local/dev
    console" changes that a logger is a logger, reachable the same way
    regardless of what level it happens to be configured at today. To
    inspect what a local run "sent" -- the approach the Playwright
    browser E2E suite already uses -- construct the service with an
    explicit `InMemoryMailProvider(sink_path=...)` instead: it captures
    every message programmatically (`messages_to`/`latest_to`) and can
    mirror it to a JSON Lines file for a separate process to read, with
    no logging path involved at all."""

    def send(self, *, to: str, subject: str, body: str, category: str) -> None:
        """Intentionally a no-op beyond accepting the call -- see this
        class's own docstring for why, and for how to actually inspect
        a message sent during local development."""


class InMemoryMailProvider:
    """Test-only sink: captures every message so a test can retrieve the
    exact link/token it just caused the server to "send", with no real
    mail transport involved. Optionally mirrors each message to a JSON
    Lines file (`sink_path`) so an out-of-process reader -- the Playwright
    browser E2E suite -- can observe messages sent by a server running in
    a different process, without any new production-reachable endpoint."""

    def __init__(self, *, sink_path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._messages: list[MailMessage] = []
        self._sink_path = sink_path

    def send(self, *, to: str, subject: str, body: str, category: str) -> None:
        message = MailMessage(to=to, subject=subject, body=body, category=category, sent_at=datetime.now(timezone.utc))
        with self._lock:
            self._messages.append(message)
            if self._sink_path is not None:
                with open(self._sink_path, "a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "to": message.to,
                                "subject": message.subject,
                                "body": message.body,
                                "category": message.category,
                                "sent_at": message.sent_at.isoformat(),
                            }
                        )
                        + "\n"
                    )

    def messages_to(self, to: str, *, category: str | None = None) -> tuple[MailMessage, ...]:
        with self._lock:
            return tuple(
                message
                for message in self._messages
                if message.to == to and (category is None or message.category == category)
            )

    def latest_to(self, to: str, *, category: str | None = None) -> MailMessage | None:
        matches = self.messages_to(to, category=category)
        return matches[-1] if matches else None


class PostmarkClientProtocol(Protocol):
    """Structural shape of the one Postmark operation this module
    calls -- satisfied by a real ``PostmarkHttpClient`` (below) or a
    plain fake in tests, exactly like ``secret_provider.py``'s
    ``SecretsManagerClientProtocol`` and ``signing.py``'s
    ``KmsClientProtocol``."""

    def send_email(self, payload: dict) -> dict:
        """POST ``payload`` to Postmark's ``/email`` endpoint and
        return ``{"status_code": int, "body": dict}``. Raises
        ``MailDeliveryError`` (category ``"timeout"`` or
        ``"temporary"``) on a transport-level failure -- a real HTTP
        error response (4xx/5xx) is returned normally, not raised,
        since classifying it is ``ProductionMailProvider``'s job, not
        the transport's."""
        ...


class PostmarkHttpClient:
    """Real HTTPS transport to Postmark's REST API using only the
    standard library -- no vendor SDK dependency for a single
    POST-JSON-get-JSON exchange, matching
    ``webguard_scanner.safe_http``'s own stdlib-only convention."""

    _HOST = "api.postmarkapp.com"
    _PATH = "/email"

    def __init__(self, *, server_token: str, timeout_seconds: float = 10.0) -> None:
        self._server_token = server_token
        self._timeout_seconds = timeout_seconds

    def send_email(self, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        connection = http.client.HTTPSConnection(self._HOST, timeout=self._timeout_seconds)
        try:
            connection.request(
                "POST",
                self._PATH,
                body=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-Postmark-Server-Token": self._server_token,
                },
            )
            response = connection.getresponse()
            raw = response.read()
            status_code = response.status
        except TimeoutError as exc:
            raise MailDeliveryError(
                "mail_transport_timeout", "Timed out contacting the mail provider.", category="timeout"
            ) from exc
        except OSError as exc:
            raise MailDeliveryError(
                "mail_transport_unreachable", "Unable to reach the mail provider.", category="temporary"
            ) from exc
        finally:
            connection.close()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError) as exc:
            raise MailDeliveryError(
                "mail_provider_response_invalid",
                "The mail provider returned an unparseable response.",
                category="temporary",
            ) from exc
        return {"status_code": status_code, "body": parsed if isinstance(parsed, dict) else {}}


def _classify_postmark_failure(*, status_code: int | None, error_code: object, vendor_message: object) -> MailDeliveryError:
    """Classify a non-success Postmark response. Primarily driven by
    the HTTP status code (a contract this module trusts completely);
    a small set of stable, long-documented Postmark ``ErrorCode``
    values refines that further. The raw ``vendor_message`` is never
    placed on the returned error's own ``.message`` -- callers may log
    it separately, but nothing here propagates vendor text outward
    (requirement 20)."""

    if status_code == 429:
        return MailDeliveryError(
            "mail_rate_limited", "The mail provider is rate-limiting this account.", category="rate_limited"
        )
    if status_code in (401, 403) or error_code == 10:
        return MailDeliveryError(
            "mail_provider_misconfigured",
            "The mail provider rejected the configured credentials.",
            category="configuration",
        )
    if isinstance(status_code, int) and status_code >= 500:
        return MailDeliveryError(
            "mail_provider_unavailable", "The mail provider is temporarily unavailable.", category="temporary"
        )
    if error_code == 406:
        return MailDeliveryError(
            "mail_recipient_inactive",
            "The recipient address is inactive or has previously bounced.",
            category="permanent",
        )
    if isinstance(status_code, int) and 400 <= status_code < 500:
        return MailDeliveryError(
            "mail_rejected", "The mail provider rejected this message.", category="permanent"
        )
    return MailDeliveryError(
        "mail_delivery_failed", "The mail provider returned an unexpected response.", category="temporary"
    )


class ProductionMailProvider:
    """Postmark-backed transactional email. Domain logic here never
    touches a vendor SDK -- only ``PostmarkClientProtocol``. Retries
    exactly once, only for a ``temporary``/``timeout`` classification,
    with the identical payload (see module docstring)."""

    def __init__(
        self,
        client: PostmarkClientProtocol,
        *,
        from_address: str,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client
        self._from_address = from_address
        self._sleep = sleep

    def send(self, *, to: str, subject: str, body: str, category: str) -> None:
        payload = {
            "From": self._from_address,
            "To": to,
            "Subject": subject,
            "TextBody": body,
            "MessageStream": "outbound",
            # Postmark's own message-categorization field (shows up in
            # their dashboard/analytics and any configured webhook) --
            # a legitimate, vendor-native way to carry the low-
            # cardinality "template/event type" requirement 5 asks
            # for, without inventing a WebGuard-specific header.
            "Tag": category,
        }
        attempts = 2
        last_error: MailDeliveryError | None = None
        for attempt in range(attempts):
            try:
                result = self._client.send_email(payload)
            except MailDeliveryError as exc:
                last_error = exc
                if exc.category in ("temporary", "timeout") and attempt < attempts - 1:
                    self._sleep(0.5)
                    continue
                log_event(
                    event="mail_delivery_failed", level="warning",
                    error_code=exc.code, reason_code=exc.category, attempt=attempt + 1,
                )
                raise
            status_code = result.get("status_code")
            response_body = result.get("body") or {}
            error_code = response_body.get("ErrorCode")
            if status_code == 200 and error_code == 0:
                log_event(event="mail_delivery_completed", level="info", attempt=attempt + 1)
                return
            classified = _classify_postmark_failure(
                status_code=status_code, error_code=error_code, vendor_message=response_body.get("Message")
            )
            last_error = classified
            if classified.category in ("temporary", "timeout") and attempt < attempts - 1:
                log_event(
                    event="mail_delivery_retry", level="info",
                    reason_code=classified.category, attempt=attempt + 1,
                )
                self._sleep(0.5)
                continue
            log_event(
                event="mail_delivery_failed", level="warning",
                error_code=classified.code, reason_code=classified.category, attempt=attempt + 1,
            )
            raise classified
        assert last_error is not None  # pragma: no cover - loop always returns or raises
        raise last_error


__all__ = [
    "DevelopmentMailProvider",
    "InMemoryMailProvider",
    "MailDeliveryError",
    "MailMessage",
    "MailProvider",
    "PostmarkClientProtocol",
    "PostmarkHttpClient",
    "ProductionMailProvider",
]
