"""Mail provider abstraction (Slice 16 requirement 26).

No production transactional-email integration exists yet -- deliberately.
This module defines the narrow interface a real provider (Postmark, SES,
...) would implement later, plus two backends usable today: a logging
sink for local/dev use (an operator running the API locally can read the
verification/reset link straight off the console) and an in-memory sink
purpose-built for tests (including the browser E2E suite, which needs to
read a just-sent link without any real mail transport existing).
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

_logger = logging.getLogger("webguard_api.mail")


@dataclass(frozen=True, slots=True)
class MailMessage:
    to: str
    subject: str
    body: str
    category: str
    sent_at: datetime


class MailProvider(Protocol):
    def send(self, *, to: str, subject: str, body: str, category: str) -> None: ...


class LoggingMailProvider:
    """Local/dev default: writes the message to the application log
    instead of sending it. An operator running the API locally can read
    a verification/reset/invitation link straight off the console."""

    def send(self, *, to: str, subject: str, body: str, category: str) -> None:
        _logger.info("mail[%s] to=%s subject=%r\n%s", category, to, subject, body)


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


__all__ = [
    "InMemoryMailProvider",
    "LoggingMailProvider",
    "MailMessage",
    "MailProvider",
]
