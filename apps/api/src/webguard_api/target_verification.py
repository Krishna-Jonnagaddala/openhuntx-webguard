"""Target ownership verification (Slice 15 requirement 3).

Migration 0002 (Slice 12) reserved the ``target_verifications`` schema
ahead of any real implementation ("no verification mechanism is
implemented this slice, and no code writes to this table yet"). This
module is that implementation -- scoped deliberately to one method,
not the two named as examples in the brief ("such as DNS TXT,
.well-known HTTP token"): the ``.well-known`` HTTP token check, because
it reuses this project's own existing, already-safety-reviewed target
validation and fetch machinery (``scope_validator.validate_target_url``
+ ``safe_http.fetch_once``) exactly, with zero new network-safety code.
A customer-supplied "my domain" value is exactly the kind of input the
scanner's own SSRF protections exist for -- this module deliberately
does not invent a second, weaker HTTP client for what is structurally
the same problem (fetch a URL derived from customer input, safely).

DNS TXT verification is not implemented this slice -- it would need a
DNS resolver library this project does not currently depend on
(the standard library has no TXT record support), and is deferred as a
named, documented gap rather than attempted with a hand-rolled DNS
parser, which would be a worse security trade than deferring.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from urllib.parse import urlsplit
from uuid import uuid4

from webguard_scanner.safe_http import FetchPolicy, SafeRequestError, fetch_once
from webguard_scanner.scope_validator import (
    TargetValidationError,
    ValidationMode,
    ValidationPolicy,
    validate_target_url,
)


class TargetVerificationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class VerificationMethod(str, Enum):
    WELL_KNOWN_HTTP = "well_known_http"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


VERIFICATION_TOKEN_TTL = timedelta(hours=24)
_WELL_KNOWN_PATH = "/.well-known/webguard-verification.txt"


@dataclass(frozen=True, slots=True)
class TargetVerificationRecord:
    verification_id: str
    target_id: str
    organization_id: str
    method: VerificationMethod
    status: VerificationStatus
    checked_at: datetime
    evidence: str | None = None
    expires_at: datetime | None = None
    # Only populated while PENDING, by the repository that just created
    # this record -- never persisted as its own column, and never
    # returned once status leaves PENDING (see module docstring: the
    # token is a one-time proof, not an ongoing secret).
    expected_token: str | None = None

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "verification_id": self.verification_id,
            "target_id": self.target_id,
            "method": self.method.value,
            "status": self.status.value,
            "checked_at": self.checked_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "evidence": self.evidence,
        }
        if self.expires_at is not None:
            payload["expires_at"] = (
                self.expires_at.astimezone(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
        if self.expected_token is not None:
            payload["instructions"] = {
                "path": _WELL_KNOWN_PATH,
                "expected_content": self.expected_token,
            }
        return payload


def well_known_verification_url(target_url: str) -> str:
    """The origin-scoped ``.well-known`` URL a verification check fetches
    -- same scheme/host/port as the asset's own target, never the
    asset's own path (``.well-known`` is origin-scoped by convention)."""

    parsed = urlsplit(target_url)
    return f"{parsed.scheme}://{parsed.netloc}{_WELL_KNOWN_PATH}"


def check_well_known_token(target_url: str, expected_token: str) -> tuple[bool, str]:
    """Fetch the well-known verification file and check it contains the
    expected token, using the identical safe-fetch machinery the
    scanner itself uses (public-address-only resolution, bounded
    response size, no redirect following). Returns ``(matched, detail)``
    -- ``detail`` is a canonical, lower-case identifier (never free text,
    since it doubles as an audit-event detail code as well as the
    verification record's own evidence field) describing the outcome,
    never the raw response body."""

    url = well_known_verification_url(target_url)
    try:
        validated = validate_target_url(url, ValidationPolicy(mode=ValidationMode.COMMERCIAL))
    except TargetValidationError as exc:
        return False, f"target-validation-failed.{exc.code}"
    try:
        response = fetch_once(
            validated,
            "GET",
            FetchPolicy(maximum_body_bytes=4096, allowed_methods=frozenset({"GET"})),
        )
    except SafeRequestError as exc:
        return False, f"fetch-failed.{exc.code}"
    if response.status != 200:
        return False, f"unexpected-status.{response.status}"
    body = response.body.decode("utf-8", errors="replace").strip()
    if body != expected_token:
        return False, "token-mismatch"
    return True, "verified-well-known-token-match"


def _without_token(record: TargetVerificationRecord) -> TargetVerificationRecord:
    if record.expected_token is None:
        return record
    return TargetVerificationRecord(
        verification_id=record.verification_id,
        target_id=record.target_id,
        organization_id=record.organization_id,
        method=record.method,
        status=record.status,
        checked_at=record.checked_at,
        evidence=record.evidence,
        expires_at=record.expires_at,
        expected_token=None,
    )


class InMemoryTargetVerificationRepository:
    """Local/unit/lab backend, matching
    :class:`PostgresTargetVerificationRepository`'s surface exactly."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_target: dict[str, TargetVerificationRecord] = {}

    def initiate(
        self,
        target_id: str,
        *,
        organization_id: str,
        method: VerificationMethod,
        now: datetime,
    ) -> TargetVerificationRecord:
        token = secrets.token_urlsafe(24)
        record = TargetVerificationRecord(
            verification_id=str(uuid4()),
            target_id=target_id,
            organization_id=organization_id,
            method=method,
            status=VerificationStatus.PENDING,
            checked_at=now,
            expires_at=now + VERIFICATION_TOKEN_TTL,
            expected_token=token,
        )
        with self._lock:
            self._by_target[target_id] = record
        return record

    def get_current(self, target_id: str, *, organization_id: str) -> TargetVerificationRecord | None:
        with self._lock:
            record = self._by_target.get(target_id)
        if record is None or record.organization_id != organization_id:
            return None
        # Matches PostgresTargetVerificationRepository's own contract:
        # the token is never returned once a check has actually run.
        return record if record.status is VerificationStatus.PENDING else _without_token(record)

    def get_pending_token(self, verification_id: str, *, organization_id: str) -> str:
        with self._lock:
            record = next(
                (r for r in self._by_target.values() if r.verification_id == verification_id),
                None,
            )
        if (
            record is None
            or record.organization_id != organization_id
            or record.status is not VerificationStatus.PENDING
            or record.expected_token is None
        ):
            raise TargetVerificationError(
                "target_verification_not_found", "No pending verification matches the requested ID."
            )
        return record.expected_token

    def record_result(
        self,
        verification_id: str,
        *,
        organization_id: str,
        matched: bool,
        detail: str,
        now: datetime,
    ) -> TargetVerificationRecord:
        with self._lock:
            record = next(
                (r for r in self._by_target.values() if r.verification_id == verification_id),
                None,
            )
            if record is None or record.organization_id != organization_id:
                raise TargetVerificationError(
                    "target_verification_not_found", "No pending verification matches the requested ID."
                )
            status = VerificationStatus.VERIFIED if matched else VerificationStatus.FAILED
            updated = TargetVerificationRecord(
                verification_id=record.verification_id,
                target_id=record.target_id,
                organization_id=record.organization_id,
                method=record.method,
                status=status,
                checked_at=now,
                evidence=detail,
                expires_at=record.expires_at,
                expected_token=None,
            )
            self._by_target[record.target_id] = updated
        return updated


__all__ = [
    "InMemoryTargetVerificationRepository",
    "TargetVerificationError",
    "TargetVerificationRecord",
    "VerificationMethod",
    "VerificationStatus",
    "check_well_known_token",
    "well_known_verification_url",
]
