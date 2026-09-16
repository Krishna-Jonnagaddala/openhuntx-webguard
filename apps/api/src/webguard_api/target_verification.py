"""Target ownership verification (Slice 15 requirement 3).

Migration 0002 (Slice 12) reserved the ``target_verifications`` schema
ahead of any real implementation ("no verification mechanism is
implemented this slice, and no code writes to this table yet"). This
module implements both methods named as examples in the brief ("such
as DNS TXT, .well-known HTTP token"):

- ``WELL_KNOWN_HTTP`` reuses this project's own existing, already-
  safety-reviewed target validation and fetch machinery
  (``scope_validator.validate_target_url`` + ``safe_http.fetch_once``)
  exactly, with zero new network-safety code. A customer-supplied "my
  domain" value is exactly the kind of input the scanner's own SSRF
  protections exist for, so this module deliberately does not invent a
  second, weaker HTTP client for what is structurally the same problem
  (fetch a URL derived from customer input, safely).
- ``DNS_TXT`` resolves a dedicated ``_webguard-verification.<host>``
  TXT record via ``dnspython`` (a real dependency now, not the
  hand-rolled parser this module's own docstring used to reject as a
  worse security trade). A DNS TXT lookup does not carry the same
  SSRF shape ``WELL_KNOWN_HTTP`` does: it asks the recursive
  resolver to look up a name, and it never opens a connection to an
  address the customer chose, so it needs no equivalent of
  ``validate_target_url``, only an operational bound (timeout) against
  a slow or unresponsive authoritative server. The hostname resolved
  is always the same ``target.url`` this organization already owns a
  tenant-scoped ``targets`` row for, never an arbitrary request-time
  string, matching ``WELL_KNOWN_HTTP``'s own trust boundary.

Real deployment forced a concrete gap in the file-based method that is
worth recording here, not just in a ticket: a domain fronted by a
no-code site builder (Wix, Squarespace, Framer, Figma Sites, and
others) commonly has no way to publish an arbitrary static file at an
arbitrary path at all, and some CDN/host combinations redirect between
``www``/apex or http/https before this method's deliberately
redirect-averse fetch ever reaches the file. DNS TXT verification
needs only DNS control, which every domain owner already has
regardless of what serves the site itself, and is therefore the
method that actually completes for that real, not hypothetical, case.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from urllib.parse import urlsplit
from uuid import uuid4

import dns.exception
import dns.resolver

from webguard_scanner.safe_http import FetchPolicy, SafeRequestError, fetch_once
from webguard_scanner.scope_validator import (
    TargetValidationError,
    ValidationMode,
    ValidationPolicy,
    validate_target_url,
)

_DNS_TXT_RECORD_PREFIX = "_webguard-verification"
_DNS_LOOKUP_TIMEOUT_SECONDS = 5.0
# Deliberately not this host's own configured resolver. Two real,
# independent reasons, not one: (1) dnspython's default Resolver()
# parses /etc/resolv.conf literally, but that file is not authoritative
# on every platform (macOS says so in its own header comment), since
# real resolution goes through scutil/mDNSResponder instead, and a
# router-advertised nameserver listed there can be simply unreachable
# while the OS's own working resolution path is fine, exactly the
# failure this project hit verifying a real customer's record: `dig`
# resolved it correctly in milliseconds while dnspython's default
# Resolver() timed out after 15 seconds against the same host's
# /etc/resolv.conf entry. (2) Even where the local resolver does work,
# a corporate VPN, a filtering resolver, or split-horizon internal DNS
# could give a customer-verification check a different answer than the
# public internet sees, which is the one that actually matters here.
_PUBLIC_DNS_RESOLVERS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")


class TargetVerificationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class VerificationMethod(str, Enum):
    WELL_KNOWN_HTTP = "well_known_http"
    DNS_TXT = "dns_txt"


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
            if self.method is VerificationMethod.DNS_TXT:
                payload["instructions"] = {
                    "record_type": "TXT",
                    "record_prefix": _DNS_TXT_RECORD_PREFIX,
                    "expected_content": self.expected_token,
                }
            else:
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


def dns_txt_record_name(target_url: str) -> str:
    """The dedicated TXT record name a verification check resolves --
    a fixed prefix on the asset's own host, never the apex domain's own
    bare name. A dedicated subdomain avoids ever having to search
    through whatever other TXT records the domain owner already has
    there for unrelated reasons (SPF, DKIM, other providers' own site
    verification), the same ``_acme-challenge.<host>`` convention
    ACME's DNS-01 challenge uses for exactly this reason."""

    hostname = urlsplit(target_url).hostname
    if not hostname:
        raise TargetVerificationError(
            "target_verification_invalid_url", "target URL has no resolvable hostname."
        )
    return f"{_DNS_TXT_RECORD_PREFIX}.{hostname}"


def check_dns_txt_token(target_url: str, expected_token: str) -> tuple[bool, str]:
    """Resolve the dedicated TXT record and check whether any of its
    values match the expected token. Returns ``(matched, detail)``, the
    same contract ``check_well_known_token`` uses.

    Unlike the HTTP method, this makes no connection to any address the
    customer chose: it only asks the recursive resolver to look up a
    name, so it needs no SSRF-style address validation, only a bound
    on how long a slow or unresponsive authoritative server can hang
    this call. Queries a fixed set of public resolvers
    (``_PUBLIC_DNS_RESOLVERS``, see that constant's own comment for
    why), never this host's own configured one."""

    try:
        record_name = dns_txt_record_name(target_url)
    except TargetVerificationError as exc:
        return False, f"target-validation-failed.{exc.code}"
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(_PUBLIC_DNS_RESOLVERS)
    resolver.timeout = _DNS_LOOKUP_TIMEOUT_SECONDS
    resolver.lifetime = _DNS_LOOKUP_TIMEOUT_SECONDS
    try:
        answer = resolver.resolve(record_name, "TXT")
    except dns.resolver.NXDOMAIN:
        return False, "dns-record-not-found"
    except dns.resolver.NoAnswer:
        return False, "dns-record-not-found"
    except dns.exception.Timeout:
        return False, "dns-lookup-timed-out"
    except dns.exception.DNSException as exc:
        return False, f"dns-lookup-failed.{type(exc).__name__.lower()}"
    for rdata in answer:
        # A TXT record's value can be split across multiple quoted
        # strings; dnspython exposes them as `strings`, a tuple of byte
        # chunks that concatenate to the record's real value.
        value = b"".join(rdata.strings).decode("utf-8", errors="replace").strip()
        if value == expected_token:
            return True, "verified-dns-txt-match"
    return False, "token-mismatch"


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
        status: VerificationStatus,
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
    "check_dns_txt_token",
    "check_well_known_token",
    "dns_txt_record_name",
    "well_known_verification_url",
]
