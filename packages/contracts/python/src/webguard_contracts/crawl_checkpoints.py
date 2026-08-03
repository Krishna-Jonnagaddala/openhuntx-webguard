
"""Signed, versioned crawl checkpoint contracts for OpenHuntX WebGuard."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import stat
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from .crawl_scans import (
    CrawlLinkSkip,
    CrawlPageScanResult,
    CrawlScanPolicy,
    CrawlScanResult,
    CrawlScanTermination,
    CrawlTerminationReason,
)
from .scans import ScanStatus


CURRENT_CRAWL_CHECKPOINT_SCHEMA_VERSION = "1.0"
SUPPORTED_CRAWL_CHECKPOINT_SCHEMA_VERSIONS = ("1.0",)
CRAWL_CHECKPOINT_TYPE = "crawl_checkpoint"
CRAWL_CHECKPOINT_INTEGRITY_ALGORITHM = "hmac-sha256"

MINIMUM_CRAWL_CHECKPOINT_KEY_BYTES = 32
MAXIMUM_CRAWL_CHECKPOINT_KEY_BYTES = 4096
MAXIMUM_CRAWL_CHECKPOINT_BYTES = 16 * 1024 * 1024
MAXIMUM_CRAWL_CHECKPOINT_PENDING_PAGES = 50
MAXIMUM_CRAWL_CHECKPOINT_URL_LENGTH = 2048


class CrawlCheckpointError(ValueError):
    """Base class for controlled checkpoint failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class CrawlCheckpointValidationError(CrawlCheckpointError):
    """Raised when an in-memory checkpoint is inconsistent."""


class CrawlCheckpointLoadError(CrawlCheckpointError):
    """Raised when a checkpoint document cannot be loaded safely."""


class CrawlCheckpointIntegrityError(CrawlCheckpointLoadError):
    """Raised when checkpoint authentication fails."""


class CrawlCheckpointResumeError(CrawlCheckpointError):
    """Raised when a checkpoint cannot safely resume a target."""


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CrawlCheckpointValidationError(
            "checkpoint_timestamp_invalid",
            "Checkpoint timestamps must be timezone-aware datetime values.",
        )
    canonical = value.astimezone(timezone.utc)
    return canonical.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CrawlCheckpointLoadError(
            "checkpoint_timestamp_invalid",
            f"{field_name} must use canonical UTC Z notation.",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_timestamp_invalid",
            f"{field_name} is not a valid timestamp.",
        ) from exc
    canonical = _utc_timestamp(parsed)
    if canonical != value:
        raise CrawlCheckpointLoadError(
            "checkpoint_timestamp_non_canonical",
            f"{field_name} is not canonical.",
        )
    return parsed.astimezone(timezone.utc)


def _canonical_url(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAXIMUM_CRAWL_CHECKPOINT_URL_LENGTH:
        raise CrawlCheckpointValidationError(
            "checkpoint_url_invalid",
            f"{field_name} must be a bounded HTTP or HTTPS URL.",
        )
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise CrawlCheckpointValidationError(
            "checkpoint_url_invalid",
            f"{field_name} is not a valid URL.",
        ) from exc

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else None
    if scheme not in {"http", "https"} or hostname is None:
        raise CrawlCheckpointValidationError(
            "checkpoint_url_invalid",
            f"{field_name} must be an absolute HTTP or HTTPS URL.",
        )
    if parsed.username is not None or parsed.password is not None:
        raise CrawlCheckpointValidationError(
            "checkpoint_url_credentials_not_allowed",
            f"{field_name} cannot contain user information.",
        )
    if parsed.query or parsed.fragment:
        raise CrawlCheckpointValidationError(
            "checkpoint_url_query_fragment_not_allowed",
            f"{field_name} cannot contain a query string or fragment.",
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise CrawlCheckpointValidationError(
            "checkpoint_url_port_invalid",
            f"{field_name} contains an invalid port.",
        ) from exc

    default_port = 443 if scheme == "https" else 80
    authority = hostname if port in {None, default_port} else f"{hostname}:{port}"
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    canonical = urlunsplit((scheme, authority, path, "", ""))
    if canonical != value:
        raise CrawlCheckpointValidationError(
            "checkpoint_url_non_canonical",
            f"{field_name} must be canonical.",
        )
    return canonical


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    assert parsed.hostname is not None
    return parsed.scheme, parsed.hostname, port


def _bounded_text(value: object, field_name: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise CrawlCheckpointValidationError(
            "checkpoint_text_invalid",
            f"{field_name} must be a string.",
        )
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise CrawlCheckpointValidationError(
            "checkpoint_text_invalid",
            f"{field_name} must be non-empty and no longer than {maximum} characters.",
        )
    return cleaned


def _bounded_integer(value: object, field_name: str, *, minimum: int = 0, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise CrawlCheckpointValidationError(
            "checkpoint_integer_invalid",
            f"{field_name} must be an integer from {minimum} to {maximum}.",
        )
    return value


def _bounded_number(value: object, field_name: str, *, minimum: float = 0.0, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CrawlCheckpointValidationError(
            "checkpoint_number_invalid",
            f"{field_name} must be a number.",
        )
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise CrawlCheckpointValidationError(
            "checkpoint_number_invalid",
            f"{field_name} must be from {minimum:g} to {maximum:g}.",
        )
    return number


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CrawlCheckpointValidationError(
            "checkpoint_json_invalid",
            "Checkpoint state cannot be encoded as canonical JSON.",
        ) from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _checkpoint_key(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise CrawlCheckpointValidationError(
            "checkpoint_key_invalid",
            "Checkpoint key must be bytes.",
        )
    key = bytes(value)
    if not MINIMUM_CRAWL_CHECKPOINT_KEY_BYTES <= len(key) <= MAXIMUM_CRAWL_CHECKPOINT_KEY_BYTES:
        raise CrawlCheckpointValidationError(
            "checkpoint_key_invalid",
            "Checkpoint key must contain 32 to 4096 bytes.",
        )
    return key


@dataclass(frozen=True, slots=True)
class CrawlCheckpointFetchPolicy:
    timeout_seconds: float
    maximum_body_bytes: int
    maximum_header_bytes: int
    maximum_header_count: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "timeout_seconds",
            _bounded_number(
                self.timeout_seconds,
                "fetch_policy.timeout_seconds",
                minimum=0.001,
                maximum=3600.0,
            ),
        )
        object.__setattr__(
            self,
            "maximum_body_bytes",
            _bounded_integer(
                self.maximum_body_bytes,
                "fetch_policy.maximum_body_bytes",
                minimum=1,
                maximum=64 * 1024 * 1024,
            ),
        )
        object.__setattr__(
            self,
            "maximum_header_bytes",
            _bounded_integer(
                self.maximum_header_bytes,
                "fetch_policy.maximum_header_bytes",
                minimum=1,
                maximum=8 * 1024 * 1024,
            ),
        )
        object.__setattr__(
            self,
            "maximum_header_count",
            _bounded_integer(
                self.maximum_header_count,
                "fetch_policy.maximum_header_count",
                minimum=1,
                maximum=10000,
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "maximum_body_bytes": self.maximum_body_bytes,
            "maximum_header_bytes": self.maximum_header_bytes,
            "maximum_header_count": self.maximum_header_count,
        }


@dataclass(frozen=True, slots=True)
class CrawlCheckpointRetryPolicy:
    maximum_attempts: int
    initial_backoff_seconds: float
    backoff_multiplier: float
    maximum_backoff_seconds: float

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "maximum_attempts",
            _bounded_integer(
                self.maximum_attempts,
                "retry_policy.maximum_attempts",
                minimum=1,
                maximum=10,
            ),
        )
        object.__setattr__(
            self,
            "initial_backoff_seconds",
            _bounded_number(
                self.initial_backoff_seconds,
                "retry_policy.initial_backoff_seconds",
                maximum=300.0,
            ),
        )
        object.__setattr__(
            self,
            "backoff_multiplier",
            _bounded_number(
                self.backoff_multiplier,
                "retry_policy.backoff_multiplier",
                minimum=1.0,
                maximum=100.0,
            ),
        )
        object.__setattr__(
            self,
            "maximum_backoff_seconds",
            _bounded_number(
                self.maximum_backoff_seconds,
                "retry_policy.maximum_backoff_seconds",
                maximum=300.0,
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "maximum_attempts": self.maximum_attempts,
            "initial_backoff_seconds": self.initial_backoff_seconds,
            "backoff_multiplier": self.backoff_multiplier,
            "maximum_backoff_seconds": self.maximum_backoff_seconds,
        }


@dataclass(frozen=True, slots=True)
class CrawlCheckpointPendingPage:
    url: str
    depth: int
    parent_url: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "url", _canonical_url(self.url, "pending_page.url"))
        object.__setattr__(
            self,
            "depth",
            _bounded_integer(
                self.depth,
                "pending_page.depth",
                minimum=0,
                maximum=3,
            ),
        )
        if self.parent_url is None:
            parent = None
        else:
            parent = _canonical_url(
                self.parent_url,
                "pending_page.parent_url",
            )
        object.__setattr__(self, "parent_url", parent)

        if self.depth == 0 and parent is not None:
            raise CrawlCheckpointValidationError(
                "checkpoint_pending_root_parent_invalid",
                "A depth-zero pending page cannot have a parent.",
            )
        if self.depth > 0 and parent is None:
            raise CrawlCheckpointValidationError(
                "checkpoint_pending_parent_required",
                "A non-root pending page requires a parent.",
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "depth": self.depth,
            "parent_url": self.parent_url,
        }


@dataclass(frozen=True, slots=True)
class CrawlCheckpoint:
    scan_id: str
    target: str
    resolved_addresses: tuple[str, ...]
    engine: str
    engine_version: str
    started_at: datetime
    updated_at: datetime
    policy: CrawlScanPolicy
    fetch_policy: CrawlCheckpointFetchPolicy
    retry_policy: CrawlCheckpointRetryPolicy
    pages: tuple[CrawlPageScanResult, ...] = ()
    pending_pages: tuple[CrawlCheckpointPendingPage, ...] = ()
    visited_urls: tuple[str, ...] = ()
    skipped_links: tuple[CrawlLinkSkip, ...] = ()
    elapsed_execution_seconds: float = 0.0
    attempts_used: int = 0
    checkpoint_type: str = field(default=CRAWL_CHECKPOINT_TYPE, init=False)
    schema_version: str = field(
        default=CURRENT_CRAWL_CHECKPOINT_SCHEMA_VERSION,
        init=False,
    )
    policy_fingerprint: str = field(default="", init=False)
    target_fingerprint: str = field(default="", init=False)

    def __post_init__(self) -> None:
        try:
            canonical_scan_id = str(uuid.UUID(str(self.scan_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise CrawlCheckpointValidationError(
                "checkpoint_scan_id_invalid",
                "scan_id must be a valid UUID.",
            ) from exc

        target = _canonical_url(self.target, "target")
        engine = _bounded_text(self.engine, "engine", 96)
        engine_version = _bounded_text(
            self.engine_version,
            "engine_version",
            64,
        )
        started_at = _parse_or_validate_datetime(
            self.started_at,
            "started_at",
        )
        updated_at = _parse_or_validate_datetime(
            self.updated_at,
            "updated_at",
        )
        if updated_at < started_at:
            raise CrawlCheckpointValidationError(
                "checkpoint_updated_before_started",
                "updated_at cannot be earlier than started_at.",
            )

        if not isinstance(self.policy, CrawlScanPolicy):
            raise CrawlCheckpointValidationError(
                "checkpoint_policy_invalid",
                "policy must be a CrawlScanPolicy.",
            )
        if not isinstance(self.fetch_policy, CrawlCheckpointFetchPolicy):
            raise CrawlCheckpointValidationError(
                "checkpoint_fetch_policy_invalid",
                "fetch_policy must be a CrawlCheckpointFetchPolicy.",
            )
        if not isinstance(self.retry_policy, CrawlCheckpointRetryPolicy):
            raise CrawlCheckpointValidationError(
                "checkpoint_retry_policy_invalid",
                "retry_policy must be a CrawlCheckpointRetryPolicy.",
            )

        addresses: set[str] = set()
        for value in self.resolved_addresses:
            try:
                addresses.add(ipaddress.ip_address(value).compressed)
            except ValueError as exc:
                raise CrawlCheckpointValidationError(
                    "checkpoint_address_invalid",
                    f"Invalid resolved address {value!r}.",
                ) from exc
        if not addresses:
            raise CrawlCheckpointValidationError(
                "checkpoint_addresses_required",
                "At least one resolved target address is required.",
            )

        if any(not isinstance(item, CrawlPageScanResult) for item in self.pages):
            raise CrawlCheckpointValidationError(
                "checkpoint_pages_invalid",
                "pages contains an invalid value.",
            )
        if any(
            not isinstance(item, CrawlCheckpointPendingPage)
            for item in self.pending_pages
        ):
            raise CrawlCheckpointValidationError(
                "checkpoint_pending_pages_invalid",
                "pending_pages contains an invalid value.",
            )
        if any(not isinstance(item, CrawlLinkSkip) for item in self.skipped_links):
            raise CrawlCheckpointValidationError(
                "checkpoint_skipped_links_invalid",
                "skipped_links contains an invalid value.",
            )

        pages = tuple(self.pages)
        pending_pages = tuple(self.pending_pages)
        skipped_links = tuple(
            sorted(self.skipped_links, key=lambda item: item.reason)
        )

        if len(pending_pages) > MAXIMUM_CRAWL_CHECKPOINT_PENDING_PAGES:
            raise CrawlCheckpointValidationError(
                "checkpoint_pending_page_limit",
                "pending_pages exceeds the checkpoint limit.",
            )
        if len(pages) + len(pending_pages) > self.policy.maximum_pages:
            raise CrawlCheckpointValidationError(
                "checkpoint_page_limit_exceeded",
                "Attempted and pending pages exceed policy.maximum_pages.",
            )

        attempted_urls = [page.url for page in pages]
        pending_urls = [page.url for page in pending_pages]
        if len(set(attempted_urls)) != len(attempted_urls):
            raise CrawlCheckpointValidationError(
                "checkpoint_page_duplicate",
                "pages contains duplicate URLs.",
            )
        if len(set(pending_urls)) != len(pending_urls):
            raise CrawlCheckpointValidationError(
                "checkpoint_pending_page_duplicate",
                "pending_pages contains duplicate URLs.",
            )
        if set(attempted_urls) & set(pending_urls):
            raise CrawlCheckpointValidationError(
                "checkpoint_page_state_overlap",
                "A URL cannot be both attempted and pending.",
            )

        root_origin = _origin(target)
        for url in attempted_urls + pending_urls:
            if _origin(url) != root_origin:
                raise CrawlCheckpointValidationError(
                    "checkpoint_origin_mismatch",
                    "Every attempted and pending page must remain on the target origin.",
                )

        if pages:
            if pages[0].url != target or pages[0].depth != 0 or pages[0].parent_url is not None:
                raise CrawlCheckpointValidationError(
                    "checkpoint_root_page_invalid",
                    "The first attempted page must be the target root.",
                )
        elif pending_pages:
            root_pending = pending_pages[0]
            if (
                root_pending.url != target
                or root_pending.depth != 0
                or root_pending.parent_url is not None
            ):
                raise CrawlCheckpointValidationError(
                    "checkpoint_pending_root_invalid",
                    "An unattempted checkpoint must begin with the target root.",
                )

        page_depth = {page.url: page.depth for page in pages}
        previous_pending_depth = -1
        for pending in pending_pages:
            if pending.depth < previous_pending_depth:
                raise CrawlCheckpointValidationError(
                    "checkpoint_pending_order_invalid",
                    "pending_pages must preserve breadth-first depth ordering.",
                )
            previous_pending_depth = pending.depth
            if pending.depth > self.policy.maximum_depth:
                raise CrawlCheckpointValidationError(
                    "checkpoint_pending_depth_exceeded",
                    "A pending page exceeds policy.maximum_depth.",
                )
            if pending.parent_url is not None:
                parent_depth = page_depth.get(pending.parent_url)
                if parent_depth is None or pending.depth != parent_depth + 1:
                    raise CrawlCheckpointValidationError(
                        "checkpoint_pending_parent_invalid",
                        "Every pending child must reference an attempted parent at the prior depth.",
                    )

        expected_visited = tuple(sorted(set(attempted_urls + pending_urls)))
        visited: list[str] = []
        for index, value in enumerate(self.visited_urls):
            visited.append(_canonical_url(value, f"visited_urls[{index}]"))
        canonical_visited = tuple(sorted(set(visited)))
        if tuple(visited) != canonical_visited or canonical_visited != expected_visited:
            raise CrawlCheckpointValidationError(
                "checkpoint_visited_urls_inconsistent",
                "visited_urls must be the sorted unique projection of attempted and pending URLs.",
            )

        elapsed = _bounded_number(
            self.elapsed_execution_seconds,
            "elapsed_execution_seconds",
            maximum=7 * 24 * 60 * 60,
        )
        attempts = _bounded_integer(
            self.attempts_used,
            "attempts_used",
            minimum=0,
            maximum=self.policy.maximum_request_attempts,
        )
        derived_attempts = sum(
            len(page.request_attempts)
            for page in pages
        )
        if attempts != derived_attempts:
            raise CrawlCheckpointValidationError(
                "checkpoint_attempt_count_inconsistent",
                "attempts_used must equal the attempts stored by completed page records.",
            )

        _validate_page_projection(
            scan_id=canonical_scan_id,
            target=target,
            engine=engine,
            engine_version=engine_version,
            started_at=started_at,
            updated_at=updated_at,
            policy=self.policy,
            pages=pages,
            skipped_links=skipped_links,
            pending_count=len(pending_pages),
        )

        policy_projection = {
            "crawl": self.policy.to_dict(),
            "fetch": self.fetch_policy.to_dict(),
            "retry": self.retry_policy.to_dict(),
        }
        target_projection = {
            "target": target,
            "resolved_addresses": sorted(addresses),
        }

        object.__setattr__(self, "scan_id", canonical_scan_id)
        object.__setattr__(self, "target", target)
        object.__setattr__(
            self,
            "resolved_addresses",
            tuple(
                sorted(
                    addresses,
                    key=lambda item: (
                        ipaddress.ip_address(item).version,
                        int(ipaddress.ip_address(item)),
                    ),
                )
            ),
        )
        object.__setattr__(self, "engine", engine)
        object.__setattr__(self, "engine_version", engine_version)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "updated_at", updated_at)
        object.__setattr__(self, "pages", pages)
        object.__setattr__(self, "pending_pages", pending_pages)
        object.__setattr__(self, "visited_urls", canonical_visited)
        object.__setattr__(self, "skipped_links", skipped_links)
        object.__setattr__(self, "elapsed_execution_seconds", elapsed)
        object.__setattr__(self, "attempts_used", attempts)
        object.__setattr__(
            self,
            "policy_fingerprint",
            _sha256(policy_projection),
        )
        object.__setattr__(
            self,
            "target_fingerprint",
            _sha256(target_projection),
        )

    @property
    def has_pending_pages(self) -> bool:
        return bool(self.pending_pages)

    def payload_dict(self) -> dict[str, object]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "resolved_addresses": list(self.resolved_addresses),
            "engine": self.engine,
            "engine_version": self.engine_version,
            "started_at": _utc_timestamp(self.started_at),
            "updated_at": _utc_timestamp(self.updated_at),
            "policy": self.policy.to_dict(),
            "fetch_policy": self.fetch_policy.to_dict(),
            "retry_policy": self.retry_policy.to_dict(),
            "policy_fingerprint": self.policy_fingerprint,
            "target_fingerprint": self.target_fingerprint,
            "page_count": len(self.pages),
            "pages": [item.to_dict() for item in self.pages],
            "pending_page_count": len(self.pending_pages),
            "pending_pages": [item.to_dict() for item in self.pending_pages],
            "visited_url_count": len(self.visited_urls),
            "visited_urls": list(self.visited_urls),
            "skipped_links": [item.to_dict() for item in self.skipped_links],
            "elapsed_execution_seconds": self.elapsed_execution_seconds,
            "attempts_used": self.attempts_used,
        }

    def to_dict(self, key: bytes) -> dict[str, object]:
        canonical_key = _checkpoint_key(key)
        payload = self.payload_dict()
        digest = hmac.new(
            canonical_key,
            _canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()
        return {
            "checkpoint_type": self.checkpoint_type,
            "schema_version": self.schema_version,
            "payload": payload,
            "integrity": {
                "algorithm": CRAWL_CHECKPOINT_INTEGRITY_ALGORITHM,
                "digest": digest,
            },
        }

    def to_json(self, key: bytes) -> str:
        return _canonical_json(self.to_dict(key)).decode("utf-8")


def _parse_or_validate_datetime(value: object, field_name: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CrawlCheckpointValidationError(
                "checkpoint_timestamp_invalid",
                f"{field_name} must be timezone-aware.",
            )
        return value.astimezone(timezone.utc)
    raise CrawlCheckpointValidationError(
        "checkpoint_timestamp_invalid",
        f"{field_name} must be a datetime.",
    )


def _validate_page_projection(
    *,
    scan_id: str,
    target: str,
    engine: str,
    engine_version: str,
    started_at: datetime,
    updated_at: datetime,
    policy: CrawlScanPolicy,
    pages: tuple[CrawlPageScanResult, ...],
    skipped_links: tuple[CrawlLinkSkip, ...],
    pending_count: int,
) -> None:
    if not pages:
        return

    if pages[0].status is ScanStatus.FAILED:
        status = ScanStatus.FAILED
        reason = CrawlTerminationReason.ROOT_REQUEST_FAILED
        pending_count = 0
    elif pending_count:
        status = ScanStatus.COMPLETED_WITH_ERRORS
        reason = CrawlTerminationReason.TIME_LIMIT_REACHED
    elif any(page.status is not ScanStatus.COMPLETED for page in pages):
        status = ScanStatus.COMPLETED_WITH_ERRORS
        reason = CrawlTerminationReason.COMPLETED
    else:
        status = ScanStatus.COMPLETED
        reason = CrawlTerminationReason.COMPLETED

    try:
        CrawlScanResult(
            scan_id=scan_id,
            scan_type="passive-http-crawl",
            status=status,
            target=target,
            engine=engine,
            engine_version=engine_version,
            started_at=started_at,
            completed_at=updated_at,
            policy=policy,
            pages=pages,
            skipped_links=skipped_links,
            termination=CrawlScanTermination(
                reason=reason,
                pages_pending=pending_count,
            ),
        )
    except Exception as exc:
        raise CrawlCheckpointValidationError(
            "checkpoint_page_projection_invalid",
            "Stored page results do not form a valid crawl report projection.",
        ) from exc


_CHECKPOINT_ROOT_FIELDS = {
    "checkpoint_type",
    "schema_version",
    "payload",
    "integrity",
}
_INTEGRITY_FIELDS = {"algorithm", "digest"}
_PAYLOAD_FIELDS = {
    "scan_id",
    "target",
    "resolved_addresses",
    "engine",
    "engine_version",
    "started_at",
    "updated_at",
    "policy",
    "fetch_policy",
    "retry_policy",
    "policy_fingerprint",
    "target_fingerprint",
    "page_count",
    "pages",
    "pending_page_count",
    "pending_pages",
    "visited_url_count",
    "visited_urls",
    "skipped_links",
    "elapsed_execution_seconds",
    "attempts_used",
}
_FETCH_FIELDS = {
    "timeout_seconds",
    "maximum_body_bytes",
    "maximum_header_bytes",
    "maximum_header_count",
}
_RETRY_FIELDS = {
    "maximum_attempts",
    "initial_backoff_seconds",
    "backoff_multiplier",
    "maximum_backoff_seconds",
}
_PENDING_FIELDS = {"url", "depth", "parent_url"}


def _strict_mapping(
    value: object,
    field_name: str,
    fields: set[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CrawlCheckpointLoadError(
            "checkpoint_object_required",
            f"{field_name} must be a JSON object.",
        )
    data = dict(value)
    if set(data) != fields:
        raise CrawlCheckpointLoadError(
            "checkpoint_fields_invalid",
            f"{field_name} contains missing or unexpected fields.",
        )
    return data


def _list(value: object, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise CrawlCheckpointLoadError(
            "checkpoint_list_required",
            f"{field_name} must be a JSON array.",
        )
    return value


def _load_pending(value: object, index: int) -> CrawlCheckpointPendingPage:
    data = _strict_mapping(
        value,
        f"pending_pages[{index}]",
        _PENDING_FIELDS,
    )
    try:
        return CrawlCheckpointPendingPage(
            url=data["url"],
            depth=data["depth"],
            parent_url=data["parent_url"],
        )
    except CrawlCheckpointValidationError as exc:
        raise CrawlCheckpointLoadError(exc.code, exc.message) from exc


def _load_checkpoint_object(
    document: Mapping[str, Any],
    key: bytes,
) -> CrawlCheckpoint:
    root = _strict_mapping(document, "checkpoint", _CHECKPOINT_ROOT_FIELDS)

    if root["checkpoint_type"] != CRAWL_CHECKPOINT_TYPE:
        raise CrawlCheckpointLoadError(
            "checkpoint_type_invalid",
            "The document is not a crawl checkpoint.",
        )
    if root["schema_version"] not in SUPPORTED_CRAWL_CHECKPOINT_SCHEMA_VERSIONS:
        raise CrawlCheckpointLoadError(
            "checkpoint_schema_unsupported",
            "The crawl checkpoint schema version is unsupported.",
        )

    integrity = _strict_mapping(
        root["integrity"],
        "integrity",
        _INTEGRITY_FIELDS,
    )
    if integrity["algorithm"] != CRAWL_CHECKPOINT_INTEGRITY_ALGORITHM:
        raise CrawlCheckpointLoadError(
            "checkpoint_integrity_algorithm_invalid",
            "The checkpoint integrity algorithm is unsupported.",
        )
    digest = integrity["digest"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise CrawlCheckpointLoadError(
            "checkpoint_integrity_digest_invalid",
            "The checkpoint integrity digest is invalid.",
        )

    payload = _strict_mapping(root["payload"], "payload", _PAYLOAD_FIELDS)
    expected = hmac.new(
        _checkpoint_key(key),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(digest, expected):
        raise CrawlCheckpointIntegrityError(
            "checkpoint_integrity_failed",
            "Checkpoint authentication failed.",
        )

    from .report_loader import (
        _load_crawl_page,
        _load_crawl_policy,
        _load_crawl_skip,
    )

    try:
        policy = _load_crawl_policy(payload["policy"])
        pages_data = _list(payload["pages"], "pages")
        pages = tuple(
            _load_crawl_page(item, index)
            for index, item in enumerate(pages_data)
        )
        pending_data = _list(payload["pending_pages"], "pending_pages")
        pending_pages = tuple(
            _load_pending(item, index)
            for index, item in enumerate(pending_data)
        )
        skipped_data = _list(payload["skipped_links"], "skipped_links")
        skipped_links = tuple(
            _load_crawl_skip(item, index)
            for index, item in enumerate(skipped_data)
        )

        fetch_data = _strict_mapping(
            payload["fetch_policy"],
            "fetch_policy",
            _FETCH_FIELDS,
        )
        retry_data = _strict_mapping(
            payload["retry_policy"],
            "retry_policy",
            _RETRY_FIELDS,
        )

        checkpoint = CrawlCheckpoint(
            scan_id=payload["scan_id"],
            target=payload["target"],
            resolved_addresses=tuple(
                _list(payload["resolved_addresses"], "resolved_addresses")
            ),
            engine=payload["engine"],
            engine_version=payload["engine_version"],
            started_at=_parse_timestamp(payload["started_at"], "started_at"),
            updated_at=_parse_timestamp(payload["updated_at"], "updated_at"),
            policy=policy,
            fetch_policy=CrawlCheckpointFetchPolicy(**fetch_data),
            retry_policy=CrawlCheckpointRetryPolicy(**retry_data),
            pages=pages,
            pending_pages=pending_pages,
            visited_urls=tuple(
                _list(payload["visited_urls"], "visited_urls")
            ),
            skipped_links=skipped_links,
            elapsed_execution_seconds=payload["elapsed_execution_seconds"],
            attempts_used=payload["attempts_used"],
        )
    except CrawlCheckpointError:
        raise
    except Exception as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_payload_invalid",
            "The checkpoint payload is invalid.",
        ) from exc

    count_pairs = (
        ("page_count", len(checkpoint.pages)),
        ("pending_page_count", len(checkpoint.pending_pages)),
        ("visited_url_count", len(checkpoint.visited_urls)),
    )
    for field_name, expected_count in count_pairs:
        value = payload[field_name]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value != expected_count
        ):
            raise CrawlCheckpointLoadError(
                "checkpoint_count_mismatch",
                f"{field_name} does not match its array.",
            )

    if payload["policy_fingerprint"] != checkpoint.policy_fingerprint:
        raise CrawlCheckpointLoadError(
            "checkpoint_policy_fingerprint_invalid",
            "The stored policy fingerprint is inconsistent.",
        )
    if payload["target_fingerprint"] != checkpoint.target_fingerprint:
        raise CrawlCheckpointLoadError(
            "checkpoint_target_fingerprint_invalid",
            "The stored target fingerprint is inconsistent.",
        )
    if checkpoint.payload_dict() != payload:
        raise CrawlCheckpointLoadError(
            "checkpoint_non_canonical",
            "The checkpoint payload is not canonical.",
        )
    return checkpoint


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_crawl_checkpoint_json(
    document: str | bytes | bytearray,
    key: bytes,
) -> CrawlCheckpoint:
    """Authenticate and strictly load one bounded checkpoint document."""

    if isinstance(document, str):
        try:
            encoded = document.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CrawlCheckpointLoadError(
                "checkpoint_encoding_invalid",
                "Checkpoint text is not valid UTF-8.",
            ) from exc
    elif isinstance(document, (bytes, bytearray)):
        encoded = bytes(document)
        try:
            document = encoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CrawlCheckpointLoadError(
                "checkpoint_encoding_invalid",
                "Checkpoint bytes are not valid UTF-8.",
            ) from exc
    else:
        raise CrawlCheckpointLoadError(
            "checkpoint_document_invalid",
            "Checkpoint document must be text or bytes.",
        )

    if len(encoded) > MAXIMUM_CRAWL_CHECKPOINT_BYTES:
        raise CrawlCheckpointLoadError(
            "checkpoint_too_large",
            "Checkpoint document exceeds the size limit.",
        )

    try:
        parsed = json.loads(
            document,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"Invalid JSON constant {value}")
            ),
        )
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_json_invalid",
            "Checkpoint document is not valid strict JSON.",
        ) from exc

    if not isinstance(parsed, Mapping):
        raise CrawlCheckpointLoadError(
            "checkpoint_object_required",
            "Checkpoint root must be a JSON object.",
        )
    return _load_checkpoint_object(parsed, key)


def load_crawl_checkpoint_file(
    path: str | Path,
    key: bytes,
) -> CrawlCheckpoint:
    """Read and authenticate one regular, non-symlink checkpoint file."""

    try:
        checkpoint_path = Path(path)
        metadata = checkpoint_path.lstat()
    except (OSError, TypeError, ValueError) as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_file_read_failed",
            "Unable to inspect the checkpoint file.",
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise CrawlCheckpointLoadError(
            "checkpoint_symlink_not_allowed",
            "Checkpoint files cannot be symbolic links.",
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise CrawlCheckpointLoadError(
            "checkpoint_not_regular_file",
            "Checkpoint path must be a regular file.",
        )
    if metadata.st_size > MAXIMUM_CRAWL_CHECKPOINT_BYTES:
        raise CrawlCheckpointLoadError(
            "checkpoint_too_large",
            "Checkpoint file exceeds the size limit.",
        )
    try:
        data = checkpoint_path.read_bytes()
    except OSError as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_file_read_failed",
            "Unable to read the checkpoint file.",
        ) from exc
    return load_crawl_checkpoint_json(data, key)


def load_crawl_checkpoint_key_file(path: str | Path) -> bytes:
    """Read a private regular key file used for HMAC checkpoint signing."""

    try:
        key_path = Path(path)
        metadata = key_path.lstat()
    except (OSError, TypeError, ValueError) as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_key_file_read_failed",
            "Unable to inspect the checkpoint key file.",
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise CrawlCheckpointLoadError(
            "checkpoint_key_symlink_not_allowed",
            "Checkpoint key files cannot be symbolic links.",
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise CrawlCheckpointLoadError(
            "checkpoint_key_not_regular_file",
            "Checkpoint key path must be a regular file.",
        )
    if os.name == "posix" and metadata.st_mode & 0o077:
        raise CrawlCheckpointLoadError(
            "checkpoint_key_permissions_insecure",
            "Checkpoint key file permissions must not grant group or other access.",
        )
    if metadata.st_size > MAXIMUM_CRAWL_CHECKPOINT_KEY_BYTES + 16:
        raise CrawlCheckpointLoadError(
            "checkpoint_key_too_large",
            "Checkpoint key file exceeds the size limit.",
        )
    try:
        key = key_path.read_bytes().strip()
    except OSError as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_key_file_read_failed",
            "Unable to read the checkpoint key file.",
        ) from exc
    try:
        return _checkpoint_key(key)
    except CrawlCheckpointValidationError as exc:
        raise CrawlCheckpointLoadError(exc.code, exc.message) from exc


def write_crawl_checkpoint_file(
    checkpoint: CrawlCheckpoint,
    path: str | Path,
    key: bytes,
    *,
    overwrite: bool = True,
) -> Path:
    """Atomically write a signed checkpoint through a same-directory temp file."""

    if not isinstance(checkpoint, CrawlCheckpoint):
        raise CrawlCheckpointValidationError(
            "checkpoint_value_invalid",
            "checkpoint must be a CrawlCheckpoint.",
        )
    canonical_key = _checkpoint_key(key)

    try:
        checkpoint_path = Path(path).expanduser()
    except (TypeError, ValueError, RuntimeError) as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_path_invalid",
            "Checkpoint path is invalid.",
        ) from exc

    try:
        exists = os.path.lexists(checkpoint_path)
    except OSError as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_path_inspection_failed",
            "Unable to inspect checkpoint destination.",
        ) from exc

    if exists:
        try:
            metadata = checkpoint_path.lstat()
        except OSError as exc:
            raise CrawlCheckpointLoadError(
                "checkpoint_path_inspection_failed",
                "Unable to inspect checkpoint destination.",
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise CrawlCheckpointLoadError(
                "checkpoint_symlink_not_allowed",
                "Checkpoint destination cannot be a symbolic link.",
            )
        if not stat.S_ISREG(metadata.st_mode):
            raise CrawlCheckpointLoadError(
                "checkpoint_not_regular_file",
                "Checkpoint destination must be a regular file.",
            )
        if not overwrite:
            raise CrawlCheckpointLoadError(
                "checkpoint_exists",
                "Checkpoint destination already exists.",
            )

    try:
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_directory_create_failed",
            "Unable to create checkpoint directory.",
        ) from exc

    document = checkpoint.to_json(canonical_key) + "\n"
    descriptor: int | None = None
    temporary_path: Path | None = None

    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{checkpoint_path.name}.",
            suffix=".tmp",
            dir=checkpoint_path.parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output:
            descriptor = None
            output.write(document)
            output.flush()
            os.fsync(output.fileno())

        if not overwrite and os.path.lexists(checkpoint_path):
            raise CrawlCheckpointLoadError(
                "checkpoint_exists",
                "Checkpoint destination already exists.",
            )

        os.replace(temporary_path, checkpoint_path)
        temporary_path = None

        try:
            directory_descriptor = os.open(
                checkpoint_path.parent,
                os.O_RDONLY,
            )
        except OSError:
            directory_descriptor = None
        if directory_descriptor is not None:
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except CrawlCheckpointError:
        raise
    except OSError as exc:
        raise CrawlCheckpointLoadError(
            "checkpoint_write_failed",
            "Unable to atomically write checkpoint file.",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass

    return checkpoint_path


def validate_crawl_checkpoint_resume(
    checkpoint: CrawlCheckpoint,
    *,
    target: str,
    resolved_addresses: tuple[str, ...],
    policy: CrawlScanPolicy,
    fetch_policy: CrawlCheckpointFetchPolicy,
    retry_policy: CrawlCheckpointRetryPolicy,
    engine: str,
    engine_version: str,
) -> None:
    """Reject stale, modified, completed, or policy-incompatible resume state."""

    if not isinstance(checkpoint, CrawlCheckpoint):
        raise CrawlCheckpointResumeError(
            "checkpoint_invalid",
            "checkpoint must be a CrawlCheckpoint.",
        )
    if not checkpoint.pending_pages:
        raise CrawlCheckpointResumeError(
            "checkpoint_no_pending_pages",
            "Checkpoint contains no pending pages to resume.",
        )

    candidate = CrawlCheckpoint(
        scan_id=checkpoint.scan_id,
        target=target,
        resolved_addresses=resolved_addresses,
        engine=engine,
        engine_version=engine_version,
        started_at=checkpoint.started_at,
        updated_at=checkpoint.updated_at,
        policy=policy,
        fetch_policy=fetch_policy,
        retry_policy=retry_policy,
        pages=checkpoint.pages,
        pending_pages=checkpoint.pending_pages,
        visited_urls=checkpoint.visited_urls,
        skipped_links=checkpoint.skipped_links,
        elapsed_execution_seconds=checkpoint.elapsed_execution_seconds,
        attempts_used=checkpoint.attempts_used,
    )

    if candidate.target_fingerprint != checkpoint.target_fingerprint:
        raise CrawlCheckpointResumeError(
            "checkpoint_target_changed",
            "The revalidated target or its resolved addresses changed.",
        )
    if candidate.policy_fingerprint != checkpoint.policy_fingerprint:
        raise CrawlCheckpointResumeError(
            "checkpoint_policy_changed",
            "The crawl, fetch, or retry policy does not match the checkpoint.",
        )
    if checkpoint.engine != engine or checkpoint.engine_version != engine_version:
        raise CrawlCheckpointResumeError(
            "checkpoint_engine_changed",
            "The checkpoint was produced by a different scanner engine version.",
        )
    if checkpoint.elapsed_execution_seconds >= policy.maximum_execution_seconds:
        raise CrawlCheckpointResumeError(
            "checkpoint_time_budget_exhausted",
            "The checkpoint has no remaining execution-time budget.",
        )
    if checkpoint.attempts_used >= policy.maximum_request_attempts:
        raise CrawlCheckpointResumeError(
            "checkpoint_request_budget_exhausted",
            "The checkpoint has no remaining request-attempt budget.",
        )


__all__ = [
    "CRAWL_CHECKPOINT_INTEGRITY_ALGORITHM",
    "CRAWL_CHECKPOINT_TYPE",
    "CURRENT_CRAWL_CHECKPOINT_SCHEMA_VERSION",
    "CrawlCheckpoint",
    "CrawlCheckpointError",
    "CrawlCheckpointFetchPolicy",
    "CrawlCheckpointIntegrityError",
    "CrawlCheckpointLoadError",
    "CrawlCheckpointPendingPage",
    "CrawlCheckpointResumeError",
    "CrawlCheckpointRetryPolicy",
    "CrawlCheckpointValidationError",
    "MAXIMUM_CRAWL_CHECKPOINT_BYTES",
    "MAXIMUM_CRAWL_CHECKPOINT_KEY_BYTES",
    "MINIMUM_CRAWL_CHECKPOINT_KEY_BYTES",
    "SUPPORTED_CRAWL_CHECKPOINT_SCHEMA_VERSIONS",
    "load_crawl_checkpoint_file",
    "load_crawl_checkpoint_json",
    "load_crawl_checkpoint_key_file",
    "validate_crawl_checkpoint_resume",
    "write_crawl_checkpoint_file",
]
