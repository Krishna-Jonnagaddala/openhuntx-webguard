"""Signed opaque cursor pagination for organization-scoped API feeds."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping

DEFAULT_PAGE_LIMIT = 50
MAXIMUM_PAGE_LIMIT = 100
MAXIMUM_CURSOR_LENGTH = 4096
DEFAULT_CURSOR_VALIDITY_SECONDS = 24 * 60 * 60
_CURSOR_VERSION = 1
_RESOURCE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")


class PaginationError(ValueError):
    """Controlled page-query or signed-cursor failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class PageRequest:
    """Validated list request before store execution."""

    limit: int = DEFAULT_PAGE_LIMIT
    cursor: str | None = None
    filters: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if (
            isinstance(self.limit, bool)
            or not isinstance(self.limit, int)
            or not 1 <= self.limit <= MAXIMUM_PAGE_LIMIT
        ):
            raise PaginationError(
                "page_limit_invalid",
                f"limit must be an integer from 1 to {MAXIMUM_PAGE_LIMIT}.",
            )
        if self.cursor is not None:
            if not isinstance(self.cursor, str) or not self.cursor:
                raise PaginationError(
                    "page_cursor_invalid", "cursor must be non-empty text."
                )
            if len(self.cursor) > MAXIMUM_CURSOR_LENGTH:
                raise PaginationError(
                    "page_cursor_too_long",
                    f"cursor cannot exceed {MAXIMUM_CURSOR_LENGTH} characters.",
                )
        if not isinstance(self.filters, tuple):
            raise PaginationError(
                "page_filters_invalid", "filters must use canonical key-value pairs."
            )
        previous = None
        normalized: list[tuple[str, str]] = []
        for item in self.filters:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not all(isinstance(value, str) for value in item)
            ):
                raise PaginationError(
                    "page_filters_invalid", "filters must use canonical key-value pairs."
                )
            key, value = item
            if not key or not value or previous is not None and key <= previous:
                raise PaginationError(
                    "page_filters_non_canonical",
                    "filters must be non-empty and ordered by unique key.",
                )
            normalized.append((key, value))
            previous = key
        object.__setattr__(self, "filters", tuple(normalized))

    @property
    def filter_map(self) -> dict[str, str]:
        return dict(self.filters)


@dataclass(frozen=True, slots=True)
class CursorPosition:
    """Decoded stable ordering position from one signed cursor."""

    ordered_at: str
    resource_id: str


class SignedCursorCodec:
    """Create and validate organization-bound HMAC pagination cursors."""

    def __init__(
        self,
        key: bytes,
        *,
        validity_seconds: int = DEFAULT_CURSOR_VALIDITY_SECONDS,
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise PaginationError(
                "cursor_key_invalid", "Cursor signing key must contain at least 32 bytes."
            )
        if (
            isinstance(validity_seconds, bool)
            or not isinstance(validity_seconds, int)
            or not 300 <= validity_seconds <= 7 * 24 * 60 * 60
        ):
            raise PaginationError(
                "cursor_validity_invalid",
                "Cursor validity must be from 300 to 604800 seconds.",
            )
        self._key = key
        self.validity_seconds = validity_seconds

    @staticmethod
    def _b64_encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @classmethod
    def _b64_decode(cls, value: str) -> bytes:
        if not isinstance(value, str) or not value:
            raise PaginationError(
                "page_cursor_invalid", "cursor is not valid base64url data."
            )
        padding = "=" * (-len(value) % 4)
        try:
            decoded = base64.b64decode(
                (value + padding).encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
            raise PaginationError(
                "page_cursor_invalid", "cursor is not valid base64url data."
            ) from exc
        if cls._b64_encode(decoded) != value:
            raise PaginationError(
                "page_cursor_non_canonical",
                "cursor base64url data is not canonical.",
            )
        return decoded

    @staticmethod
    def _canonical_json(value: object) -> bytes:
        try:
            return json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise PaginationError(
                "page_cursor_invalid", "cursor data cannot be encoded canonically."
            ) from exc

    @staticmethod
    def _timestamp(value: datetime) -> str:
        if value.tzinfo is None or value.utcoffset() is None:
            raise PaginationError(
                "page_cursor_time_invalid", "Cursor times must be timezone-aware."
            )
        return value.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

    def encode(
        self,
        *,
        organization_id: str,
        resource: str,
        filters: Mapping[str, str],
        ordered_at: str,
        resource_id: str,
        now: datetime,
    ) -> str:
        if not _RESOURCE.fullmatch(resource):
            raise PaginationError(
                "page_cursor_resource_invalid", "Cursor resource is invalid."
            )
        payload = {
            "v": _CURSOR_VERSION,
            "organization_id": organization_id,
            "resource": resource,
            "filters": dict(sorted(filters.items())),
            "ordered_at": ordered_at,
            "resource_id": resource_id,
            "expires_at": self._timestamp(
                now + timedelta(seconds=self.validity_seconds)
            ),
        }
        raw = self._canonical_json(payload)
        signature = hmac.new(self._key, raw, hashlib.sha256).digest()
        token = f"{self._b64_encode(raw)}.{self._b64_encode(signature)}"
        if len(token) > MAXIMUM_CURSOR_LENGTH:
            raise PaginationError(
                "page_cursor_too_long", "Generated cursor exceeds the API limit."
            )
        return token

    def decode(
        self,
        cursor: str,
        *,
        organization_id: str,
        resource: str,
        filters: Mapping[str, str],
        now: datetime,
    ) -> CursorPosition:
        if not isinstance(cursor, str) or not cursor or len(cursor) > MAXIMUM_CURSOR_LENGTH:
            raise PaginationError(
                "page_cursor_invalid", "cursor is missing or exceeds the API limit."
            )
        encoded_payload, separator, encoded_signature = cursor.partition(".")
        if separator != "." or not encoded_payload or not encoded_signature:
            raise PaginationError(
                "page_cursor_invalid", "cursor format is invalid."
            )
        raw = self._b64_decode(encoded_payload)
        supplied = self._b64_decode(encoded_signature)
        expected = hmac.new(self._key, raw, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, supplied):
            raise PaginationError(
                "page_cursor_signature_invalid", "cursor signature is invalid."
            )
        try:
            payload = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PaginationError(
                "page_cursor_invalid", "cursor payload is invalid."
            ) from exc
        required = {
            "v",
            "organization_id",
            "resource",
            "filters",
            "ordered_at",
            "resource_id",
            "expires_at",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise PaginationError(
                "page_cursor_invalid", "cursor payload fields are invalid."
            )
        if self._canonical_json(payload) != raw:
            raise PaginationError(
                "page_cursor_non_canonical", "cursor payload is not canonical."
            )
        if payload["v"] != _CURSOR_VERSION:
            raise PaginationError(
                "page_cursor_version_unsupported", "cursor version is unsupported."
            )
        if payload["organization_id"] != organization_id:
            raise PaginationError(
                "page_cursor_scope_mismatch", "cursor does not belong to this organization."
            )
        if payload["resource"] != resource:
            raise PaginationError(
                "page_cursor_resource_mismatch", "cursor cannot be used for this resource."
            )
        expected_filters = dict(sorted(filters.items()))
        if payload["filters"] != expected_filters:
            raise PaginationError(
                "page_cursor_filter_mismatch", "cursor filters do not match the request."
            )
        expires_at = payload["expires_at"]
        if not isinstance(expires_at, str) or not expires_at.endswith("Z"):
            raise PaginationError(
                "page_cursor_invalid", "cursor expiry is invalid."
            )
        try:
            expiry = datetime.fromisoformat(expires_at[:-1] + "+00:00")
        except ValueError as exc:
            raise PaginationError(
                "page_cursor_invalid", "cursor expiry is invalid."
            ) from exc
        if self._timestamp(expiry) != expires_at:
            raise PaginationError(
                "page_cursor_non_canonical", "cursor expiry is not canonical."
            )
        if now.astimezone(timezone.utc) >= expiry.astimezone(timezone.utc):
            raise PaginationError(
                "page_cursor_expired", "cursor has expired."
            )
        ordered_at = payload["ordered_at"]
        resource_id = payload["resource_id"]
        if not isinstance(ordered_at, str) or not ordered_at:
            raise PaginationError(
                "page_cursor_invalid", "cursor ordering time is invalid."
            )
        if not isinstance(resource_id, str) or not resource_id:
            raise PaginationError(
                "page_cursor_invalid", "cursor resource identifier is invalid."
            )
        return CursorPosition(ordered_at=ordered_at, resource_id=resource_id)


def parse_page_request(
    query: Mapping[str, tuple[str, ...]],
    *,
    allowed_filters: Mapping[str, frozenset[str]],
) -> PageRequest:
    """Validate unique list query parameters and canonicalize filters."""

    allowed = {"limit", "cursor", *allowed_filters}
    unknown = set(query) - allowed
    if unknown:
        raise PaginationError(
            "page_query_parameter_unknown",
            f"Unknown query parameter {sorted(unknown)[0]!r}.",
        )
    values: dict[str, str] = {}
    for key, items in query.items():
        if len(items) != 1:
            raise PaginationError(
                "page_query_parameter_duplicate",
                f"Query parameter {key!r} must appear exactly once.",
            )
        value = items[0]
        if value == "":
            raise PaginationError(
                "page_query_parameter_empty",
                f"Query parameter {key!r} cannot be empty.",
            )
        values[key] = value
    raw_limit = values.pop("limit", str(DEFAULT_PAGE_LIMIT))
    try:
        limit = int(raw_limit, 10)
    except ValueError as exc:
        raise PaginationError(
            "page_limit_invalid",
            f"limit must be an integer from 1 to {MAXIMUM_PAGE_LIMIT}.",
        ) from exc
    filters: list[tuple[str, str]] = []
    for name, accepted in sorted(allowed_filters.items()):
        if name not in values:
            continue
        value = values.pop(name)
        if value not in accepted:
            raise PaginationError(
                "page_filter_invalid",
                f"Query parameter {name!r} has an unsupported value.",
            )
        filters.append((name, value))
    cursor = values.pop("cursor", None)
    if values:
        raise PaginationError(
            "page_query_parameter_unknown",
            f"Unknown query parameter {sorted(values)[0]!r}.",
        )
    return PageRequest(limit=limit, cursor=cursor, filters=tuple(filters))


__all__ = [
    "CursorPosition",
    "DEFAULT_CURSOR_VALIDITY_SECONDS",
    "DEFAULT_PAGE_LIMIT",
    "MAXIMUM_CURSOR_LENGTH",
    "MAXIMUM_PAGE_LIMIT",
    "PageRequest",
    "PaginationError",
    "SignedCursorCodec",
    "parse_page_request",
]
