"""Bounded same-origin crawling for OpenHuntX WebGuard."""

from __future__ import annotations

import ipaddress
import math
import posixpath
import re
import time
from collections import Counter, deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from html.parser import HTMLParser
from threading import Event
from typing import Callable, FrozenSet
from urllib.parse import (
    unquote,
    urljoin,
    urlsplit,
    urlunsplit,
)

from webguard_contracts import (
    CrawlTerminationReason,
    RequestAttempt,
    RequestAttemptOutcome,
)

from .error_taxonomy import is_retryable_error
from .retry_policy import RetryPolicy
from .safe_http import (
    FetchPolicy,
    SafeHttpResponse,
    SafeRequestError,
    fetch_once,
)
from .scope_validator import ValidatedTarget


MAXIMUM_CRAWL_PAGES = 50
MAXIMUM_CRAWL_DEPTH = 3
MAXIMUM_LINKS_PER_PAGE = 500
MAXIMUM_CRAWL_DELAY_SECONDS = 5.0
MAXIMUM_CRAWL_URL_LENGTH = 2048
MAXIMUM_CRAWL_EXECUTION_SECONDS = 3600.0
MAXIMUM_CRAWL_REQUEST_ATTEMPTS = 150

DEFAULT_CRAWL_EXECUTION_SECONDS = 300.0
DEFAULT_CRAWL_REQUEST_ATTEMPTS = 150

DEFAULT_ALLOWED_CONTENT_TYPES = frozenset(
    {
        "application/xhtml+xml",
        "text/html",
    }
)

DEFAULT_BLOCKED_PATH_SEGMENTS = frozenset(
    {
        "checkout",
        "close-account",
        "confirm-order",
        "delete",
        "delete-account",
        "destroy",
        "log-out",
        "logout",
        "pay",
        "payment",
        "place-order",
        "purchase",
        "remove",
        "sign-out",
        "signout",
        "terminate-account",
        "unsubscribe",
    }
)

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x20\x7f]")
_MEDIA_TYPE = re.compile(
    r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$"
)


class CrawlQueryMode(str, Enum):
    """How crawler-discovered query strings are handled."""

    DROP = "drop"
    REJECT = "reject"


class CrawlPageOutcome(str, Enum):
    """Terminal result of fetching one queued crawl page."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CrawlSkipReason(str, Enum):
    """Safe reason for excluding a discovered link."""

    DESTRUCTIVE_PATH = "destructive_path"
    DUPLICATE = "duplicate"
    EXTERNAL_ORIGIN = "external_origin"
    FRAGMENT_ONLY = "fragment_only"
    LINK_LIMIT = "link_limit"
    MALFORMED_URL = "malformed_url"
    PAGE_LIMIT = "page_limit"
    QUERY_REJECTED = "query_rejected"
    UNSUPPORTED_SCHEME = "unsupported_scheme"
    USERINFO_NOT_ALLOWED = "userinfo_not_allowed"


class CrawlCancellationToken:
    """Thread-safe cancellation signal checked between HTTP requests."""

    def __init__(self) -> None:
        self._event = Event()

    def cancel(self) -> None:
        """Request graceful termination before another request starts."""

        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()


class CrawlPolicyError(ValueError):
    """Raised when crawl configuration or the root target is invalid."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class CrawlPolicy:
    """Strict limits for one bounded same-origin crawl."""

    maximum_pages: int = 10
    maximum_depth: int = 1
    maximum_links_per_page: int = 100
    minimum_delay_seconds: float = 0.1
    query_mode: CrawlQueryMode = CrawlQueryMode.DROP
    maximum_url_length: int = MAXIMUM_CRAWL_URL_LENGTH
    maximum_execution_seconds: float = DEFAULT_CRAWL_EXECUTION_SECONDS
    maximum_request_attempts: int = DEFAULT_CRAWL_REQUEST_ATTEMPTS
    allowed_content_types: FrozenSet[str] = DEFAULT_ALLOWED_CONTENT_TYPES
    blocked_path_segments: FrozenSet[str] = DEFAULT_BLOCKED_PATH_SEGMENTS

    def __post_init__(self) -> None:
        _bounded_integer(
            self.maximum_pages,
            name="maximum_pages",
            minimum=1,
            maximum=MAXIMUM_CRAWL_PAGES,
        )
        _bounded_integer(
            self.maximum_depth,
            name="maximum_depth",
            minimum=0,
            maximum=MAXIMUM_CRAWL_DEPTH,
        )
        _bounded_integer(
            self.maximum_links_per_page,
            name="maximum_links_per_page",
            minimum=1,
            maximum=MAXIMUM_LINKS_PER_PAGE,
        )
        _bounded_integer(
            self.maximum_url_length,
            name="maximum_url_length",
            minimum=128,
            maximum=MAXIMUM_CRAWL_URL_LENGTH,
        )
        _bounded_integer(
            self.maximum_request_attempts,
            name="maximum_request_attempts",
            minimum=1,
            maximum=MAXIMUM_CRAWL_REQUEST_ATTEMPTS,
        )

        if (
            isinstance(self.maximum_execution_seconds, bool)
            or not isinstance(
                self.maximum_execution_seconds,
                (int, float),
            )
        ):
            raise CrawlPolicyError(
                "maximum_execution_seconds_invalid",
                "maximum_execution_seconds must be a finite positive number.",
            )

        execution_seconds = float(self.maximum_execution_seconds)

        if (
            not math.isfinite(execution_seconds)
            or not 0 < execution_seconds
            <= MAXIMUM_CRAWL_EXECUTION_SECONDS
        ):
            raise CrawlPolicyError(
                "maximum_execution_seconds_invalid",
                "maximum_execution_seconds must be greater than zero and "
                "no more than 3600 seconds.",
            )

        if (
            isinstance(self.minimum_delay_seconds, bool)
            or not isinstance(self.minimum_delay_seconds, (int, float))
        ):
            raise CrawlPolicyError(
                "minimum_delay_invalid",
                "minimum_delay_seconds must be a finite non-negative number.",
            )

        delay = float(self.minimum_delay_seconds)

        if (
            not math.isfinite(delay)
            or not 0 <= delay <= MAXIMUM_CRAWL_DELAY_SECONDS
        ):
            raise CrawlPolicyError(
                "minimum_delay_invalid",
                "minimum_delay_seconds must be between 0 and 5 seconds.",
            )

        if not isinstance(self.query_mode, CrawlQueryMode):
            raise CrawlPolicyError(
                "query_mode_invalid",
                "query_mode must be a CrawlQueryMode value.",
            )

        allowed_types = _normalise_media_types(
            self.allowed_content_types,
        )
        blocked_segments = _normalise_blocked_segments(
            self.blocked_path_segments,
        )

        object.__setattr__(
            self,
            "maximum_execution_seconds",
            execution_seconds,
        )
        object.__setattr__(
            self,
            "minimum_delay_seconds",
            delay,
        )
        object.__setattr__(
            self,
            "allowed_content_types",
            allowed_types,
        )
        object.__setattr__(
            self,
            "blocked_path_segments",
            blocked_segments,
        )


@dataclass(frozen=True, slots=True)
class CrawlSkipSummary:
    """Aggregate count for one link exclusion reason."""

    reason: CrawlSkipReason
    count: int

    def __post_init__(self) -> None:
        if not isinstance(self.reason, CrawlSkipReason):
            raise CrawlPolicyError(
                "skip_reason_invalid",
                "reason must be a CrawlSkipReason value.",
            )

        _bounded_integer(
            self.count,
            name="skip_count",
            minimum=1,
            maximum=2_147_483_647,
        )


@dataclass(frozen=True, slots=True)
class CrawlPageRecord:
    """Non-secret audit record for one page fetch."""

    url: str
    depth: int
    parent_url: str | None
    outcome: CrawlPageOutcome
    attempts: tuple[RequestAttempt, ...]

    content_type: str | None = None
    connected_address: str | None = None
    http_status: int | None = None
    error_code: str | None = None
    retryable: bool | None = None
    discovered_links: int = 0
    queued_links: int = 0

    def __post_init__(self) -> None:
        url = _audit_url(self.url, "page_url")
        parent_url = (
            None
            if self.parent_url is None
            else _audit_url(self.parent_url, "parent_url")
        )

        _bounded_integer(
            self.depth,
            name="page_depth",
            minimum=0,
            maximum=MAXIMUM_CRAWL_DEPTH,
        )

        if not isinstance(self.outcome, CrawlPageOutcome):
            raise CrawlPolicyError(
                "page_outcome_invalid",
                "outcome must be a CrawlPageOutcome value.",
            )

        if (
            not isinstance(self.attempts, tuple)
            or not self.attempts
            or any(
                not isinstance(item, RequestAttempt)
                for item in self.attempts
            )
        ):
            raise CrawlPolicyError(
                "page_attempts_invalid",
                "attempts must contain at least one RequestAttempt.",
            )

        expected_numbers = tuple(range(1, len(self.attempts) + 1))
        actual_numbers = tuple(
            item.attempt_number
            for item in self.attempts
        )

        if actual_numbers != expected_numbers:
            raise CrawlPolicyError(
                "page_attempt_sequence_invalid",
                "Page attempts must be numbered consecutively from one.",
            )

        _bounded_integer(
            self.discovered_links,
            name="discovered_links",
            minimum=0,
            maximum=MAXIMUM_LINKS_PER_PAGE,
        )
        _bounded_integer(
            self.queued_links,
            name="queued_links",
            minimum=0,
            maximum=MAXIMUM_LINKS_PER_PAGE,
        )

        if self.queued_links > self.discovered_links:
            raise CrawlPolicyError(
                "queued_links_invalid",
                "queued_links cannot exceed discovered_links.",
            )

        content_type = (
            None
            if self.content_type is None
            else _normalise_media_type(
                self.content_type,
                field_name="page_content_type",
            )
        )

        address = None

        if self.connected_address is not None:
            try:
                address = ipaddress.ip_address(
                    self.connected_address
                ).compressed
            except ValueError as exc:
                raise CrawlPolicyError(
                    "page_connected_address_invalid",
                    "connected_address must be a valid IP address.",
                ) from exc

        if self.http_status is not None and (
            not isinstance(self.http_status, int)
            or isinstance(self.http_status, bool)
            or not 100 <= self.http_status <= 599
        ):
            raise CrawlPolicyError(
                "page_http_status_invalid",
                "http_status must be an integer from 100 to 599.",
            )

        error_code = (
            None
            if self.error_code is None
            else _identifier(
                self.error_code,
                "page_error_code",
            )
        )

        if (
            self.retryable is not None
            and not isinstance(self.retryable, bool)
        ):
            raise CrawlPolicyError(
                "page_retryable_invalid",
                "retryable must be boolean or null.",
            )

        final_attempt = self.attempts[-1]

        if self.outcome is CrawlPageOutcome.SUCCEEDED:
            if (
                address is None
                or self.http_status is None
                or final_attempt.outcome
                is not RequestAttemptOutcome.SUCCEEDED
                or final_attempt.connected_address != address
                or final_attempt.http_status != self.http_status
            ):
                raise CrawlPolicyError(
                    "page_success_metadata_required",
                    "Successful pages require successful attempt metadata.",
                )

            if error_code is not None or self.retryable is not None:
                raise CrawlPolicyError(
                    "page_success_error_invalid",
                    "Successful pages cannot contain error metadata.",
                )
        else:
            if (
                error_code is None
                or self.retryable is None
                or final_attempt.outcome
                is not RequestAttemptOutcome.FAILED
                or final_attempt.error_code != error_code
                or final_attempt.retryable is not self.retryable
            ):
                raise CrawlPolicyError(
                    "page_failure_metadata_required",
                    "Failed pages require failed attempt error metadata.",
                )

            if (
                address is not None
                or self.http_status is not None
                or content_type is not None
                or self.discovered_links != 0
                or self.queued_links != 0
            ):
                raise CrawlPolicyError(
                    "page_failure_response_invalid",
                    "Failed pages cannot contain response or discovery metadata.",
                )

        object.__setattr__(self, "url", url)
        object.__setattr__(self, "parent_url", parent_url)
        object.__setattr__(self, "content_type", content_type)
        object.__setattr__(self, "connected_address", address)
        object.__setattr__(self, "error_code", error_code)


@dataclass(frozen=True, slots=True)
class CrawlExecution:
    """Bounded crawl result without response bodies or cookie values."""

    root_url: str
    pages: tuple[CrawlPageRecord, ...]
    skipped_links: tuple[CrawlSkipSummary, ...]
    termination_reason: CrawlTerminationReason = (
        CrawlTerminationReason.COMPLETED
    )
    pages_pending: int = 0

    def __post_init__(self) -> None:
        root_url = _audit_url(self.root_url, "crawl_root_url")

        if (
            not isinstance(self.pages, tuple)
            or any(
                not isinstance(item, CrawlPageRecord)
                for item in self.pages
            )
        ):
            raise CrawlPolicyError(
                "crawl_pages_invalid",
                "pages must be a tuple of CrawlPageRecord values.",
            )

        if not isinstance(
            self.termination_reason,
            CrawlTerminationReason,
        ):
            raise CrawlPolicyError(
                "crawl_termination_reason_invalid",
                "termination_reason must be a CrawlTerminationReason value.",
            )

        _bounded_integer(
            self.pages_pending,
            name="crawl_pages_pending",
            minimum=0,
            maximum=MAXIMUM_CRAWL_PAGES,
        )

        early_reasons = {
            CrawlTerminationReason.TIME_LIMIT_REACHED,
            CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
            CrawlTerminationReason.CANCELLED,
        }

        if not self.pages and self.termination_reason not in early_reasons:
            raise CrawlPolicyError(
                "crawl_empty_pages_invalid",
                "Only cancellation or an exhausted execution budget may "
                "produce a crawl without attempted pages.",
            )

        if self.pages and self.pages[0].url != root_url:
            raise CrawlPolicyError(
                "crawl_root_page_mismatch",
                "The first page must be the crawl root.",
            )

        urls = tuple(item.url for item in self.pages)

        if len(set(urls)) != len(urls):
            raise CrawlPolicyError(
                "crawl_page_duplicate",
                "A crawl cannot contain the same page more than once.",
            )

        if (
            not isinstance(self.skipped_links, tuple)
            or any(
                not isinstance(item, CrawlSkipSummary)
                for item in self.skipped_links
            )
        ):
            raise CrawlPolicyError(
                "crawl_skips_invalid",
                "skipped_links contains an invalid value.",
            )

        reasons = tuple(
            item.reason
            for item in self.skipped_links
        )

        if len(set(reasons)) != len(reasons):
            raise CrawlPolicyError(
                "crawl_skip_duplicate",
                "A skip reason can appear only once.",
            )

        if (
            self.termination_reason
            in {
                CrawlTerminationReason.COMPLETED,
                CrawlTerminationReason.ROOT_REQUEST_FAILED,
            }
            and self.pages_pending != 0
        ):
            raise CrawlPolicyError(
                "crawl_pending_pages_invalid",
                "This termination reason cannot retain pending pages.",
            )

        if (
            self.termination_reason
            is CrawlTerminationReason.ROOT_REQUEST_FAILED
            and (
                len(self.pages) != 1
                or self.pages[0].outcome is not CrawlPageOutcome.FAILED
            )
        ):
            raise CrawlPolicyError(
                "crawl_root_failure_invalid",
                "root_request_failed requires one failed root page.",
            )

        if (
            self.pages
            and self.pages[0].outcome is CrawlPageOutcome.FAILED
            and self.termination_reason
            not in {
                CrawlTerminationReason.ROOT_REQUEST_FAILED,
                CrawlTerminationReason.TIME_LIMIT_REACHED,
                CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
                CrawlTerminationReason.CANCELLED,
            }
        ):
            raise CrawlPolicyError(
                "crawl_root_failure_termination_missing",
                "A failed root page requires an explicit root or budget "
                "termination reason.",
            )

        object.__setattr__(self, "root_url", root_url)
        object.__setattr__(
            self,
            "skipped_links",
            tuple(
                sorted(
                    self.skipped_links,
                    key=lambda item: item.reason.value,
                )
            ),
        )

    @property
    def successful_pages(self) -> tuple[CrawlPageRecord, ...]:
        return tuple(
            page
            for page in self.pages
            if page.outcome is CrawlPageOutcome.SUCCEEDED
        )

    @property
    def failed_pages(self) -> tuple[CrawlPageRecord, ...]:
        return tuple(
            page
            for page in self.pages
            if page.outcome is CrawlPageOutcome.FAILED
        )

    @property
    def requests_attempted(self) -> int:
        return sum(
            len(page.attempts)
            for page in self.pages
        )

    @property
    def requests_succeeded(self) -> int:
        return len(self.successful_pages)

    @property
    def terminated_early(self) -> bool:
        return self.termination_reason in {
            CrawlTerminationReason.TIME_LIMIT_REACHED,
            CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
            CrawlTerminationReason.CANCELLED,
        }


PageVisitor = Callable[
    [ValidatedTarget, SafeHttpResponse, int, str | None],
    None,
]


@dataclass(frozen=True, slots=True)
class _QueuedPage:
    url: str
    depth: int
    parent_url: str | None


@dataclass(slots=True)
class _ExecutionBudget:
    deadline: float
    maximum_request_attempts: int
    cancellation_token: CrawlCancellationToken | None
    attempts_used: int = 0

    def stop_reason(self) -> CrawlTerminationReason | None:
        if (
            self.cancellation_token is not None
            and self.cancellation_token.is_cancelled
        ):
            return CrawlTerminationReason.CANCELLED

        if self.attempts_used >= self.maximum_request_attempts:
            return (
                CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED
            )

        if time.monotonic() >= self.deadline:
            return CrawlTerminationReason.TIME_LIMIT_REACHED

        return None

    def reserve_attempt(self) -> CrawlTerminationReason | None:
        reason = self.stop_reason()
        if reason is not None:
            return reason

        self.attempts_used += 1
        return None

    def wait(
        self,
        seconds: float,
    ) -> CrawlTerminationReason | None:
        reason = self.stop_reason()
        if reason is not None:
            return reason

        if seconds <= 0:
            return None

        remaining = self.deadline - time.monotonic()
        if remaining <= seconds:
            return CrawlTerminationReason.TIME_LIMIT_REACHED

        time.sleep(seconds)
        return self.stop_reason()


@dataclass(frozen=True, slots=True)
class _FetchOutcome:
    response: SafeHttpResponse | None
    attempts: tuple[RequestAttempt, ...]
    error_code: str | None
    retryable: bool | None
    termination_reason: CrawlTerminationReason | None = None


class _AnchorParser(HTMLParser):
    """Extract bounded anchor href values without executing page content."""

    def __init__(self, maximum_links: int) -> None:
        super().__init__(
            convert_charrefs=True,
        )
        self.maximum_links = maximum_links
        self.hrefs: list[str] = []
        self.omitted = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "a":
            return

        href = next(
            (
                value
                for name, value in attrs
                if name.lower() == "href"
                and value is not None
            ),
            None,
        )

        if href is None:
            return

        if len(self.hrefs) < self.maximum_links:
            self.hrefs.append(href)
        else:
            self.omitted += 1


def _bounded_integer(
    value: object,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise CrawlPolicyError(
            f"{name}_invalid",
            f"{name} must be an integer from {minimum} to {maximum}.",
        )

    return value


def _identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise CrawlPolicyError(
            f"{field_name}_invalid",
            f"{field_name} must be a string.",
        )

    cleaned = value.strip().lower()

    if (
        not cleaned
        or len(cleaned) > 128
        or re.fullmatch(r"[a-z][a-z0-9._-]*", cleaned) is None
    ):
        raise CrawlPolicyError(
            f"{field_name}_invalid",
            f"{field_name} is not a valid identifier.",
        )

    return cleaned


def _normalise_media_type(
    value: object,
    *,
    field_name: str,
) -> str:
    if not isinstance(value, str):
        raise CrawlPolicyError(
            f"{field_name}_invalid",
            f"{field_name} must be a media-type string.",
        )

    cleaned = value.strip().lower()

    if _MEDIA_TYPE.fullmatch(cleaned) is None:
        raise CrawlPolicyError(
            f"{field_name}_invalid",
            f"{field_name} must be a valid media type.",
        )

    return cleaned


def _normalise_media_types(
    values: object,
) -> FrozenSet[str]:
    if not isinstance(values, frozenset) or not values:
        raise CrawlPolicyError(
            "allowed_content_types_invalid",
            "allowed_content_types must be a non-empty frozenset.",
        )

    return frozenset(
        _normalise_media_type(
            value,
            field_name="allowed_content_type",
        )
        for value in values
    )


def _normalise_blocked_segments(
    values: object,
) -> FrozenSet[str]:
    if not isinstance(values, frozenset) or not values:
        raise CrawlPolicyError(
            "blocked_path_segments_invalid",
            "blocked_path_segments must be a non-empty frozenset.",
        )

    cleaned: set[str] = set()

    for value in values:
        if not isinstance(value, str):
            raise CrawlPolicyError(
                "blocked_path_segment_invalid",
                "Blocked path segments must be strings.",
            )

        segment = value.strip().lower()

        if (
            not segment
            or len(segment) > 64
            or "/" in segment
            or "\\" in segment
            or _CONTROL_CHARACTERS.search(segment)
        ):
            raise CrawlPolicyError(
                "blocked_path_segment_invalid",
                "Blocked path segments must be bounded single segments.",
            )

        cleaned.add(segment)

    return frozenset(cleaned)


def _audit_url(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise CrawlPolicyError(
            f"{field_name}_invalid",
            f"{field_name} must be a string.",
        )

    cleaned = value.strip()

    if (
        not cleaned
        or len(cleaned) > MAXIMUM_CRAWL_URL_LENGTH
        or _CONTROL_CHARACTERS.search(cleaned)
    ):
        raise CrawlPolicyError(
            f"{field_name}_invalid",
            f"{field_name} is invalid or exceeds the URL limit.",
        )

    parsed = urlsplit(cleaned)

    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise CrawlPolicyError(
            f"{field_name}_invalid",
            f"{field_name} must be a canonical HTTP or HTTPS URL.",
        )

    return cleaned


def _effective_port(parsed) -> int:
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise CrawlPolicyError(
            "crawl_url_port_invalid",
            "A discovered URL contains an invalid port.",
        ) from exc

    if parsed_port is not None:
        return parsed_port

    return 443 if parsed.scheme.lower() == "https" else 80


def _authority(
    hostname: str,
    port: int,
    scheme: str,
) -> str:
    try:
        address = ipaddress.ip_address(hostname)
        rendered_host = (
            f"[{address.compressed}]"
            if isinstance(address, ipaddress.IPv6Address)
            else address.compressed
        )
    except ValueError:
        rendered_host = hostname.lower()

    default_port = 443 if scheme == "https" else 80

    if port == default_port:
        return rendered_host

    return f"{rendered_host}:{port}"


def _root_origin(
    target: ValidatedTarget,
) -> tuple[str, str, int]:
    parsed = urlsplit(target.normalised_url)

    if (
        parsed.scheme != target.scheme
        or parsed.hostname != target.hostname
        or _effective_port(parsed) != target.port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise CrawlPolicyError(
            "validated_target_mismatch",
            "Validated target fields do not match the normalised URL.",
        )

    return (
        target.scheme.lower(),
        target.hostname.lower(),
        target.port,
    )


def _normalise_path(path: str) -> str:
    if "\\" in path or _CONTROL_CHARACTERS.search(path):
        raise CrawlPolicyError(
            "crawl_path_invalid",
            "Discovered paths cannot contain backslashes or control characters.",
        )

    if not path:
        return "/"

    normalised = posixpath.normpath(path)

    if path.startswith("/") and not normalised.startswith("/"):
        normalised = f"/{normalised}"

    if path.endswith("/") and normalised != "/":
        normalised = f"{normalised}/"

    if not normalised.startswith("/"):
        normalised = f"/{normalised}"

    return normalised


def _is_destructive_path(
    path: str,
    blocked_segments: FrozenSet[str],
) -> bool:
    decoded = unquote(path).lower()

    if "\\" in decoded or _CONTROL_CHARACTERS.search(decoded):
        return True

    segments = (
        segment
        for segment in decoded.split("/")
        if segment
    )

    return any(
        segment in blocked_segments
        for segment in segments
    )


def _canonical_candidate(
    *,
    raw_href: str,
    base_url: str,
    root_origin: tuple[str, str, int],
    policy: CrawlPolicy,
) -> tuple[str | None, CrawlSkipReason | None]:
    href = raw_href.strip()

    if not href:
        return None, CrawlSkipReason.FRAGMENT_ONLY

    if (
        len(href) > policy.maximum_url_length
        or _CONTROL_CHARACTERS.search(href)
    ):
        return None, CrawlSkipReason.MALFORMED_URL

    if href.startswith("#"):
        return None, CrawlSkipReason.FRAGMENT_ONLY

    try:
        absolute = urljoin(base_url, href)
        parsed = urlsplit(absolute)
    except (TypeError, ValueError):
        return None, CrawlSkipReason.MALFORMED_URL

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        return None, CrawlSkipReason.UNSUPPORTED_SCHEME

    if parsed.username is not None or parsed.password is not None:
        return None, CrawlSkipReason.USERINFO_NOT_ALLOWED

    if parsed.hostname is None:
        return None, CrawlSkipReason.MALFORMED_URL

    try:
        port = _effective_port(parsed)
    except CrawlPolicyError:
        return None, CrawlSkipReason.MALFORMED_URL

    origin = (
        scheme,
        parsed.hostname.lower(),
        port,
    )

    if origin != root_origin:
        return None, CrawlSkipReason.EXTERNAL_ORIGIN

    try:
        path = _normalise_path(parsed.path)
    except CrawlPolicyError:
        return None, CrawlSkipReason.MALFORMED_URL

    if _is_destructive_path(
        path,
        policy.blocked_path_segments,
    ):
        return None, CrawlSkipReason.DESTRUCTIVE_PATH

    query = parsed.query

    if query:
        if policy.query_mode is CrawlQueryMode.REJECT:
            return None, CrawlSkipReason.QUERY_REJECTED
        query = ""

    authority = _authority(
        root_origin[1],
        root_origin[2],
        root_origin[0],
    )
    canonical = urlunsplit(
        (
            root_origin[0],
            authority,
            path,
            query,
            "",
        )
    )

    if len(canonical) > policy.maximum_url_length:
        return None, CrawlSkipReason.MALFORMED_URL

    return canonical, None


def _target_for_url(
    root_target: ValidatedTarget,
    url: str,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme=root_target.scheme,
        hostname=root_target.hostname,
        port=root_target.port,
        resolved_addresses=root_target.resolved_addresses,
    )


def _response_content_type(
    response: SafeHttpResponse,
) -> str | None:
    values = {
        value.split(";", 1)[0].strip().lower()
        for name, value in response.headers
        if name.lower() == "content-type"
        and value.strip()
    }

    if len(values) != 1:
        return None

    media_type = values.pop()

    if _MEDIA_TYPE.fullmatch(media_type) is None:
        return None

    return media_type


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _fetch_with_retry(
    target: ValidatedTarget,
    *,
    fetch_policy: FetchPolicy,
    retry_policy: RetryPolicy,
    budget: _ExecutionBudget,
) -> _FetchOutcome:
    attempts: list[RequestAttempt] = []

    while True:
        termination_reason = budget.reserve_attempt()

        if termination_reason is not None:
            if attempts and attempts[-1].retry_scheduled:
                attempts[-1] = replace(
                    attempts[-1],
                    retry_scheduled=False,
                    backoff_seconds=0.0,
                )

            return _FetchOutcome(
                response=None,
                attempts=tuple(attempts),
                error_code=(
                    None
                    if not attempts
                    else attempts[-1].error_code
                ),
                retryable=(
                    None
                    if not attempts
                    else attempts[-1].retryable
                ),
                termination_reason=termination_reason,
            )

        attempt_number = len(attempts) + 1
        attempt_started_at = _utc_now()

        try:
            response = fetch_once(
                target,
                method="GET",
                policy=fetch_policy,
            )
        except SafeRequestError as exc:
            attempt_completed_at = _utc_now()
            retryable = is_retryable_error(
                stage="request",
                code=exc.code,
            )
            retry_allowed_by_policy = (
                retryable
                and attempt_number
                < retry_policy.maximum_attempts
            )

            if not retry_allowed_by_policy:
                attempts.append(
                    RequestAttempt(
                        attempt_number=attempt_number,
                        started_at=attempt_started_at,
                        completed_at=attempt_completed_at,
                        outcome=RequestAttemptOutcome.FAILED,
                        error_code=exc.code,
                        retryable=retryable,
                        retry_scheduled=False,
                        backoff_seconds=0.0,
                    )
                )
                return _FetchOutcome(
                    response=None,
                    attempts=tuple(attempts),
                    error_code=exc.code,
                    retryable=retryable,
                )

            delay = retry_policy.delay_after_failure(
                attempt_number
            )
            termination_reason = budget.wait(delay)

            if termination_reason is not None:
                attempts.append(
                    RequestAttempt(
                        attempt_number=attempt_number,
                        started_at=attempt_started_at,
                        completed_at=attempt_completed_at,
                        outcome=RequestAttemptOutcome.FAILED,
                        error_code=exc.code,
                        retryable=retryable,
                        retry_scheduled=False,
                        backoff_seconds=0.0,
                    )
                )
                return _FetchOutcome(
                    response=None,
                    attempts=tuple(attempts),
                    error_code=exc.code,
                    retryable=retryable,
                    termination_reason=termination_reason,
                )

            attempts.append(
                RequestAttempt(
                    attempt_number=attempt_number,
                    started_at=attempt_started_at,
                    completed_at=attempt_completed_at,
                    outcome=RequestAttemptOutcome.FAILED,
                    error_code=exc.code,
                    retryable=retryable,
                    retry_scheduled=True,
                    backoff_seconds=delay,
                )
            )
            continue

        attempt_completed_at = _utc_now()
        attempts.append(
            RequestAttempt(
                attempt_number=attempt_number,
                started_at=attempt_started_at,
                completed_at=attempt_completed_at,
                outcome=RequestAttemptOutcome.SUCCEEDED,
                connected_address=response.connected_address,
                http_status=response.status,
            )
        )

        return _FetchOutcome(
            response=response,
            attempts=tuple(attempts),
            error_code=None,
            retryable=None,
        )


def crawl_same_origin(
    root_target: ValidatedTarget,
    *,
    crawl_policy: CrawlPolicy = CrawlPolicy(),
    fetch_policy: FetchPolicy = FetchPolicy(),
    retry_policy: RetryPolicy = RetryPolicy(),
    on_page: PageVisitor | None = None,
    cancellation_token: CrawlCancellationToken | None = None,
) -> CrawlExecution:
    """Fetch a budgeted breadth-first set of same-origin HTML pages.

    Only anchor ``href`` values are considered. Forms, scripts, images,
    JavaScript routes, and other active navigation mechanisms are ignored.
    Discovered URLs never change origin, never retain fragments, and never
    preserve query strings. Automatic redirects remain blocked by the safe
    HTTP client.

    Cancellation, the monotonic execution deadline, and the total
    request-attempt budget are checked before every new HTTP request.
    Response bodies are used only for bounded link extraction and the optional
    synchronous ``on_page`` callback. They are not stored in CrawlExecution.
    """

    if not isinstance(root_target, ValidatedTarget):
        raise CrawlPolicyError(
            "root_target_invalid",
            "root_target must be a ValidatedTarget value.",
        )

    if not isinstance(crawl_policy, CrawlPolicy):
        raise CrawlPolicyError(
            "crawl_policy_invalid",
            "crawl_policy must be a CrawlPolicy value.",
        )

    if on_page is not None and not callable(on_page):
        raise CrawlPolicyError(
            "page_visitor_invalid",
            "on_page must be callable or null.",
        )

    if (
        cancellation_token is not None
        and not isinstance(
            cancellation_token,
            CrawlCancellationToken,
        )
    ):
        raise CrawlPolicyError(
            "cancellation_token_invalid",
            "cancellation_token must be a CrawlCancellationToken or null.",
        )

    root_origin = _root_origin(root_target)
    root_url, root_skip = _canonical_candidate(
        raw_href=root_target.normalised_url,
        base_url=root_target.normalised_url,
        root_origin=root_origin,
        policy=crawl_policy,
    )

    if root_url is None:
        code = (
            "root_query_rejected"
            if root_skip is CrawlSkipReason.QUERY_REJECTED
            else "root_url_invalid"
        )
        raise CrawlPolicyError(
            code,
            "The validated root URL is incompatible with the crawl policy.",
        )

    queue = deque(
        (
            _QueuedPage(
                url=root_url,
                depth=0,
                parent_url=None,
            ),
        )
    )
    queued_urls = {root_url}
    pages: list[CrawlPageRecord] = []
    skip_counts: Counter[CrawlSkipReason] = Counter()
    termination_reason = CrawlTerminationReason.COMPLETED

    budget = _ExecutionBudget(
        deadline=(
            time.monotonic()
            + crawl_policy.maximum_execution_seconds
        ),
        maximum_request_attempts=(
            crawl_policy.maximum_request_attempts
        ),
        cancellation_token=cancellation_token,
    )

    while queue and len(pages) < crawl_policy.maximum_pages:
        stop_reason = budget.stop_reason()
        if stop_reason is not None:
            termination_reason = stop_reason
            break

        if pages and crawl_policy.minimum_delay_seconds > 0:
            stop_reason = budget.wait(
                crawl_policy.minimum_delay_seconds
            )
            if stop_reason is not None:
                termination_reason = stop_reason
                break

        queued_page = queue.popleft()
        page_target = _target_for_url(
            root_target,
            queued_page.url,
        )

        fetch_outcome = _fetch_with_retry(
            page_target,
            fetch_policy=fetch_policy,
            retry_policy=retry_policy,
            budget=budget,
        )

        if fetch_outcome.response is None:
            if fetch_outcome.attempts:
                pages.append(
                    CrawlPageRecord(
                        url=queued_page.url,
                        depth=queued_page.depth,
                        parent_url=queued_page.parent_url,
                        outcome=CrawlPageOutcome.FAILED,
                        attempts=fetch_outcome.attempts,
                        error_code=fetch_outcome.error_code,
                        retryable=fetch_outcome.retryable,
                    )
                )

            if fetch_outcome.termination_reason is not None:
                termination_reason = (
                    fetch_outcome.termination_reason
                )
                break

            if queued_page.depth == 0:
                termination_reason = (
                    CrawlTerminationReason.ROOT_REQUEST_FAILED
                )
                break

            continue

        response = fetch_outcome.response
        content_type = _response_content_type(response)
        discovered_links = 0
        queued_links = 0

        if on_page is not None:
            on_page(
                page_target,
                response,
                queued_page.depth,
                queued_page.parent_url,
            )

        if (
            content_type in crawl_policy.allowed_content_types
            and queued_page.depth < crawl_policy.maximum_depth
        ):
            parser = _AnchorParser(
                crawl_policy.maximum_links_per_page
            )
            parser.feed(
                response.body.decode(
                    "utf-8",
                    errors="replace",
                )
            )
            parser.close()

            discovered_links = len(parser.hrefs)
            if parser.omitted:
                skip_counts[
                    CrawlSkipReason.LINK_LIMIT
                ] += parser.omitted

            candidates: set[str] = set()

            for href in parser.hrefs:
                candidate, skip_reason = _canonical_candidate(
                    raw_href=href,
                    base_url=queued_page.url,
                    root_origin=root_origin,
                    policy=crawl_policy,
                )

                if candidate is None:
                    if skip_reason is not None:
                        skip_counts[skip_reason] += 1
                    continue

                if (
                    candidate in queued_urls
                    or candidate in candidates
                ):
                    skip_counts[
                        CrawlSkipReason.DUPLICATE
                    ] += 1
                    continue

                candidates.add(candidate)

            for candidate in sorted(candidates):
                if (
                    len(pages)
                    + 1
                    + len(queue)
                    >= crawl_policy.maximum_pages
                ):
                    skip_counts[
                        CrawlSkipReason.PAGE_LIMIT
                    ] += 1
                    continue

                queue.append(
                    _QueuedPage(
                        url=candidate,
                        depth=queued_page.depth + 1,
                        parent_url=queued_page.url,
                    )
                )
                queued_urls.add(candidate)
                queued_links += 1

        pages.append(
            CrawlPageRecord(
                url=queued_page.url,
                depth=queued_page.depth,
                parent_url=queued_page.parent_url,
                outcome=CrawlPageOutcome.SUCCEEDED,
                attempts=fetch_outcome.attempts,
                content_type=content_type,
                connected_address=response.connected_address,
                http_status=response.status,
                discovered_links=discovered_links,
                queued_links=queued_links,
            )
        )

    pages_pending = 0

    if termination_reason in {
        CrawlTerminationReason.TIME_LIMIT_REACHED,
        CrawlTerminationReason.REQUEST_ATTEMPT_LIMIT_REACHED,
        CrawlTerminationReason.CANCELLED,
    }:
        pages_pending = len(queue)
    elif queue:
        skip_counts[CrawlSkipReason.PAGE_LIMIT] += len(queue)
        termination_reason = (
            CrawlTerminationReason.PAGE_LIMIT_REACHED
        )
    elif skip_counts[CrawlSkipReason.PAGE_LIMIT] > 0:
        termination_reason = (
            CrawlTerminationReason.PAGE_LIMIT_REACHED
        )

    return CrawlExecution(
        root_url=root_url,
        pages=tuple(pages),
        skipped_links=tuple(
            CrawlSkipSummary(
                reason=reason,
                count=count,
            )
            for reason, count in skip_counts.items()
            if count > 0
        ),
        termination_reason=termination_reason,
        pages_pending=pages_pending,
    )


__all__ = [
    "CrawlCancellationToken",
    "CrawlExecution",
    "CrawlPageOutcome",
    "CrawlPageRecord",
    "CrawlPolicy",
    "CrawlPolicyError",
    "CrawlQueryMode",
    "CrawlSkipReason",
    "CrawlSkipSummary",
    "DEFAULT_ALLOWED_CONTENT_TYPES",
    "DEFAULT_BLOCKED_PATH_SEGMENTS",
    "DEFAULT_CRAWL_EXECUTION_SECONDS",
    "DEFAULT_CRAWL_REQUEST_ATTEMPTS",
    "MAXIMUM_CRAWL_DELAY_SECONDS",
    "MAXIMUM_CRAWL_DEPTH",
    "MAXIMUM_CRAWL_EXECUTION_SECONDS",
    "MAXIMUM_CRAWL_PAGES",
    "MAXIMUM_CRAWL_REQUEST_ATTEMPTS",
    "MAXIMUM_CRAWL_URL_LENGTH",
    "MAXIMUM_LINKS_PER_PAGE",
    "PageVisitor",
    "crawl_same_origin",
]
