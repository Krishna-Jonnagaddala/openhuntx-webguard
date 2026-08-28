"""Authorization resource discovery (Slice 9).

Recognizes possible authorization-sensitive object resources from pages
legitimately fetched during an authenticated crawl -- HTML links and
JSON API response bodies -- and turns them into `AuthorizationResource`
objects for the existing IDOR/BOLA comparison engine (Slice 8).

This module never generates, enumerates, or guesses an identifier. It
only recognizes identifiers that are already present in content the
authenticated identity legitimately received. Every produced resource
carries an explicit `IdentifierProvenance` recording exactly how its
identifier was observed (`HTML_LINK` or `JSON_FIELD` here); it is
`resource_graph.py`'s job, not this module's, to decide whether a given
provenance is *comparison*-eligible -- this module's only
responsibility is honest, bounded recognition.

Bounds (`ResourceDiscoveryBudget`) apply to every extraction pass:
maximum resources per page, maximum total resources for one crawl,
maximum JSON nesting depth and field count examined, maximum response
size considered, and a maximum identifier value length. No complete
response body is ever retained -- only the bounded set of recognized
identifiers and their structural context.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from html.parser import HTMLParser
from typing import FrozenSet, Iterator, Tuple
from urllib.parse import urljoin, urlsplit

from .authorization_resource import (
    AuthorizationResource,
    AuthorizationResourceError,
    IdentifierLocation,
    IdentifierProvenance,
    ResourceSource,
)
from .crawler import CrawlCancellationToken
from .safe_http import SafeHttpResponse
from .scope_validator import ValidatedTarget


class AuthenticatedCrawlStatus(str, Enum):
    """The authentication-health outcome of one authenticated resource-
    discovery crawl. `IN_PROGRESS` is never observed by a caller -- it
    is resolved to `SUCCEEDED` once the crawl finishes without an
    authentication-health failure."""

    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    AUTHENTICATION_EXPIRED = "authentication_expired"
    AUTHENTICATION_FAILED = "authentication_failed"


DEFAULT_IDENTIFIER_FIELD_PATTERNS: FrozenSet[str] = frozenset(
    {"id", "user_id", "order_id", "document_id", "basket_id", "resource_id"}
)

MAXIMUM_JSON_DEPTH = 6
MAXIMUM_JSON_FIELDS_SCANNED = 200
MAXIMUM_JSON_LIST_ITEMS_SCANNED = 20
MAXIMUM_RESOURCES_PER_PAGE = 20
MAXIMUM_TOTAL_RESOURCES = 200
MAXIMUM_IDENTIFIER_VALUE_LENGTH = 128
MAXIMUM_RESPONSE_BYTES_CONSIDERED = 2 * 1024 * 1024

_IDENTIFIER_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_NON_IDENTIFIER_SEGMENTS = frozenset(
    {
        "index.html",
        "index.htm",
        "login",
        "logout",
        "static",
        "assets",
        "public",
        "api",
        "rest",
    }
)


@dataclass(frozen=True, slots=True)
class ResourceDiscoveryBudget:
    """Explicit sub-budget for authorization resource discovery,
    separate from the crawl's own page/depth/request budget (Slice 5's
    `CrawlPolicy`) and separate from the IDOR detector's own comparison-
    request budget (Slice 8's `ActiveDetectionPolicy`) -- discovery,
    crawling, and comparison are each bounded independently."""

    maximum_resources_per_page: int = MAXIMUM_RESOURCES_PER_PAGE
    maximum_total_resources: int = MAXIMUM_TOTAL_RESOURCES
    maximum_json_depth: int = MAXIMUM_JSON_DEPTH
    maximum_json_fields_scanned: int = MAXIMUM_JSON_FIELDS_SCANNED
    maximum_identifier_value_length: int = MAXIMUM_IDENTIFIER_VALUE_LENGTH
    maximum_response_bytes: int = MAXIMUM_RESPONSE_BYTES_CONSIDERED


@dataclass(frozen=True, slots=True)
class AuthenticationHealthCriterion:
    """Bounded, explicit check for whether a page fetched during an
    authenticated crawl still reflects a valid session -- reusing the
    Slice-7 principle that HTTP 200 alone is never sufficient evidence
    of anything, applied here to the crawl phase rather than the login
    request itself. At least one of `login_page_marker`/
    `authenticated_marker` should normally be configured; an empty
    criterion never classifies a page as unhealthy except via
    `unauthenticated_statuses`.
    """

    login_page_marker: str | None = None
    authenticated_marker: str | None = None
    unauthenticated_statuses: FrozenSet[int] = frozenset({401, 403})

    def classify(self, response: SafeHttpResponse) -> str | None:
        """Returns None when the page looks authenticated, else
        ``"authentication_failed"`` (an explicit denial status) or
        ``"authentication_expired"`` (a 200 that looks like a login
        page or is missing the expected authenticated marker)."""

        if response.status in self.unauthenticated_statuses:
            return "authentication_failed"
        body_text = response.body[:65536].decode("utf-8", errors="replace")
        if self.login_page_marker and self.login_page_marker in body_text:
            return "authentication_expired"
        if (
            self.authenticated_marker
            and self.authenticated_marker not in body_text
        ):
            return "authentication_expired"
        return None


def _same_origin(target: ValidatedTarget, url: str) -> bool:
    parsed = urlsplit(url)
    if not parsed.scheme and not parsed.netloc:
        return True
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return (
        parsed.scheme == target.scheme
        and (parsed.hostname or "").lower() == target.hostname
        and port == target.port
    )


class _AnchorHrefParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.hrefs.append(value)
                return


def _discover_html_link_resources(
    target: ValidatedTarget,
    page_url: str,
    html_body: bytes,
    *,
    owning_identity: str,
    budget: ResourceDiscoveryBudget,
) -> Tuple[AuthorizationResource, ...]:
    parser = _AnchorHrefParser()
    try:
        parser.feed(html_body.decode("utf-8", errors="replace"))
    except Exception:
        return ()

    resources: list[AuthorizationResource] = []
    for href in parser.hrefs:
        if len(resources) >= budget.maximum_resources_per_page:
            break
        resolved = urljoin(page_url, href)
        # Scope control (requirement 19): a link appearing in
        # authenticated HTML never becomes a resource unless it is
        # already on this target's own origin -- discovery can never
        # expand scope beyond what was already authorized.
        if not _same_origin(target, resolved):
            continue
        parsed = urlsplit(resolved)
        segments = [segment for segment in parsed.path.split("/") if segment]
        if len(segments) < 2:
            continue
        identifier_value = segments[-1]
        resource_type = segments[-2]
        if resource_type.lower() in _NON_IDENTIFIER_SEGMENTS:
            continue
        if identifier_value.lower() in _NON_IDENTIFIER_SEGMENTS:
            continue
        if "." in identifier_value:
            continue
        if not _IDENTIFIER_SEGMENT_PATTERN.match(identifier_value):
            continue
        if len(identifier_value) > budget.maximum_identifier_value_length:
            continue
        canonical_endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        try:
            resource = AuthorizationResource(
                resource_type=resource_type,
                endpoint=canonical_endpoint,
                method="GET",
                identifier_location=IdentifierLocation.PATH,
                identifier_name="id",
                identifier_value=identifier_value,
                owning_test_identity=owning_identity,
                source=ResourceSource.OBSERVED_RESPONSE,
                provenance=IdentifierProvenance.HTML_LINK,
            )
        except AuthorizationResourceError:
            # The only failure mode AuthorizationResource itself raises
            # (an empty endpoint/owner) -- already impossible given the
            # checks above, kept as defense in depth, not a broad catch.
            continue
        resources.append(resource)
    return tuple(resources)


def _walk_json(
    value: object,
    *,
    depth: int,
    budget: ResourceDiscoveryBudget,
    fields_scanned: list[int],
) -> Iterator[tuple[str, object, int]]:
    if depth > budget.maximum_json_depth:
        return
    if isinstance(value, dict):
        for key, sub_value in value.items():
            if fields_scanned[0] >= budget.maximum_json_fields_scanned:
                return
            fields_scanned[0] += 1
            yield key, sub_value, depth
            if isinstance(sub_value, (dict, list)):
                yield from _walk_json(
                    sub_value,
                    depth=depth + 1,
                    budget=budget,
                    fields_scanned=fields_scanned,
                )
    elif isinstance(value, list):
        for item in value[:MAXIMUM_JSON_LIST_ITEMS_SCANNED]:
            if fields_scanned[0] >= budget.maximum_json_fields_scanned:
                return
            if isinstance(item, (dict, list)):
                yield from _walk_json(
                    item,
                    depth=depth + 1,
                    budget=budget,
                    fields_scanned=fields_scanned,
                )


def _discover_json_field_resources(
    target: ValidatedTarget,
    page_url: str,
    json_body: bytes,
    *,
    owning_identity: str,
    budget: ResourceDiscoveryBudget,
    field_patterns: FrozenSet[str],
    endpoint_templates: "dict[str, str] | None" = None,
) -> Tuple[AuthorizationResource, ...]:
    """``endpoint_templates`` (requirement 7's "explicit configuration"
    signal) is an optional, operator-supplied mapping of field name to
    a same-origin relative path template containing exactly one
    ``{value}`` placeholder, e.g. ``{"bid": "rest/basket/{value}"}``.
    It exists for the case where an identifier is legitimately revealed
    on one endpoint (e.g. a login response) but addresses a
    *different*, separately-known endpoint -- the self-referential
    check below cannot discover that relationship on its own, and this
    module will never guess it. Every endpoint this produces is still
    resolved relative to ``target`` and independently scope-checked."""

    try:
        parsed_body = json.loads(json_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ()

    templates = endpoint_templates or {}
    page_parsed = urlsplit(page_url)
    trailing_segment = ""
    stripped_path = page_parsed.path.rstrip("/")
    if stripped_path:
        trailing_segment = stripped_path.rsplit("/", 1)[-1]
    canonical_endpoint = f"{page_parsed.scheme}://{page_parsed.netloc}{page_parsed.path}"

    fields_scanned = [0]
    resources: list[AuthorizationResource] = []
    for key, value, _depth in _walk_json(
        parsed_body, depth=0, budget=budget, fields_scanned=fields_scanned
    ):
        if len(resources) >= budget.maximum_resources_per_page:
            break
        if not isinstance(key, str) or key.lower() not in field_patterns:
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        identifier_value = str(value)
        if not identifier_value:
            continue
        if len(identifier_value) > budget.maximum_identifier_value_length:
            continue
        # Self-referential: this JSON response's own field value matches
        # the URL's own trailing path segment -- structural proof that
        # this exact endpoint is addressable by substituting the
        # identifier, without ever fetching or guessing anything new.
        is_self_referential = bool(trailing_segment) and identifier_value == trailing_segment
        resource_type = key[: -len("_id")] if key.lower().endswith("_id") else key
        template = templates.get(key.lower())
        if template is not None:
            default_port = 443 if target.scheme == "https" else 80
            authority = (
                target.hostname
                if target.port == default_port
                else f"{target.hostname}:{target.port}"
            )
            resolved = urljoin(
                f"{target.scheme}://{authority}/",
                template.format(value=identifier_value),
            )
            if not _same_origin(target, resolved):
                continue
            endpoint = resolved
            identifier_location = IdentifierLocation.PATH
        else:
            endpoint = canonical_endpoint
            identifier_location = (
                IdentifierLocation.PATH
                if is_self_referential
                else IdentifierLocation.NONE
            )
        try:
            resource = AuthorizationResource(
                resource_type=resource_type or "resource",
                endpoint=endpoint,
                method="GET",
                identifier_location=identifier_location,
                identifier_name=key,
                identifier_value=identifier_value,
                owning_test_identity=owning_identity,
                source=ResourceSource.OBSERVED_RESPONSE,
                provenance=IdentifierProvenance.JSON_FIELD,
            )
        except AuthorizationResourceError:
            continue
        resources.append(resource)
    return tuple(resources)


def _content_type_of(response: SafeHttpResponse) -> str:
    for name, value in response.headers:
        if name.lower() == "content-type":
            return value.lower()
    return ""


@dataclass
class ResourceDiscoverySink:
    """Reusable, stateful resource-discovery stage (requirement 4):
    accumulates `AuthorizationResource`s across every page visited
    during one authenticated crawl, deduplicated by structural
    `resource_id`, bounded by `budget`, and halted (via
    `cancellation_token`) the moment `authentication_health_criterion`
    detects the session is no longer valid -- an expired-session login
    page is never mistaken for ordinary application content and never
    contributes a resource.
    """

    owning_identity: str
    budget: ResourceDiscoveryBudget = field(default_factory=ResourceDiscoveryBudget)
    field_patterns: FrozenSet[str] = DEFAULT_IDENTIFIER_FIELD_PATTERNS
    endpoint_templates: "dict[str, str]" = field(default_factory=dict)
    authentication_health_criterion: AuthenticationHealthCriterion | None = None
    cancellation_token: CrawlCancellationToken | None = None
    _resources_by_id: dict[str, AuthorizationResource] = field(
        default_factory=dict, init=False, repr=False
    )
    _pages_with_authentication_failure: list[str] = field(
        default_factory=list, init=False, repr=False
    )
    _health_status: AuthenticatedCrawlStatus = field(
        default=AuthenticatedCrawlStatus.IN_PROGRESS, init=False, repr=False
    )

    def visit_page(self, target: ValidatedTarget, response: SafeHttpResponse) -> None:
        if self._health_status is not AuthenticatedCrawlStatus.IN_PROGRESS:
            return

        if self.authentication_health_criterion is not None:
            reason = self.authentication_health_criterion.classify(response)
            if reason is not None:
                self._pages_with_authentication_failure.append(
                    target.normalised_url
                )
                self._health_status = AuthenticatedCrawlStatus(reason)
                if self.cancellation_token is not None:
                    self.cancellation_token.cancel()
                return

        if len(self._resources_by_id) >= self.budget.maximum_total_resources:
            return
        if len(response.body) > self.budget.maximum_response_bytes:
            return

        content_type = _content_type_of(response)
        discovered: Tuple[AuthorizationResource, ...] = ()
        if "json" in content_type:
            discovered = _discover_json_field_resources(
                target,
                target.normalised_url,
                response.body,
                owning_identity=self.owning_identity,
                budget=self.budget,
                field_patterns=self.field_patterns,
                endpoint_templates=self.endpoint_templates,
            )
        elif "html" in content_type:
            discovered = _discover_html_link_resources(
                target,
                target.normalised_url,
                response.body,
                owning_identity=self.owning_identity,
                budget=self.budget,
            )

        for resource in discovered:
            if len(self._resources_by_id) >= self.budget.maximum_total_resources:
                break
            self._resources_by_id.setdefault(resource.resource_id, resource)

    @property
    def resources(self) -> Tuple[AuthorizationResource, ...]:
        return tuple(self._resources_by_id.values())

    @property
    def pages_with_authentication_failure(self) -> Tuple[str, ...]:
        return tuple(self._pages_with_authentication_failure)

    @property
    def status(self) -> AuthenticatedCrawlStatus:
        if self._health_status is AuthenticatedCrawlStatus.IN_PROGRESS:
            return AuthenticatedCrawlStatus.SUCCEEDED
        return self._health_status


__all__ = [
    "DEFAULT_IDENTIFIER_FIELD_PATTERNS",
    "AuthenticatedCrawlStatus",
    "AuthenticationHealthCriterion",
    "ResourceDiscoveryBudget",
    "ResourceDiscoverySink",
]
