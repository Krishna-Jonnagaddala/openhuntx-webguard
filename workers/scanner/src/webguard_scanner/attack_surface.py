"""Shared attack-surface discovery model.

This is a discovery-layer expansion, not a new probing capability. It
replaces the single-purpose ``discover_get_form_candidates`` (still kept,
still used by nothing outside this module now) with a richer model that
represents more of a page's real attack surface -- GET forms, POST forms,
query-parameter links, script-embedded endpoint literals, sitemap/robots-
derived URLs, and OpenAPI-declared paths -- while being explicit that most
of that surface is *not* safe to probe automatically.

Existing detectors (reflected-XSS, SQLi) are unmodified by this module.
They still only understand ``active_detection.DetectionCandidate`` (a GET
query parameter on a same-origin URL). ``to_detection_candidates`` is the
one-way projection from the richer model down to that narrower one: only
candidates classified ``SAFE_TO_PROBE`` (GET, non-state-changing) are
projected. Everything else -- POST forms, JSON bodies, anything looking
state-changing -- is discovered, classified, and reported on, but never
handed to a detector that cannot represent it safely. Wiring an actual
POST/JSON-capable detector is future work; this module deliberately does
not invent one to fill the gap.

Scope enforcement: every candidate this module ever returns has already
been checked against the target's own origin (scheme + hostname + port).
A discovered URL that resolves elsewhere -- because a script, a redirect,
an OpenAPI ``servers`` entry, or a sitemap referenced it -- is recorded as
skipped (``off_origin``), never returned as a candidate, regardless of
source. Discovery never expands authorized scope.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import parse_qs, urljoin, urlsplit

from .active_detection import (
    ActiveDetectionPolicy,
    DetectionCandidate,
    fetch_same_origin_page,
)
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .scope_validator import ValidatedTarget


class InputLocation(str, Enum):
    QUERY = "query"
    PATH = "path"
    FORM = "form"
    JSON_BODY = "json_body"
    HEADER = "header"


class DiscoveryMethod(str, Enum):
    GET_FORM = "get_form"
    POST_FORM = "post_form"
    QUERY_PARAMETER = "query_parameter"
    LINK_PARAMETER = "link_parameter"
    JSON_API_MARKUP = "json_api_markup"
    SCRIPT_REFERENCE = "script_reference"
    OPENAPI_DOCUMENT = "openapi_document"
    GRAPHQL_INDICATOR = "graphql_indicator"
    SITEMAP = "sitemap"
    ROBOTS_TXT = "robots_txt"
    CRAWL_DISCOVERED = "crawl_discovered"


class SafetyClassification(str, Enum):
    """How safe this candidate is to actively probe, independent of
    whether any current detector can act on it."""

    SAFE_TO_PROBE = "safe_to_probe"
    REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION = (
        "requires_explicit_active_authorization"
    )
    POTENTIALLY_STATE_CHANGING = "potentially_state_changing"
    UNSUPPORTED = "unsupported"


_STATE_CHANGING_KEYWORDS = (
    "delete",
    "remove",
    "purchase",
    "buy",
    "checkout",
    "payment",
    "pay",
    "transfer",
    # Deliberately "change-password"/"reset-password", not bare
    # "password": a login endpoint legitimately has a "password" field
    # and is a normal, common, legitimate detection target (e.g. the
    # classic login-SQLi case) -- it is not itself a state-changing
    # action. Only the specific *mutation* of a password is.
    "change-password",
    "reset-password",
    "register",
    "create-user",
    "logout",
    "signout",
    "sign-out",
    "upload",
    "admin",
    "destroy",
    "cancel",
    "unsubscribe",
)


def _classify_safety(
    method: str, path: str, field_names: tuple[str, ...]
) -> SafetyClassification:
    if method == "GET":
        return SafetyClassification.SAFE_TO_PROBE

    haystack = (path + " " + " ".join(field_names)).lower()
    if any(keyword in haystack for keyword in _STATE_CHANGING_KEYWORDS):
        return SafetyClassification.POTENTIALLY_STATE_CHANGING

    return SafetyClassification.REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION


@dataclass(frozen=True, slots=True)
class AttackSurfaceCandidate:
    """One discovered place a security check *could* interact with the
    target -- not an authorization to do so. See SafetyClassification and
    ``to_detection_candidates`` for what's actually eligible to probe."""

    endpoint: str
    method: str
    input_location: InputLocation
    parameter: str
    baseline_value: str
    content_type: str
    source_page: str
    discovery_method: DiscoveryMethod
    safety: SafetyClassification
    authentication_required: bool | None = None
    json_body_template: str = ""
    candidate_id: str = field(init=False)

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        canonical_endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        # Identity intentionally excludes volatile probe values (baseline_value,
        # json_body_template) -- origin + path + method + content type +
        # parameter location + parameter name is what makes two discovered
        # candidates "the same place," per Slice 6's deterministic-identity
        # requirement (dedup, findings, retesting, scan comparison).
        identity_key = "|".join(
            (
                canonical_endpoint,
                self.method.upper(),
                self.content_type,
                self.input_location.value,
                self.parameter,
            )
        )
        object.__setattr__(
            self,
            "candidate_id",
            hashlib.sha256(identity_key.encode()).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class SkippedSurfaceItem:
    """One thing discovery declined to turn into a candidate, and why --
    so "not found" is always distinguishable from "found but excluded"."""

    reason: str
    detail: str


@dataclass(frozen=True, slots=True)
class AttackSurfaceBudget:
    """Independent limits for the discovery pass itself, separate from
    any detector's own probe budget."""

    maximum_endpoints: int = 40
    maximum_parameters_per_endpoint: int = 10
    maximum_forms: int = 10
    maximum_api_definitions: int = 3
    maximum_script_resources: int = 5
    maximum_response_bytes: int = 2 * 1024 * 1024
    maximum_links: int = 100


@dataclass(frozen=True, slots=True)
class AttackSurfaceDiscoveryResult:
    candidates: tuple[AttackSurfaceCandidate, ...]
    skipped: tuple[SkippedSurfaceItem, ...]
    truncated: bool
    discovered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


_INJECTABLE_INPUT_TYPES = frozenset({"text", "search", "email", "url", "tel", ""})
_INJECTABLE_TAGS = frozenset({"textarea", "select"})

# Bounded, safe *string-literal* extraction only -- this never executes
# script content. Matches quoted paths that look like API routes inside
# inline <script> text, e.g. fetch("/api/orders"), '/rest/products'.
_SCRIPT_ENDPOINT_LITERAL = re.compile(
    r"""["']((?:/api/|/rest/|/graphql)[a-zA-Z0-9_\-/]{0,128})["']"""
)


@dataclass(slots=True)
class _FormState:
    method: str
    action: str
    fields: list[str]


class _SurfaceHtmlParser(HTMLParser):
    """Bounded parser collecting forms, anchor-link query parameters, and
    inline <script> text for literal-endpoint extraction. Independent
    from html_analyzer.py's parser (security-review scope) and from
    active_candidate_discovery.py's GET-only parser (kept for backward
    compatibility, unused by this module)."""

    def __init__(self, *, maximum_forms: int, maximum_links: int) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_FormState] = []
        self.links: list[str] = []
        self.script_text: list[str] = []
        self._form_stack: list[int] = []
        self._in_script = False
        self._maximum_forms = maximum_forms
        self._maximum_links = maximum_links

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        tag_name = tag.lower()
        attributes = {name.lower(): (value or "") for name, value in attrs if name}

        if tag_name == "script":
            self._in_script = True
            return

        if tag_name == "a" and len(self.links) < self._maximum_links:
            href = attributes.get("href", "")
            if href:
                self.links.append(href)
            return

        if tag_name == "form":
            if len(self.forms) >= self._maximum_forms:
                self._form_stack.append(-1)
                return
            self.forms.append(
                _FormState(
                    method=(attributes.get("method") or "GET").upper(),
                    action=attributes.get("action", ""),
                    fields=[],
                )
            )
            self._form_stack.append(len(self.forms) - 1)
            return

        if not self._form_stack or self._form_stack[-1] == -1:
            return

        form = self.forms[self._form_stack[-1]]
        name = attributes.get("name", "").strip()
        if not name:
            return

        if tag_name == "input":
            input_type = attributes.get("type", "text").lower()
            if input_type in _INJECTABLE_INPUT_TYPES:
                form.fields.append(name)
        elif tag_name in _INJECTABLE_TAGS:
            form.fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered == "script":
            self._in_script = False
        elif lowered == "form" and self._form_stack:
            self._form_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.script_text.append(data)


def _same_origin(target: ValidatedTarget, url: str) -> bool:
    parsed = urlsplit(url)
    if not parsed.scheme and not parsed.netloc:
        return True  # relative URL, resolved against the page already
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return (
        parsed.scheme == target.scheme
        and (parsed.hostname or "").lower() == target.hostname
        and port == target.port
    )


def _origin_base_url(target: ValidatedTarget) -> str:
    """The target's own origin as a base URL, including a non-default
    port. Dropping the port here would make a same-port test target look
    off-origin to _same_origin (a real bug this fixed: the loopback test
    fixtures always run on a non-default port)."""

    default_port = 443 if target.scheme == "https" else 80
    if target.port == default_port:
        return f"{target.scheme}://{target.hostname}/"
    return f"{target.scheme}://{target.hostname}:{target.port}/"


def discover_page_attack_surface(
    target: ValidatedTarget,
    page_url: str,
    html_body: bytes,
    *,
    budget: AttackSurfaceBudget = AttackSurfaceBudget(),
) -> AttackSurfaceDiscoveryResult:
    """Discover GET forms, POST forms, link query parameters, and inline-
    script endpoint literals from one already-fetched page. Pure and
    network-free: no request is made by this function."""

    candidates: list[AttackSurfaceCandidate] = []
    skipped: list[SkippedSurfaceItem] = []
    seen_ids: set[str] = set()
    truncated = False

    if len(html_body) > budget.maximum_response_bytes:
        return AttackSurfaceDiscoveryResult(
            candidates=(),
            skipped=(
                SkippedSurfaceItem(
                    "response_too_large",
                    f"{len(html_body)} bytes exceeds "
                    f"{budget.maximum_response_bytes}.",
                ),
            ),
            truncated=True,
        )

    try:
        text = html_body.decode("utf-8", errors="replace")
    except LookupError:
        return AttackSurfaceDiscoveryResult(
            candidates=(),
            skipped=(SkippedSurfaceItem("decode_failed", "unsupported encoding"),),
            truncated=False,
        )

    parser = _SurfaceHtmlParser(
        maximum_forms=budget.maximum_forms, maximum_links=budget.maximum_links
    )
    try:
        parser.feed(text)
    except Exception as exc:  # noqa: BLE001 - malformed HTML must not crash discovery
        return AttackSurfaceDiscoveryResult(
            candidates=(),
            skipped=(
                SkippedSurfaceItem("malformed_html", exc.__class__.__name__),
            ),
            truncated=False,
        )

    def _add(candidate: AttackSurfaceCandidate) -> bool:
        nonlocal truncated
        if len(candidates) >= budget.maximum_endpoints:
            truncated = True
            return False
        if candidate.candidate_id in seen_ids:
            skipped.append(
                SkippedSurfaceItem("duplicate", candidate.endpoint)
            )
            return True
        seen_ids.add(candidate.candidate_id)
        candidates.append(candidate)
        return True

    # Forms (GET and POST).
    for form in parser.forms:
        action_url = urljoin(page_url, form.action or page_url)
        if not _same_origin(target, action_url):
            skipped.append(SkippedSurfaceItem("off_origin", action_url))
            continue

        fields = tuple(form.fields[: budget.maximum_parameters_per_endpoint])
        if not fields:
            continue

        discovery = (
            DiscoveryMethod.GET_FORM
            if form.method == "GET"
            else DiscoveryMethod.POST_FORM
        )
        content_type = (
            "application/x-www-form-urlencoded"
            if form.method != "GET"
            else ""
        )
        for field_name in fields:
            safety = _classify_safety(
                form.method, urlsplit(action_url).path, fields
            )
            candidate = AttackSurfaceCandidate(
                endpoint=action_url,
                method=form.method,
                input_location=InputLocation.FORM,
                parameter=field_name,
                baseline_value="",
                content_type=content_type,
                source_page=page_url,
                discovery_method=discovery,
                safety=safety,
            )
            if not _add(candidate):
                break

    # Links carrying query parameters.
    for href in parser.links:
        absolute = urljoin(page_url, href)
        if not _same_origin(target, absolute):
            skipped.append(SkippedSurfaceItem("off_origin", absolute))
            continue
        parsed = urlsplit(absolute)
        if not parsed.query:
            continue
        params = parse_qs(parsed.query, keep_blank_values=True)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        for name, values in list(params.items())[
            : budget.maximum_parameters_per_endpoint
        ]:
            candidate = AttackSurfaceCandidate(
                endpoint=base_url,
                method="GET",
                input_location=InputLocation.QUERY,
                parameter=name,
                baseline_value=values[0] if values else "",
                content_type="",
                source_page=page_url,
                discovery_method=DiscoveryMethod.LINK_PARAMETER,
                safety=SafetyClassification.SAFE_TO_PROBE,
            )
            if not _add(candidate):
                break

    # Script-embedded endpoint literals (string extraction only, no
    # execution). Recorded as discovered endpoints without a specific
    # parameter -- the literal alone doesn't tell us a safe input shape,
    # so these are surfaced for visibility, classified UNSUPPORTED.
    combined_script_text = "".join(parser.script_text)[
        : budget.maximum_response_bytes
    ]
    literal_matches = _SCRIPT_ENDPOINT_LITERAL.findall(combined_script_text)
    for literal in literal_matches[: budget.maximum_script_resources]:
        absolute = urljoin(page_url, literal)
        if not _same_origin(target, absolute):
            skipped.append(SkippedSurfaceItem("off_origin", absolute))
            continue
        discovery = (
            DiscoveryMethod.GRAPHQL_INDICATOR
            if "graphql" in literal.lower()
            else DiscoveryMethod.SCRIPT_REFERENCE
        )
        candidate = AttackSurfaceCandidate(
            endpoint=absolute,
            method="GET",
            input_location=InputLocation.PATH,
            parameter="",
            baseline_value="",
            content_type="application/json",
            source_page=page_url,
            discovery_method=discovery,
            safety=SafetyClassification.UNSUPPORTED,
        )
        _add(candidate)

    return AttackSurfaceDiscoveryResult(
        candidates=tuple(candidates),
        skipped=tuple(skipped),
        truncated=truncated,
    )


_OPENAPI_WELL_KNOWN_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
)


def _synthesize_example_from_schema(
    schema: Any, *, depth: int = 0, maximum_depth: int = 4
) -> Any:
    """Bounded, safe synthesis of a plausible example JSON value from an
    OpenAPI schema fragment when the document itself provides no
    concrete example. Never executes anything -- pure structural
    traversal of already-parsed JSON with an explicit depth cap."""

    if depth > maximum_depth or not isinstance(schema, dict):
        return None

    if "example" in schema:
        return schema["example"]

    schema_type = schema.get("type")
    if schema_type == "object" or isinstance(schema.get("properties"), dict):
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return {}
        result: dict[str, Any] = {}
        for name, subschema in list(properties.items())[:20]:
            if isinstance(name, str):
                result[name] = _synthesize_example_from_schema(
                    subschema, depth=depth + 1, maximum_depth=maximum_depth
                )
        return result
    if schema_type == "string":
        return "sample"
    if schema_type in ("integer", "number"):
        return 1
    if schema_type == "boolean":
        return False
    if schema_type == "array":
        return []
    return ""


def _enumerate_json_leaf_paths(
    document: Any,
    *,
    maximum_depth: int,
    maximum_parameters: int,
    maximum_array_index: int,
) -> tuple[str, ...]:
    """Deterministic, bounded leaf-path enumeration duplicated (not
    imported) from request_template.py's enumerate_json_parameter_paths:
    this discovery-layer module must not depend on the mutation-engine
    module, which itself depends on this one for AttackSurfaceCandidate/
    InputLocation/SafetyClassification -- importing the other direction
    would create a cycle. Keep any behavioural change mirrored in both."""

    paths: list[str] = []

    def walk(node: Any, prefix: str, depth: int) -> None:
        if len(paths) >= maximum_parameters or depth > maximum_depth:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if not isinstance(key, str) or len(paths) >= maximum_parameters:
                    return
                walk(value, f"{prefix}.{key}" if prefix else key, depth + 1)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                if index >= maximum_array_index or len(paths) >= maximum_parameters:
                    return
                walk(value, f"{prefix}[{index}]", depth + 1)
        elif isinstance(node, (str, int, float, bool)) and prefix:
            paths.append(prefix)

    walk(document, "", 0)
    return tuple(paths)


def _extract_json_body_candidates(
    endpoint: str,
    method: str,
    operation: Any,
    document_url: str,
    budget: AttackSurfaceBudget,
) -> list[AttackSurfaceCandidate]:
    """Derive JSON_BODY candidates from an OpenAPI operation's
    requestBody, when it declares a concrete example (or enough schema
    structure to synthesize one). No example/schema -> no JSON body
    candidates for this operation; this is a valid, common result, not a
    failure -- most OpenAPI documents in the wild are incomplete."""

    if not isinstance(operation, dict):
        return []
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []
    json_content = content.get("application/json")
    if not isinstance(json_content, dict):
        return []

    example = json_content.get("example")
    if not isinstance(example, dict):
        schema = json_content.get("schema")
        example = (
            _synthesize_example_from_schema(schema)
            if isinstance(schema, dict)
            else None
        )
    if not isinstance(example, dict) or not example:
        return []

    try:
        body_text = json.dumps(example)
    except (TypeError, ValueError):
        return []
    if len(body_text.encode("utf-8")) > budget.maximum_response_bytes:
        return []

    paths = _enumerate_json_leaf_paths(
        example,
        maximum_depth=6,
        maximum_parameters=budget.maximum_parameters_per_endpoint,
        maximum_array_index=10,
    )
    if not paths:
        return []

    safety = _classify_safety(method, endpoint, paths)
    return [
        AttackSurfaceCandidate(
            endpoint=endpoint,
            method=method,
            input_location=InputLocation.JSON_BODY,
            parameter=path,
            baseline_value="",
            content_type="application/json",
            source_page=document_url,
            discovery_method=DiscoveryMethod.OPENAPI_DOCUMENT,
            safety=safety,
            json_body_template=body_text,
        )
        for path in paths
    ]


def _extract_openapi_candidates(
    target: ValidatedTarget,
    document_url: str,
    body: bytes,
    budget: AttackSurfaceBudget,
) -> tuple[list[AttackSurfaceCandidate], list[SkippedSurfaceItem]]:
    candidates: list[AttackSurfaceCandidate] = []
    skipped: list[SkippedSurfaceItem] = []

    if len(body) > budget.maximum_response_bytes:
        return candidates, [
            SkippedSurfaceItem("response_too_large", document_url)
        ]

    try:
        document = json.loads(body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return candidates, [
            SkippedSurfaceItem("malformed_openapi_document", document_url)
        ]

    if not isinstance(document, dict):
        return candidates, [
            SkippedSurfaceItem("malformed_openapi_document", document_url)
        ]

    paths = document.get("paths")
    if not isinstance(paths, dict):
        return candidates, [
            SkippedSurfaceItem("openapi_no_paths", document_url)
        ]

    for path, operations in list(paths.items())[: budget.maximum_endpoints]:
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        absolute = urljoin(document_url, path)
        if not _same_origin(target, absolute):
            skipped.append(SkippedSurfaceItem("off_origin", absolute))
            continue
        for method in operations:
            if not isinstance(method, str):
                continue
            upper_method = method.upper()
            if upper_method not in {
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
            }:
                continue
            safety = _classify_safety(upper_method, path, ())
            candidates.append(
                AttackSurfaceCandidate(
                    endpoint=absolute,
                    method=upper_method,
                    input_location=InputLocation.PATH,
                    parameter="",
                    baseline_value="",
                    content_type="application/json",
                    source_page=document_url,
                    discovery_method=DiscoveryMethod.OPENAPI_DOCUMENT,
                    safety=safety,
                )
            )
            candidates.extend(
                _extract_json_body_candidates(
                    absolute,
                    upper_method,
                    operations[method],
                    document_url,
                    budget,
                )
            )

    return candidates, skipped


def discover_site_attack_surface(
    target: ValidatedTarget,
    *,
    policy: ActiveDetectionPolicy,
    budget: AttackSurfaceBudget = AttackSurfaceBudget(),
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> AttackSurfaceDiscoveryResult:
    """Bounded, once-per-scan discovery of sitemap.xml, robots.txt, and
    common OpenAPI document paths. Every fetch goes through the same
    same-origin, safety-hooked mechanism as page discovery -- no new
    network path is introduced. robots.txt is used purely as a source of
    additional same-origin paths to consider, never as evidence of a
    vulnerability by itself.

    ``cancellation_check`` is polled before each of the (up to) five
    auxiliary fetches this makes (sitemap, robots, up to three OpenAPI
    paths); once it returns True, discovery stops issuing further requests
    and returns whatever it has already collected."""

    if cancellation_check is None:
        cancellation_check = lambda: False

    candidates: list[AttackSurfaceCandidate] = []
    skipped: list[SkippedSurfaceItem] = []
    api_definitions_fetched = 0

    def _fetch(path: str):
        url = urljoin(_origin_base_url(target), path.lstrip("/"))
        return fetch_same_origin_page(
            target,
            url,
            policy=policy,
            before_request=before_request,
            after_request=after_request,
        )

    if cancellation_check():
        return AttackSurfaceDiscoveryResult(
            candidates=(), skipped=(SkippedSurfaceItem("cancelled", "sitemap"),),
            truncated=True,
        )

    sitemap_response = _fetch("/sitemap.xml")
    if sitemap_response is not None and sitemap_response.status == 200:
        body = sitemap_response.body[: budget.maximum_response_bytes]
        for match in re.findall(rb"<loc>([^<]+)</loc>", body):
            try:
                url = match.decode("utf-8", errors="replace")
            except LookupError:
                continue
            if not _same_origin(target, url):
                skipped.append(SkippedSurfaceItem("off_origin", url))
                continue
            parsed = urlsplit(url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query, keep_blank_values=True)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
            for name, values in params.items():
                candidates.append(
                    AttackSurfaceCandidate(
                        endpoint=base_url,
                        method="GET",
                        input_location=InputLocation.QUERY,
                        parameter=name,
                        baseline_value=values[0] if values else "",
                        content_type="",
                        source_page=url,
                        discovery_method=DiscoveryMethod.SITEMAP,
                        safety=SafetyClassification.SAFE_TO_PROBE,
                    )
                )
    else:
        skipped.append(SkippedSurfaceItem("sitemap_unavailable", "/sitemap.xml"))

    if cancellation_check():
        return AttackSurfaceDiscoveryResult(
            candidates=tuple(candidates),
            skipped=tuple(skipped) + (SkippedSurfaceItem("cancelled", "robots"),),
            truncated=True,
        )

    robots_response = _fetch("/robots.txt")
    if robots_response is not None and robots_response.status == 200:
        text = robots_response.body[: budget.maximum_response_bytes].decode(
            "utf-8", errors="replace"
        )
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.lower().startswith(("disallow:", "allow:")):
                continue
            _, _, path = stripped.partition(":")
            path = path.strip()
            if not path or path == "/":
                continue
            absolute = urljoin(
                _origin_base_url(target), path.lstrip("/")
            )
            if not _same_origin(target, absolute):
                skipped.append(SkippedSurfaceItem("off_origin", absolute))
                continue
            # robots.txt paths are discovery *input* only: recorded as an
            # UNSUPPORTED candidate (a path worth crawling later), never
            # treated as a parameterised, probeable candidate by itself.
            candidates.append(
                AttackSurfaceCandidate(
                    endpoint=absolute,
                    method="GET",
                    input_location=InputLocation.PATH,
                    parameter="",
                    baseline_value="",
                    content_type="",
                    source_page="/robots.txt",
                    discovery_method=DiscoveryMethod.ROBOTS_TXT,
                    safety=SafetyClassification.UNSUPPORTED,
                )
            )
    else:
        skipped.append(SkippedSurfaceItem("robots_unavailable", "/robots.txt"))

    for openapi_path in _OPENAPI_WELL_KNOWN_PATHS:
        if cancellation_check():
            skipped.append(SkippedSurfaceItem("cancelled", openapi_path))
            break
        if api_definitions_fetched >= budget.maximum_api_definitions:
            skipped.append(
                SkippedSurfaceItem(
                    "max_api_definitions_reached", openapi_path
                )
            )
            break
        response = _fetch(openapi_path)
        if response is None or response.status != 200:
            continue
        api_definitions_fetched += 1
        document_url = urljoin(_origin_base_url(target), openapi_path.lstrip("/"))
        new_candidates, new_skipped = _extract_openapi_candidates(
            target, document_url, response.body, budget
        )
        candidates.extend(new_candidates)
        skipped.extend(new_skipped)

    # Deterministic de-duplication across every source in this pass.
    deduped: list[AttackSurfaceCandidate] = []
    seen_ids: set[str] = set()
    for candidate in candidates:
        if candidate.candidate_id in seen_ids:
            skipped.append(SkippedSurfaceItem("duplicate", candidate.endpoint))
            continue
        seen_ids.add(candidate.candidate_id)
        deduped.append(candidate)
        if len(deduped) >= budget.maximum_endpoints:
            skipped.append(
                SkippedSurfaceItem("max_endpoints_reached", candidate.endpoint)
            )
            break

    return AttackSurfaceDiscoveryResult(
        candidates=tuple(deduped),
        skipped=tuple(skipped),
        truncated=len(deduped) < len(candidates),
    )


def merge_attack_surface_results(
    *results: AttackSurfaceDiscoveryResult,
    budget: AttackSurfaceBudget = AttackSurfaceBudget(),
) -> AttackSurfaceDiscoveryResult:
    """Combine multiple discovery passes (e.g. page-level + site-level)
    with one final, deterministic de-duplication and endpoint budget."""

    candidates: list[AttackSurfaceCandidate] = []
    skipped: list[SkippedSurfaceItem] = []
    seen_ids: set[str] = set()
    truncated = False

    for result in results:
        skipped.extend(result.skipped)
        truncated = truncated or result.truncated
        for candidate in result.candidates:
            if candidate.candidate_id in seen_ids:
                skipped.append(
                    SkippedSurfaceItem("duplicate", candidate.endpoint)
                )
                continue
            if len(candidates) >= budget.maximum_endpoints:
                truncated = True
                skipped.append(
                    SkippedSurfaceItem(
                        "max_endpoints_reached", candidate.endpoint
                    )
                )
                continue
            seen_ids.add(candidate.candidate_id)
            candidates.append(candidate)

    return AttackSurfaceDiscoveryResult(
        candidates=tuple(candidates), skipped=tuple(skipped), truncated=truncated
    )


def to_detection_candidates(
    result: AttackSurfaceDiscoveryResult,
) -> tuple[DetectionCandidate, ...]:
    """Project the SAFE_TO_PROBE, GET, query/form subset of a discovery
    result down to the narrow contract existing detectors understand.
    Everything else (POST forms, JSON bodies, anything state-changing or
    unsupported) is intentionally excluded here -- discovering it is not
    the same as authorizing a probe against it, and no current detector
    can represent those shapes safely regardless."""

    eligible: list[DetectionCandidate] = []
    for candidate in result.candidates:
        if candidate.safety is not SafetyClassification.SAFE_TO_PROBE:
            continue
        if candidate.method != "GET":
            continue
        if candidate.input_location not in (
            InputLocation.QUERY,
            InputLocation.FORM,
        ):
            continue
        if not candidate.parameter:
            continue
        eligible.append(
            DetectionCandidate(
                url=candidate.endpoint,
                parameter=candidate.parameter,
                method="GET",
                original_value=candidate.baseline_value,
            )
        )
    return tuple(eligible)


__all__ = [
    "AttackSurfaceBudget",
    "AttackSurfaceCandidate",
    "AttackSurfaceDiscoveryResult",
    "DiscoveryMethod",
    "InputLocation",
    "SafetyClassification",
    "SkippedSurfaceItem",
    "discover_page_attack_surface",
    "discover_site_attack_surface",
    "merge_attack_surface_results",
    "to_detection_candidates",
]
