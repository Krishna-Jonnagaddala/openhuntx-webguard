"""Common request-template and parameter-mutation layer (Slice 6).

Sits between attack-surface discovery and active detectors so a detector
never has to invent its own HTTP request/body construction for a new
transport shape:

    AttackSurfaceCandidate -> RequestTemplate -> mutate() -> MutatedRequest
        -> issue_templated_request() -> SafeHttpResponse

``RequestTemplate`` is a plain, serializable description of one request
shape (endpoint, method, content type, and its baseline query/form/JSON
parameter values). It deliberately carries no credentials: the
``authentication_context_ref`` field is an opaque reference for a future
protected runtime context to resolve, never a secret value itself, so
this model is safe to log or persist as-is.

Representable is not the same question as probeable. Building a
``RequestTemplate`` for a POST or JSON candidate, and being able to
``mutate()`` it, says nothing about whether any detector is authorized to
send it -- that is still governed entirely by the existing TrustScan
permit (``active_checks``, ``allowed_http_methods``), the runtime safety
engine's budgets/rate limits, and each candidate's own
``SafetyClassification`` from attack-surface discovery. Nothing in this
module bypasses any of that; it only adds the ability to *represent* and
*mutate* a wider set of request shapes than the GET-query-only
``active_detection.DetectionCandidate`` understands.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlencode, urlsplit

from .active_detection import (
    ActiveDetectionPolicy,
    DetectionCandidate,
    _build_probe_target,
    _require_same_origin,
)
from .attack_surface import (
    AttackSurfaceCandidate,
    AttackSurfaceDiscoveryResult,
    InputLocation,
    SafetyClassification,
)
from .authentication import AuthenticationMaterial, apply_authentication
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .safe_http import SafeHttpResponse, SafeRequestError, fetch_once
from .scope_validator import ValidatedTarget


def _utc_now() -> datetime:
    from datetime import timezone

    return datetime.now(timezone.utc)


class RequestTemplateError(RuntimeError):
    """Controlled failure raised by the request-template/mutation layer."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ContentType:
    NONE = ""
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    JSON = "application/json"
    # Named for readability only (Slice 13's XXE detector): mutate()
    # has no XML-body branch and never produces this content type;
    # nothing in this module validates against it, the same as the
    # three constants above it.
    XML = "application/xml"


@dataclass(frozen=True, slots=True)
class JsonMutationBudget:
    """Independent limits for parsing and mutating a JSON body -- separate
    from any detector's own probe-count budget."""

    maximum_depth: int = 6
    maximum_parameter_paths: int = 25
    maximum_string_length: int = 4096
    maximum_array_index: int = 20
    maximum_document_bytes: int = 65_536


DEFAULT_JSON_MUTATION_BUDGET = JsonMutationBudget()


@dataclass(frozen=True, slots=True)
class RequestTemplate:
    """A deterministic, serializable description of one request shape.

    Never carries secrets: ``authentication_context_ref`` is an opaque
    identifier a future protected runtime context resolves separately,
    not a credential value. ``path_parameters`` exists for forward
    compatibility (design-for, not implemented this slice) and is always
    empty today.
    """

    endpoint: str
    method: str
    content_type: str
    parameter: str = ""
    query_parameters: tuple[tuple[str, str], ...] = ()
    form_parameters: tuple[tuple[str, str], ...] = ()
    json_body: str = ""
    path_parameters: tuple[tuple[str, str], ...] = ()
    required_headers: tuple[tuple[str, str], ...] = ()
    source_candidate_id: str = ""
    safety: SafetyClassification = SafetyClassification.UNSUPPORTED
    authentication_context_ref: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str) or not self.endpoint.strip():
            raise RequestTemplateError(
                "request_template_endpoint_invalid",
                "A request template requires a non-empty endpoint.",
            )
        if not isinstance(self.method, str) or not self.method.strip():
            raise RequestTemplateError(
                "request_template_method_invalid",
                "A request template requires a non-empty method.",
            )
        object.__setattr__(self, "method", self.method.upper())


@dataclass(frozen=True, slots=True)
class MutatedRequest:
    """One fully-constructed, ready-to-send request produced by ``mutate``.

    Preserves every unrelated field of the originating template's
    baseline -- mutating one parameter never touches another.
    """

    url: str
    method: str
    content_type: str
    body: bytes
    parameter: str
    source_candidate_id: str = ""


# ---------------------------------------------------------------------------
# JSON parameter-path parsing and bounded traversal.
#
# Deterministic dotted/indexed paths: "email", "user.email",
# "profile.address.postcode", "items[0].name".
# ---------------------------------------------------------------------------

_NAME_TOKEN = re.compile(r"[^.\[\]]+")


def parse_json_parameter_path(path: str) -> tuple[str | int, ...]:
    """Parse "email", "user.email", "items[0].name" into ("email",),
    ("user", "email"), ("items", 0, "name"). A small explicit state
    machine rather than a single regex, so the "." separator between
    segments is itself accounted for -- a path like "a..b" or "a[x]"
    fails closed instead of silently skipping the bad character."""

    def _invalid() -> RequestTemplateError:
        return RequestTemplateError(
            "json_path_invalid", f"Malformed JSON parameter path: {path!r}"
        )

    if not isinstance(path, str) or not path:
        raise _invalid()

    segments: list[str | int] = []
    position = 0
    expect_name = True  # a bare name is only valid at position 0 or after "."

    while position < len(path):
        character = path[position]

        if character == "[":
            end = path.find("]", position)
            if end == -1:
                raise _invalid()
            index_text = path[position + 1 : end]
            if not index_text.isdigit():
                raise _invalid()
            segments.append(int(index_text))
            position = end + 1
            expect_name = False
            continue

        if character == ".":
            if expect_name:
                raise _invalid()
            position += 1
            expect_name = True
            continue

        if not expect_name:
            raise _invalid()

        match = _NAME_TOKEN.match(path, position)
        if match is None:
            raise _invalid()
        segments.append(match.group(0))
        position = match.end()
        expect_name = False

    if expect_name or not segments:
        raise _invalid()

    return tuple(segments)


def _get_json_value(document: Any, segments: tuple[str | int, ...]) -> Any:
    node = document
    for segment in segments:
        if isinstance(segment, str):
            if not isinstance(node, dict) or segment not in node:
                raise RequestTemplateError(
                    "json_path_not_found",
                    f"JSON path segment {segment!r} was not found in the document.",
                )
            node = node[segment]
        else:
            if not isinstance(node, list) or segment >= len(node):
                raise RequestTemplateError(
                    "json_path_not_found",
                    f"JSON array index {segment} is out of range.",
                )
            node = node[segment]
    return node


def _set_json_value(
    document: Any, segments: tuple[str | int, ...], value: Any
) -> Any:
    new_document = copy.deepcopy(document)
    node = new_document
    for segment in segments[:-1]:
        node = node[segment]
    last = segments[-1]
    if isinstance(last, str):
        if not isinstance(node, dict) or last not in node:
            raise RequestTemplateError(
                "json_path_not_found",
                f"JSON path segment {last!r} was not found in the document.",
            )
        node[last] = value
    else:
        if not isinstance(node, list) or last >= len(node):
            raise RequestTemplateError(
                "json_path_not_found",
                f"JSON array index {last} is out of range.",
            )
        node[last] = value
    return new_document


def load_bounded_json_document(
    text: str, *, budget: JsonMutationBudget = DEFAULT_JSON_MUTATION_BUDGET
) -> Any:
    """Parse a JSON document with explicit size, depth, and recursion
    protection. Raises RequestTemplateError on anything malformed or
    oversized rather than crashing or silently truncating."""

    if len(text.encode("utf-8")) > budget.maximum_document_bytes:
        raise RequestTemplateError(
            "json_document_too_large",
            "The JSON document exceeds the configured size limit.",
        )
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise RequestTemplateError(
            "json_document_malformed", "The JSON document could not be parsed."
        ) from exc

    _validate_json_depth(document, budget.maximum_depth)
    return document


def _validate_json_depth(node: Any, maximum_depth: int, depth: int = 0) -> None:
    if depth > maximum_depth:
        raise RequestTemplateError(
            "json_document_too_deep",
            "The JSON document exceeds the configured depth limit.",
        )
    if isinstance(node, dict):
        for value in node.values():
            _validate_json_depth(value, maximum_depth, depth + 1)
    elif isinstance(node, list):
        for value in node:
            _validate_json_depth(value, maximum_depth, depth + 1)


def enumerate_json_parameter_paths(
    document: Any, *, budget: JsonMutationBudget = DEFAULT_JSON_MUTATION_BUDGET
) -> tuple[str, ...]:
    """Deterministically enumerate bounded, mutable leaf paths in a JSON
    document (e.g. "user.email", "items[0].name"). Depth, array-index, and
    total-path-count limits prevent generating thousands of candidates
    from a large document. Only string/int/float/bool leaves are
    addressable -- null and unsupported types are skipped, not guessed at."""

    paths: list[str] = []

    def walk(node: Any, prefix: str, depth: int) -> None:
        if len(paths) >= budget.maximum_parameter_paths or depth > budget.maximum_depth:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if not isinstance(key, str):
                    continue
                if len(paths) >= budget.maximum_parameter_paths:
                    return
                walk(value, f"{prefix}.{key}" if prefix else key, depth + 1)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                if index >= budget.maximum_array_index:
                    break
                if len(paths) >= budget.maximum_parameter_paths:
                    return
                walk(value, f"{prefix}[{index}]", depth + 1)
        elif isinstance(node, (str, int, float, bool)) and prefix:
            paths.append(prefix)
        # None and any other type: unsupported for mutation, skipped.

    walk(document, "", 0)
    return tuple(paths)


# ---------------------------------------------------------------------------
# Building a RequestTemplate from discovery output.
# ---------------------------------------------------------------------------


def build_request_template(candidate: AttackSurfaceCandidate) -> RequestTemplate:
    """Project a Slice-5 AttackSurfaceCandidate into a RequestTemplate.

    Does not change or check safety classification -- that decision was
    already made by discovery and is carried through unchanged onto the
    resulting template.
    """

    if candidate.input_location in (InputLocation.QUERY, InputLocation.FORM) and (
        candidate.method == "GET"
    ):
        return RequestTemplate(
            endpoint=candidate.endpoint,
            method="GET",
            content_type=ContentType.NONE,
            parameter=candidate.parameter,
            query_parameters=((candidate.parameter, candidate.baseline_value),),
            source_candidate_id=candidate.candidate_id,
            safety=candidate.safety,
        )

    if candidate.input_location == InputLocation.FORM:
        return RequestTemplate(
            endpoint=candidate.endpoint,
            method=candidate.method,
            content_type=ContentType.FORM_URLENCODED,
            parameter=candidate.parameter,
            form_parameters=((candidate.parameter, candidate.baseline_value),),
            source_candidate_id=candidate.candidate_id,
            safety=candidate.safety,
        )

    if candidate.input_location == InputLocation.JSON_BODY:
        return RequestTemplate(
            endpoint=candidate.endpoint,
            method=candidate.method,
            content_type=ContentType.JSON,
            parameter=candidate.parameter,
            json_body=candidate.json_body_template,
            source_candidate_id=candidate.candidate_id,
            safety=candidate.safety,
        )

    raise RequestTemplateError(
        "request_template_unsupported_candidate",
        f"Cannot build a request template for input location "
        f"{candidate.input_location!r} and method {candidate.method!r}.",
    )


def request_template_from_detection_candidate(
    candidate: DetectionCandidate,
) -> RequestTemplate:
    """Bridge from the pre-Slice-6 GET-only DetectionCandidate contract,
    so existing detector call sites can adopt the mutation engine without
    every caller needing to already speak AttackSurfaceCandidate."""

    return RequestTemplate(
        endpoint=candidate.url,
        method="GET",
        content_type=ContentType.NONE,
        parameter=candidate.parameter,
        query_parameters=((candidate.parameter, candidate.original_value),),
        safety=SafetyClassification.SAFE_TO_PROBE,
    )


def to_request_templates(
    result: AttackSurfaceDiscoveryResult,
    *,
    allow_post: bool = False,
    allow_json: bool = False,
) -> tuple[RequestTemplate, ...]:
    """Project a wider slice of a discovery result into RequestTemplate
    objects than to_detection_candidates does: always the SAFE_TO_PROBE
    GET candidates (query/form), and -- only when the caller passes
    ``allow_post``/``allow_json`` -- REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION
    POST-form / JSON-body candidates.

    Callers must derive ``allow_post``/``allow_json`` from their own,
    already-established authorization -- in practice, whether the
    binding TrustScan permit's ``allowed_http_methods`` claim includes
    POST. This function performs no authorization check itself; it only
    answers "is this representable and does the caller assert it is
    authorized," never "is it authorized" on its own.

    POTENTIALLY_STATE_CHANGING and UNSUPPORTED candidates are never
    projected here regardless of the flags -- representability is not
    the same question as safety, and this function does not relax that
    tier under any argument.
    """

    templates: list[RequestTemplate] = []
    for candidate in result.candidates:
        if candidate.safety is SafetyClassification.SAFE_TO_PROBE:
            if candidate.method != "GET":
                continue
            templates.append(build_request_template(candidate))
            continue

        if candidate.safety is not SafetyClassification.REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION:
            continue

        if (
            allow_post
            and candidate.method == "POST"
            and candidate.input_location == InputLocation.FORM
        ):
            templates.append(build_request_template(candidate))
        elif allow_json and candidate.input_location == InputLocation.JSON_BODY:
            templates.append(build_request_template(candidate))

    return tuple(templates)


# ---------------------------------------------------------------------------
# Mutation.
# ---------------------------------------------------------------------------


def mutate(
    template: RequestTemplate,
    parameter: str,
    replacement: str,
    *,
    budget: JsonMutationBudget = DEFAULT_JSON_MUTATION_BUDGET,
) -> MutatedRequest:
    """Produce a new, bounded request with exactly one parameter's value
    replaced, preserving every other value on the template unchanged.

    Raises RequestTemplateError if ``parameter`` does not already exist on
    the template -- mutation never invents a new field, and never
    silently no-ops on a typo.
    """

    if template.content_type == ContentType.JSON:
        if not template.json_body:
            raise RequestTemplateError(
                "request_template_missing_json_body",
                "This template has no JSON body to mutate.",
            )
        document = load_bounded_json_document(template.json_body, budget=budget)
        segments = parse_json_parameter_path(parameter)
        _get_json_value(document, segments)  # existence check; fails closed
        mutated_document = _set_json_value(document, segments, replacement)
        body_text = json.dumps(mutated_document)
        if len(body_text.encode("utf-8")) > budget.maximum_document_bytes:
            raise RequestTemplateError(
                "json_document_too_large",
                "The mutated JSON document exceeds the configured size limit.",
            )
        return MutatedRequest(
            url=template.endpoint,
            method=template.method,
            content_type=ContentType.JSON,
            body=body_text.encode("utf-8"),
            parameter=parameter,
            source_candidate_id=template.source_candidate_id,
        )

    if template.content_type == ContentType.FORM_URLENCODED:
        fields = dict(template.form_parameters)
        if parameter not in fields:
            raise RequestTemplateError(
                "request_template_parameter_not_found",
                f"Form parameter {parameter!r} is not present on this template.",
            )
        fields[parameter] = replacement
        body_text = urlencode(fields)
        return MutatedRequest(
            url=template.endpoint,
            method=template.method,
            content_type=ContentType.FORM_URLENCODED,
            body=body_text.encode("utf-8"),
            parameter=parameter,
            source_candidate_id=template.source_candidate_id,
        )

    # Query-parameter (GET) request -- the only remaining supported shape.
    params = dict(template.query_parameters)
    if parameter not in params:
        raise RequestTemplateError(
            "request_template_parameter_not_found",
            f"Query parameter {parameter!r} is not present on this template.",
        )
    params[parameter] = replacement
    parsed = urlsplit(template.endpoint)
    query = urlencode(params)
    url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}?{query}"
    return MutatedRequest(
        url=url,
        method=template.method,
        content_type=ContentType.NONE,
        body=b"",
        parameter=parameter,
        source_candidate_id=template.source_candidate_id,
    )


def get_template_parameter_value(template: RequestTemplate, parameter: str) -> str:
    """Read a parameter's current baseline value from a template, across
    whichever transport it uses. A detector that wants to know the
    existing value before choosing its own baseline probe value (rather
    than always overwriting it) uses this instead of reaching into
    RequestTemplate's transport-specific fields directly."""

    if template.content_type == ContentType.JSON:
        if not template.json_body:
            raise RequestTemplateError(
                "request_template_missing_json_body",
                "This template has no JSON body to read.",
            )
        document = load_bounded_json_document(template.json_body)
        segments = parse_json_parameter_path(parameter)
        value = _get_json_value(document, segments)
        return "" if value is None else str(value)

    if template.content_type == ContentType.FORM_URLENCODED:
        fields = dict(template.form_parameters)
        if parameter not in fields:
            raise RequestTemplateError(
                "request_template_parameter_not_found",
                f"Form parameter {parameter!r} is not present on this template.",
            )
        return fields[parameter]

    params = dict(template.query_parameters)
    if parameter not in params:
        raise RequestTemplateError(
            "request_template_parameter_not_found",
            f"Query parameter {parameter!r} is not present on this template.",
        )
    return params[parameter]


def _template_baseline_body(template: RequestTemplate) -> bytes:
    if template.content_type == ContentType.JSON:
        return template.json_body.encode("utf-8") if template.json_body else b""
    if template.content_type == ContentType.FORM_URLENCODED:
        return urlencode(dict(template.form_parameters)).encode("utf-8")
    return b""


def _template_baseline_url(template: RequestTemplate) -> str:
    if template.content_type in (ContentType.JSON, ContentType.FORM_URLENCODED):
        return template.endpoint
    if not template.query_parameters:
        return template.endpoint
    parsed = urlsplit(template.endpoint)
    query = urlencode(dict(template.query_parameters))
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}?{query}"


# ---------------------------------------------------------------------------
# Issuing a request (baseline or mutated) through the same safety plumbing
# as the rest of active detection.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TemplatedProbeAttempt:
    """Structurally compatible with active_detection.ProbeAttempt (same
    requested_url/succeeded/error_code/response shape) so detector code
    can treat either transport identically once a response is in hand."""

    requested_url: str
    succeeded: bool
    error_code: str | None
    response: SafeHttpResponse | None


def issue_templated_request(
    base_target: ValidatedTarget,
    mutated: MutatedRequest,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    authentication_material: AuthenticationMaterial | None = None,
) -> TemplatedProbeAttempt:
    """Send exactly one bounded request for a MutatedRequest.

    Mirrors active_detection.issue_probe's same-origin enforcement and
    hook wiring exactly, generalized to any method/body this module
    supports. Runtime safety (budgets, rate limiting, permit
    revalidation, HTTP-method authorization) is entirely the caller's
    hooks' responsibility, unchanged from every other active probe.

    ``authentication_material`` (Slice 7): see
    ``active_detection.issue_probe``.
    """

    _require_same_origin(base_target, mutated.url)
    probe_target = _build_probe_target(base_target, mutated.url)
    extra_headers = apply_authentication(
        mutated.url, authentication_material, now=_utc_now()
    )

    if before_request is not None:
        before_request(probe_target, mutated.method)

    try:
        response = fetch_once(
            probe_target,
            method=mutated.method,
            policy=policy.fetch_policy,
            body=mutated.body,
            content_type=mutated.content_type,
            extra_headers=extra_headers,
        )
    except SafeRequestError as exc:
        if after_request is not None:
            after_request(probe_target, mutated.method, None, exc.code)
        return TemplatedProbeAttempt(
            requested_url=mutated.url,
            succeeded=False,
            error_code=exc.code,
            response=None,
        )

    if after_request is not None:
        after_request(probe_target, mutated.method, response, None)

    return TemplatedProbeAttempt(
        requested_url=mutated.url,
        succeeded=True,
        error_code=None,
        response=response,
    )


# ---------------------------------------------------------------------------
# First-class baseline execution.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BaselineObservation:
    """Bounded, non-sensitive characteristics of one baseline request.
    Never stores a complete response body -- content_fingerprint is a
    SHA-256 digest, sufficient to detect that a later response differs
    without retaining what it contained."""

    status: int
    response_length: int
    selected_headers: tuple[tuple[str, str], ...]
    content_fingerprint: str
    elapsed_milliseconds: int


_BASELINE_HEADER_ALLOWLIST = frozenset({"content-type", "server", "cache-control"})


def _selected_headers(
    headers: tuple[tuple[str, str], ...]
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (name, value)
        for name, value in headers
        if name.lower() in _BASELINE_HEADER_ALLOWLIST
    )


def execute_baseline(
    base_target: ValidatedTarget,
    template: RequestTemplate,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    authentication_material: AuthenticationMaterial | None = None,
) -> BaselineObservation | None:
    """Issue exactly one request using a template's own, unmutated
    baseline values and record bounded response characteristics.

    Returns None on any request failure -- a missing baseline is recorded
    as "no observation," never fabricated, and is never itself treated as
    a detection outcome by this function (callers decide what a missing
    baseline means for their own methodology).

    ``authentication_material`` (Slice 7): see
    ``active_detection.issue_probe``.
    """

    url = _template_baseline_url(template)
    body = _template_baseline_body(template)

    _require_same_origin(base_target, url)
    probe_target = _build_probe_target(base_target, url)
    extra_headers = apply_authentication(
        url, authentication_material, now=_utc_now()
    )

    if before_request is not None:
        before_request(probe_target, template.method)

    try:
        response = fetch_once(
            probe_target,
            method=template.method,
            policy=policy.fetch_policy,
            body=body,
            content_type=template.content_type,
            extra_headers=extra_headers,
        )
    except SafeRequestError as exc:
        if after_request is not None:
            after_request(probe_target, template.method, None, exc.code)
        return None

    if after_request is not None:
        after_request(probe_target, template.method, response, None)

    return BaselineObservation(
        status=response.status,
        response_length=len(response.body),
        selected_headers=_selected_headers(response.headers),
        content_fingerprint=hashlib.sha256(response.body).hexdigest(),
        elapsed_milliseconds=response.elapsed_milliseconds,
    )


__all__ = [
    "BaselineObservation",
    "ContentType",
    "DEFAULT_JSON_MUTATION_BUDGET",
    "JsonMutationBudget",
    "MutatedRequest",
    "RequestTemplate",
    "RequestTemplateError",
    "TemplatedProbeAttempt",
    "build_request_template",
    "enumerate_json_parameter_paths",
    "execute_baseline",
    "get_template_parameter_value",
    "issue_templated_request",
    "load_bounded_json_document",
    "mutate",
    "parse_json_parameter_path",
    "request_template_from_detection_candidate",
    "to_request_templates",
]
