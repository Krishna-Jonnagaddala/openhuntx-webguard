"""Bounded passive HTML security analysis for OpenHuntX WebGuard."""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlsplit

from webguard_contracts import (
    Confidence,
    Evidence,
    ExternalIdentifier,
    FindingIdentity,
    NormalizedFinding,
    Severity,
)

from .safe_http import SafeHttpResponse
from .scope_validator import ValidatedTarget


_SOURCE = "webguard-passive"
_SOURCE_RULE_PREFIX = "HTML"

MAXIMUM_HTML_ANALYSIS_BYTES = 1_048_576
MAXIMUM_HTML_ELEMENTS = 20_000
MAXIMUM_HTML_FORMS = 256
MAXIMUM_HTML_REFERENCES = 4_096
MAXIMUM_HTML_META_REFRESHES = 128
MAXIMUM_HTML_COMMENTS = 512
MAXIMUM_HTML_COMMENT_CHARACTERS = 65_536
MAXIMUM_HTML_VISIBLE_TEXT_CHARACTERS = 262_144

HTML_CHECKS = (
    "web.html.debug_exposure",
    "web.html.directory_listing",
    "web.html.form_action",
    "web.html.insecure_subresource",
    "web.html.meta_refresh",
    "web.html.mixed_active_content",
    "web.html.password_method",
    "web.html.password_transport",
    "web.html.sensitive_comment",
)

_HTML_MIME_TYPES = frozenset(
    {
        "application/xhtml+xml",
        "text/html",
    }
)

_HTML_SNIFF_PREFIXES = (
    b"<!doctype html",
    b"<html",
    b"<head",
    b"<body",
)

_META_REFRESH_URL = re.compile(
    r"(?:^|;)\s*url\s*=\s*(?P<quote>['\"]?)(?P<url>.*?)\1\s*$",
    re.IGNORECASE,
)

_DIRECTORY_TITLE = re.compile(
    r"^\s*(?:index of(?:\s+/.*)?|directory listing for(?:\s+/.*)?)\s*$",
    re.IGNORECASE,
)

_SECRET_COMMENT_PATTERNS = (
    ("password assignment", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]", re.I)),
    ("secret assignment", re.compile(r"\bsecret\s*[:=]", re.I)),
    ("API key assignment", re.compile(r"\bapi[_ -]?key\s*[:=]", re.I)),
    ("access token assignment", re.compile(r"\baccess[_ -]?token\s*[:=]", re.I)),
    ("private key marker", re.compile(r"(?:begin\s+(?:rsa\s+)?private\s+key|private[_ -]?key\s*[:=])", re.I)),
)

_DEVELOPMENT_COMMENT_PATTERNS = (
    ("TODO marker", re.compile(r"\bTODO\b", re.I)),
    ("FIXME marker", re.compile(r"\bFIXME\b", re.I)),
    ("debug marker", re.compile(r"\bDEBUG\b", re.I)),
    ("development hack marker", re.compile(r"\bHACK\b", re.I)),
    ("localhost reference", re.compile(r"\blocalhost(?::\d{1,5})?\b", re.I)),
    ("loopback reference", re.compile(r"\b127\.0\.0\.1\b")),
    ("staging host marker", re.compile(r"\bstaging(?:[.-][a-z0-9-]+)?\b", re.I)),
)


class HtmlAnalysisError(RuntimeError):
    """Controlled failure raised for bounded or inconsistent HTML input."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(slots=True)
class _FormRecord:
    method: str
    action: str
    has_password: bool = False


@dataclass(frozen=True, slots=True)
class _ReferenceRecord:
    kind: str
    value: str


class _BoundedHtmlParser(HTMLParser):
    """Collect only non-secret structural facts from one bounded document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.element_count = 0
        self.forms: list[_FormRecord] = []
        self._form_stack: list[int] = []
        self.references: list[_ReferenceRecord] = []
        self.meta_refreshes: list[str] = []
        self.secret_comment_markers: set[str] = set()
        self.development_comment_markers: set[str] = set()
        self.comment_count = 0
        self.comment_characters = 0
        self.visible_text_characters = 0
        self._visible_text: list[str] = []
        self._title_text: list[str] = []
        self._title_depth = 0
        self._suppressed_text_depth = 0

    @property
    def visible_text(self) -> str:
        return " ".join(self._visible_text)

    @property
    def title_text(self) -> str:
        return " ".join(self._title_text)

    def _limit(self, condition: bool, code: str, message: str) -> None:
        if condition:
            raise HtmlAnalysisError(code, message)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.element_count += 1
        self._limit(
            self.element_count > MAXIMUM_HTML_ELEMENTS,
            "html_element_limit_exceeded",
            "The HTML element limit was exceeded.",
        )

        tag_name = tag.lower()
        attributes = {
            name.lower(): (value or "").strip()
            for name, value in attrs
            if name
        }

        if tag_name in {"script", "style"}:
            self._suppressed_text_depth += 1

        if tag_name == "title":
            self._title_depth += 1

        if tag_name == "form":
            self._limit(
                len(self.forms) >= MAXIMUM_HTML_FORMS,
                "html_form_limit_exceeded",
                "The HTML form limit was exceeded.",
            )
            record = _FormRecord(
                method=(attributes.get("method") or "GET").upper(),
                action=attributes.get("action", ""),
            )
            self.forms.append(record)
            self._form_stack.append(len(self.forms) - 1)

        elif tag_name == "input" and self._form_stack:
            if attributes.get("type", "text").lower() == "password":
                self.forms[self._form_stack[-1]].has_password = True

        if tag_name == "meta":
            if attributes.get("http-equiv", "").lower() == "refresh":
                self._limit(
                    len(self.meta_refreshes) >= MAXIMUM_HTML_META_REFRESHES,
                    "html_meta_refresh_limit_exceeded",
                    "The HTML meta-refresh limit was exceeded.",
                )
                self.meta_refreshes.append(attributes.get("content", ""))

        reference: _ReferenceRecord | None = None

        if tag_name == "script" and attributes.get("src"):
            reference = _ReferenceRecord("script", attributes["src"])
        elif tag_name == "link" and attributes.get("href"):
            rel_tokens = {
                token.lower()
                for token in attributes.get("rel", "").split()
            }
            as_value = attributes.get("as", "").lower()
            if "stylesheet" in rel_tokens:
                reference = _ReferenceRecord("stylesheet", attributes["href"])
            elif (
                rel_tokens.intersection({"preload", "modulepreload"})
                and as_value in {"script", "style"}
            ):
                reference = _ReferenceRecord(
                    "script" if as_value == "script" else "stylesheet",
                    attributes["href"],
                )
        elif tag_name == "iframe" and attributes.get("src"):
            reference = _ReferenceRecord("iframe", attributes["src"])
        elif tag_name == "embed" and attributes.get("src"):
            reference = _ReferenceRecord("embed", attributes["src"])
        elif tag_name == "object" and attributes.get("data"):
            reference = _ReferenceRecord("object", attributes["data"])

        if reference is not None:
            self._limit(
                len(self.references) >= MAXIMUM_HTML_REFERENCES,
                "html_reference_limit_exceeded",
                "The HTML resource-reference limit was exceeded.",
            )
            self.references.append(reference)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()

        if tag_name == "form" and self._form_stack:
            self._form_stack.pop()

        if tag_name == "title" and self._title_depth:
            self._title_depth -= 1

        if tag_name in {"script", "style"} and self._suppressed_text_depth:
            self._suppressed_text_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._suppressed_text_depth:
            return

        cleaned = " ".join(data.split())
        if not cleaned:
            return

        self.visible_text_characters += len(cleaned)
        self._limit(
            self.visible_text_characters > MAXIMUM_HTML_VISIBLE_TEXT_CHARACTERS,
            "html_text_limit_exceeded",
            "The visible HTML text limit was exceeded.",
        )
        self._visible_text.append(cleaned)

        if self._title_depth:
            self._title_text.append(cleaned)

    def handle_comment(self, data: str) -> None:
        self.comment_count += 1
        self.comment_characters += len(data)
        self._limit(
            self.comment_count > MAXIMUM_HTML_COMMENTS,
            "html_comment_limit_exceeded",
            "The HTML comment-count limit was exceeded.",
        )
        self._limit(
            self.comment_characters > MAXIMUM_HTML_COMMENT_CHARACTERS,
            "html_comment_text_limit_exceeded",
            "The HTML comment-text limit was exceeded.",
        )

        for label, pattern in _SECRET_COMMENT_PATTERNS:
            if pattern.search(data):
                self.secret_comment_markers.add(label)

        for label, pattern in _DEVELOPMENT_COMMENT_PATTERNS:
            if pattern.search(data):
                self.development_comment_markers.add(label)


def _header_values(
    headers: Iterable[tuple[str, str]],
    expected_name: str,
) -> tuple[str, ...]:
    expected = expected_name.lower()
    return tuple(
        value.strip()
        for name, value in headers
        if name.strip().lower() == expected
    )


def _content_type(response: SafeHttpResponse) -> str | None:
    values = _header_values(response.headers, "content-type")
    if not values:
        return None
    return values[0].split(";", 1)[0].strip().lower() or None


def _charset(response: SafeHttpResponse) -> str:
    values = _header_values(response.headers, "content-type")
    if values:
        for part in values[0].split(";")[1:]:
            name, separator, value = part.partition("=")
            if separator and name.strip().lower() == "charset":
                candidate = value.strip().strip("'\"").lower()
                if candidate in {
                    "ascii",
                    "iso-8859-1",
                    "latin-1",
                    "utf-8",
                    "utf8",
                    "windows-1252",
                }:
                    return "utf-8" if candidate == "utf8" else candidate
    return "utf-8"


def _is_html_response(response: SafeHttpResponse) -> bool:
    mime_type = _content_type(response)
    if mime_type is not None:
        return mime_type in _HTML_MIME_TYPES

    prefix = response.body.lstrip()[:64].lower()
    return any(prefix.startswith(item) for item in _HTML_SNIFF_PREFIXES)


def _origin_and_path(target: ValidatedTarget) -> tuple[str, str]:
    parsed = urlsplit(target.normalised_url)

    if parsed.scheme != target.scheme or parsed.hostname != target.hostname:
        raise HtmlAnalysisError(
            "validated_target_mismatch",
            "Validated target fields do not match normalised_url.",
        )

    default_port = 443 if target.scheme == "https" else 80
    try:
        port = parsed.port or default_port
    except ValueError as exc:
        raise HtmlAnalysisError(
            "validated_target_mismatch",
            "The validated target URL contains an invalid port.",
        ) from exc

    if port != target.port:
        raise HtmlAnalysisError(
            "validated_target_mismatch",
            "Validated target port does not match normalised_url.",
        )

    hostname = target.hostname
    formatted_hostname = f"[{hostname}]" if ":" in hostname else hostname
    origin = (
        f"{target.scheme}://{formatted_hostname}"
        if port == default_port
        else f"{target.scheme}://{formatted_hostname}:{port}"
    )
    return origin, parsed.path or "/"


def _canonical_origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if scheme not in {"http", "https"} or hostname is None:
        return None

    return (
        scheme,
        hostname.lower().rstrip("."),
        port or (443 if scheme == "https" else 80),
    )


def _resolved_http_url(base_url: str, reference: str) -> str | None:
    cleaned = reference.strip()
    if not cleaned:
        return None

    try:
        resolved = urljoin(base_url, cleaned)
    except ValueError:
        return None

    return resolved if _canonical_origin(resolved) is not None else None


def _insecure_http_reference(base_url: str, reference: str) -> bool:
    resolved = _resolved_http_url(base_url, reference)
    return resolved is not None and urlsplit(resolved).scheme.lower() == "http"


def _cross_origin_action(target: ValidatedTarget, action: str) -> bool:
    resolved = _resolved_http_url(target.normalised_url, action)
    if resolved is None:
        return False
    return _canonical_origin(resolved) != _canonical_origin(target.normalised_url)


def _meta_refresh_target(content: str, base_url: str) -> str | None:
    match = _META_REFRESH_URL.search(content)
    if match is None:
        return None
    return _resolved_http_url(base_url, match.group("url").strip())


def _debug_signatures(text: str) -> tuple[str, ...]:
    lowered = text.lower()
    signatures: set[str] = set()

    if (
        "traceback (most recent call last)" in lowered
        and "line " in lowered
    ):
        signatures.add("Python traceback")

    if (
        "django version:" in lowered
        and "exception type:" in lowered
    ) or "debug = true" in lowered and "django" in lowered:
        signatures.add("Django debug page")

    if (
        "werkzeug debugger" in lowered
        or "the debugger caught an exception" in lowered
    ):
        signatures.add("Werkzeug debugger")

    if (
        "whoops, looks like something went wrong" in lowered
        and "stack trace" in lowered
    ):
        signatures.add("Laravel debug page")

    if (
        "server error in '/' application" in lowered
        and "stack trace:" in lowered
    ):
        signatures.add("ASP.NET error page")

    if (
        "java.lang." in lowered
        and "exception" in lowered
        and " at " in lowered
    ):
        signatures.add("Java exception trace")

    if re.search(
        r"\b(?:typeerror|referenceerror|syntaxerror|rangeerror|error):"
        r".{0,300}\s+at\s+\S",
        text,
        re.IGNORECASE,
    ):
        signatures.add("JavaScript stack trace")

    return tuple(sorted(signatures))


def _directory_listing_detected(title: str, visible_text: str) -> bool:
    if _DIRECTORY_TITLE.fullmatch(title.strip()):
        return True

    lowered = visible_text.lower()
    return (
        "parent directory" in lowered
        and "last modified" in lowered
        and "size" in lowered
    ) or (
        "directory listing for" in lowered
        and "parent directory" in lowered
    )


def _finding(
    *,
    target: ValidatedTarget,
    rule_id: str,
    source_rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    confidence: Confidence,
    remediation: str,
    evidence_summary: str,
    parameter: str | None = None,
    identifiers: tuple[ExternalIdentifier, ...] = (),
    references: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
) -> NormalizedFinding:
    origin, path = _origin_and_path(target)
    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule_id,
            asset=origin,
            path=path,
            method="GET",
            parameter=parameter,
        ),
        source=_SOURCE,
        source_rule_id=f"{_SOURCE_RULE_PREFIX}-{source_rule_id}",
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        remediation=remediation,
        identifiers=identifiers,
        evidence=(Evidence(evidence_summary),),
        references=references,
        tags=("html", "passive") + tags,
    )


def analyze_html_security(
    target: ValidatedTarget,
    response: SafeHttpResponse,
) -> tuple[NormalizedFinding, ...]:
    """Analyse one bounded HTML response without executing or submitting it."""

    _origin_and_path(target)

    if not isinstance(response.body, bytes):
        raise HtmlAnalysisError(
            "html_body_invalid",
            "The HTML response body must be bytes.",
        )

    if len(response.body) > MAXIMUM_HTML_ANALYSIS_BYTES:
        raise HtmlAnalysisError(
            "html_body_limit_exceeded",
            "The response body exceeds the passive HTML analysis limit.",
        )

    if not _is_html_response(response):
        return ()

    try:
        document = response.body.decode(_charset(response), errors="replace")
    except (LookupError, UnicodeError) as exc:
        raise HtmlAnalysisError(
            "html_decode_failed",
            "The HTML response could not be decoded safely.",
        ) from exc

    parser = _BoundedHtmlParser()
    try:
        parser.feed(document)
        parser.close()
    except HtmlAnalysisError:
        raise
    except Exception as exc:
        raise HtmlAnalysisError(
            "html_parse_failed",
            "The HTML response could not be parsed safely.",
        ) from exc

    findings: list[NormalizedFinding] = []
    target_origin = _canonical_origin(target.normalised_url)

    for index, form in enumerate(parser.forms, start=1):
        parameter = f"form:{index}"

        if form.has_password and target.scheme == "http":
            findings.append(
                _finding(
                    target=target,
                    parameter=parameter,
                    rule_id="web.html.password_transport.insecure",
                    source_rule_id="001",
                    title="Password form is served over unencrypted HTTP",
                    description=(
                        "A password control is present on a page delivered over "
                        "HTTP. Credentials entered into the form can be exposed "
                        "or modified in transit."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        "Serve the page and all authentication flows exclusively "
                        "over HTTPS, redirect HTTP to HTTPS, and deploy HSTS after "
                        "confirming complete HTTPS coverage."
                    ),
                    evidence_summary=(
                        "A password control was observed in this form on an HTTP "
                        "page. Field names and values were not retained."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-319"),),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ),
                    tags=("forms", "password", "transport-security"),
                )
            )

        if form.has_password and form.method == "GET":
            findings.append(
                _finding(
                    target=target,
                    parameter=parameter,
                    rule_id="web.html.password_method.get",
                    source_rule_id="002",
                    title="Password form uses the GET method",
                    description=(
                        "The password form uses GET, which can place submitted "
                        "values in URLs, browser history, logs, analytics, and "
                        "referrer data."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        "Submit authentication forms with POST over HTTPS and "
                        "ensure credentials are never placed in URLs."
                    ),
                    evidence_summary=(
                        "A password control was observed in a form whose method "
                        "is GET. Field names and values were not retained."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-598"),),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ),
                    tags=("forms", "password", "get-method"),
                )
            )

        if form.action and _cross_origin_action(target, form.action):
            findings.append(
                _finding(
                    target=target,
                    parameter=parameter,
                    rule_id="web.html.form_action.cross_origin",
                    source_rule_id="003",
                    title="Form submits to a different origin",
                    description=(
                        "The form action resolves to a different HTTP(S) origin. "
                        "Users may submit form data to infrastructure outside the "
                        "page origin."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        "Confirm that the destination is required and trusted. "
                        "Prefer same-origin submission and protect unavoidable "
                        "cross-origin workflows with clear user intent and strict "
                        "destination control."
                    ),
                    evidence_summary=(
                        "A cross-origin HTTP(S) form action was observed. The "
                        "destination path, query, and form values were not retained."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-200"),),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ),
                    tags=("forms", "cross-origin"),
                )
            )

    for index, reference in enumerate(parser.references, start=1):
        parameter = f"{reference.kind}:{index}"
        if target.scheme != "https" or not _insecure_http_reference(
            target.normalised_url,
            reference.value,
        ):
            continue

        if reference.kind in {"script", "stylesheet"}:
            findings.append(
                _finding(
                    target=target,
                    parameter=parameter,
                    rule_id=(
                        "web.html.insecure_subresource.script"
                        if reference.kind == "script"
                        else "web.html.insecure_subresource.stylesheet"
                    ),
                    source_rule_id=("004" if reference.kind == "script" else "005"),
                    title=(
                        "HTTPS page loads a script over HTTP"
                        if reference.kind == "script"
                        else "HTTPS page loads a stylesheet over HTTP"
                    ),
                    description=(
                        "The HTTPS page references an active subresource over "
                        "unencrypted HTTP. A network attacker could alter the "
                        "resource and affect page behaviour or presentation."
                    ),
                    severity=(
                        Severity.HIGH
                        if reference.kind == "script"
                        else Severity.MEDIUM
                    ),
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        "Load the resource from a trusted HTTPS origin and remove "
                        "all HTTP fallbacks from the page and build pipeline."
                    ),
                    evidence_summary=(
                        f"An HTTP {reference.kind} reference was observed on an "
                        "HTTPS page. The full resource URL was not retained."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-319"),),
                    references=(
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                    ),
                    tags=("mixed-content", reference.kind),
                )
            )
        elif reference.kind in {"iframe", "embed", "object"}:
            findings.append(
                _finding(
                    target=target,
                    parameter=parameter,
                    rule_id=f"web.html.mixed_active_content.{reference.kind}",
                    source_rule_id="006",
                    title="HTTPS page includes mixed active content",
                    description=(
                        "The HTTPS page embeds active content over HTTP. The "
                        "embedded content can be modified in transit and may "
                        "undermine the security of the HTTPS page."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        "Remove the HTTP reference or migrate the embedded "
                        "resource to a trusted HTTPS endpoint."
                    ),
                    evidence_summary=(
                        f"An HTTP {reference.kind} reference was observed on an "
                        "HTTPS page. The full resource URL was not retained."
                    ),
                    identifiers=(ExternalIdentifier("CWE", "CWE-319"),),
                    references=(
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                    ),
                    tags=("mixed-content", reference.kind),
                )
            )

    for index, content in enumerate(parser.meta_refreshes, start=1):
        destination = _meta_refresh_target(content, target.normalised_url)
        if destination is None:
            continue

        destination_origin = _canonical_origin(destination)
        cross_origin = destination_origin != target_origin
        insecure = (
            target.scheme == "https"
            and urlsplit(destination).scheme.lower() == "http"
        )

        findings.append(
            _finding(
                target=target,
                parameter=f"meta-refresh:{index}",
                rule_id=(
                    "web.html.meta_refresh.insecure"
                    if insecure
                    else (
                        "web.html.meta_refresh.external"
                        if cross_origin
                        else "web.html.meta_refresh.redirect"
                    )
                ),
                source_rule_id="007",
                title=(
                    "Meta refresh redirects from HTTPS to HTTP"
                    if insecure
                    else (
                        "Meta refresh redirects to another origin"
                        if cross_origin
                        else "Meta refresh redirect is present"
                    )
                ),
                description=(
                    "The page uses a meta refresh instruction to navigate the "
                    "browser. Automatic refresh redirects can obscure navigation "
                    "and are harder to govern than normal HTTP redirects."
                ),
                severity=(
                    Severity.MEDIUM
                    if insecure or cross_origin
                    else Severity.LOW
                ),
                confidence=Confidence.CONFIRMED,
                remediation=(
                    "Replace meta refresh navigation with an explicit, validated "
                    "server-side redirect or a user-initiated link. Keep all "
                    "destinations on HTTPS."
                ),
                evidence_summary=(
                    "A meta refresh redirect was observed. The destination path "
                    "and query were not retained."
                ),
                references=(
                    "https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta",
                ),
                tags=("redirect", "meta-refresh"),
            )
        )

    if _directory_listing_detected(parser.title_text, parser.visible_text):
        findings.append(
            _finding(
                target=target,
                parameter="response-body",
                rule_id="web.html.directory_listing.exposed",
                source_rule_id="008",
                title="Directory listing appears to be exposed",
                description=(
                    "The HTML response contains strong directory-index markers. "
                    "Directory listings can reveal files, backup artifacts, and "
                    "application structure."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                remediation=(
                    "Disable automatic directory indexing and explicitly serve "
                    "only intended files. Review the directory for sensitive or "
                    "obsolete artifacts."
                ),
                evidence_summary=(
                    "Directory-index title or listing markers were observed. "
                    "File names and links were not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-548"),),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ),
                tags=("directory-listing", "information-disclosure"),
            )
        )

    debug_signatures = _debug_signatures(parser.visible_text)
    if debug_signatures:
        findings.append(
            _finding(
                target=target,
                parameter="response-body",
                rule_id="web.html.debug_exposure.stack_trace",
                source_rule_id="009",
                title="Application debug output or stack trace is exposed",
                description=(
                    "The response contains a high-confidence framework debug or "
                    "stack-trace signature. Debug output can disclose internal "
                    "paths, component versions, and implementation details."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                remediation=(
                    "Disable production debug pages, return generic error "
                    "responses, and record detailed exceptions only in protected "
                    "server-side logs."
                ),
                evidence_summary=(
                    "Observed debug signature category or categories: "
                    + ", ".join(debug_signatures)
                    + ". Raw stack-trace text was not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-209"),),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ),
                tags=("debug", "stack-trace", "information-disclosure"),
            )
        )

    if parser.secret_comment_markers:
        findings.append(
            _finding(
                target=target,
                parameter="html-comments:secret-markers",
                rule_id="web.html.sensitive_comment.secret_marker",
                source_rule_id="010",
                title="HTML comment contains a sensitive-data marker",
                description=(
                    "A source comment contains a marker commonly associated with "
                    "credentials, secrets, tokens, or private keys. The marker "
                    "does not prove that a live secret is present, but the source "
                    "should be reviewed."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                remediation=(
                    "Remove sensitive comments from production output, rotate any "
                    "exposed credentials, and prevent secrets from entering built "
                    "HTML artifacts."
                ),
                evidence_summary=(
                    "Observed comment marker category or categories: "
                    + ", ".join(sorted(parser.secret_comment_markers))
                    + ". Comment text and candidate values were not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-615"),),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ),
                tags=("comments", "sensitive-data"),
            )
        )

    if parser.development_comment_markers:
        findings.append(
            _finding(
                target=target,
                parameter="html-comments:development-markers",
                rule_id="web.html.sensitive_comment.development_marker",
                source_rule_id="011",
                title="HTML comment contains a development marker",
                description=(
                    "A source comment contains a development, debugging, local, "
                    "or staging marker that may reveal internal workflow details."
                ),
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                remediation=(
                    "Review production HTML generation and remove unnecessary "
                    "development comments and internal environment references."
                ),
                evidence_summary=(
                    "Observed development marker category or categories: "
                    + ", ".join(sorted(parser.development_comment_markers))
                    + ". Comment text was not retained."
                ),
                identifiers=(ExternalIdentifier("CWE", "CWE-615"),),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ),
                tags=("comments", "development-marker"),
            )
        )

    return tuple(
        sorted(
            findings,
            key=lambda item: (
                item.identity.rule_id,
                item.identity.parameter or "",
            ),
        )
    )


__all__ = [
    "HTML_CHECKS",
    "HtmlAnalysisError",
    "MAXIMUM_HTML_ANALYSIS_BYTES",
    "MAXIMUM_HTML_COMMENTS",
    "MAXIMUM_HTML_ELEMENTS",
    "MAXIMUM_HTML_FORMS",
    "MAXIMUM_HTML_META_REFRESHES",
    "MAXIMUM_HTML_REFERENCES",
    "MAXIMUM_HTML_VISIBLE_TEXT_CHARACTERS",
    "analyze_html_security",
]
