"""Discover GET-form active-detection candidates from one HTML page.

Deliberately independent from html_analyzer.py's internal parser: this
module only needs form method/action/field names (not the full passive
security-check surface), and keeping it separate avoids adding any risk to
the already-audited passive HTML analyzer. It has its own, tighter bounds.

Only same-origin GET forms are considered. Only field types that
represent free-text-ish user input (text/search/email/url/tel/absent-type
inputs, textarea, select) become candidates; password, file, hidden,
checkbox, radio, submit, and button fields are excluded -- either because
injecting into them is not a meaningful reflected-XSS probe, or because
doing so risks unintended side effects (hidden fields sometimes carry
CSRF-adjacent state that should not be tampered with).
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .active_detection import DetectionCandidate
from .scope_validator import ValidatedTarget

MAXIMUM_DISCOVERED_FORMS = 5
MAXIMUM_FIELDS_PER_FORM = 5
MAXIMUM_DISCOVERED_CANDIDATES = 15
MAXIMUM_DISCOVERY_HTML_BYTES = 2 * 1024 * 1024

_INJECTABLE_INPUT_TYPES = frozenset(
    {"text", "search", "email", "url", "tel", ""}
)
_INJECTABLE_TAGS = frozenset({"textarea", "select"})


@dataclass(slots=True)
class _FormState:
    method: str
    action: str
    fields: list[str]


class _BoundedFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_FormState] = []
        self._form_stack: list[int] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        tag_name = tag.lower()
        attributes = {
            name.lower(): (value or "") for name, value in attrs if name
        }

        if tag_name == "form":
            if len(self.forms) >= MAXIMUM_DISCOVERED_FORMS:
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
        if len(form.fields) >= MAXIMUM_FIELDS_PER_FORM:
            return

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
        if tag.lower() == "form" and self._form_stack:
            self._form_stack.pop()


def discover_get_form_candidates(
    target: ValidatedTarget,
    page_url: str,
    html_body: bytes,
) -> tuple[DetectionCandidate, ...]:
    """Return same-origin GET-form candidates discovered on one page.

    ``page_url`` is the URL the HTML was actually fetched from (used to
    resolve relative form actions). Candidates whose resolved action falls
    off ``target``'s origin are silently dropped, not raised -- the caller
    is expected to run many pages through this function and only wants the
    in-scope subset.
    """

    if len(html_body) > MAXIMUM_DISCOVERY_HTML_BYTES:
        return ()

    try:
        text = html_body.decode("utf-8", errors="replace")
    except LookupError:
        return ()

    parser = _BoundedFormParser()
    try:
        parser.feed(text)
    except Exception:
        return ()

    candidates: list[DetectionCandidate] = []
    seen: set[tuple[str, str]] = set()

    for form in parser.forms:
        if form.method != "GET" or not form.fields:
            continue

        action_url = urljoin(page_url, form.action or page_url)
        parsed_action = urlsplit(action_url)
        port = parsed_action.port
        if port is None:
            port = 443 if parsed_action.scheme == "https" else 80

        if (
            parsed_action.scheme != target.scheme
            or (parsed_action.hostname or "").lower() != target.hostname
            or port != target.port
        ):
            continue

        for field_name in form.fields:
            key = (action_url, field_name)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                DetectionCandidate(url=action_url, parameter=field_name)
            )
            if len(candidates) >= MAXIMUM_DISCOVERED_CANDIDATES:
                return tuple(candidates)

    return tuple(candidates)


__all__ = [
    "MAXIMUM_DISCOVERED_CANDIDATES",
    "MAXIMUM_DISCOVERED_FORMS",
    "MAXIMUM_DISCOVERY_HTML_BYTES",
    "MAXIMUM_FIELDS_PER_FORM",
    "discover_get_form_candidates",
]
