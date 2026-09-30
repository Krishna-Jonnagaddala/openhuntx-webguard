"""Controlled session/authentication application layer (Slice 7).

One shared mechanism sits between a resolved authentication context and
`safe_http`: no detector, no crawler, and no discovery code independently
injects `Authorization`/`Cookie`/`X-Api-Key` headers. Everything that
needs to send an authenticated request goes through
``apply_authentication`` here.

Secret separation is the load-bearing property of this module:

- ``AuthenticationMaterial`` holds resolved secret values (a bearer
  token, session cookies) **only in memory**, for the duration of one
  request-issuance call. It is never constructed from, or attached to,
  anything that gets logged, audited, checkpointed, or included in a
  finding/report -- those all carry an ``authentication_context_id``
  (or nothing at all), never this object.
- Its ``__repr__``/``__str__`` are overridden to return a fixed redacted
  string, as defense in depth against accidental logging (an f-string,
  a debugger, an uncaught-exception traceback that happens to include a
  local variable) -- not the only control, but a real one.
- The header allowlist (`Authorization`, `Cookie`) and hard blocklist
  (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`,
  `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-For`) are enforced here
  *and* independently re-checked in `safe_http.fetch_once` -- the same
  defense-in-depth pattern already used for scope/method enforcement
  elsewhere in this codebase.
- Cookies are attached only when a request's origin **exactly** matches
  the cookie's own bound domain. A session issued for `app.example.com`
  is never sent to `third-party.example`, a sibling subdomain, a
  different port, or a downgraded (https->http) scheme -- merely because
  a scanned page linked there. There is no subdomain-wildcard cookie
  matching in this slice; that is a deliberately narrower, safer default
  than real browsers use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Tuple
from urllib.parse import urlsplit


class AuthenticationError(RuntimeError):
    """Controlled failure raised by the authentication-application layer."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


MAXIMUM_COOKIES = 20
MAXIMUM_COOKIE_VALUE_BYTES = 4096
MAXIMUM_BEARER_TOKEN_BYTES = 8192

_ALLOWED_AUTHENTICATION_HEADERS = frozenset({"authorization", "cookie"})
_FORBIDDEN_AUTHENTICATION_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "forwarded",
        "x-forwarded-host",
        "x-forwarded-for",
    }
)

_REDACTED = "<redacted>"


@dataclass(frozen=True, slots=True)
class SessionCookie:
    """One bounded, origin-scoped session cookie.

    ``domain`` must be an exact hostname (no leading dot, no wildcard) --
    matching is exact-hostname-only, not subdomain-inclusive, by
    deliberate design (see module docstring). ``port`` is required and
    checked exactly too: this is deliberately *stricter* than RFC 6265
    browser cookie semantics (which ignore port), matching this
    project's existing scope model, where a target's identity is
    scheme+host+port, not host alone -- a session bound to
    ``app.example.com:443`` is never sent to ``app.example.com:8443``.
    """

    name: str
    value: str
    domain: str
    port: int
    path: str = "/"
    secure: bool = False
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise AuthenticationError(
                "authentication_cookie_name_invalid",
                "A session cookie requires a non-empty name.",
            )
        if not isinstance(self.value, str):
            raise AuthenticationError(
                "authentication_cookie_value_invalid",
                "A session cookie value must be a string.",
            )
        if len(self.value.encode("utf-8")) > MAXIMUM_COOKIE_VALUE_BYTES:
            raise AuthenticationError(
                "authentication_cookie_too_large",
                f"Cookie {self.name!r} exceeds the "
                f"{MAXIMUM_COOKIE_VALUE_BYTES}-byte limit.",
            )
        if not isinstance(self.domain, str) or not self.domain:
            raise AuthenticationError(
                "authentication_cookie_domain_invalid",
                "A session cookie requires a non-empty, exact domain.",
            )
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not (1 <= self.port <= 65535)
        ):
            raise AuthenticationError(
                "authentication_cookie_port_invalid",
                "A session cookie requires a valid port number.",
            )

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def __repr__(self) -> str:
        return (
            f"SessionCookie(name={self.name!r}, domain={self.domain!r}, "
            f"value={_REDACTED})"
        )

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class AuthenticationMaterial:
    """Resolved secret material for one request-issuance call.

    In-memory only. Never store this on a dataclass that gets
    serialized, logged, checkpointed, or included in a finding/report.
    """

    bearer_token: str | None = None
    cookies: Tuple[SessionCookie, ...] = ()
    basic_username: str | None = None
    basic_password: str | None = None

    def __post_init__(self) -> None:
        if self.bearer_token is not None:
            if not isinstance(self.bearer_token, str) or not self.bearer_token:
                raise AuthenticationError(
                    "authentication_bearer_token_invalid",
                    "A bearer token must be a non-empty string.",
                )
            if len(self.bearer_token.encode("utf-8")) > MAXIMUM_BEARER_TOKEN_BYTES:
                raise AuthenticationError(
                    "authentication_bearer_token_too_large",
                    f"Bearer token exceeds the {MAXIMUM_BEARER_TOKEN_BYTES}-byte limit.",
                )
        if len(self.cookies) > MAXIMUM_COOKIES:
            raise AuthenticationError(
                "authentication_too_many_cookies",
                f"{len(self.cookies)} cookies exceed the {MAXIMUM_COOKIES}-cookie limit.",
            )
        if (self.basic_username is None) != (self.basic_password is None):
            raise AuthenticationError(
                "authentication_basic_credentials_incomplete",
                "Basic authentication requires both a username and a password.",
            )

    def __repr__(self) -> str:
        present = []
        if self.bearer_token is not None:
            present.append("bearer_token")
        if self.cookies:
            present.append(f"cookies[{len(self.cookies)}]")
        if self.basic_username is not None:
            present.append("basic_auth")
        return f"AuthenticationMaterial({', '.join(present) or 'empty'}={_REDACTED})"

    __str__ = __repr__


def _cookie_matches_request(cookie: SessionCookie, url: str, *, now: datetime) -> bool:
    if cookie.is_expired(now):
        return False
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    # Exact match only: no cross-origin forwarding, no subdomain
    # wildcarding, no port-insensitive matching -- stricter than RFC 6265
    # browser cookies, matching this project's own scheme+host+port
    # scope model.
    if hostname != cookie.domain.lower() or port != cookie.port:
        return False
    if cookie.secure and parsed.scheme != "https":
        return False
    if cookie.path != "/" and not (parsed.path or "/").startswith(cookie.path):
        return False
    return True


def apply_authentication(
    url: str,
    material: AuthenticationMaterial | None,
    *,
    now: datetime,
) -> Tuple[Tuple[str, str], ...]:
    """Return the additional headers to send for one request against
    ``url``, given resolved authentication material.

    Returns an empty tuple for ``material=None`` (unauthenticated
    request) -- this is the normal, default path every existing
    detector/crawl/discovery call already takes, unchanged.
    """

    if material is None:
        return ()

    headers: list[tuple[str, str]] = []

    if material.bearer_token is not None:
        headers.append(("Authorization", f"Bearer {material.bearer_token}"))
    elif material.basic_username is not None:
        import base64

        token = base64.b64encode(
            f"{material.basic_username}:{material.basic_password}".encode("utf-8")
        ).decode("ascii")
        headers.append(("Authorization", f"Basic {token}"))

    matching_cookies = [
        cookie
        for cookie in material.cookies
        if _cookie_matches_request(cookie, url, now=now)
    ]
    if matching_cookies:
        cookie_header = "; ".join(
            f"{cookie.name}={cookie.value}" for cookie in matching_cookies
        )
        headers.append(("Cookie", cookie_header))

    for name, _ in headers:
        lowered = name.lower()
        if lowered in _FORBIDDEN_AUTHENTICATION_HEADERS:
            raise AuthenticationError(
                "authentication_header_forbidden",
                f"Header {name!r} cannot be set by authentication application.",
            )
        if lowered not in _ALLOWED_AUTHENTICATION_HEADERS:
            raise AuthenticationError(
                "authentication_header_not_allowed",
                f"Header {name!r} is not on the authentication header allowlist.",
            )

    return tuple(headers)


__all__ = [
    "MAXIMUM_BEARER_TOKEN_BYTES",
    "MAXIMUM_COOKIES",
    "MAXIMUM_COOKIE_VALUE_BYTES",
    "AuthenticationError",
    "AuthenticationMaterial",
    "SessionCookie",
    "apply_authentication",
]
