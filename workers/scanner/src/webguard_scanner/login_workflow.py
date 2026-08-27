"""Controlled login workflow (Slice 7).

Sends exactly one bounded login request through the same safe_http/
runtime-safety plumbing as every other active request, then verifies
success against a caller-specified, explicit criterion -- never assumes
HTTP 200 means a login succeeded. On any ambiguity, fails closed: no
session is extracted, and the caller must not proceed with authenticated
scanning.

Credentials (username/password) are accepted as plain arguments, never
stored on a dataclass this module returns -- LoginResult carries session
cookies (already the bounded, redacted SessionCookie type) and a bearer
token if the response's success criterion said to extract one, never the
submitted password.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import Message
from typing import Callable
from urllib.parse import urlsplit

from .active_detection import (
    ActiveDetectionPolicy,
    _build_probe_target,
    _require_same_origin,
)
from .authentication import SessionCookie
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .safe_http import SafeHttpResponse, SafeRequestError, fetch_once
from .scope_validator import ValidatedTarget


class LoginWorkflowError(RuntimeError):
    """Controlled failure raised by the login-workflow layer."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class LoginCredentials:
    """Plain, in-memory-only credential pair for one login attempt."""

    username: str
    password: str

    def __post_init__(self) -> None:
        if not isinstance(self.username, str) or not self.username:
            raise LoginWorkflowError(
                "login_username_invalid", "A username must be a non-empty string."
            )
        if not isinstance(self.password, str) or not self.password:
            raise LoginWorkflowError(
                "login_password_invalid", "A password must be a non-empty string."
            )

    def __repr__(self) -> str:
        return f"LoginCredentials(username={self.username!r}, password=<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class LoginSuccessCriterion:
    """Bounded, explicit verification of login success. At least one of
    these must be supplied; the workflow never assumes 2xx means
    success."""

    expected_status: int | None = None
    expected_redirect_contains: str | None = None
    expected_body_marker: str | None = None
    expected_cookie_name: str | None = None

    def __post_init__(self) -> None:
        if not any(
            (
                self.expected_status is not None,
                self.expected_redirect_contains,
                self.expected_body_marker,
                self.expected_cookie_name,
            )
        ):
            raise LoginWorkflowError(
                "login_success_criterion_missing",
                "A login workflow requires at least one explicit success "
                "criterion (status, redirect, body marker, or cookie name).",
            )


@dataclass(frozen=True, slots=True)
class LoginWorkflow:
    """One controlled login request shape."""

    target_url: str
    method: str
    content_type: str
    username_field: str
    password_field: str
    success: LoginSuccessCriterion

    def __post_init__(self) -> None:
        if not isinstance(self.target_url, str) or not self.target_url.strip():
            raise LoginWorkflowError(
                "login_target_url_invalid", "A login workflow requires a target URL."
            )
        object.__setattr__(self, "method", self.method.upper())


@dataclass(frozen=True, slots=True)
class LoginResult:
    """Outcome of one login attempt. Never carries the submitted
    password or any raw request/response body."""

    success: bool
    reason: str
    cookies: tuple[SessionCookie, ...] = ()
    status: int | None = None


def _extract_cookies(
    response: SafeHttpResponse, *, domain: str, port: int, now: datetime
) -> tuple[SessionCookie, ...]:
    cookies: list[SessionCookie] = []
    for name, value in response.headers:
        if name.lower() != "set-cookie":
            continue
        # Bounded, minimal Set-Cookie parsing: name=value is the only
        # part this layer trusts; Path/Secure/Expires are read if present,
        # anything else in the header is ignored -- this is not a general
        # cookie-jar implementation, only enough to capture a session
        # token from a controlled login fixture.
        first_pair, *attributes = value.split(";")
        if "=" not in first_pair:
            continue
        cookie_name, cookie_value = first_pair.split("=", 1)
        cookie_name = cookie_name.strip()
        cookie_value = cookie_value.strip()
        if not cookie_name:
            continue
        secure = False
        path = "/"
        for attribute in attributes:
            cleaned = attribute.strip().lower()
            if cleaned == "secure":
                secure = True
            elif cleaned.startswith("path="):
                path = attribute.strip()[len("path=") :] or "/"
        try:
            cookies.append(
                SessionCookie(
                    name=cookie_name,
                    value=cookie_value,
                    domain=domain,
                    port=port,
                    path=path,
                    secure=secure,
                )
            )
        except Exception:  # noqa: BLE001, S112 - a malformed Set-Cookie is skipped, not fatal
            continue
    return tuple(cookies)


def execute_login(
    base_target: ValidatedTarget,
    workflow: LoginWorkflow,
    credentials: LoginCredentials,
    *,
    policy: ActiveDetectionPolicy,
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> LoginResult:
    """Issue exactly one bounded login request and verify success against
    the workflow's own explicit criterion. Never assumes 2xx means
    success. Fails closed (LoginResult(success=False, ...)) on any
    ambiguity, any probe failure, or cancellation -- never raises for a
    routine login failure, since a wrong-credentials attempt is an
    expected, ordinary outcome, not a code-level error.
    """

    if cancellation_check is not None and cancellation_check():
        return LoginResult(success=False, reason="cancelled")

    _require_same_origin(base_target, workflow.target_url)
    probe_target = _build_probe_target(base_target, workflow.target_url)

    if workflow.content_type == "application/json":
        import json

        body = json.dumps(
            {
                workflow.username_field: credentials.username,
                workflow.password_field: credentials.password,
            }
        ).encode("utf-8")
    else:
        from urllib.parse import urlencode

        body = urlencode(
            {
                workflow.username_field: credentials.username,
                workflow.password_field: credentials.password,
            }
        ).encode("utf-8")

    if before_request is not None:
        before_request(probe_target, workflow.method)

    try:
        response = fetch_once(
            probe_target,
            method=workflow.method,
            policy=policy.fetch_policy,
            body=body,
            content_type=workflow.content_type,
            allow_redirect_status=workflow.success.expected_redirect_contains is not None,
        )
    except SafeRequestError as exc:
        if after_request is not None:
            after_request(probe_target, workflow.method, None, exc.code)
        return LoginResult(success=False, reason=f"probe_failed:{exc.code}")

    if after_request is not None:
        after_request(probe_target, workflow.method, response, None)

    criterion = workflow.success
    parsed = urlsplit(workflow.target_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if criterion.expected_status is not None and response.status != criterion.expected_status:
        return LoginResult(
            success=False, reason="status_mismatch", status=response.status
        )

    if criterion.expected_redirect_contains:
        location = next(
            (value for name, value in response.headers if name.lower() == "location"),
            "",
        )
        if criterion.expected_redirect_contains not in location:
            return LoginResult(
                success=False, reason="redirect_marker_absent", status=response.status
            )

    if criterion.expected_body_marker:
        body_text = response.body.decode("utf-8", errors="replace")
        if criterion.expected_body_marker not in body_text:
            return LoginResult(
                success=False, reason="body_marker_absent", status=response.status
            )

    cookies = _extract_cookies(
        response, domain=base_target.hostname, port=port, now=datetime.now(timezone.utc)
    )

    if criterion.expected_cookie_name:
        if not any(cookie.name == criterion.expected_cookie_name for cookie in cookies):
            return LoginResult(
                success=False, reason="expected_cookie_absent", status=response.status
            )

    return LoginResult(success=True, reason="verified", cookies=cookies, status=response.status)


__all__ = [
    "LoginCredentials",
    "LoginResult",
    "LoginSuccessCriterion",
    "LoginWorkflow",
    "LoginWorkflowError",
    "execute_login",
]
