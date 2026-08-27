"""Unit tests for the controlled login workflow (Slice 7).

Covers: never assuming HTTP 200 means success, each of the four bounded
success criteria (status/redirect/body-marker/cookie), fail-closed
behavior on ambiguous or failed login, cancellation, and that a
LoginResult never carries the submitted password.
"""

from __future__ import annotations

import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import parse_qs

from webguard_scanner import (
    ActiveDetectionPolicy,
    LoginCredentials,
    LoginSuccessCriterion,
    LoginWorkflow,
    LoginWorkflowError,
    ValidatedTarget,
    execute_login,
)


def _target(url: str = "http://example.com/") -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme="http",
        hostname="example.com",
        port=80,
        resolved_addresses=("93.184.216.34",),
    )


class _FakeResponse:
    def __init__(
        self, body: bytes, status: int = 200, headers: list[tuple[str, str]] | None = None
    ) -> None:
        self.status = status
        self.reason = "OK"
        self._body = body
        self._position = 0
        self.msg = Message()
        self.msg.add_header("Content-Length", str(len(body)))
        self._extra_headers = headers or []

    def getheaders(self):
        return [("Content-Length", str(len(self._body)))] + self._extra_headers

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = len(self._body) - self._position
        chunk = self._body[self._position : self._position + amount]
        self._position += len(chunk)
        return chunk


class _LoginConnection:
    def __init__(self, responder) -> None:
        self.responder = responder
        self.sock = None
        self._context = None
        self.sent_bodies: list[bytes] = []

    def putrequest(self, method, path, **kwargs) -> None:
        return None

    def putheader(self, name, value) -> None:
        return None

    def endheaders(self, message_body=None) -> None:
        self.sent_bodies.append(message_body or b"")

    def getresponse(self):
        fields = parse_qs(self.sent_bodies[-1].decode())
        username = fields.get("username", [""])[0]
        password = fields.get("password", [""])[0]
        return self.responder(username, password)

    def close(self) -> None:
        pass


def _workflow(**success_kwargs) -> LoginWorkflow:
    return LoginWorkflow(
        target_url="http://example.com/login",
        method="POST",
        content_type="application/x-www-form-urlencoded",
        username_field="username",
        password_field="password",
        success=LoginSuccessCriterion(**success_kwargs),
    )


def _policy() -> ActiveDetectionPolicy:
    from webguard_scanner import FetchPolicy

    return ActiveDetectionPolicy(
        fetch_policy=FetchPolicy(allowed_methods=frozenset({"GET", "HEAD", "POST"}))
    )


class LoginSuccessCriterionTests(unittest.TestCase):
    def test_requires_at_least_one_criterion(self) -> None:
        with self.assertRaises(LoginWorkflowError) as caught:
            LoginSuccessCriterion()
        self.assertEqual(caught.exception.code, "login_success_criterion_missing")


class ExecuteLoginTests(unittest.TestCase):
    def test_correct_credentials_with_redirect_criterion_succeeds(self) -> None:
        def responder(username, password):
            if username == "user-a" and password == "correct-password":
                return _FakeResponse(
                    b"", status=302, headers=[("Location", "/account")]
                )
            return _FakeResponse(b"<html>Invalid login</html>", status=200)

        connection = _LoginConnection(responder)
        workflow = _workflow(expected_redirect_contains="/account")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="correct-password"),
                policy=_policy(),
            )
        self.assertTrue(result.success)
        self.assertEqual(result.status, 302)

    def test_wrong_credentials_fails_closed(self) -> None:
        def responder(username, password):
            return _FakeResponse(b"<html>Invalid login</html>", status=200)

        connection = _LoginConnection(responder)
        workflow = _workflow(expected_redirect_contains="/account")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="wrong-password"),
                policy=_policy(),
            )
        self.assertFalse(result.success)

    def test_http_200_alone_is_never_treated_as_success(self) -> None:
        """The core requirement: a 200 response with no expected marker
        must not be assumed to mean the login succeeded."""

        def responder(username, password):
            # Server returns 200 for *everything*, success or failure --
            # a deliberately adversarial fixture for this exact test.
            return _FakeResponse(b"<html>welcome or not, who knows</html>", status=200)

        connection = _LoginConnection(responder)
        workflow = _workflow(expected_body_marker="Welcome, user-a")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="correct-password"),
                policy=_policy(),
            )
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "body_marker_absent")

    def test_body_marker_criterion_succeeds_when_present(self) -> None:
        def responder(username, password):
            return _FakeResponse(b"<html>Welcome, user-a!</html>", status=200)

        connection = _LoginConnection(responder)
        workflow = _workflow(expected_body_marker="Welcome, user-a")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="correct-password"),
                policy=_policy(),
            )
        self.assertTrue(result.success)

    def test_expected_cookie_criterion_extracts_session_cookie(self) -> None:
        def responder(username, password):
            return _FakeResponse(
                b"<html>ok</html>",
                status=200,
                headers=[("Set-Cookie", "session=abc123; Path=/; Secure")],
            )

        connection = _LoginConnection(responder)
        workflow = _workflow(expected_cookie_name="session")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="correct-password"),
                policy=_policy(),
            )
        self.assertTrue(result.success)
        self.assertEqual(len(result.cookies), 1)
        self.assertEqual(result.cookies[0].name, "session")
        self.assertEqual(result.cookies[0].value, "abc123")
        self.assertTrue(result.cookies[0].secure)

    def test_missing_expected_cookie_fails_closed(self) -> None:
        def responder(username, password):
            return _FakeResponse(b"<html>ok</html>", status=200)

        connection = _LoginConnection(responder)
        workflow = _workflow(expected_cookie_name="session")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="correct-password"),
                policy=_policy(),
            )
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "expected_cookie_absent")

    def test_cancellation_before_login_makes_no_request(self) -> None:
        connection = _LoginConnection(lambda u, p: _FakeResponse(b"", status=200))
        workflow = _workflow(expected_status=200)
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="x"),
                policy=_policy(),
                cancellation_check=lambda: True,
            )
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "cancelled")
        self.assertEqual(connection.sent_bodies, [])

    def test_off_origin_login_target_is_rejected(self) -> None:
        workflow = LoginWorkflow(
            target_url="http://third-party.example/login",
            method="POST",
            content_type="application/x-www-form-urlencoded",
            username_field="username",
            password_field="password",
            success=LoginSuccessCriterion(expected_status=200),
        )
        with self.assertRaises(Exception):
            execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="x"),
                policy=_policy(),
            )

    def test_login_result_never_contains_submitted_password(self) -> None:
        def responder(username, password):
            return _FakeResponse(b"<html>Welcome, user-a!</html>", status=200)

        connection = _LoginConnection(responder)
        workflow = _workflow(expected_body_marker="Welcome")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = execute_login(
                _target(),
                workflow,
                LoginCredentials(username="user-a", password="super-secret-password-xyz"),
                policy=_policy(),
            )
        self.assertNotIn("super-secret-password-xyz", repr(result))
        self.assertNotIn("super-secret-password-xyz", str(result))


class LoginCredentialsRedactionTests(unittest.TestCase):
    def test_repr_never_contains_password(self) -> None:
        credentials = LoginCredentials(username="user-a", password="super-secret")
        self.assertNotIn("super-secret", repr(credentials))
        self.assertIn("user-a", repr(credentials))


if __name__ == "__main__":
    unittest.main()
