"""Unit tests for the session/authentication application layer (Slice 7).

Covers secret redaction (__repr__/__str__ never leak values), header
allowlist/blocklist enforcement, and cross-origin/cross-scheme/cross-port
cookie non-forwarding -- the core security properties this module exists
to guarantee.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from webguard_scanner import (
    AuthenticationError,
    AuthenticationMaterial,
    SessionCookie,
    apply_authentication,
)


def _now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


class SecretRedactionTests(unittest.TestCase):
    def test_authentication_material_repr_never_contains_bearer_token(self) -> None:
        material = AuthenticationMaterial(bearer_token="super-secret-token-value")
        self.assertNotIn("super-secret-token-value", repr(material))
        self.assertNotIn("super-secret-token-value", str(material))

    def test_authentication_material_repr_never_contains_cookie_value(self) -> None:
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(
                    name="session",
                    value="super-secret-cookie-value",
                    domain="app.example.com",
                    port=80,
                ),
            )
        )
        self.assertNotIn("super-secret-cookie-value", repr(material))
        self.assertNotIn("super-secret-cookie-value", str(material))

    def test_authentication_material_repr_never_contains_basic_password(self) -> None:
        material = AuthenticationMaterial(
            basic_username="user-a", basic_password="hunter2-super-secret"
        )
        self.assertNotIn("hunter2-super-secret", repr(material))

    def test_session_cookie_repr_never_contains_value(self) -> None:
        cookie = SessionCookie(
            name="session",
            value="super-secret-cookie-value",
            domain="app.example.com",
            port=80,
        )
        self.assertNotIn("super-secret-cookie-value", repr(cookie))
        self.assertIn("session", repr(cookie))
        self.assertIn("app.example.com", repr(cookie))

    def test_exception_message_never_contains_secret_value(self) -> None:
        # An oversized-token error must describe the limit, not echo the
        # offending secret back in the exception message.
        with self.assertRaises(AuthenticationError) as caught:
            AuthenticationMaterial(bearer_token="x" * 100_000)
        self.assertNotIn("x" * 100_000, caught.exception.message)


class BoundsTests(unittest.TestCase):
    def test_oversized_bearer_token_is_rejected(self) -> None:
        with self.assertRaises(AuthenticationError) as caught:
            AuthenticationMaterial(bearer_token="a" * 8193)
        self.assertEqual(caught.exception.code, "authentication_bearer_token_too_large")

    def test_oversized_cookie_value_is_rejected(self) -> None:
        with self.assertRaises(AuthenticationError) as caught:
            SessionCookie(
                name="session", value="a" * 4097, domain="app.example.com", port=80
            )
        self.assertEqual(caught.exception.code, "authentication_cookie_too_large")

    def test_too_many_cookies_is_rejected(self) -> None:
        cookies = tuple(
            SessionCookie(name=f"c{i}", value="v", domain="app.example.com", port=80)
            for i in range(21)
        )
        with self.assertRaises(AuthenticationError) as caught:
            AuthenticationMaterial(cookies=cookies)
        self.assertEqual(caught.exception.code, "authentication_too_many_cookies")

    def test_incomplete_basic_credentials_rejected(self) -> None:
        with self.assertRaises(AuthenticationError) as caught:
            AuthenticationMaterial(basic_username="user-a")
        self.assertEqual(
            caught.exception.code, "authentication_basic_credentials_incomplete"
        )

    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaises(AuthenticationError) as caught:
            SessionCookie(name="session", value="v", domain="app.example.com", port=0)
        self.assertEqual(caught.exception.code, "authentication_cookie_port_invalid")


class ApplyAuthenticationTests(unittest.TestCase):
    def test_no_material_produces_no_headers(self) -> None:
        self.assertEqual(
            apply_authentication("http://app.example.com/", None, now=_now()), ()
        )

    def test_bearer_token_produces_authorization_header(self) -> None:
        material = AuthenticationMaterial(bearer_token="tok123")
        headers = apply_authentication("http://app.example.com/", material, now=_now())
        self.assertEqual(headers, (("Authorization", "Bearer tok123"),))

    def test_basic_auth_produces_base64_authorization_header(self) -> None:
        material = AuthenticationMaterial(basic_username="user-a", basic_password="pass")
        headers = apply_authentication("http://app.example.com/", material, now=_now())
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0][0], "Authorization")
        self.assertTrue(headers[0][1].startswith("Basic "))

    def test_matching_cookie_is_attached(self) -> None:
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(name="session", value="abc", domain="app.example.com", port=80),
            )
        )
        headers = apply_authentication(
            "http://app.example.com/account", material, now=_now()
        )
        self.assertEqual(headers, (("Cookie", "session=abc"),))

    def test_cookie_never_forwarded_to_a_different_domain(self) -> None:
        """authorized.example's session must never be sent to evil.example,
        even though both are 'the same request call' from the caller's
        point of view -- proves the exact-domain check, not scope
        enforcement elsewhere, is what blocks this."""
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(
                    name="session", value="abc", domain="authorized.example", port=80
                ),
            )
        )
        headers = apply_authentication("http://evil.example/", material, now=_now())
        self.assertEqual(headers, ())

    def test_cookie_never_forwarded_to_a_sibling_subdomain(self) -> None:
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(name="session", value="abc", domain="app.example.com", port=80),
            )
        )
        headers = apply_authentication(
            "http://other.example.com/", material, now=_now()
        )
        self.assertEqual(headers, ())

    def test_cookie_never_forwarded_to_a_different_port(self) -> None:
        """Deliberately stricter than RFC 6265 browser cookies (which
        ignore port): a session bound to app.example.com:443 must never
        be sent to app.example.com:8443, matching this project's own
        scheme+host+port scope model."""
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(name="session", value="abc", domain="app.example.com", port=443),
            )
        )
        headers = apply_authentication(
            "https://app.example.com:8443/", material, now=_now()
        )
        self.assertEqual(headers, ())
        # Same host, matching port -> attached.
        headers_matching = apply_authentication(
            "https://app.example.com/", material, now=_now()
        )
        self.assertEqual(headers_matching, (("Cookie", "session=abc"),))

    def test_secure_cookie_never_forwarded_over_downgraded_http(self) -> None:
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(
                    name="session",
                    value="abc",
                    domain="app.example.com",
                    port=80,
                    secure=True,
                ),
            )
        )
        headers = apply_authentication("http://app.example.com/", material, now=_now())
        self.assertEqual(headers, ())
        # Same domain, https -> attached (note: a real Secure cookie
        # would be bound to port 443, this test only varies the scheme).
        secure_material = AuthenticationMaterial(
            cookies=(
                SessionCookie(
                    name="session",
                    value="abc",
                    domain="app.example.com",
                    port=443,
                    secure=True,
                ),
            )
        )
        headers_https = apply_authentication(
            "https://app.example.com/", secure_material, now=_now()
        )
        self.assertEqual(headers_https, (("Cookie", "session=abc"),))

    def test_expired_cookie_is_never_attached(self) -> None:
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(
                    name="session",
                    value="abc",
                    domain="app.example.com",
                    port=80,
                    expires_at=_now() - timedelta(hours=1),
                ),
            )
        )
        headers = apply_authentication("http://app.example.com/", material, now=_now())
        self.assertEqual(headers, ())

    def test_path_scoped_cookie_only_attached_within_its_path(self) -> None:
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(
                    name="admin_session",
                    value="abc",
                    domain="app.example.com",
                    port=80,
                    path="/admin",
                ),
            )
        )
        self.assertEqual(
            apply_authentication("http://app.example.com/public", material, now=_now()),
            (),
        )
        self.assertEqual(
            apply_authentication(
                "http://app.example.com/admin/panel", material, now=_now()
            ),
            (("Cookie", "admin_session=abc"),),
        )

    def test_redirect_to_external_origin_never_receives_cookie(self) -> None:
        """A page on the authenticated origin redirecting to an external
        site must not carry the session along -- exercised here as
        "the redirect target URL never matches the cookie's own origin,"
        the same mechanism that blocks any other off-origin URL."""
        material = AuthenticationMaterial(
            cookies=(
                SessionCookie(name="session", value="abc", domain="app.example.com", port=443),
            )
        )
        redirect_target = "https://attacker-controlled.example/callback"
        headers = apply_authentication(redirect_target, material, now=_now())
        self.assertEqual(headers, ())


if __name__ == "__main__":
    unittest.main()
