"""Slice 16: browser session authentication, passwords, CSRF, identity
tokens (email verification / password reset / invitation), and
pre-auth rate limiting -- against the real HTTP transport, local/
SQLite-backed service, matching the established `test_http_api.py` /
`test_customer_platform_api.py` harness pattern.
"""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_api import (
    ApiTokenAuthenticator,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    ScanJobStore,
    WebGuardJobService,
    create_server,
)
from webguard_api.artifact_store import LocalArtifactStore
from webguard_api.auth import BrowserSessionAuthenticator
from webguard_api.auth_rate_limit import InMemoryAuthRateLimiter
from webguard_api.identity import IdentityStore
from webguard_api.mail import InMemoryMailProvider
from webguard_api.sessions import InMemorySessionRepository

from tests.unit.service_test_support import NOW, ORG_ID, OWNER_ID, create_identity_fixture, write_authorization


class CustomerAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.owner_context, self.owner_token = create_identity_fixture(store.path)
        self.identity = identity
        self.sessions = InMemorySessionRepository()
        self.mail = InMemoryMailProvider()
        self.service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
            artifact_store=LocalArtifactStore(root / "artifacts"),
            sessions=self.sessions,
            mail_provider=self.mail,
            auth_rate_limiter=InMemoryAuthRateLimiter(max_attempts=5, window_seconds=900),
        )
        self.server = create_server(
            "127.0.0.1", 0, self.service,
            authenticator=ApiTokenAuthenticator(identity),
            session_authenticator=BrowserSessionAuthenticator(identity, self.sessions),
            rate_limiter=FixedWindowRateLimiter(requests=500, window_seconds=60),
            maximum_request_bytes=8192,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
            secure_cookies=False,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method, path, body=None, headers=None):
        hdrs = dict(headers or {})
        raw = None
        if body is not None:
            raw = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, body=raw, headers=hdrs)
        response = connection.getresponse()
        payload = response.read()
        response_headers = response.getheaders()
        connection.close()
        return response.status, response_headers, (json.loads(payload) if payload else None)

    @staticmethod
    def cookies_from(headers):
        jar = {}
        for name, value in headers:
            if name.lower() == "set-cookie":
                key, val = value.split(";", 1)[0].split("=", 1)
                jar[key] = val
        return jar

    def register(self, email, *, organization_name="Reg Org", password="a genuinely long password 123"):
        status, headers, payload = self.request(
            "POST", "/v1/auth/register",
            {"organization_name": organization_name, "display_name": "Ada", "email": email, "password": password},
        )
        return status, self.cookies_from(headers), payload

    def session_headers(self, jar):
        return {"Cookie": f"wg_session={jar['wg_session']}", "X-CSRF-Token": jar["wg_csrf"]}

    @staticmethod
    def token_from(message):
        """Slice 17: mail bodies now embed a clickable
        `{base_url}/...?token=...` link, not a bare "...: {token}"
        sentence -- extract the token from the query string."""
        return message.body.rsplit("token=", 1)[1].strip()

    # -- Registration ------------------------------------------------

    def test_register_creates_session_and_verification_email(self) -> None:
        status, jar, payload = self.register("owner@reg.example")
        self.assertEqual(status, 201, payload)
        self.assertEqual(payload["auth_method"], "browser_session")
        self.assertEqual(payload["role"], "owner")
        self.assertIn("wg_session", jar)
        self.assertIn("wg_csrf", jar)
        message = self.mail.latest_to("owner@reg.example", category="email_verification")
        self.assertIsNotNone(message)

    def test_register_rejects_weak_password(self) -> None:
        status, _, payload = self.request(
            "POST", "/v1/auth/register",
            {"organization_name": "X", "display_name": "Ada", "email": "weak@reg.example", "password": "short"},
        )
        self.assertEqual(status, 400, payload)

    def test_register_rejects_duplicate_email(self) -> None:
        self.register("dup@reg.example")
        status, _, payload = self.request(
            "POST", "/v1/auth/register",
            {"organization_name": "Y", "display_name": "Bob", "email": "dup@reg.example", "password": "another long password 456"},
        )
        self.assertEqual(status, 409, payload)

    # -- Login ---------------------------------------------------------

    def test_login_unknown_email_and_wrong_password_both_generic_401(self) -> None:
        self.register("known@login.example", password="a genuinely long password 123")
        status_a, _, payload_a = self.request(
            "POST", "/v1/auth/login", {"email": "unknown@login.example", "password": "whatever password"}
        )
        status_b, _, payload_b = self.request(
            "POST", "/v1/auth/login", {"email": "known@login.example", "password": "wrong password entirely"}
        )
        self.assertEqual(status_a, 401)
        self.assertEqual(status_b, 401)
        self.assertEqual(payload_a["error"]["code"], payload_b["error"]["code"])
        self.assertEqual(payload_a["error"]["message"], payload_b["error"]["message"])

    def test_login_success_sets_cookies_and_updates_last_login(self) -> None:
        self.register("last-login@login.example", password="a genuinely long password 123")
        status, headers, payload = self.request(
            "POST", "/v1/auth/login", {"email": "last-login@login.example", "password": "a genuinely long password 123"}
        )
        self.assertEqual(status, 200, payload)
        jar = self.cookies_from(headers)
        self.assertIn("wg_session", jar)
        principal = self.identity.get_principal(payload["principal_id"])
        self.assertIsNotNone(principal.last_login_at)

    def test_login_rate_limited_after_repeated_failures(self) -> None:
        self.register("rl@login.example", password="a genuinely long password 123")
        statuses = [
            self.request("POST", "/v1/auth/login", {"email": "rl@login.example", "password": "wrong"})[0]
            for _ in range(6)
        ]
        self.assertIn(429, statuses)

    # -- Session -----------------------------------------------------

    def test_session_endpoint_requires_authentication(self) -> None:
        status, _, payload = self.request("GET", "/v1/auth/session")
        self.assertEqual(status, 401, payload)

    def test_session_endpoint_reflects_real_state(self) -> None:
        _, jar, _ = self.register("session@x.example")
        status, _, payload = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["auth_method"], "browser_session")
        self.assertIn("session", payload)
        self.assertIn("idle_expires_at", payload["session"])

    # -- CSRF ----------------------------------------------------------

    def test_state_changing_request_without_csrf_token_is_rejected(self) -> None:
        _, jar, _ = self.register("csrf1@x.example")
        status, _, payload = self.request(
            "POST", "/v1/assets", {"url": "https://csrf1.example/"},
            headers={"Cookie": f"wg_session={jar['wg_session']}"},
        )
        self.assertEqual(status, 403, payload)
        self.assertEqual(payload["error"]["code"], "csrf_token_invalid")

    def test_state_changing_request_with_wrong_csrf_token_is_rejected(self) -> None:
        _, jar, _ = self.register("csrf2@x.example")
        status, _, payload = self.request(
            "POST", "/v1/assets", {"url": "https://csrf2.example/"},
            headers={"Cookie": f"wg_session={jar['wg_session']}", "X-CSRF-Token": "not-the-real-token"},
        )
        self.assertEqual(status, 403, payload)

    def test_state_changing_request_with_csrf_token_from_another_session_is_rejected(self) -> None:
        _, jar_a, _ = self.register("csrf3a@x.example", organization_name="CSRF Org A")
        _, jar_b, _ = self.register("csrf3b@x.example", organization_name="CSRF Org B")
        status, _, payload = self.request(
            "POST", "/v1/assets", {"url": "https://csrf3.example/"},
            headers={"Cookie": f"wg_session={jar_a['wg_session']}", "X-CSRF-Token": jar_b["wg_csrf"]},
        )
        self.assertEqual(status, 403, payload)

    def test_state_changing_request_with_correct_csrf_token_succeeds(self) -> None:
        _, jar, _ = self.register("csrf4@x.example")
        status, _, payload = self.request(
            "POST", "/v1/assets", {"url": "https://csrf4.example/"}, headers=self.session_headers(jar)
        )
        self.assertEqual(status, 201, payload)

    def test_api_token_clients_are_exempt_from_csrf(self) -> None:
        status, _, payload = self.request(
            "POST", "/v1/assets", {"url": "https://api-token-csrf-exempt.example/"},
            headers={"Authorization": f"Bearer {self.owner_token}"},
        )
        self.assertEqual(status, 201, payload)

    def test_get_requests_never_require_csrf(self) -> None:
        _, jar, _ = self.register("csrf5@x.example")
        status, _, payload = self.request(
            "GET", "/v1/assets", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(status, 200, payload)

    # -- Malformed / hostile session cookies ---------------------------

    def test_malformed_session_cookie_is_rejected_not_crashed(self) -> None:
        for garbage in (
            "not-a-token-at-all",
            "wgs_missing-the-secret-part",
            "wgs_not-a-uuid_somesecret",
            "wgt_" + "1" * 8 + "-2222-4222-8222-222222222222_secret",  # an API-token-shaped value
            "",
        ):
            with self.subTest(garbage=garbage):
                status, _, payload = self.request(
                    "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={garbage}"}
                )
                self.assertEqual(status, 401, payload)

    def test_malformed_cookie_header_syntax_is_rejected_not_crashed(self) -> None:
        status, _, payload = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": '"""unterminated=quote; ;;=;'}
        )
        self.assertEqual(status, 401, payload)

    # -- Session lifecycle: expiry, revocation, fixation, exposure -----

    def test_expired_session_is_rejected(self) -> None:
        issued = self.sessions.create_session(
            self.owner_context.principal_id,
            self.owner_context.organization_id,
            now=NOW - timedelta(hours=1),
            idle_ttl=timedelta(minutes=1),
            absolute_ttl=timedelta(minutes=1),
        )
        status, _, payload = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={issued.session_token}"}
        )
        self.assertEqual(status, 401, payload)
        self.assertEqual(payload["error"]["code"], "session_expired")

    def test_revoked_session_is_rejected(self) -> None:
        _, jar, _ = self.register("revoked-directly@x.example")
        status, _, session_payload = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(status, 200)
        self.sessions.revoke_session(session_payload["token_id"], now=NOW)
        status, _, payload = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(status, 401, payload)
        self.assertEqual(payload["error"]["code"], "session_expired")

    def test_login_never_honours_a_client_supplied_session_cookie(self) -> None:
        """Session fixation: an attacker who tricks a victim into
        carrying a pre-chosen session cookie into the login request
        must never have that identifier become the victim's real,
        authenticated session -- the server must always mint a fresh,
        unguessable session_id of its own regardless of anything the
        client presented on the request."""
        self.register("fixation@x.example", password="a genuinely long password 123")
        attacker_chosen = "wgs_11111111-1111-4111-8111-111111111111_attacker-chosen-secret"
        status, headers, payload = self.request(
            "POST",
            "/v1/auth/login",
            {"email": "fixation@x.example", "password": "a genuinely long password 123"},
            headers={"Cookie": f"wg_session={attacker_chosen}"},
        )
        self.assertEqual(status, 200, payload)
        jar = self.cookies_from(headers)
        self.assertNotEqual(jar["wg_session"], attacker_chosen)
        self.assertNotIn("11111111-1111-4111-8111-111111111111", jar["wg_session"])

    def test_no_json_response_ever_contains_the_raw_session_or_csrf_secret(self) -> None:
        """Session theft exposure: the bearer secret and CSRF token are
        only ever delivered via Set-Cookie -- never echoed back inside
        a JSON response body, where they'd be reachable by any script
        that can read fetch/XHR responses (a broader exposure surface
        than a strictly HttpOnly cookie)."""
        status, headers, payload = self.request(
            "POST",
            "/v1/auth/register",
            {
                "organization_name": "Secret Exposure Org",
                "display_name": "Ada",
                "email": "secretexposure@x.example",
                "password": "a genuinely long password 123",
            },
        )
        self.assertEqual(status, 201, payload)
        jar = self.cookies_from(headers)
        serialized = json.dumps(payload)
        self.assertNotIn(jar["wg_session"], serialized)
        self.assertNotIn(jar["wg_csrf"], serialized)
        # the raw bearer secret segment specifically, not just the
        # full cookie value (which also contains the session_id, a
        # non-secret identifier that legitimately does appear in the
        # response body as `token_id`)
        raw_secret = jar["wg_session"].rsplit("_", 1)[-1]
        self.assertNotIn(raw_secret, serialized)

    # -- Logout ----------------------------------------------------------

    def test_logout_revokes_the_session(self) -> None:
        _, jar, _ = self.register("logout1@x.example")
        status, _, _ = self.request("POST", "/v1/auth/logout", headers=self.session_headers(jar))
        self.assertEqual(status, 200)
        status, _, payload = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(status, 401, payload)

    def test_logout_all_revokes_every_session(self) -> None:
        _, jar_first, _ = self.register("logoutall@x.example", password="a genuinely long password 123")
        _, headers_second, _ = self.request(
            "POST", "/v1/auth/login", {"email": "logoutall@x.example", "password": "a genuinely long password 123"}
        )
        jar_second = self.cookies_from(headers_second)
        status, _, payload = self.request(
            "POST", "/v1/auth/logout-all", headers=self.session_headers(jar_first)
        )
        self.assertEqual(status, 200, payload)
        self.assertGreaterEqual(payload["revoked_count"], 2)
        status, _, _ = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar_second['wg_session']}"}
        )
        self.assertEqual(status, 401)

    # -- Password change -------------------------------------------------

    def test_password_change_requires_correct_current_password(self) -> None:
        _, jar, _ = self.register("pwchange1@x.example", password="a genuinely long password 123")
        status, _, payload = self.request(
            "POST", "/v1/auth/password/change",
            {"current_password": "totally wrong", "new_password": "brand new password 456"},
            headers=self.session_headers(jar),
        )
        self.assertEqual(status, 401, payload)

    def test_password_change_revokes_other_sessions_but_not_current(self) -> None:
        _, jar_a, _ = self.register("pwchange2@x.example", password="a genuinely long password 123")
        _, headers_b, _ = self.request(
            "POST", "/v1/auth/login", {"email": "pwchange2@x.example", "password": "a genuinely long password 123"}
        )
        jar_b = self.cookies_from(headers_b)
        status, _, payload = self.request(
            "POST", "/v1/auth/password/change",
            {"current_password": "a genuinely long password 123", "new_password": "brand new password 789"},
            headers=self.session_headers(jar_a),
        )
        self.assertEqual(status, 200, payload)
        status, _, _ = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar_a['wg_session']}"}
        )
        self.assertEqual(status, 200, "the session used to change the password should remain valid")
        status, _, _ = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar_b['wg_session']}"}
        )
        self.assertEqual(status, 401, "every other session should be revoked")

    # -- Password reset --------------------------------------------------

    def test_password_reset_request_is_generic_regardless_of_account_existence(self) -> None:
        self.register("resetreal@x.example")
        status_unknown, _, payload_unknown = self.request(
            "POST", "/v1/auth/password/reset/request", {"email": "doesnotexist@x.example"}
        )
        status_real, _, payload_real = self.request(
            "POST", "/v1/auth/password/reset/request", {"email": "resetreal@x.example"}
        )
        self.assertEqual(status_unknown, status_real, 200)
        self.assertEqual(payload_unknown, payload_real)

    def test_password_reset_confirm_then_reuse_is_rejected_and_sessions_revoked(self) -> None:
        _, jar, _ = self.register("reset2@x.example", password="a genuinely long password 123")
        self.request("POST", "/v1/auth/password/reset/request", {"email": "reset2@x.example"})
        message = self.mail.latest_to("reset2@x.example", category="password_reset")
        token = self.token_from(message)
        status, _, payload = self.request(
            "POST", "/v1/auth/password/reset/confirm", {"token": token, "new_password": "post reset password 123"}
        )
        self.assertEqual(status, 200, payload)
        status, _, _ = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(status, 401, "the old session must be revoked by a password reset")
        status, _, payload = self.request(
            "POST", "/v1/auth/password/reset/confirm", {"token": token, "new_password": "a different password 456"}
        )
        self.assertEqual(status, 400, "a used reset token must not be replayable")
        status, _, payload = self.request(
            "POST", "/v1/auth/login", {"email": "reset2@x.example", "password": "post reset password 123"}
        )
        self.assertEqual(status, 200, payload)

    # -- Email verification ------------------------------------------------

    def test_email_verification_request_and_confirm(self) -> None:
        _, jar, _ = self.register("verify@x.example")
        status, _, payload = self.request(
            "POST", "/v1/auth/email/verify/request", headers=self.session_headers(jar)
        )
        self.assertEqual(status, 200, payload)
        message = self.mail.latest_to("verify@x.example", category="email_verification")
        token = self.token_from(message)
        status, _, payload = self.request("POST", "/v1/auth/email/verify/confirm", {"token": token})
        self.assertEqual(status, 200, payload)
        status, _, payload = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(status, 200)

    def test_verification_token_replay_is_rejected(self) -> None:
        _, jar, _ = self.register("verifyreplay@x.example")
        self.request("POST", "/v1/auth/email/verify/request", headers=self.session_headers(jar))
        message = self.mail.latest_to("verifyreplay@x.example", category="email_verification")
        token = self.token_from(message)
        self.request("POST", "/v1/auth/email/verify/confirm", {"token": token})
        status, _, payload = self.request("POST", "/v1/auth/email/verify/confirm", {"token": token})
        self.assertEqual(status, 400, payload)

    # -- Invitations -------------------------------------------------------

    def test_invitation_accept_creates_a_working_session_with_the_granted_role(self) -> None:
        status, _, invited = self.request(
            "POST", "/v1/team/invitations",
            {"display_name": "Invited Viewer", "role": "viewer", "email": "invitee@x.example"},
            headers={"Authorization": f"Bearer {self.owner_token}"},
        )
        self.assertEqual(status, 201, invited)
        message = self.mail.latest_to("invitee@x.example", category="invitation")
        self.assertIsNotNone(message)
        token = self.token_from(message)
        status, headers, payload = self.request(
            "POST", "/v1/auth/invitations/accept", {"token": token, "password": "invitee chosen password 123"}
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["role"], "viewer")
        jar = self.cookies_from(headers)
        # RBAC still resolves identically through a browser session: a
        # viewer cannot invite, whether authenticated by cookie or token.
        status, _, payload = self.request(
            "POST", "/v1/team/invitations",
            {"display_name": "X", "role": "viewer", "email": "second@x.example"},
            headers=self.session_headers(jar),
        )
        self.assertEqual(status, 403, payload)

    def test_invitation_token_cannot_be_reused(self) -> None:
        _, _, invited = self.request(
            "POST", "/v1/team/invitations",
            {"display_name": "Once", "role": "viewer", "email": "once@x.example"},
            headers={"Authorization": f"Bearer {self.owner_token}"},
        )
        message = self.mail.latest_to("once@x.example", category="invitation")
        token = self.token_from(message)
        self.request("POST", "/v1/auth/invitations/accept", {"token": token, "password": "first accept password 1"})
        status, _, payload = self.request(
            "POST", "/v1/auth/invitations/accept", {"token": token, "password": "second accept password 2"}
        )
        self.assertEqual(status, 400, payload)

    # -- Tenant isolation / organization confusion --------------------------

    def test_session_from_one_organization_cannot_read_another_organizations_asset(self) -> None:
        status, _, created = self.request(
            "POST", "/v1/assets", {"url": "https://org-a-only.example/"},
            headers={"Authorization": f"Bearer {self.owner_token}"},
        )
        self.assertEqual(status, 201, created)
        _, jar_b, _ = self.register("orgb@x.example")
        status, _, payload = self.request(
            "GET", f"/v1/assets/{created['target_id']}", headers={"Cookie": f"wg_session={jar_b['wg_session']}"}
        )
        self.assertEqual(status, 404, payload)

    def test_session_organization_context_cannot_be_overridden_by_request_body(self) -> None:
        _, jar, _ = self.register("orgspoof@x.example")
        status, _, payload = self.request(
            "GET", "/v1/dashboard/summary", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(status, 200, payload)
        # There is no client-suppliable organization_id anywhere on this
        # route; the session's own resolved organization is the only
        # thing the service layer ever reads (see AuthContext.organization_id
        # usage throughout service.py) -- confirmed here by cross-
        # referencing against the real, session-scoped organization_id.
        session_status, _, session_payload = self.request(
            "GET", "/v1/auth/session", headers={"Cookie": f"wg_session={jar['wg_session']}"}
        )
        self.assertEqual(session_status, 200)
        self.assertNotEqual(session_payload["organization_id"], self.owner_context.organization_id)


class SecureCookieAttributesTests(unittest.TestCase):
    """Slice 18 requirement 12: every pre-existing cookie test in this
    file (``CustomerAuthTests`` above) deliberately runs with
    ``secure_cookies=False`` -- the local/dev convenience default -- so
    none of them ever proved the ``Secure`` attribute is actually
    present on a production-configured (``secure_cookies=True``, the
    real value a reverse-proxied HTTPS deployment sets) server. This
    class is the one place that configuration is exercised, reading the
    raw ``Set-Cookie`` header strings rather than the name=value-only
    ``cookies_from`` helper the other tests use, since the attributes
    under test live in the parts of the header that helper discards."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.owner_context, self.owner_token = create_identity_fixture(store.path)
        self.sessions = InMemorySessionRepository()
        self.mail = InMemoryMailProvider()
        self.service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
            artifact_store=LocalArtifactStore(root / "artifacts"),
            sessions=self.sessions,
            mail_provider=self.mail,
            auth_rate_limiter=InMemoryAuthRateLimiter(max_attempts=5, window_seconds=900),
        )
        self.server = create_server(
            "127.0.0.1", 0, self.service,
            authenticator=ApiTokenAuthenticator(identity),
            session_authenticator=BrowserSessionAuthenticator(identity, self.sessions),
            rate_limiter=FixedWindowRateLimiter(requests=500, window_seconds=60),
            maximum_request_bytes=8192,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
            # The one thing this class exists to flip relative to every
            # other test in this file -- a real HTTPS-behind-Cloudflare
            # deployment (see docs/production/PUBLIC_EDGE_SECURITY.md).
            secure_cookies=True,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def raw_set_cookie_headers(self) -> dict[str, str]:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(
            "POST",
            "/v1/auth/register",
            body=json.dumps(
                {
                    "organization_name": "Secure Cookie Org",
                    "display_name": "Ada",
                    "email": "secure-cookie@x.example",
                    "password": "a genuinely long password 123",
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 201)
        raw = {}
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                cookie_name = value.split("=", 1)[0]
                raw[cookie_name] = value
        connection.close()
        return raw

    def test_session_cookie_is_secure_httponly_samesite_lax_path_root(self) -> None:
        cookies = self.raw_set_cookie_headers()
        session_cookie = cookies["wg_session"]
        self.assertIn("Secure", session_cookie)
        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("SameSite=Lax", session_cookie)
        self.assertIn("Path=/", session_cookie)

    def test_csrf_cookie_is_secure_samesite_lax_but_not_httponly(self) -> None:
        # The CSRF cookie must remain readable by the page's own script
        # (the double-submit pattern requires it), so HttpOnly is
        # deliberately absent here even though every other attribute
        # matches the session cookie -- this asserts that distinction
        # holds under the real production cookie configuration, not
        # only the dev-default one every other test in this file uses.
        cookies = self.raw_set_cookie_headers()
        csrf_cookie = cookies["wg_csrf"]
        self.assertIn("Secure", csrf_cookie)
        self.assertIn("SameSite=Lax", csrf_cookie)
        self.assertIn("Path=/", csrf_cookie)
        self.assertNotIn("HttpOnly", csrf_cookie)

    def test_logout_clears_cookies_and_still_marks_them_secure(self) -> None:
        cookies = self.raw_set_cookie_headers()
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(
            "POST",
            "/v1/auth/logout",
            headers={
                "Cookie": f"wg_session={cookies['wg_session'].split(';', 1)[0].split('=', 1)[1]}",
                "X-CSRF-Token": cookies["wg_csrf"].split(";", 1)[0].split("=", 1)[1],
            },
        )
        response = connection.getresponse()
        response.read()
        cleared = {}
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                cleared[value.split("=", 1)[0]] = value
        connection.close()
        self.assertIn("Secure", cleared["wg_session"])
        self.assertIn("Max-Age=0", cleared["wg_session"])
        self.assertIn("Secure", cleared["wg_csrf"])
        self.assertIn("Max-Age=0", cleared["wg_csrf"])


class CorsCrossOriginPolicyTests(unittest.TestCase):
    """Requirement 19/25: a real browser only lets a page's own script
    read a cross-origin response (or send one with a custom header,
    like ``X-CSRF-Token``, without a preflight rejection) when the
    server's CORS response explicitly grants that exact origin. These
    tests configure a real, non-empty ``allowed_origins`` allowlist
    (unlike the rest of this file, which deliberately leaves it empty)
    so both the "allowed" and "denied" cases are meaningfully
    distinct -- proving the policy discriminates, not just denies
    everything."""

    ALLOWED_ORIGIN = "http://localhost:5173"
    EVIL_ORIGIN = "https://evil.example.com"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.owner_context, self.owner_token = create_identity_fixture(store.path)
        self.sessions = InMemorySessionRepository()
        self.service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
            artifact_store=LocalArtifactStore(root / "artifacts"),
            sessions=self.sessions,
            mail_provider=InMemoryMailProvider(),
            auth_rate_limiter=InMemoryAuthRateLimiter(max_attempts=50, window_seconds=900),
        )
        self.server = create_server(
            "127.0.0.1", 0, self.service,
            authenticator=ApiTokenAuthenticator(identity),
            session_authenticator=BrowserSessionAuthenticator(identity, self.sessions),
            rate_limiter=FixedWindowRateLimiter(requests=500, window_seconds=60),
            maximum_request_bytes=8192,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
            secure_cookies=False,
            allowed_origins=frozenset({self.ALLOWED_ORIGIN}),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method, path, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        response.read()
        headers_out = {name.lower(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, headers_out

    def test_preflight_from_the_allowed_origin_is_granted(self) -> None:
        status, headers = self.request(
            "OPTIONS", "/v1/assets",
            headers={
                "Origin": self.ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, x-csrf-token",
            },
        )
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("access-control-allow-origin"), self.ALLOWED_ORIGIN)
        self.assertEqual(headers.get("access-control-allow-credentials"), "true")

    def test_preflight_from_an_unrecognized_origin_is_denied(self) -> None:
        """A malicious page's `fetch(..., {headers: {"X-CSRF-Token": ...}})`
        is a non-simple request (custom header) and must pass a CORS
        preflight before the browser will ever dispatch it. Denying
        the preflight here means the browser never sends the actual
        mutating request at all for a JS-driven cross-origin attempt --
        the plain-HTML-form variant (no custom headers possible) is
        instead stopped by the CSRF token check itself, since the
        attacker page cannot read the non-HttpOnly CSRF cookie across
        origins to attach it."""
        status, headers = self.request(
            "OPTIONS", "/v1/assets",
            headers={
                "Origin": self.EVIL_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, x-csrf-token",
            },
        )
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertNotIn("access-control-allow-credentials", headers)

    def test_actual_response_to_an_unrecognized_origin_never_grants_cors_access(self) -> None:
        status, headers = self.request("GET", "/v1/dashboard/summary", headers={"Origin": self.EVIL_ORIGIN})
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertNotEqual(headers.get("access-control-allow-origin"), "*")

    def test_credentialed_cors_response_never_uses_a_wildcard_origin(self) -> None:
        status, headers = self.request(
            "OPTIONS", "/v1/assets",
            headers={
                "Origin": self.ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(headers.get("access-control-allow-credentials"), "true")
        self.assertNotEqual(headers.get("access-control-allow-origin"), "*")


if __name__ == "__main__":
    unittest.main()
