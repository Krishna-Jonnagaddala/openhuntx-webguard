"""Slice 18 requirement 13: trusted-proxy-aware client IP resolution.

`CF-Connecting-IP`/`X-Forwarded-For` must only ever be honored when the
*direct* TCP peer is itself inside a configured trusted-proxy network
-- never from an arbitrary direct client. This is what every rate-limit
bucket key and audit `ip_address` field is derived from
(`_resolve_client_ip` in http_api.py), so getting it wrong either lets
a shared proxy IP pool every real client's quota together, or lets an
attacker spoof an arbitrary source IP into abuse protection and audit
logging.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import tempfile
import threading
import unittest
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
from webguard_api.mail import InMemoryMailProvider
from webguard_api.sessions import InMemorySessionRepository

from tests.unit.service_test_support import NOW, create_identity_fixture, write_authorization


class _TrustedProxyTestCase(unittest.TestCase):
    """Shared harness -- only `trusted_proxy_networks` varies between
    subclasses below."""

    trusted_proxy_networks: frozenset = frozenset()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.owner_context, self.owner_token = create_identity_fixture(store.path)
        self.identity = identity
        self.mail = InMemoryMailProvider()
        self.service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
            artifact_store=LocalArtifactStore(root / "artifacts"),
            sessions=InMemorySessionRepository(),
            mail_provider=self.mail,
            auth_rate_limiter=InMemoryAuthRateLimiter(max_attempts=3, window_seconds=900),
        )
        self.server = create_server(
            "127.0.0.1",
            0,
            self.service,
            authenticator=ApiTokenAuthenticator(identity),
            session_authenticator=BrowserSessionAuthenticator(identity, self.service.sessions),
            rate_limiter=FixedWindowRateLimiter(requests=500, window_seconds=60),
            maximum_request_bytes=8192,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
            secure_cookies=False,
            trusted_proxy_networks=self.trusted_proxy_networks,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def login_attempt(self, email: str, *, forwarded_for: str | None = None, cf_connecting_ip: str | None = None):
        headers = {"Content-Type": "application/json"}
        if forwarded_for is not None:
            headers["X-Forwarded-For"] = forwarded_for
        if cf_connecting_ip is not None:
            headers["CF-Connecting-IP"] = cf_connecting_ip
        body = json.dumps({"email": email, "password": "wrong password entirely"}).encode()
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request("POST", "/v1/auth/login", body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        connection.close()
        return response.status


class UntrustedProxyDefaultTests(_TrustedProxyTestCase):
    """Default: no trusted proxies configured -- headers are never
    read at all, matching every pre-Slice-18 deployment exactly."""

    trusted_proxy_networks = frozenset()

    def test_forwarded_headers_are_ignored_and_share_one_bucket(self) -> None:
        # Both "distinct" claimed IPs actually share the real peer's
        # (127.0.0.1's) rate-limit bucket, since the header is never
        # honored without a configured trust relationship.
        for _ in range(6):
            self.login_attempt("nobody@x.example", cf_connecting_ip="1.1.1.1")
        status = self.login_attempt("nobody@x.example", cf_connecting_ip="2.2.2.2")
        self.assertEqual(status, 429, "the real peer's own bucket should already be exhausted")


class TrustedProxyTests(_TrustedProxyTestCase):
    """127.0.0.1/32 is configured as a trusted proxy -- the test
    client's own connections all originate from 127.0.0.1, so this
    exercises the "peer is a trusted proxy" branch for real."""

    trusted_proxy_networks = frozenset({ipaddress.ip_network("127.0.0.1/32")})

    def test_cf_connecting_ip_is_honored_and_gives_each_claimed_ip_its_own_bucket(self) -> None:
        statuses = [self.login_attempt("nobody@x.example", cf_connecting_ip="9.9.9.9") for _ in range(6)]
        self.assertIn(429, statuses, "9.9.9.9's own bucket should have been exhausted")
        # A DIFFERENT claimed IP must get its own, unexhausted bucket.
        status = self.login_attempt("nobody@x.example", cf_connecting_ip="8.8.8.8")
        self.assertNotEqual(status, 429)

    def test_x_forwarded_for_leftmost_entry_is_used_when_cf_header_absent(self) -> None:
        statuses = [
            self.login_attempt("nobody@x.example", forwarded_for="7.7.7.7, 127.0.0.1") for _ in range(6)
        ]
        self.assertIn(429, statuses)
        status = self.login_attempt("nobody@x.example", forwarded_for="6.6.6.6, 127.0.0.1")
        self.assertNotEqual(status, 429)

    def test_cf_connecting_ip_takes_priority_over_x_forwarded_for(self) -> None:
        for _ in range(6):
            self.login_attempt("nobody@x.example", cf_connecting_ip="5.5.5.5", forwarded_for="4.4.4.4")
        # Exhausted under 5.5.5.5 (CF header wins) -- 4.4.4.4 alone
        # (no CF header) must still have its own, unexhausted bucket.
        status = self.login_attempt("nobody@x.example", forwarded_for="4.4.4.4")
        self.assertNotEqual(status, 429)

    def test_malformed_forwarded_header_falls_back_to_the_real_peer(self) -> None:
        statuses = [
            self.login_attempt("nobody@x.example", cf_connecting_ip="not-an-ip-address") for _ in range(6)
        ]
        self.assertIn(429, statuses, "an unparseable header must fall back to the real (rate-limited) peer")


if __name__ == "__main__":
    unittest.main()
