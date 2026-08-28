"""True end-to-end test of authenticated scanning (Slice 7):

    login (execute_login) -> register authentication context (real HTTP)
    -> issue authenticated permit (real HTTP) -> submit job (real HTTP)
    -> real worker -> real executor -> authenticated discovery ->
    RequestTemplate -> reflected-XSS detector -> finding -> report
    (real HTTP retrieval)

Uses a purpose-built, clearly-labeled local fixture with two isolated
identities (user-a, user-b) -- not Juice Shop, not a public site.

Scoping note (stated here rather than left implicit): the authentication
context repository is deliberately in-memory only (see
webguard_api.authentication_contexts's module docstring for why). It
does not persist across separate OS-process invocations the way the
SQLite-backed job/permit/identity stores do, so this test constructs the
service, executor, and worker directly (as the pre-existing
test_active_checks_e2e_lab.py already does for its own "real API + real
worker" section) and shares one repository instance between them, rather
than issuing the authentication-context-registration step through
separate `webguard-api` CLI subprocess invocations. Every other step
(permit issuance, job submission, job-result retrieval) goes through
real HTTP over a real socket, exactly like the existing active-checks
E2E test.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import ssl
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from webguard_contracts import (
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    load_webguard_report_json,
    write_owned_target_authorization_file,
)
from webguard_scanner import ActiveDetectionPolicy, FetchPolicy, ValidatedTarget
from webguard_scanner.login_workflow import (
    LoginCredentials,
    LoginSuccessCriterion,
    LoginWorkflow,
    execute_login,
)
from webguard_api.cli import main
from webguard_api import (
    ApiTokenAuthenticator,
    AuthenticationContextRepository,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    IdentityStore,
    ScanJobExecutor,
    ScanJobStore,
    ScanJobWorker,
    TrustScanSigner,
    WebGuardJobService,
    create_server,
)

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"

_REAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context

_USERS = {"user-a": "correct-horse-battery-staple-a", "user-b": "correct-horse-battery-staple-b"}


class _AuthenticatedFixtureHandler(BaseHTTPRequestHandler):
    """Two isolated identities (user-a, user-b), five routes:
    /login, /public, /account, /api/profile, /logout.

    /account and /api/profile only reveal real content with a valid
    session cookie; /api/profile reflects ?q= unescaped (deliberate,
    bounded XSS surface for the detector) only when authenticated.
    """

    sessions: dict[str, str] = {}

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def _respond(
        self, body: bytes, *, status: int = 200, headers: list[tuple[str, str]] | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _session_identity(self) -> str | None:
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                return self.sessions.get(value)
        return None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        identity = self._session_identity()

        if parsed.path in ("/", "/public"):
            self._respond(b"<html><body>Public page. Nothing sensitive here.</body></html>")
            return

        if parsed.path == "/account":
            if identity is None:
                self._respond(b"<html><body>Please log in to view your account.</body></html>")
                return
            body = (
                f"<html><body>Welcome, {identity}!"
                f'<form method="GET" action="/api/profile"><input name="q"></form>'
                f"</body></html>"
            ).encode()
            self._respond(body)
            return

        if parsed.path == "/api/profile":
            if identity is None:
                self._respond(b"<html><body>Please log in.</body></html>")
                return
            value = parse_qs(parsed.query).get("q", [""])[0]
            body = f"<html><body>Profile for {identity}: {value}</body></html>".encode()
            self._respond(body)
            return

        if parsed.path == "/logout":
            cookie_header = self.headers.get("Cookie", "")
            for part in cookie_header.split(";"):
                name, _, value = part.strip().partition("=")
                if name == "session":
                    self.sessions.pop(value, None)
            self._respond(b"<html><body>Logged out.</body></html>")
            return

        self._respond(b"<html><body>not found</body></html>", status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != "/login":
            self._respond(b"<html><body>not found</body></html>", status=404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b""
        fields = parse_qs(raw_body.decode())
        username = fields.get("username", [""])[0]
        password = fields.get("password", [""])[0]
        if _USERS.get(username) == password:
            token = f"tok-{username}-{len(self.sessions)}"
            self.sessions[token] = username
            self._respond(
                b"",
                status=302,
                headers=[("Location", "/account"), ("Set-Cookie", f"session={token}; Path=/")],
            )
            return
        self._respond(b"<html><body>Invalid credentials.</body></html>", status=200)


def _extract(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    assert match is not None, f"pattern {pattern!r} not found in: {text}"
    return match.group(1)


def _generate_self_signed_certificate(directory: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.DNSName("auth-e2e-lab-fixture.test"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "fixture-cert.pem"
    with open(cert_path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    return cert_path


@unittest.skipUnless(
    RUN_INTEGRATION, "Set WEBGUARD_RUN_INTEGRATION=1 to run this end-to-end lab test."
)
class AuthenticatedScanningEndToEndLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(
            Path(cls.certificate_directory.name)
        )
        _AuthenticatedFixtureHandler.sessions = {}
        cls.fixture_server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _AuthenticatedFixtureHandler
        )
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(certfile=cls.certificate_path)
        cls.fixture_server.socket = tls_context.wrap_socket(
            cls.fixture_server.socket, server_side=True
        )
        cls.fixture_thread = threading.Thread(
            target=cls.fixture_server.serve_forever, daemon=True
        )
        cls.fixture_thread.start()
        cls.fixture_port = cls.fixture_server.server_address[1]
        cls.target = f"https://auth-e2e-lab-fixture.test:{cls.fixture_port}/account"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()
        cls.fixture_thread.join(timeout=5)
        cls.certificate_directory.cleanup()

    def _validated_target(self, path: str = "/account") -> ValidatedTarget:
        url = f"https://auth-e2e-lab-fixture.test:{self.fixture_port}{path}"
        return ValidatedTarget(
            original_url=url,
            normalised_url=url,
            scheme="https",
            hostname="auth-e2e-lab-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def _trusting_tls_context(self) -> ssl.SSLContext:
        context = _REAL_CREATE_DEFAULT_CONTEXT()
        context.load_verify_locations(cafile=str(self.certificate_path))
        return context

    def test_authenticated_pages_are_unreachable_without_login(self) -> None:
        """Sanity precondition for the rest of this test: an
        unauthenticated fetch of /account never reveals the real page."""
        target = self._validated_target()
        with patch(
            "webguard_scanner.safe_http.ssl.create_default_context",
            side_effect=self._trusting_tls_context,
        ):
            from webguard_scanner.safe_http import fetch_once

            response = fetch_once(target, method="GET", policy=FetchPolicy())
        self.assertNotIn(b"Welcome", response.body)
        self.assertIn(b"Please log in", response.body)

    def test_full_authenticated_scanning_pipeline(self) -> None:
        with TemporaryDirectory() as directory, patch(
            "webguard_scanner.safe_http.ssl.create_default_context",
            side_effect=self._trusting_tls_context,
        ):
            root = Path(directory)
            database = root / "jobs.sqlite3"
            auth_dir = root / "authorizations"
            artifacts = root / "artifacts"

            # -- Step 1: acquire a real session by actually logging in ---
            # (mirrors what a future `webguard-api login` CLI helper would
            # automate; not built this slice -- see the phase 7 audit doc)
            login_target = self._validated_target("/login")
            login_workflow = LoginWorkflow(
                target_url=f"https://auth-e2e-lab-fixture.test:{self.fixture_port}/login",
                method="POST",
                content_type="application/x-www-form-urlencoded",
                username_field="username",
                password_field="password",
                success=LoginSuccessCriterion(expected_redirect_contains="/account"),
            )
            login_policy = ActiveDetectionPolicy(
                fetch_policy=FetchPolicy(allowed_methods=frozenset({"GET", "HEAD", "POST"}))
            )
            login_result = execute_login(
                login_target,
                login_workflow,
                LoginCredentials(username="user-a", password=_USERS["user-a"]),
                policy=login_policy,
            )
            self.assertTrue(login_result.success, login_result.reason)
            self.assertEqual(len(login_result.cookies), 1)
            session_cookie = login_result.cookies[0]
            self.assertEqual(session_cookie.name, "session")

            # -- Authorization (fixture-owned, wide real-clock window) --
            now = datetime.now(timezone.utc)
            authorization_id = "a1a2a3a4-b5b6-4978-8899-aabbccddeeff"
            auth_dir.mkdir(parents=True, exist_ok=True)
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=authorization_id,
                    organization="Auth E2E Lab Org",
                    authorized_by="Auth E2E Lab Operator",
                    target=self.target,
                    allowed_hosts=("auth-e2e-lab-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="True end-to-end authenticated-scanning validation",
                    limits=OwnedTargetLimits(),
                ),
                auth_dir / "fixture.json",
            )

            # -- CLI: bootstrap owner --------------------------------------
            import io
            from contextlib import redirect_stdout

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "bootstrap",
                        "--organization",
                        "Auth E2E Lab Org",
                        "--principal",
                        "Owner",
                        "--database",
                        str(database),
                        "--authorizations",
                        str(auth_dir),
                        "--artifacts",
                        str(artifacts),
                    ]
                )
            self.assertEqual(result, 0)
            text = output.getvalue()
            organization_id = _extract(r"Organization ID: (\S+)", text)
            owner_principal_id = _extract(r"Owner principal ID: (\S+)", text)
            owner_token = _extract(r"API token: (\S+)", text)

            with redirect_stdout(io.StringIO()):
                result = main(
                    [
                        "authorization",
                        "assign",
                        "--organization-id",
                        organization_id,
                        "--principal-id",
                        owner_principal_id,
                        "--authorization-id",
                        authorization_id,
                        "--database",
                        str(database),
                        "--authorizations",
                        str(auth_dir),
                        "--artifacts",
                        str(artifacts),
                    ]
                )
            self.assertEqual(result, 0)

            # -- Real API + real worker, sharing one AuthenticationContextRepository --
            store = ScanJobStore(database)
            identity = IdentityStore(database)
            authorizations = AuthorizationRepository(auth_dir)
            trustscan_signer = TrustScanSigner(store.trustscan_signing_private_key())
            shared_authentication_contexts = AuthenticationContextRepository()
            executor = ScanJobExecutor(
                authorizations=authorizations,
                store=store,
                trustscan_signer=trustscan_signer,
                artifact_directory=artifacts,
                organization_resolver=store.organization_id_for_job,
                authorization_assignment_checker=identity.authorization_is_assigned,
                authentication_contexts=shared_authentication_contexts,
            )
            service = WebGuardJobService(
                store=store,
                authorizations=authorizations,
                identity=identity,
                trustscan_signer=trustscan_signer,
                authentication_contexts=shared_authentication_contexts,
            )
            worker = ScanJobWorker(store=store, executor=executor, poll_seconds=0.02)
            server = create_server(
                "127.0.0.1",
                0,
                service,
                authenticator=ApiTokenAuthenticator(identity),
                rate_limiter=FixedWindowRateLimiter(requests=1000, window_seconds=60),
                maximum_request_bytes=16384,
            )
            stop = threading.Event()
            worker_thread = threading.Thread(target=worker.run_forever, args=(stop,), daemon=True)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)

            with patch(
                "webguard_api.executor.validate_target_url",
                side_effect=lambda *a, **k: self._validated_target(),
            ), patch(
                "webguard_scanner.owned_target._public_addresses",
                side_effect=lambda target: target.resolved_addresses,
            ):
                worker_thread.start()
                server_thread.start()
                host, port = server.server_address[:2]
                try:
                    # -- Step 2: register the authentication context (real HTTP) --
                    context_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "identity_label": "user-a",
                            "method": "cookie_session",
                            "expires_at": (now + timedelta(days=1))
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                            "cookies": [
                                {
                                    "name": session_cookie.name,
                                    "value": session_cookie.value,
                                    "domain": "auth-e2e-lab-fixture.test",
                                    "port": self.fixture_port,
                                    "path": "/",
                                }
                            ],
                        }
                    ).encode("utf-8")
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request(
                        "POST",
                        "/v1/authentication-contexts",
                        body=context_body,
                        headers={
                            "Authorization": f"Bearer {owner_token}",
                            "Content-Type": "application/json",
                            "Content-Length": str(len(context_body)),
                        },
                    )
                    response = connection.getresponse()
                    context_payload = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, context_payload)
                    authentication_context_id = context_payload["authentication_context_id"]
                    # The secret must never be echoed back over the wire.
                    self.assertNotIn(session_cookie.value, json.dumps(context_payload))

                    # -- Step 3: issue an authenticated, XSS-authorized permit (real HTTP) --
                    permit_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "confirm_authorization": authorization_id,
                            "permitted_modes": ["single_page"],
                            "allowed_http_methods": ["GET", "HEAD"],
                            # Computed fresh here, not from the outer
                            # `now` captured before this test's earlier
                            # real HTTP round-trips (login, context
                            # setup) -- on a loaded CI runner those
                            # alone can exceed a small fixed buffer
                            # measured from a stale timestamp, making
                            # not_before arrive already in the past and
                            # get rejected by the server's (correct)
                            # anti-backdating check.
                            "not_before": (
                                datetime.now(timezone.utc) + timedelta(milliseconds=500)
                            )
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                            "expires_at": (now + timedelta(days=7))
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                            "maximum_request_attempts": 15,
                            "maximum_requests_per_second": 1.0,
                            "maximum_concurrency": 1,
                            "active_checks": ["active.xss.reflected"],
                            "authentication_context_id": authentication_context_id,
                            "authorization_comparison_plan_id": None,
                        }
                    ).encode("utf-8")
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request(
                        "POST",
                        "/v1/permits",
                        body=permit_body,
                        headers={
                            "Authorization": f"Bearer {owner_token}",
                            "Content-Type": "application/json",
                            "Content-Length": str(len(permit_body)),
                        },
                    )
                    response = connection.getresponse()
                    permit_payload = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, permit_payload)
                    permit_id = permit_payload["permit"]["claims"]["permit_id"]
                    self.assertEqual(
                        permit_payload["permit"]["claims"]["authentication_context_id"],
                        authentication_context_id,
                    )
                    time.sleep(0.6)

                    # -- Step 4: submit the scan job (real HTTP) --
                    job_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "confirm_authorization": authorization_id,
                            "mode": "single_page",
                        }
                    ).encode("utf-8")
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request(
                        "POST",
                        "/v1/jobs",
                        body=job_body,
                        headers={
                            "Authorization": f"Bearer {owner_token}",
                            "TrustScan-Permit": permit_id,
                            "Content-Type": "application/json",
                            "Content-Length": str(len(job_body)),
                            "Idempotency-Key": "auth-e2e-1",
                        },
                    )
                    response = connection.getresponse()
                    created = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, created)
                    job_id = created["job_id"]

                    # -- Step 5: wait for the real worker to finish --
                    deadline = time.monotonic() + 10
                    result_payload = None
                    while time.monotonic() < deadline:
                        connection = http.client.HTTPConnection(host, port, timeout=5)
                        connection.request(
                            "GET",
                            f"/v1/jobs/{job_id}/result",
                            headers={"Authorization": f"Bearer {owner_token}"},
                        )
                        response = connection.getresponse()
                        payload = json.loads(response.read())
                        connection.close()
                        if response.status == 200:
                            result_payload = payload
                            break
                        time.sleep(0.05)
                    self.assertIsNotNone(result_payload)
                    assert result_payload is not None
                    self.assertEqual(result_payload["state"], "completed", result_payload)

                    # -- Audit trail check while the server is still up --
                    # (real HTTP), which recorded both the authentication-
                    # context registration and the authenticated-permit
                    # issuance.
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request(
                        "GET",
                        "/v1/audit-events",
                        headers={"Authorization": f"Bearer {owner_token}"},
                    )
                    response = connection.getresponse()
                    audit_events_text = response.read().decode()
                    connection.close()
                    self.assertEqual(response.status, 200, audit_events_text)
                    self.assertNotIn(session_cookie.value, audit_events_text)
                    self.assertNotIn(_USERS["user-a"], audit_events_text)
                    self.assertIn(
                        "authentication_contexts.register", audit_events_text
                    )
                finally:
                    stop.set()
                    server.shutdown()
                    server.server_close()
                    worker_thread.join(timeout=3)
                    server_thread.join(timeout=3)

            # -- Step 6: verify the finding, and that credentials never leaked --
            report_path = artifacts / result_payload["report_ref"]
            report_text = report_path.read_text(encoding="utf-8")
            report = load_webguard_report_json(report_text)
            active_findings = [f for f in report.findings if f.source == "webguard-active"]
            self.assertTrue(
                active_findings,
                f"expected an active finding on the authenticated page; "
                f"report findings: {[f.identity.rule_id for f in report.findings]}",
            )
            finding = active_findings[0]
            self.assertEqual([i.value for i in finding.identifiers], ["CWE-79"])
            self.assertIn("/api/profile", finding.identity.path)

            # Credentials/session values must never appear anywhere in the
            # persisted report, regardless of finding content.
            self.assertNotIn(session_cookie.value, report_text)
            self.assertNotIn(_USERS["user-a"], report_text)

            # Nor in the owned-target preflight audit file.
            audit_path = artifacts / result_payload["audit_ref"]
            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertNotIn(session_cookie.value, audit_text)
            self.assertNotIn(_USERS["user-a"], audit_text)

if __name__ == "__main__":
    unittest.main()
