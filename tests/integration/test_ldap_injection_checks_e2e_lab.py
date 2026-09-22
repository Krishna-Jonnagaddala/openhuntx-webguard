"""One true end-to-end test of the LDAP-injection active-detection feature:

CLI permit issuance (--active-check active.ldapi.error) -> HTTP API job
submission -> real worker claiming the job -> real ScanJobExecutor ->
active-detector registry lookup -> the error-based LDAP injection
detector -> a CWE-90 NormalizedFinding merged into the persisted report,
read back through the HTTP API's job-result endpoint.

Structurally this is the same chain, scaffolding, and narrowly-justified
mocks as test_sqli_checks_e2e_lab.py; see that file's module docstring
(and test_active_checks_e2e_lab.py's, which it in turn points to) for why
each mock exists: validate_target_url is pointed at the local fixture
because the executor otherwise re-validates the target's URL shape and
would reject "https://ldapi-e2e-lab-fixture.test:<port>/" as an unknown
host; owned_target._public_addresses is patched to skip the public-only
filter because the fixture resolves to 127.0.0.1, a private address the
real filter exists to reject; and ssl.create_default_context is patched
so the scanner's own outbound HTTPS client trusts the fixture's
freshly-generated self-signed certificate. Nothing else about the
pipeline is mocked.

The fixture itself reuses the exact mechanism test_ldap_injection_detector_live.py
already proved works: a real ldap3.Connection on the MOCK_SYNC client
strategy (pure Python, no real LDAP wire connection, no real directory
server) with one fake entry, in front of a vulnerable route that
interpolates the raw "uid" query parameter straight into an LDAP search
filter string. ldap3's own client-side filter compiler genuinely raises
ldap3.core.exceptions.LDAPInvalidFilterError on the detector's diagnostic
value, an unbalanced-parenthesis filter, before any request would reach
a real or mocked directory. See that file's own docstring for the fuller
account of why this is a real filter-parse failure and not a canned
string.
"""

from __future__ import annotations

import http.client
import io
import ipaddress
import json
import os
import re
import ssl
import threading
import time
import unittest
from contextlib import redirect_stdout
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

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException

    _LDAP3_AVAILABLE = True
except ImportError:
    _LDAP3_AVAILABLE = False

from webguard_contracts import (
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    load_webguard_report_json,
    write_owned_target_authorization_file,
)
from webguard_scanner import ValidatedTarget
from webguard_api.cli import main
from webguard_api import (
    ApiTokenAuthenticator,
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

_SEARCH_BASE = "dc=example,dc=com"


def _build_mock_connection():
    """Builds a real ``ldap3.Connection`` on the ``MOCK_SYNC`` strategy
    with one directory entry (``uid=1``). Only ever called from
    ``setUpClass`` on the skip-gated test below, so ``ldap3`` is always
    importable by the time this runs even though the name is not bound
    at module level when the package is missing."""

    server = ldap3.Server("webguard-e2e-lab-fixture-mock")
    connection = ldap3.Connection(
        server,
        user="cn=fixture,dc=example,dc=com",
        password="not-a-real-secret",
        client_strategy=ldap3.MOCK_SYNC,
    )
    connection.strategy.add_entry(
        "uid=1,ou=people,dc=example,dc=com",
        {"objectClass": ["person"], "uid": ["1"], "cn": ["Fixture User"]},
    )
    connection.bind()
    return connection


class _LdapiFixtureHandler(BaseHTTPRequestHandler):
    """A self-submitting search form at "/" whose "uid" parameter is
    interpolated, unescaped, straight into a real ldap3 search filter
    string against a real (mocked-transport) ldap3.Connection -- genuinely
    vulnerable, for this one E2E proof only. See
    test_ldap_injection_detector_live.py for the fuller fixture with a
    safe, escaped control route.

    ``ldap_connection`` is set once, on the class, by ``setUpClass``
    before the server starts serving; nothing here references ``ldap3``
    at class-definition time, so this class is still definable when
    ``ldap3`` is not installed."""

    ldap_connection = None
    _lock = threading.Lock()

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def _respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if "uid" not in query:
            body = (
                b"<html><body>"
                b'<form method="GET" action=""><input name="uid"></form>'
                b"</body></html>"
            )
            self._respond(body)
            return
        value = query["uid"][0]
        search_filter = f"(uid={value})"
        try:
            with self._lock:
                found = self.ldap_connection.search(
                    _SEARCH_BASE, search_filter, attributes=["cn"]
                )
                count = len(self.ldap_connection.entries) if found else 0
            self._respond(f"<html>Results: {count}</html>".encode())
        except LDAPException as exc:
            # Rendered the way a minimal app's own error page or
            # traceback would: the real exception's fully-qualified
            # class name plus its real message, nothing invented.
            qualified = f"{type(exc).__module__}.{type(exc).__qualname__}"
            self._respond(
                f"<html>{qualified}: {exc}</html>".encode(), status=500
            )


def _extract(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    assert match is not None, f"pattern {pattern!r} not found in: {text}"
    return match.group(1)


def _generate_self_signed_certificate(directory: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
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
                    x509.DNSName("ldapi-e2e-lab-fixture.test"),
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
    _LDAP3_AVAILABLE and RUN_INTEGRATION,
    "Set WEBGUARD_RUN_INTEGRATION=1 and pip install ldap3 to run this "
    "end-to-end LDAP-injection lab test.",
)
class LdapInjectionChecksEndToEndLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(
            Path(cls.certificate_directory.name)
        )
        _LdapiFixtureHandler.ldap_connection = _build_mock_connection()
        cls.fixture_server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _LdapiFixtureHandler
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
        cls.target = f"https://ldapi-e2e-lab-fixture.test:{cls.fixture_port}/"
        cls.fixture_url = f"https://127.0.0.1:{cls.fixture_port}/"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()
        cls.fixture_thread.join(timeout=5)
        cls.certificate_directory.cleanup()

    def _validated_target(self) -> ValidatedTarget:
        return ValidatedTarget(
            original_url=self.target,
            normalised_url=self.target,
            scheme="https",
            hostname="ldapi-e2e-lab-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def _trusting_tls_context(self) -> ssl.SSLContext:
        context = _REAL_CREATE_DEFAULT_CONTEXT()
        context.load_verify_locations(cafile=str(self.certificate_path))
        return context

    def test_cli_to_report_end_to_end_ldap_injection(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "jobs.sqlite3"
            auth_dir = root / "authorizations"
            artifacts = root / "artifacts"

            now = datetime.now(timezone.utc)
            authorization_id = "b2c3d4e5-f6a7-4890-9bcd-ef0123456789"
            auth_dir.mkdir(parents=True, exist_ok=True)
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=authorization_id,
                    organization="LDAPi E2E Lab Org",
                    authorized_by="LDAPi E2E Lab Operator",
                    target=self.target,
                    allowed_hosts=("ldapi-e2e-lab-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="True end-to-end LDAP injection active-detection validation",
                    limits=OwnedTargetLimits(),
                ),
                auth_dir / "fixture.json",
            )

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "bootstrap",
                        "--organization",
                        "LDAPi E2E Lab Org",
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
            owner_principal_id = _extract(
                r"Owner principal ID: (\S+)", text
            )
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

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "permit",
                        "issue",
                        "--token",
                        owner_token,
                        "--target",
                        self.target,
                        "--authorization-id",
                        authorization_id,
                        "--mode",
                        "single_page",
                        "--active-check",
                        "active.ldapi.error",
                        "--database",
                        str(database),
                        "--authorizations",
                        str(auth_dir),
                        "--artifacts",
                        str(artifacts),
                    ]
                )
            self.assertEqual(result, 0)
            permit_text = output.getvalue()
            self.assertIn(
                "Active checks authorized: active.ldapi.error", permit_text
            )
            permit_id = _extract(r"Permit ID: (\S+)", permit_text)
            time.sleep(0.6)

            store = ScanJobStore(database)
            identity = IdentityStore(database)
            authorizations = AuthorizationRepository(auth_dir)
            trustscan_signer = TrustScanSigner(
                store.trustscan_signing_private_key()
            )
            executor = ScanJobExecutor(
                authorizations=authorizations,
                store=store,
                trustscan_signer=trustscan_signer,
                artifact_directory=artifacts,
                organization_resolver=store.organization_id_for_job,
                authorization_assignment_checker=(
                    identity.authorization_is_assigned
                ),
            )
            service = WebGuardJobService(
                store=store,
                authorizations=authorizations,
                identity=identity,
                trustscan_signer=trustscan_signer,
            )
            worker = ScanJobWorker(
                store=store, executor=executor, poll_seconds=0.02
            )
            server = create_server(
                "127.0.0.1",
                0,
                service,
                authenticator=ApiTokenAuthenticator(identity),
                rate_limiter=FixedWindowRateLimiter(
                    requests=1000, window_seconds=60
                ),
                maximum_request_bytes=8192,
            )
            stop = threading.Event()
            worker_thread = threading.Thread(
                target=worker.run_forever, args=(stop,), daemon=True
            )
            server_thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )

            with patch(
                "webguard_api.executor.validate_target_url",
                return_value=self._validated_target(),
            ), patch(
                "webguard_scanner.owned_target._public_addresses",
                side_effect=lambda target: target.resolved_addresses,
            ), patch(
                "webguard_scanner.safe_http.ssl.create_default_context",
                side_effect=self._trusting_tls_context,
            ):
                worker_thread.start()
                server_thread.start()
                host, port = server.server_address[:2]
                try:
                    job_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "confirm_authorization": authorization_id,
                            "mode": "single_page",
                        }
                    ).encode("utf-8")
                    connection = http.client.HTTPConnection(
                        host, port, timeout=5
                    )
                    connection.request(
                        "POST",
                        "/v1/jobs",
                        body=job_body,
                        headers={
                            "Authorization": f"Bearer {owner_token}",
                            "TrustScan-Permit": permit_id,
                            "Content-Type": "application/json",
                            "Content-Length": str(len(job_body)),
                            "Idempotency-Key": "e2e-active-ldapi-1",
                        },
                    )
                    response = connection.getresponse()
                    created = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, created)
                    job_id = created["job_id"]

                    deadline = time.monotonic() + 10
                    result_payload = None
                    while time.monotonic() < deadline:
                        connection = http.client.HTTPConnection(
                            host, port, timeout=5
                        )
                        connection.request(
                            "GET",
                            f"/v1/jobs/{job_id}/result",
                            headers={
                                "Authorization": f"Bearer {owner_token}"
                            },
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
                    self.assertEqual(
                        result_payload["state"], "completed", result_payload
                    )
                finally:
                    stop.set()
                    server.shutdown()
                    server.server_close()
                    worker_thread.join(timeout=3)
                    server_thread.join(timeout=3)

            report_path = artifacts / result_payload["report_ref"]
            report = load_webguard_report_json(
                report_path.read_text(encoding="utf-8")
            )
            active_findings = [
                f for f in report.findings if f.source == "webguard-active"
            ]
            self.assertTrue(
                active_findings,
                f"expected an active LDAP injection finding; report "
                f"findings: {[f.identity.rule_id for f in report.findings]}",
            )
            finding = active_findings[0]
            self.assertEqual(
                [i.value for i in finding.identifiers], ["CWE-90"]
            )
            self.assertTrue(
                finding.identity.rule_id.startswith("active.ldapi.error")
            )


if __name__ == "__main__":
    unittest.main()
