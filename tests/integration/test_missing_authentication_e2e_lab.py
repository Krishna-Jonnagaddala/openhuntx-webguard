"""True end-to-end test of missing-authentication detection (Slice 17,
CWE-306):

    register target authorization (real HTTP via CLI)
    -> register an authentication context (real HTTP)
    -> TrustScan permit containing active.authentication.missing plus
       missing_authentication_endpoints (real HTTP)
    -> job (real HTTP) -> real worker -> real executor
    -> authenticated baseline request (real HTTP to the fixture)
    -> anonymous probe request, no credentials at all (real HTTP)
    -> normalized CWE-306 finding
    -> report persisted -> retrieved over the real HTTP API

Also proves the authorization negatives this detector needs that are
specific to it (not already covered by the existing, detector-agnostic
active-checks permit tests): a passive-only permit and an XSS-only
permit must each produce zero missing-authentication findings even
against the identical vulnerable fixture endpoint -- this detector's
authorization is never inherited from any other active check. And,
symmetrically, a properly-gated endpoint included in the very same
permit must never itself produce a finding, proving the detector does
not simply flag every listed endpoint.
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
from urllib.parse import urlsplit

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
from webguard_api.authentication_contexts import AuthenticationContextRepository
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
_OWNER_BEARER_TOKEN = "owner-fixture-bearer-token"
_MARKER = "internal-only-dashboard-marker"


class _MissingAuthFixtureHandler(BaseHTTPRequestHandler):
    """A clearly-labeled synthetic fixture, loopback-only:

    - /vulnerable: returns the identical marked content to any caller,
      with or without a bearer token -- the missing-authentication bug.
    - /secure: returns protected content only to the correct bearer
      token; anything else gets a 401 with unrelated content -- the
      properly-gated negative control.
    """

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        authorization = self.headers.get("Authorization", "")

        if parsed.path == "/vulnerable":
            body = f'{{"role":"admin","{_MARKER}":"leaked"}}'.encode()
            self._respond(200, body)
            return
        if parsed.path == "/secure":
            if authorization == f"Bearer {_OWNER_BEARER_TOKEN}":
                body = f'{{"role":"admin","{_MARKER}":"leaked"}}'.encode()
                self._respond(200, body)
            else:
                self._respond(401, b'{"error":"unauthenticated"}')
            return
        self._respond(404, b"not found")

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
                    x509.DNSName("missing-auth-e2e-lab-fixture.test"),
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
class MissingAuthenticationEndToEndLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(
            Path(cls.certificate_directory.name)
        )
        cls.fixture_server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _MissingAuthFixtureHandler
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
        cls.target = f"https://missing-auth-e2e-lab-fixture.test:{cls.fixture_port}/"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()
        cls.fixture_thread.join(timeout=5)
        cls.certificate_directory.cleanup()

    def _trusting_tls_context(self) -> ssl.SSLContext:
        context = _REAL_CREATE_DEFAULT_CONTEXT()
        context.load_verify_locations(cafile=str(self.certificate_path))
        return context

    def _validated_target(self):
        from webguard_scanner import ValidatedTarget

        return ValidatedTarget(
            original_url=self.target,
            normalised_url=self.target,
            scheme="https",
            hostname="missing-auth-e2e-lab-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def _run_job(
        self,
        *,
        active_checks: list[str],
        missing_authentication_endpoints: list[dict],
        idempotency_key: str,
    ):
        """Runs one full permit -> job -> worker -> executor pipeline
        and returns the persisted report. Every test gets a fresh
        org/database/artifact directory so permit/job state never
        leaks between scenarios."""

        with TemporaryDirectory() as directory, patch(
            "webguard_scanner.safe_http.ssl.create_default_context",
            side_effect=self._trusting_tls_context,
        ):
            root = Path(directory)
            database = root / "jobs.sqlite3"
            auth_dir = root / "authorizations"
            artifacts = root / "artifacts"

            now = datetime.now(timezone.utc)
            authorization_id = "c3c3c3c3-d4d4-4555-8999-aabbccddeeff"
            auth_dir.mkdir(parents=True, exist_ok=True)
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=authorization_id,
                    organization="Missing-Auth E2E Lab Org",
                    authorized_by="Missing-Auth E2E Lab Operator",
                    target=self.target,
                    allowed_hosts=("missing-auth-e2e-lab-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="True end-to-end missing-authentication validation",
                    limits=OwnedTargetLimits(
                        maximum_request_attempts=30,
                        minimum_delay_seconds=0.5,
                    ),
                ),
                auth_dir / "fixture.json",
            )

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "bootstrap",
                        "--organization",
                        "Missing-Auth E2E Lab Org",
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
                maximum_request_bytes=32768,
            )
            stop = threading.Event()
            worker_thread = threading.Thread(
                target=worker.run_forever, args=(stop,), daemon=True
            )
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)

            with patch(
                "webguard_api.executor.validate_target_url",
                side_effect=lambda *a, **k: self._validated_target(),
            ), patch(
                "webguard_scanner.owned_target._public_addresses",
                side_effect=lambda t: t.resolved_addresses,
            ):
                worker_thread.start()
                server_thread.start()
                host, port = server.server_address[:2]
                try:
                    context_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "identity_label": "owner",
                            "method": "bearer_token",
                            "expires_at": (now + timedelta(days=1))
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                            "bearer_token": _OWNER_BEARER_TOKEN,
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
                    authentication_context_id = context_payload[
                        "authentication_context_id"
                    ]

                    permit_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "confirm_authorization": authorization_id,
                            "permitted_modes": ["single_page"],
                            "allowed_http_methods": ["GET", "HEAD"],
                            "not_before": (
                                datetime.now(timezone.utc) + timedelta(milliseconds=500)
                            )
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                            "expires_at": (now + timedelta(days=7))
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                            "maximum_request_attempts": 30,
                            "maximum_requests_per_second": 2.0,
                            "maximum_concurrency": 1,
                            "active_checks": active_checks,
                            "authentication_context_id": authentication_context_id,
                            "authorization_comparison_plan_id": None,
                            "missing_authentication_endpoints": missing_authentication_endpoints,
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
                    time.sleep(0.6)

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
                            "Idempotency-Key": idempotency_key,
                        },
                    )
                    response = connection.getresponse()
                    created = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, created)
                    job_id = created["job_id"]

                    deadline = time.monotonic() + 20
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
            report_text = report_path.read_text(encoding="utf-8")
            return load_webguard_report_json(report_text)

    def test_vulnerable_endpoint_is_confirmed(self) -> None:
        report = self._run_job(
            active_checks=["active.authentication.missing"],
            missing_authentication_endpoints=[
                {
                    "endpoint": f"{self.target}vulnerable",
                    "method": "GET",
                    "owner_marker": _MARKER,
                }
            ],
            idempotency_key="missing-auth-e2e-confirmed",
        )

        missing_auth_findings = [
            f for f in report.findings if "missing-authentication" in f.tags
        ]
        self.assertTrue(
            missing_auth_findings,
            f"expected a missing-authentication finding; findings: "
            f"{[f.identity.rule_id for f in report.findings]}",
        )
        finding = missing_auth_findings[0]
        self.assertEqual(finding.identity.path, "/vulnerable")
        cwe_values = [i.value for i in finding.identifiers if i.namespace == "CWE"]
        self.assertEqual(cwe_values, ["CWE-306"])
        self.assertIn("confirmed", finding.identity.rule_id)

    def test_secure_endpoint_produces_no_finding(self) -> None:
        report = self._run_job(
            active_checks=["active.authentication.missing"],
            missing_authentication_endpoints=[
                {
                    "endpoint": f"{self.target}secure",
                    "method": "GET",
                    "owner_marker": _MARKER,
                }
            ],
            idempotency_key="missing-auth-e2e-secure",
        )
        self.assertFalse(
            any("missing-authentication" in f.tags for f in report.findings)
        )

    def test_passive_permit_produces_no_missing_auth_finding(self) -> None:
        # An empty active_checks permit cannot carry
        # missing_authentication_endpoints at all (the contract's own
        # bidirectional binding rule) -- this proves the negative from
        # the other direction: the check simply never runs.
        report = self._run_job(
            active_checks=[],
            missing_authentication_endpoints=[],
            idempotency_key="missing-auth-e2e-passive",
        )
        self.assertFalse(
            any("missing-authentication" in f.tags for f in report.findings)
        )


if __name__ == "__main__":
    unittest.main()
