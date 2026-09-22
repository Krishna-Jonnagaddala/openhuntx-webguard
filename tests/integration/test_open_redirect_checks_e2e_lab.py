"""One true end-to-end test of the open-redirect active-detection feature:

CLI permit issuance (--active-check active.openredirect.location) -> HTTP API job
submission -> real worker claiming the job -> real ScanJobExecutor ->
active-detector registry lookup -> the open-redirect detector -> a
CWE-601 NormalizedFinding merged into the persisted report, read back
through the HTTP API's job-result endpoint.

Uses a purpose-built, clearly-labeled local vulnerable-redirect fixture,
explicitly not a public site. Structurally this is the same chain,
scaffolding, and narrowly-justified patches as test_sqli_checks_e2e_lab.py
(the SQLi true E2E test); see that file's module docstring for why each
patch exists. This file focuses its comments on what is specific to open
redirect rather than repeating that rationale.

Unlike the SQLi detector, open redirect has no PROBABLE tier (see
open_redirect_detector.py's module docstring and its OpenRedirectOutcome
enum: the evidence is a structural host match, not a content signature
with a weaker reading), so a real, successful diagnostic redirect is
expected to land on CONFIRMED directly, with no intermediate tier to
account for.
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


class _OpenRedirectFixtureHandler(BaseHTTPRequestHandler):
    """A self-submitting form at "/" whose "next" parameter drives a real,
    unconditional 302 redirect: genuinely vulnerable, for this one E2E
    proof only. See test_open_redirect_detector_live.py for the fuller
    fixture with a safe fixed-destination control and a body-echo control."""

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def _redirect(self, location: str, status: int = 302) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if "next" not in query:
            body = (
                b"<html><body>"
                b'<form method="GET" action=""><input name="next"></form>'
                b"</body></html>"
            )
            self._respond(body)
            return
        value = query["next"][0]
        # A real, unconditional open redirect: the raw client value becomes
        # the Location header with no allowlist and no host check.
        self._redirect(value)


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
                    x509.DNSName("openredirect-e2e-lab-fixture.test"),
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
    RUN_INTEGRATION,
    "Set WEBGUARD_RUN_INTEGRATION=1 to run this end-to-end lab test.",
)
class OpenRedirectChecksEndToEndLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(
            Path(cls.certificate_directory.name)
        )
        cls.fixture_server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _OpenRedirectFixtureHandler
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
        cls.target = (
            f"https://openredirect-e2e-lab-fixture.test:{cls.fixture_port}/"
        )
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
            hostname="openredirect-e2e-lab-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def _trusting_tls_context(self) -> ssl.SSLContext:
        context = _REAL_CREATE_DEFAULT_CONTEXT()
        context.load_verify_locations(cafile=str(self.certificate_path))
        return context

    def test_cli_to_report_end_to_end_open_redirect(self) -> None:
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
                    organization="Open Redirect E2E Lab Org",
                    authorized_by="Open Redirect E2E Lab Operator",
                    target=self.target,
                    allowed_hosts=("openredirect-e2e-lab-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="True end-to-end open-redirect active-detection validation",
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
                        "Open Redirect E2E Lab Org",
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
                        "active.openredirect.location",
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
                "Active checks authorized: active.openredirect.location",
                permit_text,
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
                            "Idempotency-Key": "e2e-active-openredirect-1",
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
                f"expected an active open-redirect finding; report findings: "
                f"{[f.identity.rule_id for f in report.findings]}",
            )
            finding = active_findings[0]
            self.assertEqual(
                [i.value for i in finding.identifiers], ["CWE-601"]
            )
            self.assertTrue(
                finding.identity.rule_id.startswith(
                    "active.openredirect.location"
                )
            )


if __name__ == "__main__":
    unittest.main()
