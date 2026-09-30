"""One true end-to-end test of the active-detection feature:

CLI permit issuance -> HTTP API job submission -> real worker claiming the
job -> real ScanJobExecutor -> active-detector registry lookup ->
reflected-XSS detector -> a NormalizedFinding merged into the persisted
report.

Uses a purpose-built, clearly-labeled local HTTP fixture (a self-
submitting reflected-XSS search form on 127.0.0.1) -- explicitly NOT
Juice Shop and NOT a public site, per this slice's own instruction. Slice
1/2 already established that Juice Shop has no server-side reflection
surface for this detector's methodology; this test instead proves the
detector correctly fires end-to-end through the real orchestration when
one genuinely exists, under real HTTP, real permit/RBAC enforcement, and
the real runtime safety engine.

Three things are mocked, all narrowly and all explained here rather than
left implicit:

1. `webguard_api.executor.validate_target_url` -- pointed at the local
   fixture's loopback address, the same, already-established convention
   every other lab-integration test in this repository uses for local
   targets (production SSRF/commercial-mode validation correctly rejects
   loopback, so tests targeting a local fixture patch this one function,
   never the detection pipeline itself).
2. `webguard_scanner.owned_target._public_addresses` -- the owned-target
   preflight independently re-validates that resolved addresses are
   public (defense in depth beyond validate_target_url, and a real,
   deliberate security property of ScanJobExecutor that this test does
   not want to weaken for everyone else). It is patched to skip the
   public-only filter for this one loopback fixture address, exactly
   parallel to (1) and for the identical reason.
3. `ssl.create_default_context` (scoped to `webguard_scanner.safe_http`
   only) -- returns a context that trusts a real, freshly generated,
   self-signed certificate for this test's fixture server instead of the
   system CA bundle. `CERT_REQUIRED` and `check_hostname` remain fully
   enforced and are exercised for real: this is exactly what a private
   test CA is for, not a weakening of TLS verification. This is needed
   because `ScanJobExecutor`'s owned-target preflight requires an HTTPS
   target with no lab-mode exception -- unlike the passive-scan-only lab
   tests elsewhere in this repository, this test genuinely runs the full
   production executor, so the fixture must terminate real TLS.

Everything else in the executor -- permit binding/revalidation, the
runtime safety engine, owned-target preflight's non-address checks,
active-detector discovery and probing -- runs completely for real.
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

# Captured before any patching: webguard_scanner.safe_http.ssl is the same
# module object as this file's own `ssl` import, so patching
# ssl.create_default_context patches it everywhere, including here.
# _trusting_tls_context below must call this captured original, not
# ssl.create_default_context, or it recurses into its own mock.
_REAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context


class _ReflectedXssFixtureHandler(BaseHTTPRequestHandler):
    """A clearly-labeled synthetic vulnerable page: a self-submitting
    search form that reflects ?q= unescaped. Loopback-only."""

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if "q" in query:
            value = query["q"][0]
            body = f"<html><body>{value}</body></html>".encode()
        else:
            body = (
                b"<html><body>"
                b'<form method="GET" action="">'
                b'<input name="q">'
                b"</form></body></html>"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _extract(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    assert match is not None, f"pattern {pattern!r} not found in: {text}"
    return match.group(1)


def _generate_self_signed_certificate(directory: Path) -> Path:
    """A real, freshly generated, self-signed certificate for 127.0.0.1,
    written to a PEM file. Used as this test's private trust anchor (see
    the module docstring) -- not a stand-in for real certificate
    validation, which stays fully enforced against this exact CA."""

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
                    x509.DNSName("e2e-lab-fixture.test"),
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
class ActiveChecksEndToEndLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(
            Path(cls.certificate_directory.name)
        )

        cls.fixture_server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _ReflectedXssFixtureHandler
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
        # OwnedTargetAuthorization requires a DNS hostname, not an IP
        # literal -- e2e-lab-fixture.test (RFC 2606 reserved test TLD) is
        # never actually resolved, since validate_target_url is mocked;
        # the real connection (see _validated_target) goes to 127.0.0.1,
        # matching the fixture certificate's IP SAN.
        cls.target = f"https://e2e-lab-fixture.test:{cls.fixture_port}/"
        cls.fixture_url = f"https://127.0.0.1:{cls.fixture_port}/"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()
        cls.fixture_thread.join(timeout=5)
        cls.certificate_directory.cleanup()

    def _validated_target(self) -> ValidatedTarget:
        # normalised_url/hostname must exactly match the authorization's
        # canonical target string (a separate cross-check in
        # validate_owned_target_preflight, beyond validate_target_url).
        # Only resolved_addresses drives the real TCP connection, to the
        # fixture's actual loopback port; the certificate carries a
        # matching DNS SAN so TLS hostname verification passes for real.
        return ValidatedTarget(
            original_url=self.target,
            normalised_url=self.target,
            scheme="https",
            hostname="e2e-lab-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def _trusting_tls_context(self) -> ssl.SSLContext:
        context = _REAL_CREATE_DEFAULT_CONTEXT()
        context.load_verify_locations(cafile=str(self.certificate_path))
        return context

    def test_cli_to_report_end_to_end_reflected_xss(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "jobs.sqlite3"
            auth_dir = root / "authorizations"
            artifacts = root / "artifacts"

            # -- Authorization (fixture-owned, wide real-clock window) --
            now = datetime.now(timezone.utc)
            authorization_id = "f1e2d3c4-b5a6-4978-8899-aabbccddeeff"
            auth_dir.mkdir(parents=True, exist_ok=True)
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=authorization_id,
                    organization="E2E Lab Org",
                    authorized_by="E2E Lab Operator",
                    target=self.target,
                    allowed_hosts=("e2e-lab-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="True end-to-end active-detection validation",
                    limits=OwnedTargetLimits(),
                ),
                auth_dir / "fixture.json",
            )

            # -- CLI: bootstrap owner ------------------------------------
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "bootstrap",
                        "--organization",
                        "E2E Lab Org",
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

            # -- CLI: assign the authorization ----------------------------
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

            # -- CLI: issue a permit authorizing the reflected-XSS check --
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
                        "active.xss.reflected",
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
                "Active checks authorized: active.xss.reflected",
                permit_text,
            )
            permit_id = _extract(r"Permit ID: (\S+)", permit_text)
            # The CLI's not_before carries a small forward buffer (see
            # cli.py) so a fresh permit isn't rejected as backdated by the
            # service's own, slightly-later clock read; a realistic
            # operator pause covers it here too.
            time.sleep(0.6)

            # -- Real API + real worker (real executor, real detector) --
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
                            "Idempotency-Key": "e2e-active-xss-1",
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
                        result_payload["state"],
                        "completed",
                        result_payload,
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
                f"expected an active finding; report findings: "
                f"{[f.identity.rule_id for f in report.findings]}",
            )
            finding = active_findings[0]
            self.assertEqual(
                [i.value for i in finding.identifiers], ["CWE-79"]
            )
            self.assertIn(finding.confidence.value, ("confirmed", "high"))


if __name__ == "__main__":
    unittest.main()
