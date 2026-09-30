"""True end-to-end test of authorization-comparison (IDOR/BOLA) scanning
(Slice 8):

    register user-A context + register user-B context (real HTTP)
    -> register authorization-comparison plan (real HTTP, resource_scope
       explicitly supplied -- never generated or enumerated)
    -> issue permit (active.authorization.idor + comparison plan, real
       HTTP)
    -> submit job (real HTTP) -> real worker -> real executor
    -> authorization-differential detector -> CWE-639/OWASP-API finding
    -> persisted report -> API retrieval

Uses a purpose-built, clearly-labeled local fixture with two isolated
identities and both a secure and a deliberately vulnerable object-access
endpoint -- not Juice Shop, not a public site.

Scoping note (same as Slice 7's authenticated-scanning E2E test, for the
identical reason): both AuthenticationContextRepository and
AuthorizationComparisonPlanRepository are in-memory only, so this test
constructs the service, executor, and worker directly and shares both
repositories between them, using real HTTP for every step that
references them, exactly mirroring the established pattern.
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
from webguard_api.cli import main
from webguard_api import (
    ApiTokenAuthenticator,
    AuthenticationContextRepository,
    AuthorizationComparisonPlanRepository,
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

_TOKENS = {"user-a": "token-user-a-xyz", "user-b": "token-user-b-xyz"}
_ORDERS = {
    "A-001": {"owner": "user-a", "content": '{"order":"A-001","owner":"user-a","total":42}'},
    "B-001": {"owner": "user-b", "content": '{"order":"B-001","owner":"user-b","total":77}'},
}


class _IdorFixtureHandler(BaseHTTPRequestHandler):
    """Two identities (bearer tokens), secure and vulnerable order-lookup
    endpoints sharing the same underlying data, plus a shared/public
    endpoint for false-positive coverage."""

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def _identity(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[len("Bearer ") :]
        for identity, expected in _TOKENS.items():
            if token == expected:
                return identity
        return None

    def _respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        identity = self._identity()

        if parsed.path == "/api/public/info":
            self._respond(b'{"info":"public, same for everyone"}')
            return

        if parsed.path == "/api/shared/team-document":
            if identity is None:
                self._respond(b'{"error":"unauthenticated"}', status=403)
                return
            self._respond(b'{"document":"team roadmap, shared by design"}')
            return

        if parsed.path.startswith("/api/orders/"):
            order_id = parsed.path.rsplit("/", 1)[-1]
            order = _ORDERS.get(order_id)
            if identity is None:
                self._respond(b'{"error":"unauthenticated"}', status=403)
                return
            if order is None:
                self._respond(b'{"error":"not found"}', status=404)
                return
            # SECURE: ownership is actually checked.
            if order["owner"] != identity:
                self._respond(b'{"error":"forbidden"}', status=403)
                return
            self._respond(order["content"].encode())
            return

        if parsed.path.startswith("/api/orders-vuln/"):
            order_id = parsed.path.rsplit("/", 1)[-1]
            order = _ORDERS.get(order_id)
            if identity is None:
                self._respond(b'{"error":"unauthenticated"}', status=403)
                return
            if order is None:
                self._respond(b'{"error":"not found"}', status=404)
                return
            # VULNERABLE: any authenticated identity, regardless of who,
            # gets the real content -- no ownership check at all.
            self._respond(order["content"].encode())
            return

        self._respond(b'{"error":"not found"}', status=404)


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
                    x509.DNSName("idor-e2e-lab-fixture.test"),
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


_REAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context


@unittest.skipUnless(
    RUN_INTEGRATION, "Set WEBGUARD_RUN_INTEGRATION=1 to run this end-to-end lab test."
)
class IdorAuthorizationEndToEndLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(
            Path(cls.certificate_directory.name)
        )
        cls.fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _IdorFixtureHandler)
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
        cls.target = f"https://idor-e2e-lab-fixture.test:{cls.fixture_port}/"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()
        cls.fixture_thread.join(timeout=5)
        cls.certificate_directory.cleanup()

    def _validated_target(self) -> object:
        from webguard_scanner import ValidatedTarget

        return ValidatedTarget(
            original_url=self.target,
            normalised_url=self.target,
            scheme="https",
            hostname="idor-e2e-lab-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def _trusting_tls_context(self) -> ssl.SSLContext:
        context = _REAL_CREATE_DEFAULT_CONTEXT()
        context.load_verify_locations(cafile=str(self.certificate_path))
        return context

    def test_full_idor_comparison_pipeline(self) -> None:
        with TemporaryDirectory() as directory, patch(
            "webguard_scanner.safe_http.ssl.create_default_context",
            side_effect=self._trusting_tls_context,
        ):
            root = Path(directory)
            database = root / "jobs.sqlite3"
            auth_dir = root / "authorizations"
            artifacts = root / "artifacts"

            now = datetime.now(timezone.utc)
            authorization_id = "b1b2b3b4-c5c6-4978-8899-aabbccddeeff"
            auth_dir.mkdir(parents=True, exist_ok=True)
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=authorization_id,
                    organization="IDOR E2E Lab Org",
                    authorized_by="IDOR E2E Lab Operator",
                    target=self.target,
                    allowed_hosts=("idor-e2e-lab-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="True end-to-end IDOR/BOLA validation",
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
                        "IDOR E2E Lab Org",
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
            shared_comparison_plans = AuthorizationComparisonPlanRepository()
            executor = ScanJobExecutor(
                authorizations=authorizations,
                store=store,
                trustscan_signer=trustscan_signer,
                artifact_directory=artifacts,
                organization_resolver=store.organization_id_for_job,
                authorization_assignment_checker=identity.authorization_is_assigned,
                authentication_contexts=shared_authentication_contexts,
                authorization_comparison_plans=shared_comparison_plans,
            )
            service = WebGuardJobService(
                store=store,
                authorizations=authorizations,
                identity=identity,
                trustscan_signer=trustscan_signer,
                authentication_contexts=shared_authentication_contexts,
                authorization_comparison_plans=shared_comparison_plans,
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
            worker_thread = threading.Thread(target=worker.run_forever, args=(stop,), daemon=True)
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
                    # -- Register user-A and user-B authentication contexts (real HTTP) --
                    context_ids = {}
                    for label, token in _TOKENS.items():
                        body = json.dumps(
                            {
                                "target": self.target,
                                "authorization_id": authorization_id,
                                "identity_label": label,
                                "method": "bearer_token",
                                "expires_at": (now + timedelta(days=1))
                                .isoformat(timespec="microseconds")
                                .replace("+00:00", "Z"),
                                "bearer_token": token,
                            }
                        ).encode("utf-8")
                        connection = http.client.HTTPConnection(host, port, timeout=5)
                        connection.request(
                            "POST",
                            "/v1/authentication-contexts",
                            body=body,
                            headers={
                                "Authorization": f"Bearer {owner_token}",
                                "Content-Type": "application/json",
                                "Content-Length": str(len(body)),
                            },
                        )
                        response = connection.getresponse()
                        payload = json.loads(response.read())
                        connection.close()
                        self.assertEqual(response.status, 201, payload)
                        context_ids[label] = payload["authentication_context_id"]

                    # -- Register the comparison plan (real HTTP), resource_scope
                    # explicitly supplied -- both the secure and the vulnerable
                    # endpoint, plus a shared resource for false-positive proof.
                    resource_scope = [
                        {
                            "resource_type": "order",
                            "method": "GET",
                            "primary_endpoint": f"{self.target}api/orders/A-001",
                            "secondary_endpoint": f"{self.target}api/orders/B-001",
                            "identifier_location": "path",
                            "identifier_name": "id",
                            "expected_access": "private_to_owner",
                        },
                        {
                            "resource_type": "order-vuln",
                            "method": "GET",
                            "primary_endpoint": f"{self.target}api/orders-vuln/A-001",
                            "secondary_endpoint": f"{self.target}api/orders-vuln/B-001",
                            "identifier_location": "path",
                            "identifier_name": "id",
                            "expected_access": "private_to_owner",
                        },
                        {
                            "resource_type": "shared_document",
                            "method": "GET",
                            "primary_endpoint": f"{self.target}api/shared/team-document",
                            "secondary_endpoint": f"{self.target}api/shared/team-document",
                            "identifier_location": "none",
                            "identifier_name": "",
                            "expected_access": "shared",
                        },
                    ]
                    plan_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "primary_context_id": context_ids["user-a"],
                            "secondary_context_id": context_ids["user-b"],
                            "resource_scope": resource_scope,
                            "expires_at": (now + timedelta(days=1))
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                        }
                    ).encode("utf-8")
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request(
                        "POST",
                        "/v1/authorization-comparisons",
                        body=plan_body,
                        headers={
                            "Authorization": f"Bearer {owner_token}",
                            "Content-Type": "application/json",
                            "Content-Length": str(len(plan_body)),
                        },
                    )
                    response = connection.getresponse()
                    plan_payload = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, plan_payload)
                    comparison_plan_id = plan_payload["comparison_plan_id"]

                    # -- Issue the permit (real HTTP): IDOR active_check +
                    # the comparison plan reference, both required together.
                    permit_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "confirm_authorization": authorization_id,
                            "permitted_modes": ["single_page"],
                            "allowed_http_methods": ["GET", "HEAD"],
                            # Computed fresh here, not from the outer
                            # `now` captured before this test's earlier
                            # real HTTP round-trips (login, context/
                            # plan setup) -- on a loaded CI runner
                            # those alone can exceed a small fixed
                            # buffer measured from a stale timestamp,
                            # making not_before arrive already in the
                            # past and get rejected by the server's
                            # (correct) anti-backdating check.
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
                            "active_checks": ["active.authorization.idor"],
                            "authentication_context_id": None,
                            "authorization_comparison_plan_id": comparison_plan_id,
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
                        permit_payload["permit"]["claims"][
                            "authorization_comparison_plan_id"
                        ],
                        comparison_plan_id,
                    )
                    time.sleep(0.6)

                    # -- Submit the job (real HTTP) --
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
                            "Idempotency-Key": "idor-e2e-1",
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
                    self.assertEqual(result_payload["state"], "completed", result_payload)
                finally:
                    stop.set()
                    server.shutdown()
                    server.server_close()
                    worker_thread.join(timeout=3)
                    server_thread.join(timeout=3)

            report_path = artifacts / result_payload["report_ref"]
            report_text = report_path.read_text(encoding="utf-8")
            report = load_webguard_report_json(report_text)
            idor_findings = [f for f in report.findings if "idor" in f.tags]
            self.assertTrue(
                idor_findings,
                f"expected an IDOR finding on the vulnerable endpoint; "
                f"report findings: {[f.identity.rule_id for f in report.findings]}",
            )
            finding = idor_findings[0]
            cwe_values = [i.value for i in finding.identifiers if i.namespace == "CWE"]
            self.assertEqual(cwe_values, ["CWE-639"])
            owasp_values = [
                i.value for i in finding.identifiers if i.namespace == "OWASP-API"
            ]
            self.assertTrue(owasp_values)
            self.assertIn("orders-vuln", finding.identity.path)
            # The secure endpoint and the shared resource must never
            # appear as findings.
            self.assertFalse(
                any("orders/" in f.identity.path and "vuln" not in f.identity.path
                    for f in idor_findings)
            )
            self.assertFalse(any("shared" in f.identity.path for f in idor_findings))

            # Bearer tokens must never appear anywhere in the report.
            self.assertNotIn(_TOKENS["user-a"], report_text)
            self.assertNotIn(_TOKENS["user-b"], report_text)


if __name__ == "__main__":
    unittest.main()
