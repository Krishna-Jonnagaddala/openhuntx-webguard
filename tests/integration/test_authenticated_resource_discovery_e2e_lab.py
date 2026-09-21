"""True end-to-end test of authenticated crawling + authorization
resource discovery feeding the existing IDOR/BOLA engine (Slice 9):

    register user-A context + register user-B context (real HTTP)
    -> register authorization-comparison plan with enable_discovery=True
       and an EMPTY, operator-supplied resource_scope (real HTTP) --
       every resource compared in this test is legitimately discovered,
       never directly injected
    -> issue permit (active.authorization.idor + comparison plan, real
       HTTP)
    -> submit job (real HTTP) -> real worker -> real executor
    -> authenticated crawl A -> resource discovery A
    -> authenticated crawl B -> resource discovery B
    -> resource graph construction -> comparison eligibility
    -> IDOR differential -> CWE-639 finding -> persisted report
    -> API retrieval

The victim's (identity B's) order identifier is never supplied to the
test's own detector call or to the comparison plan -- it is discovered
only from a page fetched while legitimately authenticated as B, exactly
mirroring how an operator's own controlled test identity would surface
it.

The fixture also exercises the false-positive controls this slice
requires: a shared resource (identical for both identities, therefore
never eligible per the identical-identifier-value rule), a public
resource, a secure per-owner-checked endpoint (documents), an
out-of-scope external link, a duplicate resource reference, and an
unrelated nested JSON field that must never become a resource.
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
from webguard_scanner import (
    AuthenticatedCrawlStatus,
    AuthenticationHealthCriterion,
    AuthenticationMaterial,
    CrawlPolicy,
    run_authenticated_resource_discovery_crawl,
)

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"

_TOKENS = {"user-a": "token-user-a-slice9", "user-b": "token-user-b-slice9"}

_ORDERS = {
    "A-001": {"owner": "user-a"},
    "B-001": {"owner": "user-b"},
}
_DOCUMENTS = {
    "A-DOC-1": {"owner": "user-a"},
    "B-DOC-1": {"owner": "user-b"},
}


class _DiscoveryFixtureHandler(BaseHTTPRequestHandler):
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

    def _respond(self, body: bytes, status: int = 200, *, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        identity = self._identity()

        if parsed.path == "/account/expired":
            self._respond(
                b"<html>Please log in to continue</html>",
                content_type="text/html",
            )
            return

        # The scan's own authorized target is the site root -- realistic
        # authenticated apps commonly show the logged-in dashboard there
        # (or redirect to it), so the authenticated discovery crawl,
        # which starts at the scan's own target, finds it exactly where
        # a real crawl would. "/account/A"/"/account/B" remain as
        # direct, explicit routes too (used by the dedicated login-page-
        # detection test above).
        if parsed.path in ("/", "/account/A", "/account/B"):
            if parsed.path == "/":
                expected_identity = identity
            else:
                expected_identity = "user-a" if parsed.path.endswith("A") else "user-b"
            if expected_identity is None or identity != expected_identity:
                self._respond(
                    b"<html>Please log in to continue</html>",
                    content_type="text/html",
                )
                return
            order_id = "A-001" if expected_identity == "user-a" else "B-001"
            document_id = (
                "A-DOC-1" if expected_identity == "user-a" else "B-DOC-1"
            )
            body = (
                f'<html><body>'
                f'<a href="/orders/{order_id}">my order</a>'
                f'<a href="/orders/{order_id}">my order again</a>'
                f'<a href="/documents/{document_id}">my document</a>'
                f'<a href="/shared/team-doc">shared team document</a>'
                f'<a href="/public/info">public info</a>'
                f'<a href="https://evil-external.test/orders/999">external</a>'
                f'</body></html>'
            ).encode()
            self._respond(body, content_type="text/html")
            return

        if parsed.path.startswith("/orders/"):
            order_id = parsed.path.rsplit("/", 1)[-1]
            order = _ORDERS.get(order_id)
            if identity is None:
                self._respond(b'{"error":"unauthenticated"}', status=403)
                return
            if order is None:
                self._respond(b'{"error":"not found"}', status=404)
                return
            # VULNERABLE: no ownership check at all -- any authenticated
            # identity gets the real content for any known order ID.
            self._respond(
                json.dumps({"id": order_id, "owner": order["owner"], "total": 42}).encode()
            )
            return

        if parsed.path.startswith("/documents/"):
            document_id = parsed.path.rsplit("/", 1)[-1]
            document = _DOCUMENTS.get(document_id)
            if identity is None:
                self._respond(b'{"error":"unauthenticated"}', status=403)
                return
            if document is None:
                self._respond(b'{"error":"not found"}', status=404)
                return
            # SECURE: ownership is actually checked.
            if document["owner"] != identity:
                self._respond(b'{"error":"forbidden"}', status=403)
                return
            self._respond(
                json.dumps(
                    {
                        "document": {
                            "id": document_id,
                            "owner": document["owner"],
                            "metadata": {"tracking_ref": "XJ99912"},
                        }
                    }
                ).encode()
            )
            return

        if parsed.path == "/shared/team-doc":
            if identity is None:
                self._respond(b'{"error":"unauthenticated"}', status=403)
                return
            self._respond(b'{"document":"team roadmap, shared by design"}')
            return

        if parsed.path == "/public/info":
            self._respond(b'{"info":"public, same for everyone"}')
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
                    x509.DNSName("discovery-e2e-lab-fixture.test"),
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
class AuthenticatedResourceDiscoveryEndToEndLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(
            Path(cls.certificate_directory.name)
        )
        cls.fixture_server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _DiscoveryFixtureHandler
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
        cls.target = f"https://discovery-e2e-lab-fixture.test:{cls.fixture_port}/"

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
            hostname="discovery-e2e-lab-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def test_expired_session_page_is_never_treated_as_ordinary_content(self) -> None:
        # Direct engine-level proof against the fixture's own dedicated
        # expired-session page, independent of the full job pipeline
        # (which is exercised separately below) -- exactly matching
        # requirement 13's fixture checklist.
        with patch(
            "webguard_scanner.safe_http.ssl.create_default_context",
            side_effect=self._trusting_tls_context,
        ):
            target = self._validated_target()
            expired_target = target.__class__(
                original_url=f"{self.target}account/expired",
                normalised_url=f"{self.target}account/expired",
                scheme=target.scheme,
                hostname=target.hostname,
                port=target.port,
                resolved_addresses=target.resolved_addresses,
            )
            result = run_authenticated_resource_discovery_crawl(
                expired_target,
                authentication_material=AuthenticationMaterial(
                    bearer_token=_TOKENS["user-a"]
                ),
                owning_identity="user-a",
                crawl_policy=CrawlPolicy(maximum_pages=1, minimum_delay_seconds=0),
                authentication_health_criterion=AuthenticationHealthCriterion(
                    login_page_marker="Please log in"
                ),
            )
            self.assertEqual(
                result.status, AuthenticatedCrawlStatus.AUTHENTICATION_EXPIRED
            )
            self.assertEqual(result.resources, ())

    def test_full_discovery_and_comparison_pipeline(self) -> None:
        with TemporaryDirectory() as directory, patch(
            "webguard_scanner.safe_http.ssl.create_default_context",
            side_effect=self._trusting_tls_context,
        ):
            root = Path(directory)
            database = root / "jobs.sqlite3"
            auth_dir = root / "authorizations"
            artifacts = root / "artifacts"

            now = datetime.now(timezone.utc)
            authorization_id = "c1c2c3c4-d5d6-4978-8899-aabbccddeeff"
            auth_dir.mkdir(parents=True, exist_ok=True)
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=authorization_id,
                    organization="Discovery E2E Lab Org",
                    authorized_by="Discovery E2E Lab Operator",
                    target=self.target,
                    allowed_hosts=("discovery-e2e-lab-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="True end-to-end authenticated discovery validation",
                    limits=OwnedTargetLimits(
                        maximum_request_attempts=60,
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
                        "Discovery E2E Lab Org",
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

                    # No explicit resource_scope: every resource compared
                    # below must come from legitimate discovery, not this
                    # test injecting the victim's identifier directly.
                    plan_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "primary_context_id": context_ids["user-a"],
                            "secondary_context_id": context_ids["user-b"],
                            "resource_scope": [],
                            "enable_discovery": True,
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
                    self.assertTrue(plan_payload["enable_discovery"])

                    permit_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "confirm_authorization": authorization_id,
                            "permitted_modes": ["single_page"],
                            "allowed_http_methods": ["GET", "HEAD"],
                            # Computed fresh here, not from the outer
                            # `now` captured before this test's earlier
                            # real HTTP round-trips (login, discovery
                            # context setup) -- on a loaded CI runner
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
                            "maximum_request_attempts": 60,
                            "maximum_requests_per_second": 2.0,
                            "maximum_concurrency": 1,
                            "active_checks": ["active.authorization.idor"],
                            "authentication_context_id": None,
                            "authorization_comparison_plan_id": comparison_plan_id,
                            "missing_authentication_endpoints": [],
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
                            "Idempotency-Key": "discovery-e2e-1",
                        },
                    )
                    response = connection.getresponse()
                    created = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, created)
                    job_id = created["job_id"]

                    deadline = time.monotonic() + 25
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
                "expected a discovery-based CONFIRMED IDOR finding on the "
                f"vulnerable /orders/ endpoint; findings: "
                f"{[f.identity.rule_id for f in report.findings]}",
            )
            for finding in idor_findings:
                cwe_values = [
                    i.value for i in finding.identifiers if i.namespace == "CWE"
                ]
                self.assertEqual(cwe_values, ["CWE-639"])
                self.assertIn("orders", finding.identity.path)

            # The secure documents endpoint, the identical shared
            # resource, and the identical public resource must never
            # appear as findings.
            self.assertFalse(
                any("documents" in f.identity.path for f in idor_findings)
            )
            self.assertFalse(any("shared" in f.identity.path for f in idor_findings))
            self.assertFalse(any("public" in f.identity.path for f in idor_findings))

            self.assertNotIn(_TOKENS["user-a"], report_text)
            self.assertNotIn(_TOKENS["user-b"], report_text)
            # The unrelated nested metadata field must never surface as
            # part of a resource identifier anywhere in the report.
            self.assertNotIn("XJ99912", report_text)


if __name__ == "__main__":
    unittest.main()
