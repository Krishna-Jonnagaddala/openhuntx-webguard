"""True end-to-end test of XXE/callback detection:

    register target authorization (real HTTP via CLI)
    -> TrustScan permit containing active.xxe.callback (real HTTP)
    -> job (real HTTP) -> real worker -> real executor
    -> discovery (POST-form candidate on the fixture's root page)
    -> request template built directly (XXE replaces the whole body,
       not through mutate())
    -> callback registration (real CallbackRepository)
    -> XXE probe (real HTTP POST of a crafted application/xml document
       to the fixture)
    -> the fixture's own vulnerable expat parser performs a real
       outbound fetch of the entity's SYSTEM identifier
    -> callback observed (real HTTP, real socket, real receiver)
    -> normalized CWE-611 finding
    -> report persisted, then retrieved over the real HTTP API

Structurally this is a near line-for-line mirror of
test_ssrf_callback_e2e_lab.py: same TLS fixture setup, same real
CallbackRepository/CallbackHttpReceiver wired into ScanJobExecutor's
callback_repository parameter, same three narrowly-justified patches
(validate_target_url, owned_target._public_addresses, ssl.create_
default_context). See that file, and test_sqli_checks_e2e_lab.py, for
why each of those three patches exists. This file's fixture is
different because XXE's own detector is: it replaces an entire request
body with a crafted XML document rather than substituting one
parameter's value, so the vulnerable route here is a real
xml.parsers.expat parser with a deliberately-assigned
ExternalEntityRefHandler, the identical mechanism already proven in
test_xxe_callback_detector_live.py, not a form field being echoed or
concatenated into a query.
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
import urllib.request
import xml.parsers.expat
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

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
from webguard_api.callback_server import CallbackHttpReceiver
from webguard_api.callback_service import CallbackRepository

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


def _external_entity_ref_handler(context, base, system_id, public_id):
    """Genuinely resolves an external entity: fetches whatever URL the
    posted document's SYSTEM identifier names, for real, over a real
    socket, before letting expat continue. Any failure is swallowed,
    the same way a real vulnerable application's own error handling
    would swallow it, since the point of the attack is the outbound
    request itself, not its response. Identical in every respect to
    the handler already proven in test_xxe_callback_detector_live.py.
    """

    if system_id:
        try:
            with urllib.request.urlopen(system_id, timeout=3):
                pass
        except Exception:
            pass
    return 1


class _XxeE2eFixtureHandler(BaseHTTPRequestHandler):
    """A dual-purpose root route. GET renders a self-submitting POST
    form, the shape the executor's discovery step needs to produce a
    POST-form candidate. POST parses the raw request body with a real,
    deliberately vulnerable expat parser, regardless of what the
    "comment" field says: the detector under test discards the whole
    posted body and content type before this route ever sees it, and
    sends its own crafted application/xml document instead."""

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def do_GET(self) -> None:  # noqa: N802
        body = (
            b"<html><body>"
            b'<form method="POST" action=""><input name="comment"></form>'
            b"</body></html>"
        )
        self._respond(200, body, content_type="text/html; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""

        parser = xml.parsers.expat.ParserCreate()
        # The vulnerable line: an application choosing to resolve
        # external entities instead of leaving this unset.
        parser.ExternalEntityRefHandler = _external_entity_ref_handler
        try:
            parser.Parse(body, True)
        except xml.parsers.expat.ExpatError:
            # Whatever happened (or didn't) during parsing already
            # happened; a parse error here isn't this route's concern.
            pass

        # The detector never reads this response body for
        # classification, only whether a callback arrives, so 200 is
        # returned regardless of what parsing did.
        self._respond(200, b"processed")

    def _respond(self, status: int, body: bytes, *, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
                    x509.DNSName("xxe-e2e-lab-fixture.test"),
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
class XxeCallbackEndToEndLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(
            Path(cls.certificate_directory.name)
        )
        cls.fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _XxeE2eFixtureHandler)
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
        cls.target = f"https://xxe-e2e-lab-fixture.test:{cls.fixture_port}/"

        cls.callback_repository = CallbackRepository(base_url="http://127.0.0.1:0/")
        cls.callback_receiver = CallbackHttpReceiver(cls.callback_repository)
        cls.callback_receiver.start()
        cls.callback_repository.set_base_url(cls.callback_receiver.base_url)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()
        cls.fixture_thread.join(timeout=5)
        cls.callback_receiver.stop()
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
            hostname="xxe-e2e-lab-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def _run_job_with_active_checks(self, active_checks: list[str]):
        """Runs one full permit -> job -> worker -> executor pipeline
        with the given active_checks and returns the persisted report.
        Every test method gets a fresh org/database/artifact directory
        so permit/job state never leaks between scenarios."""

        with TemporaryDirectory() as directory, patch(
            "webguard_scanner.safe_http.ssl.create_default_context",
            side_effect=self._trusting_tls_context,
        ):
            root = Path(directory)
            database = root / "jobs.sqlite3"
            auth_dir = root / "authorizations"
            artifacts = root / "artifacts"

            now = datetime.now(timezone.utc)
            authorization_id = "c3c3c3c3-d4d4-4555-9999-bbccddeeff00"
            auth_dir.mkdir(parents=True, exist_ok=True)
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=authorization_id,
                    organization="XXE E2E Lab Org",
                    authorized_by="XXE E2E Lab Operator",
                    target=self.target,
                    allowed_hosts=("xxe-e2e-lab-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="True end-to-end XXE/callback validation",
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
                        "XXE E2E Lab Org",
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
            executor = ScanJobExecutor(
                authorizations=authorizations,
                store=store,
                trustscan_signer=trustscan_signer,
                artifact_directory=artifacts,
                organization_resolver=store.organization_id_for_job,
                authorization_assignment_checker=identity.authorization_is_assigned,
                callback_repository=self.callback_repository,
            )
            service = WebGuardJobService(
                store=store,
                authorizations=authorizations,
                identity=identity,
                trustscan_signer=trustscan_signer,
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
                    permit_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "confirm_authorization": authorization_id,
                            "permitted_modes": ["single_page"],
                            # POST is required here, not just GET: the
                            # XXE probe itself is a POST of a crafted
                            # XML document, and to_request_templates
                            # only projects a POST-form candidate when
                            # the binding permit's own
                            # allowed_http_methods claim includes POST.
                            "allowed_http_methods": ["GET", "POST"],
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
                            "active_checks": active_checks,
                            "authentication_context_id": None,
                            "authorization_comparison_plan_id": None,
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
                            "Idempotency-Key": f"xxe-e2e-{'-'.join(active_checks) or 'passive'}",
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
            return load_webguard_report_json(report_text), report_text

    def test_full_xxe_callback_pipeline(self) -> None:
        report, _ = self._run_job_with_active_checks(["active.xxe.callback"])

        active_findings = [f for f in report.findings if f.source == "webguard-active"]
        self.assertTrue(
            active_findings,
            f"expected an active XXE finding; report findings: "
            f"{[f.identity.rule_id for f in report.findings]}",
        )
        finding = active_findings[0]
        self.assertEqual([i.value for i in finding.identifiers], ["CWE-611"])
        self.assertTrue(finding.identity.rule_id.startswith("active.xxe.callback"))


if __name__ == "__main__":
    unittest.main()
