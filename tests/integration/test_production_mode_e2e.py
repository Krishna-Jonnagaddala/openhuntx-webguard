"""The production-mode end-to-end proof (Slice 13 requirement 22):

    environment=production, database_backend=postgresql
    -> ProductionServiceConfig -> WebGuardPostgresPool -> real PostgreSQL
    -> create organization/principal/API token (PostgresIdentityRepository)
    -> authorize a target (filesystem OwnedTargetAuthorization, assigned
       via PostgresIdentityRepository -- unchanged from every prior slice)
    -> issue a TrustScan permit over real HTTP (KmsSigningProvider,
       against a fake-but-cryptographically-real KMS client)
    -> submit a scan job over real HTTP (PostgresJobRepository)
    -> a real worker claims and executes it (PostgresJobRepository's
       atomic lease, unchanged Scanner v1 detection pipeline)
    -> a finding is persisted (PostgresFindingRepository)
    -> the scan record completes (PostgresScanRepository)
    -> the finding is retrieved back over real HTTP (GET /v1/findings)

No AWS or public infrastructure is used: `_FakeKmsClient` performs real
ECDSA P-256/SHA-256 signing with the `cryptography` library locally,
matching AWS KMS's own request/response shape (DER-encoded signature
and DER SubjectPublicKeyInfo public key) closely enough that
`KmsSigningProvider`'s verification path is exercised for real -- only
the network boundary to AWS is substituted, exactly as
`webguard_api.signing`'s own module docstring anticipates for tests.
Requires a real PostgreSQL reachable at `WEBGUARD_POSTGRES_TEST_DSN`
(see `infra/compose/compose.postgres.yml`) with migrations applied.
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
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from webguard_contracts import (
    OrganizationRole,
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    PrincipalType,
    load_webguard_report_json,
    write_owned_target_authorization_file,
)
from webguard_scanner import ValidatedTarget
from webguard_api.http_api import create_server
from webguard_api.production_config import ProductionServiceConfig
from webguard_api.production_startup import build_production_components

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_PRODUCTION_E2E = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

# P1-2 Phase H: create_target and record_finding now run under
# api_tenant_data/worker_tenant_data respectively (see postgres_pool.py's
# tenant_connection and postgres_targets.py/postgres_findings.py's own
# methods), so this real build_production_components-backed E2E needs
# the same role/ACL/function/runtime-grant bootstrap
# tests/contract/test_identity_repository_contract.py's own setUpClass
# applies, in the same order: exactly what a real deployment must also
# apply before this code ever runs against it.
_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
_ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
_TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
_FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
_CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"
_RUNTIME_GRANT_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_runtime_grant.sql"
_ALL_BOOTSTRAP_ROLES = (
    "api_tenant_data",
    "worker_tenant_data",
    "scheduler_tenant_data",
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
)

_REAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context


class _FakeKmsClient:
    """Duck-typed `KmsClientProtocol` performing real ECDSA P-256/
    SHA-256 signing in-process -- no AWS credentials, no network call.
    Response shapes (DER signature, DER SubjectPublicKeyInfo public
    key) match AWS KMS's real `Sign`/`GetPublicKey` output for
    `ECC_NIST_P256` / `ECDSA_SHA_256`."""

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        assert MessageType == "RAW"
        assert SigningAlgorithm == "ECDSA_SHA_256"
        signature = self._private_key.sign(Message, ec.ECDSA(hashes.SHA256()))
        return {"Signature": signature, "KeyId": KeyId, "SigningAlgorithm": SigningAlgorithm}

    def get_public_key(self, *, KeyId):
        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {"KeyId": KeyId, "PublicKey": public_bytes}


class _FakeS3NotFoundError(Exception):
    """Structurally matches `botocore.exceptions.ClientError` -- see
    `webguard_production_harness.py`'s identical fake for the full
    rationale."""

    def __init__(self) -> None:
        super().__init__("NoSuchKey")
        self.response = {"Error": {"Code": "NoSuchKey"}}


class _FakeS3Client:
    """Duck-typed `S3ClientProtocol`, in-memory only -- no AWS
    credentials, no network call. See `webguard_production_harness.py`'s
    identical fake for the full rationale (this file predates that
    harness's extraction and keeps its own local `_Fake*` clients for
    the same reason `_FakeKmsClient` above is not imported from it)."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_object(self, *, Bucket, Key, Body, ServerSideEncryption, SSEKMSKeyId, ContentType):
        self.objects[Key] = Body
        return {}

    def get_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise _FakeS3NotFoundError()
        return {"Body": io.BytesIO(self.objects[Key])}

    def head_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise _FakeS3NotFoundError()
        return {}

    def delete_object(self, *, Bucket, Key):
        self.objects.pop(Key, None)
        return {}


class _FakePostmarkTransport:
    """Duck-typed `PostmarkClientProtocol`, in-memory only -- always
    reports success, so `ProductionMailProvider`'s real logic executes
    but no network call to Postmark is ever made."""

    def send_email(self, payload: dict) -> dict:
        return {"status_code": 200, "body": {"ErrorCode": 0, "Message": "OK", "MessageID": "fake-message-id"}}


class _ReflectedXssFixtureHandler(BaseHTTPRequestHandler):
    """The same controlled, self-submitting reflected-XSS fixture used
    by `test_active_checks_e2e_lab.py` -- a deterministic finding
    source, not Juice Shop (whose seeded content this slice does not
    want this proof to depend on)."""

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
                    x509.DNSName("prod-e2e-fixture.test"),
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


def _extract(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    assert match is not None, f"pattern {pattern!r} not found in: {text}"
    return match.group(1)


@unittest.skipUnless(
    RUN_PRODUCTION_E2E,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run the production-mode E2E.",
)
class ProductionModeEndToEndTests(unittest.TestCase):
    @classmethod
    def _admin_connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def _apply_tenant_isolation_bootstrap(cls) -> None:
        for sql_path in (
            _ROLES_SQL_PATH,
            _TENANT_ACL_SQL_PATH,
            _FUNCTION_ACL_SQL_PATH,
            _CONTROL_FUNCTIONS_SQL_PATH,
            _RUNTIME_GRANT_SQL_PATH,
        ):
            with cls._admin_connect() as connection:
                connection.execute(sql_path.read_text(encoding="utf-8"))

    @classmethod
    def _drop_tenant_isolation_bootstrap(cls) -> None:
        with cls._admin_connect() as connection:
            connection.autocommit = True
            connection.execute("DROP SCHEMA IF EXISTS webguard_control CASCADE")
            for role in _ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    @classmethod
    def setUpClass(cls) -> None:
        cls._apply_tenant_isolation_bootstrap()
        cls.certificate_directory = TemporaryDirectory()
        cls.certificate_path = _generate_self_signed_certificate(Path(cls.certificate_directory.name))
        cls.fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectedXssFixtureHandler)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(certfile=cls.certificate_path)
        cls.fixture_server.socket = tls_context.wrap_socket(cls.fixture_server.socket, server_side=True)
        cls.fixture_thread = threading.Thread(target=cls.fixture_server.serve_forever, daemon=True)
        cls.fixture_thread.start()
        cls.fixture_port = cls.fixture_server.server_address[1]
        cls.target = f"https://prod-e2e-fixture.test:{cls.fixture_port}/"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_server.shutdown()
        cls.fixture_server.server_close()
        cls.fixture_thread.join(timeout=5)
        cls.certificate_directory.cleanup()
        cls._drop_tenant_isolation_bootstrap()

    def _validated_target(self) -> ValidatedTarget:
        return ValidatedTarget(
            original_url=self.target,
            normalised_url=self.target,
            scheme="https",
            hostname="prod-e2e-fixture.test",
            port=self.fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    def _trusting_tls_context(self) -> ssl.SSLContext:
        context = _REAL_CREATE_DEFAULT_CONTEXT()
        context.load_verify_locations(cafile=str(self.certificate_path))
        return context

    def test_full_production_pipeline_organization_to_finding_retrieval(self) -> None:
        from unittest.mock import patch

        with TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir = root / "authorizations"
            artifacts = root / "artifacts"
            auth_dir.mkdir(parents=True, exist_ok=True)

            now = datetime.now(timezone.utc)
            authorization_id = str(uuid4())
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=authorization_id,
                    organization="Production E2E Org",
                    authorized_by="Production E2E Operator",
                    target=self.target,
                    allowed_hosts=("prod-e2e-fixture.test",),
                    issued_at=now - timedelta(days=1),
                    expires_at=now + timedelta(days=300),
                    purpose="Slice 13 production-mode end-to-end validation",
                    limits=OwnedTargetLimits(),
                ),
                auth_dir / "fixture.json",
            )

            secret = ("k" * 32).encode()
            import base64

            config = ProductionServiceConfig(
                environment="production",
                service_identity="e2e-worker-1",
                database_backend="postgresql",
                database_url=POSTGRES_TEST_DSN,
                signing_provider="kms",
                kms_key_id="fake-kms-key-e2e",
                callback_service_hostname="callback.e2e.invalid",
                migration_mode="pre_applied",
                authorization_directory=str(auth_dir),
                artifact_directory=str(artifacts),
                cursor_signing_secret=base64.urlsafe_b64encode(secret).decode(),
                mail_provider="postmark",
                postmark_server_token="fake-postmark-server-token-e2e",  # noqa: S105 - never reaches a real network call
                mail_from_address="alerts@webguard-e2e.invalid",
                web_app_base_url="http://127.0.0.1:5173",
                object_storage_provider="s3",
                object_storage_bucket="webguard-e2e-fake-bucket",
                object_storage_region="eu-west-2",
                object_storage_kms_key_id="fake-kms-key-e2e-s3",
            )
            components = build_production_components(
                config, kms_client=_FakeKmsClient(), s3_client=_FakeS3Client(), mail_transport=_FakePostmarkTransport()
            )
            self.addCleanup(components.pool.close)

            # -- create organization/principal/token/target directly
            # through the production identity repository (requirement 22:
            # "create organization -> create target") --
            organization = components.identity.create_organization(
                "Production E2E Org", now=now
            )
            owner = components.identity.create_principal(
                organization.organization_id,
                "E2E Owner",
                principal_type=PrincipalType.USER,
                role=OrganizationRole.OWNER,
                now=now,
            )
            issued_token = components.identity.create_token(
                owner.principal_id, label="e2e-token", now=now
            )
            target_record = components.targets.create_target(
                organization.organization_id,
                self.target,
                created_by=owner.principal_id,
                now=now,
            )
            self.assertEqual(target_record.url, self.target)

            # -- authorize the target (assignment, via the production
            # identity repository -- the document itself stays
            # filesystem-based, unchanged from every prior slice) --
            components.identity.assign_authorization(
                organization.organization_id,
                authorization_id,
                assigned_by=owner.principal_id,
                now=now,
            )

            server = create_server(
                "127.0.0.1",
                0,
                components.service,
                authenticator=components.authenticator,
                rate_limiter=components.rate_limiter,
                maximum_request_bytes=8192,
            )
            stop = threading.Event()
            worker_thread = threading.Thread(
                target=components.worker.run_forever, args=(stop,), daemon=True
            )
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)

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
                    # -- requirement 17: /ready must reflect the real,
                    # production-wired PostgreSQL dependency (not a
                    # mocked or generic readiness_check), and its
                    # response must never leak the database host/port/
                    # credentials or the KMS key identifier even though
                    # both are reachable from this same process's
                    # configuration --
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request("GET", "/ready")
                    response = connection.getresponse()
                    ready_body_raw = response.read()
                    connection.close()
                    self.assertEqual(response.status, 200, ready_body_raw)
                    ready_payload = json.loads(ready_body_raw)
                    self.assertEqual(ready_payload["status"], "ready")
                    self.assertEqual(ready_payload["reason"], "ready")
                    ready_text = ready_body_raw.decode("utf-8")
                    self.assertNotIn("5433", ready_text)
                    self.assertNotIn("webguard_dev_only_not_for_production", ready_text)
                    self.assertNotIn("fake-kms-key-e2e", ready_text)
                    self.assertNotIn(urlsplit(POSTGRES_TEST_DSN).hostname or "\0", ready_text)

                    # -- issue a TrustScan permit over real HTTP, real
                    # KMS-backed signing --
                    permit_body = json.dumps(
                        {
                            "target": self.target,
                            "authorization_id": authorization_id,
                            "confirm_authorization": authorization_id,
                            "permitted_modes": ["single_page"],
                            "allowed_http_methods": ["GET", "HEAD"],
                            "not_before": (datetime.now(timezone.utc) + timedelta(milliseconds=500))
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                            "expires_at": (now + timedelta(days=7))
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                            "maximum_request_attempts": 15,
                            "maximum_requests_per_second": 1.0,
                            "maximum_concurrency": 1,
                            "active_checks": ["active.xss.reflected"],
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
                            "Authorization": f"Bearer {issued_token.token}",
                            "Content-Type": "application/json",
                            "Content-Length": str(len(permit_body)),
                        },
                    )
                    response = connection.getresponse()
                    permit_payload = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, permit_payload)
                    permit_id = permit_payload["permit"]["claims"]["permit_id"]
                    # The permit's not_before carries a small forward
                    # buffer (see the comment above); give real
                    # wall-clock time a moment to pass it before
                    # submitting the job, matching every other E2E
                    # test's identical pattern.
                    time.sleep(0.6)

                    # -- submit a scan job over real HTTP --
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
                            "Authorization": f"Bearer {issued_token.token}",
                            "TrustScan-Permit": permit_id,
                            "Content-Type": "application/json",
                            "Content-Length": str(len(job_body)),
                            "Idempotency-Key": "production-e2e-job-1",
                        },
                    )
                    response = connection.getresponse()
                    created = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, created)
                    job_id = created["job_id"]

                    deadline = time.monotonic() + 15
                    result_payload = None
                    while time.monotonic() < deadline:
                        connection = http.client.HTTPConnection(host, port, timeout=5)
                        connection.request(
                            "GET",
                            f"/v1/jobs/{job_id}/result",
                            headers={"Authorization": f"Bearer {issued_token.token}"},
                        )
                        response = connection.getresponse()
                        payload = json.loads(response.read())
                        connection.close()
                        if response.status == 200:
                            result_payload = payload
                            break
                        time.sleep(0.05)
                    self.assertIsNotNone(result_payload)
                    self.assertEqual(result_payload["state"], "completed", result_payload)

                    # -- retrieve the finding through the real HTTP API
                    # (requirement 16/22: "the finding is retrieved
                    # through existing /v1/... API") --
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request(
                        "GET", "/v1/findings",
                        headers={"Authorization": f"Bearer {issued_token.token}"},
                    )
                    response = connection.getresponse()
                    findings_payload = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 200, findings_payload)
                    http_findings = findings_payload["findings"]
                    self.assertTrue(http_findings, "expected at least one finding from GET /v1/findings")
                    xss_via_http = [f for f in http_findings if f["check_id"].startswith("active.xss.reflected")]
                    self.assertEqual(len(xss_via_http), 1, http_findings)

                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request(
                        "GET", f"/v1/findings/{xss_via_http[0]['finding_id']}",
                        headers={"Authorization": f"Bearer {issued_token.token}"},
                    )
                    response = connection.getresponse()
                    single_finding_payload = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 200, single_finding_payload)
                    self.assertEqual(single_finding_payload["status"], "open")
                finally:
                    stop.set()
                    server.shutdown()
                    server.server_close()
                    worker_thread.join(timeout=3)
                    server_thread.join(timeout=3)

            # -- scan record completed in PostgreSQL --
            scans = components.scans.list_scans_scoped(organization.organization_id)
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0].status, "completed")
            self.assertGreaterEqual(scans[0].finding_count, 1)

            # Coverage Truth Map v1 (product vision pillar 5): a real
            # single-page scan through the real executor must have
            # persisted at least one coverage_records row for this
            # asset's base passive check plan, not just findings.
            asset = self.target.rstrip("/")
            coverage = components.coverage.list_coverage_for_asset(
                organization.organization_id, asset
            )
            self.assertTrue(coverage, "expected at least one coverage record for this asset")
            self.assertTrue(
                all(item.identity_label == "unauthenticated" for item in coverage),
                "v1 coverage population only covers the base, unauthenticated check plan",
            )

            # -- cross-tenant isolation: a second organization must see
            # none of this organization's findings/scans --
            other_org = components.identity.create_organization("Other Org E2E", now=now)
            self.assertEqual(
                components.scans.list_scans_scoped(other_org.organization_id), ()
            )
            self.assertEqual(
                components.findings.list_findings_scoped_page(other_org.organization_id, limit=10)[0],
                (),
            )
            self.assertEqual(
                components.coverage.list_coverage_for_asset(other_org.organization_id, asset),
                (),
            )

            # Slice 17: the report's bytes now live in the (fake-backed)
            # object store the executor wrote through, not on local
            # disk -- read it back the same way the real API's
            # download route does, through `ArtifactStore`.
            report_bytes = components.service.artifact_store.get_reference(result_payload["report_ref"])
            report = load_webguard_report_json(report_bytes.decode("utf-8"))
            self.assertTrue(any(f.identity.rule_id.startswith("active.xss.reflected") for f in report.findings))


if __name__ == "__main__":
    unittest.main()
