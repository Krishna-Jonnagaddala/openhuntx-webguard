"""Slice 14 production-mode end-to-end proofs (requirements 13-16):

    authenticated scanning -> IDOR/BOLA -> schedule materialization
    -> report metadata

all against real PostgreSQL, real HTTP, and the same production
component assembly (`build_production_components`) the Slice 13 E2E
test already proves for the core pipeline. Each test reuses fixtures
already proven correct elsewhere in this suite rather than inventing
new ones: the IDOR fixture from `test_idor_authorization_e2e_lab.py`,
and the same KMS/certificate helpers from `test_production_mode_e2e.py`.
Only the network boundary to AWS (KMS and, new this slice, Secrets
Manager) is substituted -- no code path in this file talks to a real
AWS account.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

from webguard_contracts import (
    OrganizationRole,
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    PrincipalType,
    ScanJobMode,
    write_owned_target_authorization_file,
)
from webguard_scanner import ValidatedTarget
from webguard_api.http_api import create_server
from webguard_api.production_config import ProductionServiceConfig
from webguard_api.production_startup import build_production_components

from tests.integration.test_idor_authorization_e2e_lab import _IdorFixtureHandler, _ORDERS, _TOKENS
from tests.integration.test_production_mode_e2e import (
    _FakeKmsClient,
    _FakePostmarkTransport,
    _FakeS3Client,
    _ReflectedXssFixtureHandler,
    _generate_self_signed_certificate,
)

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_PRODUCTION_E2E = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)


class _FakeSecretsManagerClient:
    """Slice 14: a duck-typed AWS Secrets Manager client
    (`SecretsManagerClientProtocol`) backed by an in-memory dict seeded
    directly by the test -- exactly the "operator provisioned the
    secret out-of-band" model `SecretsManagerSecretProvider` assumes.
    Zero network access, zero `boto3` dependency."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    def get_secret_value(self, *, SecretId: str) -> dict:
        if SecretId not in self._secrets:
            raise KeyError(f"no such secret: {SecretId}")
        return {"SecretString": self._secrets[SecretId]}


class _AuthenticatedXssFixtureHandler(_ReflectedXssFixtureHandler):
    """The same reflected-XSS fixture, gated behind a bearer token: the
    vulnerable `?q=` parameter only reflects for a request carrying the
    expected `Authorization: Bearer <token>` header; every other request
    gets a static, non-reflecting page. This is what makes a finding
    here actual proof that `SecretProvider` resolution -> real
    `AuthenticationMaterial` -> `apply_authentication()` genuinely
    happened, not merely that the unauthenticated pipeline still works
    (which Slice 13's own E2E test already proves)."""

    expected_bearer_token = "prod-e2e-secret-bearer-token"

    def do_GET(self) -> None:  # noqa: N802
        if self.headers.get("Authorization") != f"Bearer {self.expected_bearer_token}":
            body = b"<html><body>authentication required</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@unittest.skipUnless(
    RUN_PRODUCTION_E2E,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run the production-mode E2E.",
)
class ProductionRuntimeCompletionEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self._root = Path(self._temporary.name)

    @staticmethod
    def _validated_target(target: str) -> ValidatedTarget:
        from urllib.parse import urlsplit

        parsed = urlsplit(target)
        return ValidatedTarget(
            original_url=target,
            normalised_url=target,
            scheme=parsed.scheme,
            hostname=parsed.hostname,
            port=parsed.port,
            resolved_addresses=("127.0.0.1",),
        )

    def _build_components(self):
        auth_dir = self._root / "authorizations"
        auth_dir.mkdir()
        artifacts = self._root / "artifacts"
        artifacts.mkdir()
        secret = ("k" * 32).encode()
        import base64

        config = ProductionServiceConfig(
            environment="production",
            service_identity=f"e2e-worker-{uuid4().hex[:8]}",
            database_backend="postgresql",
            database_url=POSTGRES_TEST_DSN,
            signing_provider="kms",
            kms_key_id="fake-kms-key-e2e-phase3",
            callback_service_hostname="callback.e2e.invalid",
            migration_mode="pre_applied",
            authorization_directory=str(auth_dir),
            artifact_directory=str(artifacts),
            cursor_signing_secret=base64.urlsafe_b64encode(secret).decode(),
            secret_provider="aws_secrets_manager",
            mail_provider="postmark",
            postmark_server_token="fake-postmark-server-token-e2e-phase3",  # noqa: S105 - never reaches a real network call
            mail_from_address="alerts@webguard-e2e.invalid",
            web_app_base_url="http://127.0.0.1:5173",
            object_storage_provider="s3",
            object_storage_bucket="webguard-e2e-phase3-fake-bucket",
            object_storage_region="eu-west-2",
            object_storage_kms_key_id="fake-kms-key-e2e-phase3-s3",
        )
        components = build_production_components(
            config,
            kms_client=_FakeKmsClient(),
            s3_client=_FakeS3Client(),
            mail_transport=_FakePostmarkTransport(),
            secrets_manager_client=_FakeSecretsManagerClient(
                {
                    "prod-e2e-bearer-secret": json.dumps(
                        {"bearer_token": _AuthenticatedXssFixtureHandler.expected_bearer_token}
                    ),
                    "prod-e2e-user-a-secret": json.dumps({"bearer_token": _TOKENS["user-a"]}),
                    "prod-e2e-user-b-secret": json.dumps({"bearer_token": _TOKENS["user-b"]}),
                }
            ),
        )
        self.addCleanup(components.pool.close)
        return config, components, auth_dir

    def _bootstrap_org(self, components):
        now = _utc_now()
        organization = components.identity.create_organization(f"E2E Org {uuid4().hex[:8]}", now=now)
        owner = components.identity.create_principal(
            organization.organization_id, "E2E Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=now,
        )
        token = components.identity.create_token(owner.principal_id, label="e2e-token", now=now)
        return organization, owner, token, now

    def _authorize_target(
        self, components, auth_dir, organization, owner, target, now,
        *, allowed_hosts=("127.0.0.1",), limits=None,
    ):
        authorization_id = str(uuid4())
        write_owned_target_authorization_file(
            OwnedTargetAuthorization(
                authorization_id=authorization_id,
                organization="Slice 14 E2E Org",
                authorized_by="Slice 14 E2E Operator",
                target=target,
                allowed_hosts=allowed_hosts,
                issued_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(days=300),
                purpose="Slice 14 production runtime-completion E2E",
                limits=limits if limits is not None else OwnedTargetLimits(),
            ),
            auth_dir / f"{authorization_id}.json",
        )
        components.targets.create_target(
            organization.organization_id, target, created_by=owner.principal_id, now=now
        )
        components.identity.assign_authorization(
            organization.organization_id, authorization_id, assigned_by=owner.principal_id, now=now
        )
        return authorization_id

    @staticmethod
    def _run_server(components, *, tls_context=None):
        server = create_server(
            "127.0.0.1", 0, components.service,
            authenticator=components.authenticator, rate_limiter=components.rate_limiter,
            maximum_request_bytes=8192,
        )
        stop = threading.Event()
        worker_thread = threading.Thread(target=components.worker.run_forever, args=(stop,), daemon=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        return server, stop, worker_thread, server_thread

    def test_authenticated_production_scan_resolves_secret_via_secrets_manager(self) -> None:
        """Requirement 13: PostgreSQL -> create org -> authorize target
        -> create authentication-context metadata (secret_reference_id
        only, never a raw credential in the request body) -> resolve
        the controlled secret via SecretsManagerSecretProvider ->
        authenticated scan -> finding -> Postgres persistence -> API
        retrieval."""

        config, components, auth_dir = self._build_components()
        organization, owner, token, now = self._bootstrap_org(components)

        cert_path = _generate_self_signed_certificate(self._root)
        fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthenticatedXssFixtureHandler)
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path))
        fixture_server.socket = context.wrap_socket(fixture_server.socket, server_side=True)
        fixture_thread = threading.Thread(target=fixture_server.serve_forever, daemon=True)
        fixture_thread.start()
        self.addCleanup(fixture_server.shutdown)
        fixture_port = fixture_server.server_address[1]
        target = f"https://prod-e2e-fixture.test:{fixture_port}/"

        authorization_id = self._authorize_target(components, auth_dir, organization, owner, target, now, allowed_hosts=("prod-e2e-fixture.test",))

        server, stop, worker_thread, server_thread = self._run_server(components)
        trust_store = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trust_store.load_verify_locations(cafile=str(cert_path))

        with patch(
            "webguard_api.executor.validate_target_url", return_value=self._validated_target(target)
        ), patch(
            "webguard_scanner.owned_target._public_addresses", side_effect=lambda t: t.resolved_addresses
        ), patch(
            "webguard_scanner.safe_http.ssl.create_default_context", return_value=trust_store
        ):
            worker_thread.start()
            server_thread.start()
            host, port = server.server_address[:2]
            try:
                context_body = json.dumps(
                    {
                        "target": target,
                        "authorization_id": authorization_id,
                        "identity_label": "prod-e2e-bearer-identity",
                        "method": "bearer_token",
                        "expires_at": (now + timedelta(days=1)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "secret_reference_id": "prod-e2e-bearer-secret",
                    }
                ).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/authentication-contexts", body=context_body,
                    headers={"Authorization": f"Bearer {token.token}", "Content-Type": "application/json", "Content-Length": str(len(context_body))},
                )
                response = connection.getresponse()
                context_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, context_payload)
                authentication_context_id = context_payload["authentication_context_id"]
                self.assertNotIn("bearer_token", context_payload)
                self.assertNotIn("secret_reference_id", context_payload)

                permit_body = json.dumps(
                    {
                        "target": target, "authorization_id": authorization_id, "confirm_authorization": authorization_id,
                        "permitted_modes": ["single_page"], "allowed_http_methods": ["GET", "HEAD"],
                        "not_before": (datetime.now(timezone.utc) + timedelta(milliseconds=500)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "expires_at": (now + timedelta(days=7)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "maximum_request_attempts": 15, "maximum_requests_per_second": 1.0, "maximum_concurrency": 1,
                        "active_checks": ["active.xss.reflected"], "authentication_context_id": authentication_context_id,
                        "authorization_comparison_plan_id": None,
                    }
                ).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/permits", body=permit_body,
                    headers={"Authorization": f"Bearer {token.token}", "Content-Type": "application/json", "Content-Length": str(len(permit_body))},
                )
                response = connection.getresponse()
                permit_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, permit_payload)
                permit_id = permit_payload["permit"]["claims"]["permit_id"]
                time.sleep(0.6)

                job_body = json.dumps(
                    {"target": target, "authorization_id": authorization_id, "confirm_authorization": authorization_id, "mode": "single_page"}
                ).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/jobs", body=job_body,
                    headers={
                        "Authorization": f"Bearer {token.token}", "TrustScan-Permit": permit_id,
                        "Content-Type": "application/json", "Content-Length": str(len(job_body)),
                        "Idempotency-Key": "phase3-auth-e2e-job-1",
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
                    connection.request("GET", f"/v1/jobs/{job_id}/result", headers={"Authorization": f"Bearer {token.token}"})
                    response = connection.getresponse()
                    payload = json.loads(response.read())
                    connection.close()
                    if response.status == 200:
                        result_payload = payload
                        break
                    time.sleep(0.05)
                self.assertIsNotNone(result_payload)
                self.assertEqual(result_payload["state"], "completed", result_payload)

                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request("GET", "/v1/findings", headers={"Authorization": f"Bearer {token.token}"})
                response = connection.getresponse()
                findings_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 200, findings_payload)
                xss_findings = [f for f in findings_payload["findings"] if f["check_id"].startswith("active.xss.reflected")]
                self.assertEqual(len(xss_findings), 1, findings_payload)
            finally:
                stop.set()
                server.shutdown()
                server.server_close()
                worker_thread.join(timeout=3)
                server_thread.join(timeout=3)

    def test_production_idor_comparison_persists_cwe_639_finding(self) -> None:
        """Requirement 14: two controlled identities -> two auth
        contexts (secret_reference_id only) -> persisted comparison
        plan (PostgreSQL) -> unchanged Slice 8/9 IDOR differential
        engine -> CWE-639 finding persisted -> API retrieval. No direct
        victim-identifier injection: resource_scope is explicit,
        operator-supplied endpoints, exactly as the plan model requires."""

        config, components, auth_dir = self._build_components()
        organization, owner, token, now = self._bootstrap_org(components)

        cert_path = _generate_self_signed_certificate(self._root)
        fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _IdorFixtureHandler)
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path))
        fixture_server.socket = context.wrap_socket(fixture_server.socket, server_side=True)
        fixture_thread = threading.Thread(target=fixture_server.serve_forever, daemon=True)
        fixture_thread.start()
        self.addCleanup(fixture_server.shutdown)
        fixture_port = fixture_server.server_address[1]
        target = f"https://prod-e2e-fixture.test:{fixture_port}/"

        authorization_id = self._authorize_target(
            components, auth_dir, organization, owner, target, now,
            allowed_hosts=("prod-e2e-fixture.test",),
            limits=OwnedTargetLimits(maximum_request_attempts=30, minimum_delay_seconds=0.5),
        )

        server, stop, worker_thread, server_thread = self._run_server(components)
        trust_store = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trust_store.load_verify_locations(cafile=str(cert_path))

        with patch(
            "webguard_api.executor.validate_target_url", return_value=self._validated_target(target)
        ), patch(
            "webguard_scanner.owned_target._public_addresses", side_effect=lambda t: t.resolved_addresses
        ), patch(
            "webguard_scanner.safe_http.ssl.create_default_context", return_value=trust_store
        ):
            worker_thread.start()
            server_thread.start()
            host, port = server.server_address[:2]
            try:
                context_ids = {}
                for label, secret_ref in (("user-a", "prod-e2e-user-a-secret"), ("user-b", "prod-e2e-user-b-secret")):
                    body = json.dumps(
                        {
                            "target": target, "authorization_id": authorization_id, "identity_label": label,
                            "method": "bearer_token",
                            "expires_at": (now + timedelta(days=1)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                            "secret_reference_id": secret_ref,
                        }
                    ).encode()
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    connection.request(
                        "POST", "/v1/authentication-contexts", body=body,
                        headers={"Authorization": f"Bearer {token.token}", "Content-Type": "application/json", "Content-Length": str(len(body))},
                    )
                    response = connection.getresponse()
                    payload = json.loads(response.read())
                    connection.close()
                    self.assertEqual(response.status, 201, payload)
                    context_ids[label] = payload["authentication_context_id"]

                resource_scope = [
                    {
                        "resource_type": "order", "method": "GET",
                        "primary_endpoint": f"{target}api/orders/A-001", "secondary_endpoint": f"{target}api/orders/B-001",
                        "identifier_location": "path", "identifier_name": "id", "expected_access": "private_to_owner",
                    },
                    {
                        "resource_type": "order-vuln", "method": "GET",
                        "primary_endpoint": f"{target}api/orders-vuln/A-001", "secondary_endpoint": f"{target}api/orders-vuln/B-001",
                        "identifier_location": "path", "identifier_name": "id", "expected_access": "private_to_owner",
                    },
                ]
                plan_body = json.dumps(
                    {
                        "target": target, "authorization_id": authorization_id,
                        "primary_context_id": context_ids["user-a"], "secondary_context_id": context_ids["user-b"],
                        "resource_scope": resource_scope,
                        "expires_at": (now + timedelta(days=1)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                    }
                ).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/authorization-comparisons", body=plan_body,
                    headers={"Authorization": f"Bearer {token.token}", "Content-Type": "application/json", "Content-Length": str(len(plan_body))},
                )
                response = connection.getresponse()
                plan_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, plan_payload)
                comparison_plan_id = plan_payload["comparison_plan_id"]

                permit_body = json.dumps(
                    {
                        "target": target, "authorization_id": authorization_id, "confirm_authorization": authorization_id,
                        "permitted_modes": ["single_page"], "allowed_http_methods": ["GET", "HEAD"],
                        "not_before": (datetime.now(timezone.utc) + timedelta(milliseconds=500)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "expires_at": (now + timedelta(days=7)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "maximum_request_attempts": 30, "maximum_requests_per_second": 2.0, "maximum_concurrency": 1,
                        "active_checks": ["active.authorization.idor"], "authentication_context_id": None,
                        "authorization_comparison_plan_id": comparison_plan_id,
                    }
                ).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/permits", body=permit_body,
                    headers={"Authorization": f"Bearer {token.token}", "Content-Type": "application/json", "Content-Length": str(len(permit_body))},
                )
                response = connection.getresponse()
                permit_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, permit_payload)
                permit_id = permit_payload["permit"]["claims"]["permit_id"]
                time.sleep(0.6)

                job_body = json.dumps(
                    {"target": target, "authorization_id": authorization_id, "confirm_authorization": authorization_id, "mode": "single_page"}
                ).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/jobs", body=job_body,
                    headers={
                        "Authorization": f"Bearer {token.token}", "TrustScan-Permit": permit_id,
                        "Content-Type": "application/json", "Content-Length": str(len(job_body)),
                        "Idempotency-Key": "phase3-idor-e2e-job-1",
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
                    connection.request("GET", f"/v1/jobs/{job_id}/result", headers={"Authorization": f"Bearer {token.token}"})
                    response = connection.getresponse()
                    payload = json.loads(response.read())
                    connection.close()
                    if response.status == 200:
                        result_payload = payload
                        break
                    time.sleep(0.05)
                self.assertIsNotNone(result_payload)
                self.assertEqual(result_payload["state"], "completed", result_payload)

                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request("GET", "/v1/findings", headers={"Authorization": f"Bearer {token.token}"})
                response = connection.getresponse()
                findings_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 200, findings_payload)
                idor_findings = [f for f in findings_payload["findings"] if f["check_id"].startswith("active.authorization.idor")]
                # Both cross-identity directions against the vulnerable
                # endpoint are independently confirmed (A accessing B's
                # resource, and B accessing A's) -- the secure endpoint
                # and the shared endpoint correctly produce none.
                self.assertEqual(len(idor_findings), 2, findings_payload)
                self.assertTrue(all(f["cwe_id"] == "CWE-639" for f in idor_findings), idor_findings)
            finally:
                stop.set()
                server.shutdown()
                server.server_close()
                worker_thread.join(timeout=3)
                server_thread.join(timeout=3)

    def test_production_schedule_materializes_exactly_one_job_under_concurrent_scheduler_ticks(self) -> None:
        """Requirements 15/3/4: a persisted schedule's due occurrence
        materializes into the same normal scan/job objects a
        user-triggered submission creates, a real worker claims and
        executes it, and findings persist -- and two concurrent
        scheduler ticks racing the same due occurrence produce exactly
        one job, never two, proving the revision-CAS plus
        idempotency-key database guarantees documented in
        `postgres_schedules.py`."""

        config, components, auth_dir = self._build_components()
        organization, owner, token, now = self._bootstrap_org(components)

        cert_path = _generate_self_signed_certificate(self._root)
        fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectedXssFixtureHandler)
        import ssl

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(str(cert_path))
        fixture_server.socket = tls_context.wrap_socket(fixture_server.socket, server_side=True)
        fixture_thread = threading.Thread(target=fixture_server.serve_forever, daemon=True)
        fixture_thread.start()
        self.addCleanup(fixture_server.shutdown)
        fixture_port = fixture_server.server_address[1]
        target = f"https://prod-e2e-fixture.test:{fixture_port}/"

        authorization_id = self._authorize_target(components, auth_dir, organization, owner, target, now, allowed_hosts=("prod-e2e-fixture.test",))

        trust_store = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trust_store.load_verify_locations(cafile=str(cert_path))

        with patch(
            "webguard_api.executor.validate_target_url", return_value=self._validated_target(target)
        ), patch(
            "webguard_scanner.owned_target._public_addresses", side_effect=lambda t: t.resolved_addresses
        ), patch(
            "webguard_scanner.safe_http.ssl.create_default_context", return_value=trust_store
        ):
            # Issue a permit directly (no HTTP server needed for this
            # test -- requirement 15 is about the scheduler/worker path,
            # not the HTTP surface, which the other three tests here and
            # Slice 13's own E2E already prove thoroughly).
            not_before = _utc_now() + timedelta(milliseconds=200)
            permit_signed = components.service.issue_permit(
                _owner_auth_context(components, organization, owner, token),
                json.dumps(
                    {
                        "target": target, "authorization_id": authorization_id, "confirm_authorization": authorization_id,
                        "permitted_modes": ["single_page"], "allowed_http_methods": ["GET", "HEAD"],
                        "not_before": not_before.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "expires_at": (now + timedelta(days=7)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "maximum_request_attempts": 15, "maximum_requests_per_second": 1.0, "maximum_concurrency": 1,
                        "active_checks": [], "authentication_context_id": None, "authorization_comparison_plan_id": None,
                    }
                ).encode(),
                request_id=str(uuid4()),
            )
            permit_id = permit_signed["permit"]["claims"]["permit_id"]
            permit_sha256 = permit_signed["permit"]["permit_sha256"]
            time.sleep(0.3)

            authorization = components.authorizations.get(authorization_id)
            schedule = components.jobs.create_schedule(
                organization_id=organization.organization_id, created_by=owner.principal_id,
                name="phase3-dedup-schedule", target=target, authorization_id=authorization_id,
                authorization_sha256=authorization.fingerprint, mode=ScanJobMode.SINGLE_PAGE,
                interval_seconds=3600, starts_at=_utc_now() - timedelta(seconds=1), now=_utc_now(),
                permit_id=permit_id, permit_sha256=permit_sha256,
            )

            winners = []
            errors = []
            barrier = threading.Barrier(3)

            def tick() -> None:
                barrier.wait(timeout=5)
                try:
                    summary = components.scheduler.run_once()
                    winners.append(summary.enqueued)
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=tick) for _ in range(3)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)

            self.assertEqual(errors, [])
            self.assertEqual(sum(winners), 1, "exactly one scheduler tick must materialize the due occurrence")

            jobs, _ = components.jobs.list_jobs_scoped_page(organization.organization_id, limit=10)
            self.assertEqual(len(jobs), 1, jobs)

            deadline = time.monotonic() + 5
            job_completed = False
            while time.monotonic() < deadline:
                lease = components.jobs.claim_next_leased(
                    now=_utc_now(), worker_id="phase3-schedule-worker", lease_seconds=10.0
                )
                if lease is not None:
                    outcome = components.executor.execute(lease.record)
                    components.jobs.finish_result_leased(
                        lease.record.job_id, worker_id=lease.worker_id, lease_token=lease.lease_token,
                        scan_id=outcome.report.scan_id, result_status=outcome.report.status,
                        report_ref=outcome.report_ref, audit_ref=outcome.audit_ref, now=_utc_now(),
                    )
                    job_completed = True
                    break
                time.sleep(0.05)
            self.assertTrue(job_completed, "the scheduler-materialized job must be claimable and executable")

            reread = components.jobs.get_scoped(jobs[0].job_id, organization.organization_id)
            self.assertEqual(reread.state.value, "completed", reread)

    def test_production_report_metadata_persists_checksum_and_reference(self) -> None:
        """Requirement 16 (Slice 14) + requirement 15 (Slice 17): a
        completed scan -> report requested -> report metadata persisted
        in PostgreSQL -> checksum/reference available through the API
        -> the report is downloaded and its bytes verified against the
        persisted checksum. Runs against the *actual* production
        default artifact store (`ObjectStorageArtifactStore`, backed by
        `_FakeS3Client` -- only the AWS network boundary is
        substituted, never `webguard_api`'s own production code path;
        see `test_production_mode_e2e.py`'s `_FakeS3Client` docstring).
        No `LocalArtifactStore` substitution happens anywhere in this
        test, unlike before Slice 17 completed object storage."""

        config, components, auth_dir = self._build_components()
        organization, owner, token, now = self._bootstrap_org(components)

        cert_path = _generate_self_signed_certificate(self._root)
        fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectedXssFixtureHandler)
        import ssl

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(str(cert_path))
        fixture_server.socket = tls_context.wrap_socket(fixture_server.socket, server_side=True)
        fixture_thread = threading.Thread(target=fixture_server.serve_forever, daemon=True)
        fixture_thread.start()
        self.addCleanup(fixture_server.shutdown)
        fixture_port = fixture_server.server_address[1]
        target = f"https://prod-e2e-fixture.test:{fixture_port}/"
        authorization_id = self._authorize_target(components, auth_dir, organization, owner, target, now, allowed_hosts=("prod-e2e-fixture.test",))

        trust_store = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trust_store.load_verify_locations(cafile=str(cert_path))

        server, stop, worker_thread, server_thread = self._run_server(components)
        with patch(
            "webguard_api.executor.validate_target_url", return_value=self._validated_target(target)
        ), patch(
            "webguard_scanner.owned_target._public_addresses", side_effect=lambda t: t.resolved_addresses
        ), patch(
            "webguard_scanner.safe_http.ssl.create_default_context", return_value=trust_store
        ):
            worker_thread.start()
            server_thread.start()
            host, port = server.server_address[:2]
            try:
                permit_body = json.dumps(
                    {
                        "target": target, "authorization_id": authorization_id, "confirm_authorization": authorization_id,
                        "permitted_modes": ["single_page"], "allowed_http_methods": ["GET", "HEAD"],
                        "not_before": (datetime.now(timezone.utc) + timedelta(milliseconds=500)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "expires_at": (now + timedelta(days=7)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "maximum_request_attempts": 15, "maximum_requests_per_second": 1.0, "maximum_concurrency": 1,
                        "active_checks": [], "authentication_context_id": None, "authorization_comparison_plan_id": None,
                    }
                ).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/permits", body=permit_body,
                    headers={"Authorization": f"Bearer {token.token}", "Content-Type": "application/json", "Content-Length": str(len(permit_body))},
                )
                response = connection.getresponse()
                permit_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, permit_payload)
                permit_id = permit_payload["permit"]["claims"]["permit_id"]
                time.sleep(0.6)

                job_body = json.dumps(
                    {"target": target, "authorization_id": authorization_id, "confirm_authorization": authorization_id, "mode": "single_page"}
                ).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/jobs", body=job_body,
                    headers={
                        "Authorization": f"Bearer {token.token}", "TrustScan-Permit": permit_id,
                        "Content-Type": "application/json", "Content-Length": str(len(job_body)),
                        "Idempotency-Key": "phase3-report-e2e-job-1",
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
                    connection.request("GET", f"/v1/jobs/{job_id}/result", headers={"Authorization": f"Bearer {token.token}"})
                    response = connection.getresponse()
                    payload = json.loads(response.read())
                    connection.close()
                    if response.status == 200:
                        result_payload = payload
                        break
                    time.sleep(0.05)
                self.assertIsNotNone(result_payload)
                scan_id = result_payload["scan_id"]

                report_body = json.dumps({"scan_id": scan_id}).encode()
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "POST", "/v1/reports", body=report_body,
                    headers={"Authorization": f"Bearer {token.token}", "Content-Type": "application/json", "Content-Length": str(len(report_body))},
                )
                response = connection.getresponse()
                report_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, report_payload)
                self.assertIsNotNone(report_payload["checksum"])
                self.assertEqual(len(report_payload["checksum"]), 64)
                report_id = report_payload["report_id"]

                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request("GET", f"/v1/reports/{report_id}", headers={"Authorization": f"Bearer {token.token}"})
                response = connection.getresponse()
                fetched = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 200, fetched)
                self.assertEqual(fetched["checksum"], report_payload["checksum"])
                self.assertEqual(fetched["scan_id"], scan_id)

                # Slice 17 requirement 15: the report a worker just
                # wrote through the real (fake-S3-backed)
                # ObjectStorageArtifactStore is downloadable through
                # the real HTTP API, and its bytes match the checksum
                # persisted at registration time -- proving the whole
                # generate -> store -> register -> download -> verify
                # pipeline against a real (if network-substituted)
                # object-storage backend, not a local-disk stand-in.
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request(
                    "GET", f"/v1/reports/{report_id}/download", headers={"Authorization": f"Bearer {token.token}"}
                )
                response = connection.getresponse()
                downloaded_bytes = response.read()
                connection.close()
                self.assertEqual(response.status, 200)
                self.assertEqual(
                    hashlib.sha256(downloaded_bytes).hexdigest(),
                    report_payload["checksum"],
                    "downloaded report bytes must match the checksum computed and persisted at registration time",
                )
            finally:
                stop.set()
                server.shutdown()
                server.server_close()
                worker_thread.join(timeout=3)
                server_thread.join(timeout=3)


def _owner_auth_context(components, organization, owner, issued_token):
    return components.authenticator.authenticate(
        [f"Bearer {issued_token.token}"], now=_utc_now()
    )


if __name__ == "__main__":
    unittest.main()
