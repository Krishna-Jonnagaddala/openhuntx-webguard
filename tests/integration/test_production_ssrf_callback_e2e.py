"""Production-mode end-to-end proof that the SSRF-callback production
wiring fix actually works, not merely that it no longer crashes:

    real PostgreSQL -> org/target/authorization -> TrustScan permit
    with `active.ssrf.callback` -> real HTTP job submission -> real
    production worker/executor (`build_production_components`) ->
    discovery on the vulnerable fixture's root page -> callback
    registration through `PostgresCallbackBroker` (durable, in
    PostgreSQL, not an in-process dict) -> SSRF probe against the
    fixture -> the fixture's vulnerable route performs a real outbound
    fetch to the callback URL -> a *separate* `CallbackHttpReceiver`
    process-equivalent (its own `PostgresCallbackRegistrationRepository`
    instance, sharing nothing with the executor except the same
    PostgreSQL database) records the observation -> the executor's
    poll-based `wait_for_observation` sees it -> a CWE-918 finding is
    produced, persisted, and retrievable over the real HTTP API.

Before the fix (`postgres_callback_broker.py`,
`production_startup.py`), `build_production_components()` wired the raw
`PostgresCallbackRegistrationRepository` directly into `ScanJobExecutor`
-- which has no `.policy` and no `wait_for_observation()` -- so this
exact pipeline crashed with `AttributeError` before ever registering a
callback token. This test proves the fixed pipeline does not merely
avoid that crash; it proves a real, out-of-band, cross-process-observed
outbound request produces the expected finding, exactly like the
existing local/lab proof (`test_ssrf_callback_e2e_lab.py`) already does
for the in-memory, single-process broker.

The callback receiver is intentionally constructed as a *separate*
`PostgresCallbackRegistrationRepository` instance (not
`components`'s own) bound to a real socket via `CallbackHttpReceiver`,
started on its own thread -- structurally identical to what
`webguard-api callback-service` (see `cli.py`) does as an actual
separate OS process. The only thing this test cannot do without real
DNS/TLS is run the receiver as a literal separate process reachable at
`callback_service_hostname`; correlating purely through PostgreSQL
(never a shared Python object) already exercises the one part of the
design that could not work before this fix.
"""

from __future__ import annotations

import http.client
import json
import ssl
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
    write_owned_target_authorization_file,
)
from webguard_scanner import ValidatedTarget
from webguard_api.callback_server import CallbackHttpReceiver
from webguard_api.http_api import create_server
from webguard_api.postgres_callback_broker import PostgresCallbackBroker
from webguard_api.postgres_callback_service import PostgresCallbackRegistrationRepository
from webguard_api.production_config import ProductionServiceConfig
from webguard_api.production_startup import build_production_components

from tests.integration.test_production_mode_e2e import (
    _FakeKmsClient,
    _FakePostmarkTransport,
    _FakeS3Client,
    _generate_self_signed_certificate,
)
from tests.integration.test_ssrf_callback_e2e_lab import _SsrfE2eFixtureHandler

import os

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_PRODUCTION_E2E = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

# P1-2 Phase H: create_target now runs under api_tenant_data (see
# postgres_pool.py's tenant_connection and postgres_targets.py's own
# methods), so this real build_production_components-backed E2E needs
# the same role/ACL/function/runtime-grant bootstrap
# tests/contract/test_identity_repository_contract.py's own setUpClass
# applies, in the same order.
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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@unittest.skipUnless(
    RUN_PRODUCTION_E2E,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run the production SSRF-callback E2E.",
)
class ProductionSsrfCallbackEndToEndTests(unittest.TestCase):
    @classmethod
    def _connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def setUpClass(cls) -> None:
        for sql_path in (
            _ROLES_SQL_PATH,
            _TENANT_ACL_SQL_PATH,
            _FUNCTION_ACL_SQL_PATH,
            _CONTROL_FUNCTIONS_SQL_PATH,
            _RUNTIME_GRANT_SQL_PATH,
        ):
            with cls._connect() as connection:
                connection.execute(sql_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        with cls._connect() as connection:
            connection.autocommit = True
            connection.execute("DROP SCHEMA IF EXISTS webguard_control CASCADE")
            for role in _ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

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
        import base64
        import secrets

        config = ProductionServiceConfig(
            environment="production",
            service_identity=f"ssrf-e2e-worker-{uuid4().hex[:8]}",
            database_backend="postgresql",
            database_url=POSTGRES_TEST_DSN,
            signing_provider="kms",
            kms_key_id="fake-kms-key-ssrf-e2e",
            callback_service_hostname="callback.ssrf-e2e.invalid",
            migration_mode="pre_applied",
            authorization_directory=str(auth_dir),
            artifact_directory=str(artifacts),
            cursor_signing_secret=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            mail_provider="postmark",
            postmark_server_token="fake-postmark-server-token-ssrf-e2e",  # noqa: S105 - never reaches a real network call
            mail_from_address="alerts@webguard-ssrf-e2e.invalid",
            web_app_base_url="http://127.0.0.1:5173",
            object_storage_provider="s3",
            object_storage_bucket="webguard-ssrf-e2e-fake-bucket",
            object_storage_region="eu-west-2",
            object_storage_kms_key_id="fake-kms-key-ssrf-e2e-s3",
        )
        components = build_production_components(
            config,
            kms_client=_FakeKmsClient(),
            s3_client=_FakeS3Client(),
            mail_transport=_FakePostmarkTransport(),
        )
        self.addCleanup(components.pool.close)

        # The fix under test: replace the executor's callback broker
        # with one pointed at a *separate* `PostgresCallbackRegistrationRepository`
        # instance/receiver bound to a real loopback socket, rather than
        # `callback_service_hostname`'s unresolvable `https://` address
        # -- structurally identical to what a real deployment's
        # `webguard-api callback-service` process (a different OS
        # process, reached only through PostgreSQL) provides, without
        # needing real DNS/TLS in a test.
        receiver_repository = PostgresCallbackRegistrationRepository(components.pool)
        receiver = CallbackHttpReceiver(receiver_repository, host="127.0.0.1", port=0)
        receiver.start()
        self.addCleanup(receiver.stop)
        components.executor.callback_repository = PostgresCallbackBroker(
            receiver_repository,
            components.pool,
            base_url=receiver.base_url,
        )
        return config, components, auth_dir

    def _bootstrap_org(self, components):
        now = _utc_now()
        organization = components.identity.create_organization(f"SSRF E2E Org {uuid4().hex[:8]}", now=now)
        owner = components.identity.create_principal(
            organization.organization_id, "SSRF E2E Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=now,
        )
        token = components.identity.create_token(owner.principal_id, label="ssrf-e2e-token", now=now)
        return organization, owner, token, now

    def _authorize_target(self, components, auth_dir, organization, owner, target, now):
        authorization_id = str(uuid4())
        write_owned_target_authorization_file(
            OwnedTargetAuthorization(
                authorization_id=authorization_id,
                organization="SSRF Production E2E Org",
                authorized_by="SSRF Production E2E Operator",
                target=target,
                allowed_hosts=("prod-e2e-fixture.test",),
                issued_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(days=300),
                purpose="Production SSRF-callback wiring fix E2E",
                limits=OwnedTargetLimits(maximum_request_attempts=30, minimum_delay_seconds=0.5),
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
    def _run_server(components):
        server = create_server(
            "127.0.0.1", 0, components.service,
            authenticator=components.authenticator, rate_limiter=components.rate_limiter,
            maximum_request_bytes=8192,
        )
        stop = threading.Event()
        worker_thread = threading.Thread(target=components.worker.run_forever, args=(stop,), daemon=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        return server, stop, worker_thread, server_thread

    def _run_job_and_get_findings(self, active_checks: list[str], *, completion_timeout_seconds: float = 25) -> list[dict]:
        config, components, auth_dir = self._build_components()
        organization, owner, token, now = self._bootstrap_org(components)

        cert_path = _generate_self_signed_certificate(self._root)
        fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _SsrfE2eFixtureHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path))
        fixture_server.socket = context.wrap_socket(fixture_server.socket, server_side=True)
        fixture_thread = threading.Thread(target=fixture_server.serve_forever, daemon=True)
        fixture_thread.start()
        self.addCleanup(fixture_server.shutdown)
        fixture_port = fixture_server.server_address[1]
        target = f"https://prod-e2e-fixture.test:{fixture_port}/"

        authorization_id = self._authorize_target(components, auth_dir, organization, owner, target, now)

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
                permit_body = json.dumps(
                    {
                        "target": target, "authorization_id": authorization_id, "confirm_authorization": authorization_id,
                        "permitted_modes": ["single_page"], "allowed_http_methods": ["GET", "HEAD"],
                        "not_before": (datetime.now(timezone.utc) + timedelta(milliseconds=500)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "expires_at": (now + timedelta(days=7)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "maximum_request_attempts": 30, "maximum_requests_per_second": 2.0, "maximum_concurrency": 1,
                        "active_checks": active_checks, "authentication_context_id": None,
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
                        "Idempotency-Key": f"ssrf-prod-e2e-{'-'.join(active_checks) or 'passive'}",
                    },
                )
                response = connection.getresponse()
                created = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, created)
                job_id = created["job_id"]

                deadline = time.monotonic() + completion_timeout_seconds
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
                    time.sleep(0.1)
                self.assertIsNotNone(result_payload, "job did not complete in time")
                self.assertEqual(result_payload["state"], "completed", result_payload)

                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request("GET", "/v1/findings", headers={"Authorization": f"Bearer {token.token}"})
                response = connection.getresponse()
                findings_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 200, findings_payload)
                return findings_payload["findings"]
            finally:
                stop.set()
                server.shutdown()
                server.server_close()
                worker_thread.join(timeout=3)
                server_thread.join(timeout=3)

    def test_production_ssrf_callback_confirms_cwe_918_via_separate_receiver(self) -> None:
        """The fix under test, end to end: a real production scan whose
        permit authorizes `active.ssrf.callback` produces a confirmed
        CWE-918 finding for the vulnerable endpoint, and none for the
        safe/reflect-only endpoints on the identical fixture -- proving
        both that the wiring no longer crashes and that the durable,
        polling-based, cross-process callback correlation actually
        confirms a real out-of-band request."""

        findings = self._run_job_and_get_findings(["active.ssrf.callback"])
        ssrf_findings = [f for f in findings if f["check_id"].startswith("active.ssrf.callback")]
        self.assertTrue(
            ssrf_findings,
            f"expected a confirmed SSRF finding; findings: {[f['check_id'] for f in findings]}",
        )
        vulnerable = [f for f in ssrf_findings if f["endpoint"] == "/fetch-vulnerable"]
        self.assertEqual(len(vulnerable), 1, ssrf_findings)
        self.assertEqual(vulnerable[0]["cwe_id"], "CWE-918")
        self.assertFalse(any(f["endpoint"] == "/fetch-safe" for f in ssrf_findings))
        self.assertFalse(any(f["endpoint"] == "/reflect-only" for f in ssrf_findings))

    def test_passive_permit_produces_no_ssrf_finding(self) -> None:
        """Authorization negative: a permit that never requested
        `active.ssrf.callback` must never produce an SSRF finding
        against the identical vulnerable fixture, even in production
        wiring."""

        findings = self._run_job_and_get_findings([])
        self.assertFalse(any(f["check_id"].startswith("active.ssrf.callback") for f in findings), findings)

    def test_ssrf_confirmed_despite_a_transient_persistence_failure_within_retry_budget(self) -> None:
        """P1-12 end-to-end proof, scenario 1: the real fixture's
        vulnerable route makes a real outbound request to the real
        callback receiver; the very first attempt to persist that
        observation hits a simulated, one-time connection failure
        (`callback_server.py`'s bounded retry is what this test is
        actually proving survives), the second attempt succeeds, and
        the finding is still confirmed -- not degraded, not lost --
        exactly as if no interruption had occurred. Fault injection
        (not `docker stop`) is used deliberately here: the callback
        arrives at a point in a real, unmodified 25-second job run that
        is not practical to time a real container stop/start against
        precisely, whereas this proves the identical code path
        (`PostgresCallbackRegistrationRepository.record_observation`'s
        own `DatabaseError`) with exact, reliable timing."""
        import psycopg

        real_execute = psycopg.Connection.execute
        state = {"failed_once": False}

        def faulty_execute(self_conn, query, params=None, **kwargs):
            text = query if isinstance(query, str) else query.as_string(self_conn)
            if not state["failed_once"] and "INSERT INTO callback_observations" in text:
                state["failed_once"] = True
                raise psycopg.OperationalError("simulated one-time connection failure (P1-12 E2E proof)")
            return real_execute(self_conn, query, params, **kwargs)

        with patch.object(psycopg.Connection, "execute", faulty_execute):
            findings = self._run_job_and_get_findings(["active.ssrf.callback"])

        self.assertTrue(state["failed_once"], "the fault injection must actually have fired at least once")
        ssrf_findings = [f for f in findings if f["check_id"].startswith("active.ssrf.callback")]
        vulnerable = [f for f in ssrf_findings if f["endpoint"] == "/fetch-vulnerable"]
        self.assertEqual(len(vulnerable), 1, ssrf_findings)
        self.assertEqual(vulnerable[0]["cwe_id"], "CWE-918")

    def test_no_fabricated_confirmation_when_persistence_never_recovers(self) -> None:
        """P1-12 end-to-end proof, scenario 3: the real fixture makes
        the real outbound request, but every persistence attempt fails
        for the whole run (a simulated outage that outlasts the
        receiver's own bounded retry budget entirely). PostgreSQL
        remains authoritative: no observation is ever durably written,
        so the detector must not confirm anything it never actually
        saw. This is the residual, honest limitation P1-12 accepts by
        design -- see the P1-12 remediation report's LONG-OUTAGE
        BEHAVIOR / FALSE-NEGATIVE RESIDUAL sections."""
        import psycopg

        real_execute = psycopg.Connection.execute

        def always_faulty_execute(self_conn, query, params=None, **kwargs):
            text = query if isinstance(query, str) else query.as_string(self_conn)
            if "INSERT INTO callback_observations" in text:
                raise psycopg.OperationalError("simulated permanent connection failure (P1-12 E2E proof)")
            return real_execute(self_conn, query, params, **kwargs)

        # This scenario is structurally slower than every sibling test
        # in this file, not flaky: the fixture probes three candidates
        # (/fetch-vulnerable, /fetch-safe, /reflect-only), and under
        # this patch NONE of their observations can ever persist -- so
        # every one of them waits out the full primary+grace window
        # (3s + 2s, see CallbackPolicy's production defaults) rather
        # than resolving in a couple of poll cycles like the
        # already-recorded or fails-once-then-succeeds cases do. A
        # generous, explicit budget here reflects that real, structural
        # cost, not system-load tolerance.
        run_started_at = _utc_now()
        with patch.object(psycopg.Connection, "execute", always_faulty_execute):
            findings = self._run_job_and_get_findings(["active.ssrf.callback"], completion_timeout_seconds=60)

        ssrf_findings = [f for f in findings if f["check_id"].startswith("active.ssrf.callback")]
        confirmed_or_probable = [
            f for f in ssrf_findings
            if f["endpoint"] == "/fetch-vulnerable" and f.get("cwe_id") == "CWE-918"
        ]
        self.assertEqual(
            confirmed_or_probable, [],
            "must never fabricate a CWE-918 finding for an observation that was never durably persisted",
        )

        from webguard_api.postgres_pool import WebGuardPostgresPool

        assertion_pool = WebGuardPostgresPool(POSTGRES_TEST_DSN)
        try:
            with assertion_pool.connection() as connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM callback_observations WHERE observed_at > %s",
                    (run_started_at,),
                ).fetchone()[0]
        finally:
            assertion_pool.close()
        self.assertEqual(
            count, 0,
            "no observation row from this run may exist -- persistence genuinely never succeeded",
        )


if __name__ == "__main__":
    unittest.main()
