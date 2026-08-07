from __future__ import annotations

import os
import stat
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from webguard_api import (
    AuthorizationRepository,
    JobExecutionError,
    ScanJobExecutor,
    ScanJobStore,
)
from webguard_contracts import (
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    load_signed_trustscan_safety_receipt_json,
)
from webguard_scanner import (
    CrawlCancellationToken,
    SafeHttpResponse,
    ValidatedTarget,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    TARGET,
    authorization,
    completed_report,
    create_trustscan_permit,
    ORG_ID,
    OWNER_ID,
    trustscan_signer,
    write_authorization,
)


class ScanJobExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "authorizations"
        self.auth_path = write_authorization(self.auth_dir)
        self.artifacts = self.root / "artifacts"
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        self.signer = trustscan_signer(self.store)
        self.permit = create_trustscan_permit(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def running_record(self, *, mode: ScanJobMode = ScanJobMode.CRAWL):
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key=f"internstack-{mode.value}",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=mode,
            submitted_at=NOW,
        )
        queued, _ = self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=self.permit.permit.claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
        )
        claimed = self.store.claim_next(now=NOW)
        assert claimed is not None
        return claimed

    @staticmethod
    def validated_target() -> ValidatedTarget:
        return ValidatedTarget(
            original_url=TARGET,
            normalised_url=TARGET,
            scheme="https",
            hostname="example.com",
            port=443,
            resolved_addresses=("204.69.207.1",),
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_crawl_execution_writes_private_audit_and_report(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        observed = {}

        def fake_crawl(target, **kwargs):
            audit = self.artifacts / "jobs" / record.job_id / "authorization-audit.json"
            observed["audit_existed_before_scan"] = audit.is_file()
            observed["policy"] = kwargs["crawl_policy"]
            observed["token"] = kwargs["cancellation_token"]
            return completed_report(kwargs["scan_id"])

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            crawl_scanner=fake_crawl,
        )
        token = CrawlCancellationToken()
        outcome = executor.execute(record, cancellation_token=token)
        report = self.artifacts / outcome.report_ref
        audit = self.artifacts / outcome.audit_ref
        safety_receipt = self.artifacts / outcome.safety_receipt_ref
        self.assertTrue(observed["audit_existed_before_scan"])
        self.assertIs(observed["token"], token)
        self.assertEqual(observed["policy"].maximum_pages, 10)
        self.assertTrue(report.is_file())
        self.assertTrue(audit.is_file())
        self.assertTrue(safety_receipt.is_file())
        loaded_receipt = load_signed_trustscan_safety_receipt_json(
            safety_receipt.read_text(encoding="utf-8")
        )
        self.signer.verify_safety_receipt(loaded_receipt)
        self.assertEqual(loaded_receipt.claims.job_id, record.job_id)
        self.assertEqual(loaded_receipt.claims.termination_reason, "completed")
        self.assertEqual(loaded_receipt.fingerprint, outcome.safety_receipt_sha256)
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(audit.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(safety_receipt.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(report.parent.stat().st_mode), 0o700)
        self.assertNotIn(str(self.artifacts), outcome.report_ref)

    @patch("webguard_api.executor.validate_target_url")
    def test_runtime_permit_revocation_blocks_next_request_and_writes_receipt(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()

        def fake_crawl(target, **kwargs):
            kwargs["before_request"](target, "GET")
            kwargs["after_request"](
                target,
                "GET",
                SafeHttpResponse(
                    status=200,
                    reason="OK",
                    headers=(),
                    body=b"",
                    connected_address="204.69.207.1",
                    elapsed_milliseconds=5,
                ),
                None,
            )
            self.store.revoke_scan_permit_scoped(
                self.permit.permit.claims.permit_id,
                ORG_ID,
                revoked_by=OWNER_ID,
                now=NOW,
            )
            kwargs["before_request"](target, "GET")
            raise AssertionError("revoked permit must block before the second request")

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            crawl_scanner=fake_crawl,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "trustscan_permit_revoked")
        self.assertIsNotNone(caught.exception.safety_receipt_ref)
        receipt_path = self.artifacts / caught.exception.safety_receipt_ref
        loaded = load_signed_trustscan_safety_receipt_json(
            receipt_path.read_text(encoding="utf-8")
        )
        self.signer.verify_safety_receipt(loaded)
        self.assertEqual(loaded.claims.requests_permitted, 1)
        self.assertEqual(loaded.claims.requests_blocked, 1)
        self.assertEqual(loaded.claims.termination_reason, "safety_blocked")
        self.assertEqual(
            loaded.fingerprint,
            caught.exception.safety_receipt_sha256,
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_single_page_uses_single_scanner(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record(mode=ScanJobMode.SINGLE_PAGE)
        observed = {}

        def fake_single(target, **kwargs):
            observed.update(kwargs)
            return completed_report(kwargs["scan_id"])

        def unexpected_crawl(*_args, **_kwargs):
            raise AssertionError("crawl scanner must not be called")

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            single_scanner=fake_single,
            crawl_scanner=unexpected_crawl,
        )
        outcome = executor.execute(record)
        self.assertIn("fetch_policy", observed)
        self.assertNotIn("crawl_policy", observed)
        self.assertEqual(outcome.report.status.value, "completed")

    @patch("webguard_api.executor.validate_target_url")
    def test_authorization_changed_after_submission_is_rejected(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        changed = authorization(purpose="Changed purpose")
        self.auth_path.unlink()
        write_authorization(self.auth_dir, changed)
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(JobExecutionError, "changed"):
            executor.execute(record)
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_pre_cancelled_token_writes_no_artifacts(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        token = CrawlCancellationToken()
        token.cancel()
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(JobExecutionError, "cancelled"):
            executor.execute(record, cancellation_token=token)
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_existing_job_artifact_directory_prevents_overwrite(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        job_dir = self.artifacts / "jobs" / record.job_id
        job_dir.mkdir(parents=True)
        os.chmod(job_dir, 0o700)
        (job_dir / "authorization-audit.json").write_text("existing", encoding="utf-8")
        os.chmod(job_dir / "authorization-audit.json", 0o600)
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaises(JobExecutionError):
            executor.execute(record)

    def test_non_running_record_is_rejected(self) -> None:
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key="internstack-queued",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )
        queued, _ = self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=self.permit.permit.claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
        )
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(JobExecutionError, "running"):
            executor.execute(queued)

    def test_unbound_legacy_job_fails_closed_before_network(self) -> None:
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key="legacy-unbound-job",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )
        self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
        )
        record = self.store.claim_next(now=NOW)
        assert record is not None
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "trustscan_permit_missing")
        self.assertFalse(self.artifacts.exists())

    def test_revoked_permit_fails_closed_before_network(self) -> None:
        record = self.running_record()
        self.store.revoke_scan_permit_scoped(
            self.permit.permit.claims.permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "trustscan_permit_revoked")
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_authorization_expiry_is_revalidated_at_execution(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW + timedelta(days=60),
        )
        with self.assertRaisesRegex(JobExecutionError, "expired"):
            executor.execute(record)


if __name__ == "__main__":
    unittest.main()
