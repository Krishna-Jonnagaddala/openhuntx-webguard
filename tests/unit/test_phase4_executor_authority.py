from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from webguard_api import (
    AuthorizationRepository,
    IdentityStore,
    JobExecutionError,
    ScanJobExecutor,
    ScanJobStore,
)
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
    load_signed_trustscan_safety_receipt_json,
)
from webguard_scanner import SafeHttpResponse, ValidatedTarget

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    create_trustscan_permit,
    trustscan_signer,
    write_authorization,
)


class Phase4ExecutorAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"
        self.auth_dir = self.root / "authorizations"
        self.artifacts = self.root / "artifacts"

        write_authorization(self.auth_dir)

        self.store = ScanJobStore(self.path)
        self.identity = IdentityStore(self.path)
        self.signer = trustscan_signer(self.store)

        self.identity.create_organization(
            "Phase 4 Runtime Tenant",
            now=NOW,
            organization_id=ORG_ID,
        )
        self.identity.create_principal(
            ORG_ID,
            "Phase 4 Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )
        self.identity.assign_authorization(
            ORG_ID,
            AUTH_ID,
            assigned_by=OWNER_ID,
            now=NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

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

    def running_job(self, key: str):
        permit = create_trustscan_permit(self.store)
        request = ScanJobRequest(
            idempotency_key=key,
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )
        queued, created = self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )
        self.assertTrue(created)

        running = self.store.claim_next(now=NOW)
        self.assertIsNotNone(running)
        self.assertEqual(running.job_id, queued.job_id)
        return running

    def remove_assignment(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """
                DELETE FROM organization_authorizations
                WHERE organization_id = ?
                  AND authorization_id = ?
                """,
                (ORG_ID, AUTH_ID),
            )
            connection.commit()
        finally:
            connection.close()

    def executor(self, *, crawl_scanner=None) -> ScanJobExecutor:
        kwargs = dict(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            authorization_assignment_checker=(
                self.identity.authorization_is_assigned
            ),
        )
        if crawl_scanner is not None:
            kwargs["crawl_scanner"] = crawl_scanner
        return ScanJobExecutor(**kwargs)

    @patch("webguard_api.executor.validate_target_url")
    def test_assignment_removed_after_claim_blocks_before_scanner(
        self,
        validate_mock,
    ) -> None:
        record = self.running_job(
            "phase4-assignment-removed-after-claim"
        )
        self.remove_assignment()

        def unexpected_scanner(*_args, **_kwargs):
            raise AssertionError(
                "Scanner must not run after assignment removal."
            )

        executor = self.executor(crawl_scanner=unexpected_scanner)

        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)

        self.assertEqual(
            caught.exception.code,
            "authorization_not_assigned",
        )
        validate_mock.assert_not_called()
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_assignment_removed_during_execution_blocks_next_request(
        self,
        validate_mock,
    ) -> None:
        validate_mock.return_value = self.validated_target()

        record = self.running_job(
            "phase4-assignment-removed-during-execution"
        )
        second_network_step_reached = False

        def fake_crawl(target, **kwargs):
            nonlocal second_network_step_reached

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

            self.remove_assignment()
            self.assertFalse(
                self.identity.authorization_is_assigned(
                    ORG_ID,
                    AUTH_ID,
                )
            )

            kwargs["before_request"](target, "GET")
            second_network_step_reached = True
            raise AssertionError(
                "Runtime guard failed before the second request."
            )

        executor = self.executor(crawl_scanner=fake_crawl)

        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)

        self.assertFalse(second_network_step_reached)
        self.assertEqual(
            caught.exception.code,
            "authorization_not_assigned",
        )
        self.assertIsNotNone(caught.exception.safety_receipt_ref)
        self.assertIsNotNone(caught.exception.safety_receipt_sha256)

        receipt_path = self.artifacts / caught.exception.safety_receipt_ref
        receipt = load_signed_trustscan_safety_receipt_json(
            receipt_path.read_text(encoding="utf-8")
        )
        self.signer.verify_safety_receipt(receipt)
        self.assertEqual(receipt.claims.requests_permitted, 1)
        self.assertEqual(receipt.claims.requests_blocked, 1)
        self.assertEqual(
            receipt.claims.termination_reason,
            "safety_blocked",
        )


if __name__ == "__main__":
    unittest.main()
