"""Proves that a permit's ordinary lifecycle gates (expiry, revocation,
target binding) are evaluated identically whether or not active_checks
is populated -- an active-checks claim does not create a bypass or a
second, weaker authorization path. These gates run before
_apply_active_detection is ever reached, so no network request (passive
or active) is attempted once any of them fails.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from webguard_api import AuthorizationRepository, JobExecutionError, ScanJobExecutor, ScanJobStore
from webguard_contracts import (
    ScanJobMode,
    ScanJobRequest,
    write_owned_target_authorization_file,
)
from webguard_scanner import ValidatedTarget

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    create_trustscan_permit,
    write_authorization,
)


class ActiveChecksPermitLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "authorizations"
        write_authorization(self.auth_dir)
        self.artifacts = self.root / "artifacts"
        self.store = ScanJobStore(self.root / "jobs.sqlite3")

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
            resolved_addresses=("93.184.216.34",),
        )

    def running_record(self, permit):
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key="active-checks-lifecycle",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.SINGLE_PAGE,
            submitted_at=NOW,
        )
        self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )
        claimed = self.store.claim_next(now=NOW)
        assert claimed is not None
        return claimed

    def make_executor(self, *, clock=None) -> ScanJobExecutor:
        return ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self._signer(),
            artifact_directory=self.artifacts,
            clock=clock or (lambda: NOW),
        )

    def _signer(self):
        from tests.unit.service_test_support import trustscan_signer

        return trustscan_signer(self.store)

    @patch("webguard_api.executor.validate_target_url")
    def test_expired_permit_with_active_checks_fails_closed_before_network(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.xss.reflected",),
            expires_at=NOW + timedelta(hours=1),
        )
        record = self.running_record(permit)
        # Advance the clock well past expiry.
        executor = self.make_executor(clock=lambda: NOW + timedelta(days=1))
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "trustscan_permit_expired")
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_revoked_permit_with_active_checks_fails_closed_before_network(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.sqli.error",),
        )
        record = self.running_record(permit)
        self.store.revoke_scan_permit_scoped(
            permit.permit.claims.permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )
        executor = self.make_executor()
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "trustscan_permit_revoked")
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_wrong_target_permit_with_active_checks_fails_closed(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        other_auth = authorization(
            authorization_id="11111111-2222-4333-8444-555566667777",
            target="https://other.example/",
            allowed_hosts=("other.example",),
        )
        write_owned_target_authorization_file(
            other_auth, self.auth_dir / "other.example.json"
        )
        permit = create_trustscan_permit(
            self.store,
            value=other_auth,
            active_checks=("active.xss.reflected",),
        )
        request = ScanJobRequest(
            idempotency_key="active-checks-wrong-target",
            target=TARGET,  # deliberately does not match other_auth.target
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.SINGLE_PAGE,
            submitted_at=NOW,
        )
        self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )
        record = self.store.claim_next(now=NOW)
        assert record is not None
        executor = self.make_executor()
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertIn(
            caught.exception.code,
            (
                "trustscan_permit_target_mismatch",
                "authorization_target_mismatch",
                "trustscan_permit_authorization_mismatch",
            ),
        )
        self.assertFalse(self.artifacts.exists())


if __name__ == "__main__":
    unittest.main()
