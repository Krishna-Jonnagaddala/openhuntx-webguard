from __future__ import annotations

import queue
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from webguard_api import (
    AuthorizationRepository,
    IdentityStore,
    ScanJobStore,
    ScanScheduleCoordinator,
    TrustScanRuntimeSafetyEngine,
    TrustScanRuntimeSafetyError,
)
from webguard_api.permits import validate_permit_use
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
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


SCHEDULE_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
RUNTIME_JOB_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
RUNTIME_SCAN_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def request(key: str) -> ScanJobRequest:
    auth = authorization()
    return ScanJobRequest(
        idempotency_key=key,
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256=auth.fingerprint,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


def runtime_target() -> ValidatedTarget:
    from urllib.parse import urlsplit

    parsed = urlsplit(TARGET)
    return ValidatedTarget(
        original_url=TARGET,
        normalised_url=TARGET,
        scheme=parsed.scheme,
        hostname=parsed.hostname or "",
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        resolved_addresses=("203.0.113.10",),
    )


def runtime_response() -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=(),
        body=b"",
        connected_address="203.0.113.10",
        elapsed_milliseconds=1,
    )


class PauseBeforeEnqueueStore(ScanJobStore):
    """Create a deterministic permit-revocation TOCTOU window."""

    def __init__(self, path: Path) -> None:
        self.before_enqueue = threading.Event()
        self.continue_enqueue = threading.Event()
        super().__init__(path)

    def enqueue_due_schedule(self, *args, **kwargs):
        self.before_enqueue.set()

        if not self.continue_enqueue.wait(timeout=10):
            raise RuntimeError(
                "Timed out waiting to continue scheduler enqueue."
            )

        return super().enqueue_due_schedule(*args, **kwargs)


class Phase3RevocationCancellationRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"
        self.store = ScanJobStore(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_cancellation_and_claim_have_one_safe_atomic_outcome(self) -> None:
        record, _ = self.store.submit(
            request("phase3-cancel-claim-race")
        )

        claiming_store = ScanJobStore(self.path)
        cancelling_store = ScanJobStore(self.path)

        barrier = threading.Barrier(2)
        outcomes: queue.Queue[tuple[str, object]] = queue.Queue()

        def claim() -> None:
            try:
                barrier.wait(timeout=10)
                outcomes.put(
                    (
                        "claim",
                        claiming_store.claim_next_leased(
                            now=NOW,
                            worker_id="phase3-cancel-race-worker",
                            lease_seconds=30,
                        ),
                    )
                )
            except BaseException as exc:
                outcomes.put(("claim", exc))

        def cancel() -> None:
            try:
                barrier.wait(timeout=10)
                outcomes.put(
                    (
                        "cancel",
                        cancelling_store.request_cancellation(
                            record.job_id,
                            now=NOW,
                        ),
                    )
                )
            except BaseException as exc:
                outcomes.put(("cancel", exc))

        threads = [
            threading.Thread(target=claim, daemon=True),
            threading.Thread(target=cancel, daemon=True),
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=15)
            if thread.is_alive():
                self.fail("Cancellation/claim race did not terminate.")

        results = {
            name: value
            for name, value in (
                outcomes.get_nowait(),
                outcomes.get_nowait(),
            )
        }

        for value in results.values():
            if isinstance(value, BaseException):
                self.fail(f"Unexpected race exception: {value!r}")

        final = self.store.get(record.job_id)

        if results["claim"] is None:
            self.assertIs(final.state, ScanJobState.CANCELLED)
            self.assertTrue(final.cancellation_requested)
        else:
            self.assertIs(final.state, ScanJobState.RUNNING)
            self.assertTrue(final.cancellation_requested)
            self.assertEqual(
                results["claim"].record.job_id,
                record.job_id,
            )

    def test_revoked_queued_permit_must_not_transition_job_to_running(
        self,
    ) -> None:
        permit = create_trustscan_permit(self.store)

        record, _ = self.store.submit(
            request("phase3-revoked-before-claim"),
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )

        self.store.revoke_scan_permit_scoped(
            permit.permit.claims.permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )

        claimed = self.store.claim_next_leased(
            now=NOW,
            worker_id="phase3-revoked-permit-worker",
            lease_seconds=30,
        )

        self.assertIsNone(
            claimed,
            "A job backed by a revoked TrustScan permit entered RUNNING.",
        )
        self.assertIs(
            self.store.get(record.job_id).state,
            ScanJobState.QUEUED,
        )

    def test_expired_queued_permit_must_not_transition_job_to_running(
        self,
    ) -> None:
        permit = create_trustscan_permit(
            self.store,
            expires_at=NOW + timedelta(seconds=1),
        )

        record, _ = self.store.submit(
            request("phase3-expired-before-claim"),
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )

        claimed = self.store.claim_next_leased(
            now=NOW + timedelta(seconds=2),
            worker_id="phase3-expired-permit-worker",
            lease_seconds=30,
        )

        self.assertIsNone(
            claimed,
            "A job backed by an expired TrustScan permit entered RUNNING.",
        )
        self.assertIs(
            self.store.get(record.job_id).state,
            ScanJobState.QUEUED,
        )

    def test_legacy_claim_next_cannot_bypass_revoked_permit(
        self,
    ) -> None:
        permit = create_trustscan_permit(self.store)

        record, _ = self.store.submit(
            request("phase3-legacy-revoked-claim"),
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )

        self.store.revoke_scan_permit_scoped(
            permit.permit.claims.permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )

        claimed = self.store.claim_next(
            now=NOW,
        )

        self.assertIsNone(
            claimed,
            "Legacy claim_next bypassed TrustScan permit revocation.",
        )
        self.assertIs(
            self.store.get(record.job_id).state,
            ScanJobState.QUEUED,
        )

    def test_runtime_revocation_blocks_before_next_request(self) -> None:
        permit = create_trustscan_permit(self.store)
        signer = trustscan_signer(self.store)
        auth = authorization()

        def revalidate() -> None:
            current = self.store.get_scan_permit_scoped(
                permit.permit.claims.permit_id,
                ORG_ID,
            )
            validate_permit_use(
                current,
                signer=signer,
                organization_id=ORG_ID,
                authorization=auth,
                target=TARGET,
                mode=ScanJobMode.CRAWL,
                now=NOW,
            )

        engine = TrustScanRuntimeSafetyEngine(
            permit=permit,
            signer=signer,
            organization_id=ORG_ID,
            job_id=RUNTIME_JOB_ID,
            scan_id=RUNTIME_SCAN_ID,
            target=TARGET,
            revalidate=revalidate,
            clock=lambda: NOW,
            monotonic=lambda: 0.0,
            sleeper=lambda _seconds: None,
        )

        self.store.revoke_scan_permit_scoped(
            permit.permit.claims.permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )

        with self.assertRaises(
            TrustScanRuntimeSafetyError
        ) as caught:
            engine.before_request(runtime_target(), "GET")

        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_revoked",
        )
        self.assertEqual(engine.requests_attempted, 1)
        self.assertEqual(engine.requests_permitted, 0)
        self.assertEqual(engine.requests_blocked, 1)

    def test_runtime_expiry_blocks_next_request(self) -> None:
        base = create_trustscan_permit(self.store)
        signer = trustscan_signer(self.store)

        short_claims = replace(
            base.permit.claims,
            permit_id=str(uuid4()),
            expires_at=NOW + timedelta(seconds=1),
        )
        short_permit = self.store.create_scan_permit(
            signer.sign(short_claims)
        )

        auth = authorization()
        current_time = [NOW + timedelta(milliseconds=500)]

        def revalidate() -> None:
            current = self.store.get_scan_permit_scoped(
                short_permit.permit.claims.permit_id,
                ORG_ID,
            )
            validate_permit_use(
                current,
                signer=signer,
                organization_id=ORG_ID,
                authorization=auth,
                target=TARGET,
                mode=ScanJobMode.CRAWL,
                now=current_time[0],
            )

        engine = TrustScanRuntimeSafetyEngine(
            permit=short_permit,
            signer=signer,
            organization_id=ORG_ID,
            job_id=RUNTIME_JOB_ID,
            scan_id=RUNTIME_SCAN_ID,
            target=TARGET,
            revalidate=revalidate,
            clock=lambda: current_time[0],
            monotonic=lambda: 0.0,
            sleeper=lambda _seconds: None,
        )

        engine.before_request(runtime_target(), "GET")
        engine.after_request(
            runtime_target(),
            "GET",
            runtime_response(),
            None,
        )

        current_time[0] = NOW + timedelta(seconds=2)

        with self.assertRaises(
            TrustScanRuntimeSafetyError
        ) as caught:
            engine.before_request(runtime_target(), "GET")

        self.assertEqual(
            caught.exception.code,
            "trustscan_permit_expired",
        )
        self.assertEqual(engine.requests_permitted, 1)
        self.assertEqual(engine.requests_blocked, 1)

    def test_scheduler_revocation_race_cannot_enqueue_job(self) -> None:
        auth_dir = self.root / "authorizations"
        write_authorization(auth_dir)

        race_store = PauseBeforeEnqueueStore(self.path)

        identity = IdentityStore(self.path)
        identity.create_organization(
            "Phase 3 Tenant",
            now=NOW,
            organization_id=ORG_ID,
        )
        identity.create_principal(
            ORG_ID,
            "Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )
        identity.assign_authorization(
            ORG_ID,
            AUTH_ID,
            assigned_by=OWNER_ID,
            now=NOW,
        )

        permit = create_trustscan_permit(race_store)

        race_store.create_schedule(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name="Phase 3 revocation race",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL,
            interval_seconds=3600,
            starts_at=NOW,
            now=NOW,
            schedule_id=SCHEDULE_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )

        coordinator = ScanScheduleCoordinator(
            store=race_store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            trustscan_signer=trustscan_signer(race_store),
            clock=lambda: NOW,
        )

        outcomes: queue.Queue[object] = queue.Queue()

        def scheduler_pass() -> None:
            try:
                outcomes.put(coordinator.run_once())
            except BaseException as exc:
                outcomes.put(exc)

        thread = threading.Thread(
            target=scheduler_pass,
            daemon=True,
        )
        thread.start()

        self.assertTrue(
            race_store.before_enqueue.wait(timeout=10),
            "Scheduler did not reach the post-validation enqueue boundary.",
        )

        revocation_store = ScanJobStore(self.path)
        revocation_store.revoke_scan_permit_scoped(
            permit.permit.claims.permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )

        race_store.continue_enqueue.set()

        thread.join(timeout=15)
        if thread.is_alive():
            self.fail("Scheduler revocation race did not terminate.")

        result = outcomes.get_nowait()

        if isinstance(result, BaseException):
            self.fail(f"Unexpected scheduler exception: {result!r}")

        with sqlite3.connect(self.path) as connection:
            job_count = connection.execute(
                "SELECT COUNT(*) FROM scan_jobs"
            ).fetchone()[0]

        self.assertEqual(
            result.enqueued,
            0,
            "Scheduler enqueued work after its TrustScan permit was revoked.",
        )
        self.assertEqual(
            job_count,
            0,
            "A queued job was persisted after concurrent permit revocation.",
        )


if __name__ == "__main__":
    unittest.main()
