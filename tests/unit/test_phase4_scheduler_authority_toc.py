from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    AuthorizationRepository,
    IdentityStore,
    ScanJobStore,
    ScanScheduleCoordinator,
)
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
)

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


SCHEDULE_ID = (
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)


class HookedEnqueueStore(ScanJobStore):
    """Expose the scheduler validation -> enqueue boundary."""

    def __init__(self, path: Path) -> None:
        self.before_enqueue = None
        super().__init__(path)

    def enqueue_due_schedule(
        self,
        *args,
        **kwargs,
    ):
        hook = self.before_enqueue

        if hook is not None:
            self.before_enqueue = None
            hook()

        return super().enqueue_due_schedule(
            *args,
            **kwargs,
        )


class MutableClock:
    def __init__(self, value) -> None:
        self.current = value

    def __call__(self):
        return self.current


class AdvancingAuthorizationRepository(
    AuthorizationRepository
):
    """Advance wall time after scheduler reads authorization."""

    def __init__(
        self,
        directory: Path,
        *,
        clock: MutableClock,
        advance_to,
    ) -> None:
        super().__init__(directory)
        self.clock = clock
        self.advance_to = advance_to
        self.advanced = False

    def get(self, authorization_id: str):
        value = super().get(
            authorization_id
        )

        if not self.advanced:
            self.advanced = True
            self.clock.current = self.advance_to

        return value


class Phase4SchedulerAuthorityTOCTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = (
            tempfile.TemporaryDirectory()
        )
        self.root = Path(
            self.temporary.name
        )
        self.path = (
            self.root / "jobs.sqlite3"
        )
        self.auth_dir = (
            self.root / "authorizations"
        )

        write_authorization(
            self.auth_dir
        )

        self.store = HookedEnqueueStore(
            self.path
        )

        self.identity = IdentityStore(
            self.path
        )

        self.identity.create_organization(
            "Phase 4 Scheduler Tenant",
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

    def create_schedule(
        self,
        *,
        permit,
    ):
        return self.store.create_schedule(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name="Phase 4 authority race",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=(
                authorization().fingerprint
            ),
            mode=ScanJobMode.CRAWL,
            interval_seconds=3600,
            starts_at=NOW,
            now=NOW,
            schedule_id=SCHEDULE_ID,
            permit_id=(
                permit.permit.claims.permit_id
            ),
            permit_sha256=(
                permit.permit.fingerprint
            ),
        )

    def coordinator(
        self,
        *,
        authorizations=None,
        clock=None,
    ) -> ScanScheduleCoordinator:
        effective_authorizations = (
            AuthorizationRepository(
                self.auth_dir
            )
            if authorizations is None
            else authorizations
        )

        effective_clock = (
            (lambda: NOW)
            if clock is None
            else clock
        )

        return ScanScheduleCoordinator(
            store=self.store,
            authorizations=effective_authorizations,
            identity=self.identity,
            trustscan_signer=trustscan_signer(
                self.store
            ),
            clock=effective_clock,
        )

    def test_assignment_removed_after_validation_cannot_cross_claim_boundary(
        self,
    ) -> None:
        permit = create_trustscan_permit(
            self.store
        )

        self.create_schedule(
            permit=permit
        )

        def remove_assignment() -> None:
            connection = sqlite3.connect(
                self.path
            )

            try:
                connection.execute(
                    """
                    DELETE FROM organization_authorizations
                    WHERE organization_id = ?
                      AND authorization_id = ?
                    """,
                    (
                        ORG_ID,
                        AUTH_ID,
                    ),
                )
                connection.commit()
            finally:
                connection.close()

        self.store.before_enqueue = (
            remove_assignment
        )

        summary = (
            self.coordinator().run_once()
        )

        assignment_remains = (
            self.identity.authorization_is_assigned(
                ORG_ID,
                AUTH_ID,
            )
        )

        claimed = self.store.claim_next(
            now=NOW
        )

        self.assertFalse(
            assignment_remains
        )

        self.assertIsNone(
            claimed,
            msg=(
                "Removed organization authorization "
                "must not cross the worker-claim "
                "boundary."
            ),
        )

        self.assertEqual(
            summary.enqueued,
            0,
            msg=(
                "A schedule must not materialize work "
                "after its organization authorization "
                "assignment has been removed."
            ),
        )

    def test_expired_permit_cannot_cross_claim_boundary_after_stale_scheduler_snapshot(
        self,
    ) -> None:
        expiry = (
            NOW + timedelta(seconds=1)
        )

        permit = create_trustscan_permit(
            self.store,
            expires_at=expiry,
        )

        self.create_schedule(
            permit=permit
        )

        clock = MutableClock(NOW)

        repository = (
            AdvancingAuthorizationRepository(
                self.auth_dir,
                clock=clock,
                advance_to=(
                    NOW
                    + timedelta(seconds=2)
                ),
            )
        )

        summary = self.coordinator(
            authorizations=repository,
            clock=clock,
        ).run_once()

        self.assertEqual(
            summary.inspected,
            1,
        )

        claimed = self.store.claim_next(
            now=clock.current
        )

        self.assertIsNone(
            claimed,
            msg=(
                "A permit that expired during a "
                "scheduler pass must not cross the "
                "worker-claim boundary."
            ),
        )


if __name__ == "__main__":
    unittest.main()
