from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import ApiServiceError, AuthorizationRepository, ScanJobStore, WebGuardJobService
from webguard_contracts import OrganizationRole

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    TARGET,
    VIEWER_ID,
    VIEWER_TOKEN_ID,
    create_identity_fixture,
    create_trustscan_permit,
    write_authorization,
)

REQUEST_ID = "66666666-6666-4666-8666-666666666666"


def timestamp(value) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def body(**changes) -> bytes:
    values = {
        "name": "Daily passive crawl",
        "target": TARGET,
        "authorization_id": AUTH_ID,
        "confirm_authorization": AUTH_ID,
        "mode": "crawl",
        "interval_seconds": 86400,
        "starts_at": timestamp(NOW + timedelta(hours=1)),
    }
    values.update(changes)
    return json.dumps(values).encode("utf-8")


class ScheduleServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        self.store = ScanJobStore(root / "jobs.sqlite3")
        self.identity, self.context, _ = create_identity_fixture(self.store.path)
        self.permit = create_trustscan_permit(self.store)
        self.permit_id = self.permit.permit.claims.permit_id
        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self, context=None, payload=None):
        return self.service.create_schedule(
            self.context if context is None else context,
            body() if payload is None else payload,
            permit_id=self.permit_id,
            request_id=REQUEST_ID,
        )

    def test_owner_creates_schedule(self) -> None:
        result = self.create()
        self.assertEqual(result["organization_id"], ORG_ID)
        self.assertEqual(result["state"], "active")
        self.assertNotIn("authorization_sha256", result)

    def test_list_and_get_are_tenant_scoped(self) -> None:
        created = self.create()
        listing = self.service.list_schedules(self.context, request_id=REQUEST_ID)
        self.assertEqual(len(listing["schedules"]), 1)
        fetched = self.service.get_schedule(
            self.context,
            created["schedule_id"],
            request_id=REQUEST_ID,
        )
        self.assertEqual(fetched["schedule_id"], created["schedule_id"])

    def test_pause_and_resume(self) -> None:
        created = self.create()
        paused = self.service.pause_schedule(
            self.context,
            created["schedule_id"],
            request_id=REQUEST_ID,
        )
        self.assertEqual(paused["state"], "paused")
        resumed = self.service.resume_schedule(
            self.context,
            created["schedule_id"],
            request_id=REQUEST_ID,
        )
        self.assertEqual(resumed["state"], "active")
        self.assertEqual(
            resumed["next_run_at"],
            timestamp(NOW + timedelta(days=1)),
        )

    def test_viewer_can_read_but_cannot_create_or_update(self) -> None:
        created = self.create()
        _, viewer, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.VIEWER,
            principal_id=VIEWER_ID,
            token_id=VIEWER_TOKEN_ID,
        )
        fetched = self.service.get_schedule(
            viewer,
            created["schedule_id"],
            request_id=REQUEST_ID,
        )
        self.assertEqual(fetched["schedule_id"], created["schedule_id"])
        with self.assertRaises(ApiServiceError) as create_error:
            self.create(context=viewer)
        self.assertEqual(create_error.exception.status, 403)
        with self.assertRaises(ApiServiceError) as update_error:
            self.service.pause_schedule(
                viewer,
                created["schedule_id"],
                request_id=REQUEST_ID,
            )
        self.assertEqual(update_error.exception.status, 403)

    def test_analyst_can_create_and_update(self) -> None:
        _, analyst, _ = create_identity_fixture(
            self.store.path,
            role=OrganizationRole.ANALYST,
            principal_id="77777777-7777-4777-8777-777777777777",
            token_id="88888888-8888-4888-8888-888888888888",
        )
        created = self.create(context=analyst)
        paused = self.service.pause_schedule(
            analyst,
            created["schedule_id"],
            request_id=REQUEST_ID,
        )
        self.assertEqual(paused["state"], "paused")

    def test_start_in_past_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as context:
            self.create(payload=body(starts_at=timestamp(NOW - timedelta(seconds=1))))
        self.assertEqual(context.exception.code, "schedule_start_in_past")
        self.assertEqual(context.exception.status, 400)

    def test_start_more_than_one_year_away_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as context:
            self.create(payload=body(starts_at=timestamp(NOW + timedelta(days=366))))
        self.assertEqual(context.exception.code, "schedule_start_too_distant")

    def test_target_mismatch_is_rejected(self) -> None:
        with self.assertRaises(ApiServiceError) as context:
            self.create(payload=body(target="https://different.example/"))
        self.assertEqual(context.exception.code, "authorization_target_mismatch")

    def test_unknown_schedule_is_404(self) -> None:
        with self.assertRaises(ApiServiceError) as context:
            self.service.get_schedule(
                self.context,
                "99999999-9999-4999-8999-999999999999",
                request_id=REQUEST_ID,
            )
        self.assertEqual(context.exception.status, 404)

    def test_schedule_actions_are_audited(self) -> None:
        created = self.create()
        self.service.pause_schedule(
            self.context,
            created["schedule_id"],
            request_id=REQUEST_ID,
        )
        actions = {event.action for event in self.identity.list_audit_events(ORG_ID)}
        self.assertIn("schedules.create", actions)
        self.assertIn("schedules.pause", actions)


if __name__ == "__main__":
    unittest.main()
