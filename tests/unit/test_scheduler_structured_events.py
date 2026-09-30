"""P1-B1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
call-site proofs that ScanScheduleCoordinator emits the required
structured events with correct fields, including edge-triggered (not
per-poll-cycle) outage detection/recovery. Reuses test_scheduler.py's
own fast, real-SQLite fixture pattern.
"""

from __future__ import annotations

import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from webguard_api import AuthorizationRepository, IdentityStore, ScanJobStore, ScanScheduleCoordinator
from webguard_api.db_errors import DatabaseUnavailableError
from webguard_api.structured_logging import configure_structured_logging
from webguard_contracts import OrganizationRole, PrincipalType, ScanJobMode

from tests.unit.service_test_support import (
    AUTH_ID, NOW, ORG_ID, OWNER_ID, TARGET,
    authorization, create_trustscan_permit, trustscan_signer, write_authorization,
)

SCHEDULE_ID = "66666666-6666-4666-8666-666666666666"


def _lines(buf: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def _events(buf: io.StringIO, name: str) -> list[dict]:
    return [line for line in _lines(buf) if line.get("event") == name]


class SchedulerStructuredEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "authorizations"
        write_authorization(self.auth_dir)
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        self.identity = IdentityStore(self.store.path)
        self.identity.create_organization("InternStack", now=NOW, organization_id=ORG_ID)
        self.identity.create_principal(
            ORG_ID, "Owner", principal_type=PrincipalType.USER, role=OrganizationRole.OWNER,
            now=NOW, principal_id=OWNER_ID,
        )
        self.identity.assign_authorization(ORG_ID, AUTH_ID, assigned_by=OWNER_ID, now=NOW)
        self.signer = trustscan_signer(self.store)
        self.permit = create_trustscan_permit(self.store)
        self.buf = io.StringIO()
        configure_structured_logging(service="scheduler", stream=self.buf)

    def create_schedule(self, **changes):
        values = dict(
            organization_id=ORG_ID, created_by=OWNER_ID, name="Hourly", target=TARGET,
            authorization_id=AUTH_ID, authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL, interval_seconds=3600, starts_at=NOW, now=NOW, schedule_id=SCHEDULE_ID,
        )
        values.update(changes)
        values.setdefault("permit_id", self.permit.permit.claims.permit_id)
        values.setdefault("permit_sha256", self.permit.permit.fingerprint)
        return self.store.create_schedule(**values)

    def coordinator(self, **changes):
        values = dict(
            store=self.store, authorizations=AuthorizationRepository(self.auth_dir),
            identity=self.identity, trustscan_signer=self.signer, clock=lambda: NOW,
        )
        values.update(changes)
        return ScanScheduleCoordinator(**values)

    def test_schedule_materialized_has_correct_fields(self) -> None:
        self.create_schedule()
        summary = self.coordinator().run_once()
        self.assertEqual(summary.enqueued, 1)

        events = _events(self.buf, "schedule_materialized")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["schedule_id"], SCHEDULE_ID)
        self.assertIn("job_id", events[0])
        self.assertEqual(events[0]["level"], "info")

    def test_schedule_materialization_failed_has_error_code(self) -> None:
        other_auth = "77777777-7777-4777-8777-777777777777"
        self.create_schedule(authorization_id=other_auth)
        summary = self.coordinator().run_once()
        self.assertEqual(summary.blocked, 1)

        events = _events(self.buf, "schedule_materialization_failed")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["schedule_id"], SCHEDULE_ID)
        self.assertEqual(events[0]["error_code"], "authorization_not_assigned")
        self.assertEqual(events[0]["level"], "warning")

    def test_scheduler_started_and_stopped_bracket_run_forever(self) -> None:
        coordinator = self.coordinator(poll_seconds=0.1)
        stop_event = threading.Event()
        thread = threading.Thread(target=coordinator.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        time.sleep(0.05)
        stop_event.set()
        thread.join(timeout=3)

        self.assertEqual(len(_events(self.buf, "scheduler_started")), 1)
        self.assertEqual(len(_events(self.buf, "scheduler_stopped")), 1)

    def test_database_outage_detected_and_recovered_are_edge_triggered(self) -> None:
        coordinator = self.coordinator(poll_seconds=0.1)
        real_list = self.store.list_due_schedules
        state = {"fail": True}

        def flaky_list(*args, **kwargs):
            if state["fail"]:
                raise DatabaseUnavailableError("database_unavailable", "simulated outage")
            return real_list(*args, **kwargs)

        self.store.list_due_schedules = flaky_list  # type: ignore[method-assign]
        stop_event = threading.Event()
        thread = threading.Thread(target=coordinator.run_forever, args=(stop_event,), daemon=True)
        thread.start()
        time.sleep(0.35)  # several failed iterations at a 0.1s poll interval
        self.assertEqual(
            len(_events(self.buf, "database_outage_detected")), 1,
            "must be exactly one event for the whole outage episode, not one per poll cycle",
        )
        self.assertEqual(len(_events(self.buf, "database_outage_recovered")), 0)

        state["fail"] = False
        time.sleep(0.35)
        stop_event.set()
        thread.join(timeout=3)

        self.assertEqual(len(_events(self.buf, "database_outage_detected")), 1)
        self.assertEqual(len(_events(self.buf, "database_outage_recovered")), 1)


if __name__ == "__main__":
    unittest.main()
