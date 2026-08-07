from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from webguard_api import (
    ApiTokenAuthenticator,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    JobExecutionOutcome,
    ScanJobStore,
    ScanJobWorker,
    ScanScheduleCoordinator,
    WebGuardJobService,
    create_server,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    TARGET,
    completed_report,
    create_identity_fixture,
    write_authorization,
)

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"


class FakeExecutor:
    def execute(self, record, *, cancellation_token):
        report = completed_report("b6a39765-16c6-42b4-91f0-998bf07f1912")
        return JobExecutionOutcome(
            report=report,
            report_ref=f"jobs/{record.job_id}/report.json",
            audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
        )


@unittest.skipUnless(
    RUN_INTEGRATION,
    "Set WEBGUARD_RUN_INTEGRATION=1 to run service integration tests.",
)
class ScanScheduleServiceIntegrationTests(unittest.TestCase):
    def test_authenticated_schedule_materializes_and_completes_job(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir = root / "authorizations"
            write_authorization(auth_dir)
            store = ScanJobStore(root / "jobs.sqlite3")
            identity, context, token = create_identity_fixture(store.path)
            repository = AuthorizationRepository(auth_dir)
            service = WebGuardJobService(
                store=store,
                authorizations=repository,
                identity=identity,
                clock=lambda: NOW,
            )
            scheduler = ScanScheduleCoordinator(
                store=store,
                authorizations=repository,
                identity=identity,
                clock=lambda: NOW,
            )
            worker = ScanJobWorker(
                store=store,
                executor=FakeExecutor(),
                poll_seconds=0.01,
                clock=lambda: NOW,
            )
            server = create_server(
                "127.0.0.1",
                0,
                service,
                authenticator=ApiTokenAuthenticator(identity),
                rate_limiter=FixedWindowRateLimiter(requests=100, window_seconds=60),
                maximum_request_bytes=4096,
                clock=lambda: NOW,
                epoch_clock=lambda: 1000.0,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            try:
                starts_at = NOW.isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                )
                body = json.dumps(
                    {
                        "name": "Hourly authorised crawl",
                        "target": TARGET,
                        "authorization_id": AUTH_ID,
                        "confirm_authorization": AUTH_ID,
                        "mode": "crawl",
                        "interval_seconds": 3600,
                        "starts_at": starts_at,
                    }
                ).encode("utf-8")
                connection = http.client.HTTPConnection(host, port, timeout=3)
                connection.request(
                    "POST",
                    "/v1/schedules",
                    body=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                    },
                )
                response = connection.getresponse()
                created = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201)
                self.assertEqual(created["organization_id"], context.organization_id)

                summary = scheduler.run_once()
                self.assertEqual(summary.enqueued, 1)
                schedule = store.get_schedule_scoped(
                    created["schedule_id"], context.organization_id
                )
                self.assertIsNotNone(schedule.last_job_id)
                assert schedule.last_job_id is not None

                self.assertTrue(worker.run_once())
                connection = http.client.HTTPConnection(host, port, timeout=3)
                connection.request(
                    "GET",
                    f"/v1/jobs/{schedule.last_job_id}/result",
                    headers={"Authorization": f"Bearer {token}"},
                )
                response = connection.getresponse()
                result = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 200)
                self.assertEqual(result["state"], "completed")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
