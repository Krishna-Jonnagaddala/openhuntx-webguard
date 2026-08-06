from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from webguard_api import (
    AuthorizationRepository,
    JobExecutionOutcome,
    ScanJobStore,
    ScanJobWorker,
    WebGuardJobService,
    create_server,
)

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET, completed_report, write_authorization


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
class ScanJobServiceIntegrationTests(unittest.TestCase):
    def test_http_submission_flows_through_persistent_worker_queue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir = root / "authorizations"
            write_authorization(auth_dir)
            store = ScanJobStore(root / "jobs.sqlite3")
            service = WebGuardJobService(
                store=store,
                authorizations=AuthorizationRepository(auth_dir),
                clock=lambda: NOW,
            )
            worker = ScanJobWorker(
                store=store,
                executor=FakeExecutor(),
                poll_seconds=0.01,
                clock=lambda: NOW,
            )
            stop = threading.Event()
            worker_thread = threading.Thread(
                target=worker.run_forever,
                args=(stop,),
                daemon=True,
            )
            server = create_server(
                "127.0.0.1",
                0,
                service,
                maximum_request_bytes=4096,
            )
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            worker_thread.start()
            server_thread.start()
            host, port = server.server_address[:2]
            try:
                body = json.dumps(
                    {
                        "target": TARGET,
                        "authorization_id": AUTH_ID,
                        "confirm_authorization": AUTH_ID,
                        "mode": "crawl",
                    }
                ).encode("utf-8")
                connection = http.client.HTTPConnection(host, port, timeout=3)
                connection.request(
                    "POST",
                    "/v1/jobs",
                    body=body,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                        "Idempotency-Key": "service-integration-1",
                    },
                )
                response = connection.getresponse()
                created = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201)
                job_id = created["job_id"]

                deadline = time.monotonic() + 3
                result = None
                while time.monotonic() < deadline:
                    connection = http.client.HTTPConnection(host, port, timeout=3)
                    connection.request("GET", f"/v1/jobs/{job_id}/result")
                    response = connection.getresponse()
                    payload = json.loads(response.read())
                    connection.close()
                    if response.status == 200:
                        result = payload
                        break
                    self.assertEqual(response.status, 409)
                    time.sleep(0.02)
                self.assertIsNotNone(result)
                assert result is not None
                self.assertEqual(result["state"], "completed")
                self.assertEqual(result["report_ref"], f"jobs/{job_id}/report.json")
                self.assertNotIn("findings", result)
            finally:
                stop.set()
                server.shutdown()
                server.server_close()
                worker_thread.join(timeout=2)
                server_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
