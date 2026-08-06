from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    ApiServiceError,
    AuthorizationRepository,
    ScanJobStore,
    WebGuardJobService,
)
from webguard_contracts import ScanJobState, ScanStatus

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET, write_authorization


def body(**changes) -> bytes:
    values = {
        "target": TARGET,
        "authorization_id": AUTH_ID,
        "confirm_authorization": AUTH_ID,
        "mode": "crawl",
    }
    values.update(changes)
    return json.dumps(values).encode("utf-8")


class WebGuardJobServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        self.store = ScanJobStore(root / "jobs.sqlite3")
        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_submit_returns_queued_job(self) -> None:
        document, created = self.service.submit(
            body(),
            idempotency_key="internstack-20260806",
        )
        self.assertTrue(created)
        self.assertEqual(document["state"], "queued")
        self.assertEqual(document["request"]["authorization_id"], AUTH_ID)
        self.assertNotIn("confirm_authorization", json.dumps(document))

    def test_idempotent_submit_returns_same_job(self) -> None:
        first, created = self.service.submit(body(), idempotency_key="internstack-20260806")
        self.assertTrue(created)
        second, created = self.service.submit(body(), idempotency_key="internstack-20260806")
        self.assertFalse(created)
        self.assertEqual(second["job_id"], first["job_id"])

    def test_idempotency_conflict_is_http_409(self) -> None:
        self.service.submit(body(), idempotency_key="internstack-20260806")
        with self.assertRaises(ApiServiceError) as caught:
            self.service.submit(
                body(mode="single_page"),
                idempotency_key="internstack-20260806",
            )
        self.assertEqual(caught.exception.status, 409)

    def test_invalid_body_is_http_400(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.submit(b"{}", idempotency_key="internstack-20260806")
        self.assertEqual(caught.exception.status, 400)

    def test_target_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(ApiServiceError, "does not match"):
            self.service.submit(
                body(target="https://www.internstack.in/"),
                idempotency_key="internstack-20260806",
            )


    def test_invalid_idempotency_key_is_http_400(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.submit(body(), idempotency_key="short")
        self.assertEqual(caught.exception.status, 400)

    def test_get_unknown_job_is_http_404(self) -> None:
        with self.assertRaises(ApiServiceError) as caught:
            self.service.get("b6a39765-16c6-42b4-91f0-998bf07f1912")
        self.assertEqual(caught.exception.status, 404)

    def test_cancel_queued_job(self) -> None:
        document, _ = self.service.submit(body(), idempotency_key="internstack-20260806")
        cancelled = self.service.cancel(document["job_id"])
        self.assertEqual(cancelled["state"], "cancelled")

    def test_result_is_not_ready_for_queued_job(self) -> None:
        document, _ = self.service.submit(body(), idempotency_key="internstack-20260806")
        with self.assertRaises(ApiServiceError) as caught:
            self.service.result(document["job_id"])
        self.assertEqual(caught.exception.status, 409)

    def test_result_returns_refs_not_report_body(self) -> None:
        document, _ = self.service.submit(body(), idempotency_key="internstack-20260806")
        job_id = document["job_id"]
        self.store.claim_next(now=NOW)
        self.store.finish_result(
            job_id,
            scan_id="b6a39765-16c6-42b4-91f0-998bf07f1912",
            result_status=ScanStatus.COMPLETED,
            report_ref=f"jobs/{job_id}/report.json",
            audit_ref=f"jobs/{job_id}/authorization-audit.json",
            now=NOW + timedelta(seconds=1),
        )
        result = self.service.result(job_id)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["report_ref"], f"jobs/{job_id}/report.json")
        self.assertNotIn("findings", result)
        self.assertNotIn("authorization", result)


if __name__ == "__main__":
    unittest.main()
