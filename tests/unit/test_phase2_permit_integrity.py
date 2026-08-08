from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from webguard_api import (
    ApiServiceError,
    AuthorizationRepository,
    ScanJobStore,
    WebGuardJobService,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    TARGET,
    create_identity_fixture,
    create_trustscan_permit,
    write_authorization,
)


OTHER_ORG_ID = "88888888-8888-4888-8888-888888888888"


def job_submission() -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
        }
    ).encode("utf-8")


def schedule_submission() -> bytes:
    starts_at = (
        NOW + timedelta(hours=1)
    ).isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )

    return json.dumps(
        {
            "name": "Phase2 permit integrity schedule",
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
            "interval_seconds": 86400,
            "starts_at": starts_at,
        }
    ).encode("utf-8")


class Phase2PermitIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)

        auth_dir = root / "authorizations"
        write_authorization(auth_dir)

        self.store = ScanJobStore(
            root / "jobs.sqlite3"
        )

        self.identity, self.context, _ = (
            create_identity_fixture(self.store.path)
        )

        self.permit = create_trustscan_permit(
            self.store
        )
        self.permit_id = (
            self.permit.permit.claims.permit_id
        )

        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(
                auth_dir
            ),
            identity=self.identity,
            clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _row_count(self, table: str) -> int:
        if table == "scan_jobs":
            statement = "SELECT COUNT(*) FROM scan_jobs"
        elif table == "scan_schedules":
            statement = "SELECT COUNT(*) FROM scan_schedules"
        else:
            self.fail(
                f"Unexpected audit table: {table}"
            )

        connection = sqlite3.connect(
            self.store.path
        )

        try:
            return int(
                connection.execute(
                    statement
                ).fetchone()[0]
            )
        finally:
            connection.close()

    def _permit_document(self) -> tuple[str, dict]:
        connection = sqlite3.connect(
            self.store.path
        )
        connection.row_factory = sqlite3.Row

        try:
            row = connection.execute(
                """
                SELECT *
                FROM scan_permits
                WHERE permit_id = ?
                """,
                (self.permit_id,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(row)

        for column in row.keys():
            value = row[column]

            if not isinstance(value, str):
                continue

            try:
                document = json.loads(value)
            except json.JSONDecodeError:
                continue

            if (
                isinstance(document, dict)
                and isinstance(
                    document.get("claims"),
                    dict,
                )
                and isinstance(
                    document.get("signature"),
                    dict,
                )
            ):
                return column, document

        self.fail(
            "Could not identify the persisted "
            "TrustScan permit JSON column."
        )

    def _write_permit_document(
        self,
        document: dict,
    ) -> None:
        column, _ = self._permit_document()

        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        connection = sqlite3.connect(
            self.store.path
        )

        try:
            if column == "permit_json":
                connection.execute(
                    """
                    UPDATE scan_permits
                    SET permit_json = ?
                    WHERE permit_id = ?
                    """,
                    (encoded, self.permit_id),
                )
            elif column == "signed_permit_json":
                connection.execute(
                    """
                    UPDATE scan_permits
                    SET signed_permit_json = ?
                    WHERE permit_id = ?
                    """,
                    (encoded, self.permit_id),
                )
            elif column == "permit_document":
                connection.execute(
                    """
                    UPDATE scan_permits
                    SET permit_document = ?
                    WHERE permit_id = ?
                    """,
                    (encoded, self.permit_id),
                )
            elif column == "document_json":
                connection.execute(
                    """
                    UPDATE scan_permits
                    SET document_json = ?
                    WHERE permit_id = ?
                    """,
                    (encoded, self.permit_id),
                )
            else:
                self.fail(
                    "Unexpected TrustScan permit "
                    f"JSON column: {column}"
                )

            connection.commit()
        finally:
            connection.close()

    def _tamper_claim(
        self,
        name: str,
        value: object,
    ) -> None:
        _, document = self._permit_document()

        self.assertIn(name, document["claims"])

        document["claims"][name] = value

        self._write_permit_document(
            document
        )

    def _tamper_signature(self) -> None:
        _, document = self._permit_document()

        signature = document["signature"]

        candidates = [
            key
            for key, value in signature.items()
            if (
                key != "algorithm"
                and isinstance(value, str)
                and value
            )
        ]

        self.assertTrue(
            candidates,
            msg=(
                "Could not identify a signature "
                "value to tamper."
            ),
        )

        # The actual Ed25519 signature should be
        # the longest encoded signature field.
        key = max(
            candidates,
            key=lambda item: len(signature[item]),
        )

        value = signature[key]

        replacement = (
            "A"
            if value[0] != "A"
            else "B"
        )

        signature[key] = (
            replacement + value[1:]
        )

        self._write_permit_document(
            document
        )

    def _assert_job_rejected(
        self,
        key: str,
    ) -> ApiServiceError:
        before = self._row_count(
            "scan_jobs"
        )

        with self.assertRaises(
            ApiServiceError
        ) as caught:
            self.service.submit(
                self.context,
                job_submission(),
                idempotency_key=key,
                permit_id=self.permit_id,
                request_id=str(uuid4()),
            )

        after = self._row_count(
            "scan_jobs"
        )

        self.assertEqual(
            after,
            before,
            msg=(
                "A job was persisted after "
                "TrustScan permit tampering."
            ),
        )

        return caught.exception

    def test_untampered_persisted_permit_authorizes_job(
        self,
    ) -> None:
        before = self._row_count(
            "scan_jobs"
        )

        job, created = self.service.submit(
            self.context,
            job_submission(),
            idempotency_key=(
                "phase2-permit-positive-control"
            ),
            permit_id=self.permit_id,
            request_id=str(uuid4()),
        )

        self.assertTrue(created)
        self.assertEqual(
            job["state"],
            "queued",
        )
        self.assertEqual(
            self._row_count("scan_jobs"),
            before + 1,
        )

    def test_tampered_signature_cannot_authorize_job(
        self,
    ) -> None:
        self._tamper_signature()

        self._assert_job_rejected(
            "phase2-tampered-signature"
        )

    def test_tampered_target_claim_cannot_authorize_job(
        self,
    ) -> None:
        self._tamper_claim(
            "target",
            "https://tampered.example/",
        )

        self._assert_job_rejected(
            "phase2-tampered-target"
        )

    def test_tampered_authorization_id_cannot_authorize_job(
        self,
    ) -> None:
        _, document = self._permit_document()

        current = document[
            "claims"
        ]["authorization_id"]

        self.assertIsInstance(
            current,
            str,
        )
        self.assertTrue(current)

        replacement = (
            "a"
            if current[-1] != "a"
            else "b"
        )

        changed = (
            current[:-1] + replacement
        )

        self._tamper_claim(
            "authorization_id",
            changed,
        )

        self._assert_job_rejected(
            "phase2-tampered-auth-id"
        )

    def test_tampered_authorization_fingerprint_cannot_authorize_job(
        self,
    ) -> None:
        _, document = self._permit_document()

        current = document[
            "claims"
        ]["authorization_sha256"]

        self.assertIsInstance(
            current,
            str,
        )
        self.assertEqual(
            len(current),
            64,
        )

        replacement = (
            "a"
            if current[0] != "a"
            else "b"
        )

        changed = (
            replacement + current[1:]
        )

        self._tamper_claim(
            "authorization_sha256",
            changed,
        )

        self._assert_job_rejected(
            "phase2-tampered-auth-sha"
        )

    def test_tampered_mode_claim_cannot_authorize_job(
        self,
    ) -> None:
        self._tamper_claim(
            "permitted_modes",
            ["single_page"],
        )

        self._assert_job_rejected(
            "phase2-tampered-mode"
        )

    def test_tampered_request_budget_cannot_authorize_job(
        self,
    ) -> None:
        _, document = self._permit_document()

        current = document[
            "claims"
        ]["maximum_request_attempts"]

        self.assertIsInstance(
            current,
            int,
        )
        self.assertGreater(
            current,
            1,
        )

        self._tamper_claim(
            "maximum_request_attempts",
            current - 1,
        )

        self._assert_job_rejected(
            "phase2-tampered-budget"
        )

    def test_tampered_organization_claim_cannot_authorize_job(
        self,
    ) -> None:
        self._tamper_claim(
            "organization_id",
            OTHER_ORG_ID,
        )

        error = self._assert_job_rejected(
            "phase2-tampered-org"
        )

        self.assertEqual(
            error.status,
            500,
        )
        self.assertEqual(
            error.code,
            "trustscan_permit_document_invalid",
        )
        self.assertEqual(
            error.message,
            "Persisted TrustScan permit document is invalid.",
        )

    def test_tampered_signature_cannot_create_schedule(
        self,
    ) -> None:
        self._tamper_signature()

        before = self._row_count(
            "scan_schedules"
        )

        with self.assertRaises(
            ApiServiceError
        ):
            self.service.create_schedule(
                self.context,
                schedule_submission(),
                permit_id=self.permit_id,
                request_id=str(uuid4()),
            )

        self.assertEqual(
            self._row_count(
                "scan_schedules"
            ),
            before,
            msg=(
                "A schedule was persisted after "
                "TrustScan permit tampering."
            ),
        )


if __name__ == "__main__":
    unittest.main()
