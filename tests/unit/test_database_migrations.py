from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import DATABASE_SCHEMA_VERSION, JobStoreError, ScanJobStore
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanJobState

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET


JOB_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def request() -> ScanJobRequest:
    return ScanJobRequest(
        idempotency_key="migration-test",
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256="a" * 64,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


def timestamp(value) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def create_v1_database(
    path: Path,
    *,
    state: ScanJobState = ScanJobState.QUEUED,
    cancellation_requested: bool = False,
) -> None:
    value = request()
    started_at = None
    if state is ScanJobState.RUNNING:
        started_at = timestamp(NOW + timedelta(seconds=1))
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE service_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE scan_jobs (
                job_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                request_fingerprint TEXT NOT NULL,
                target TEXT NOT NULL,
                authorization_id TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                mode TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                revision INTEGER NOT NULL,
                cancellation_requested INTEGER NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                scan_id TEXT,
                result_status TEXT,
                report_ref TEXT,
                audit_ref TEXT,
                error_code TEXT,
                error_message TEXT
            );
            CREATE TABLE job_scopes (
                job_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                FOREIGN KEY (job_id) REFERENCES scan_jobs(job_id) ON DELETE CASCADE
            );
            INSERT INTO service_metadata(key, value)
                VALUES ('schema_version', '1');
            """
        )
        connection.execute(
            """
            INSERT INTO scan_jobs (
                job_id, idempotency_key, request_fingerprint,
                target, authorization_id, authorization_sha256, mode,
                submitted_at, state, updated_at, revision,
                cancellation_requested, started_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                JOB_ID,
                value.idempotency_key,
                value.fingerprint,
                value.target,
                value.authorization_id,
                value.authorization_sha256,
                value.mode.value,
                timestamp(value.submitted_at),
                state.value,
                timestamp(NOW + timedelta(seconds=1)),
                4,
                int(cancellation_requested),
                started_at,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def create_v4_database(path: Path) -> None:
    create_v1_database(path)
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        ScanJobStore._migrate_v1_to_v2(connection)
        ScanJobStore._migrate_v2_to_v3(connection)
        ScanJobStore._migrate_v3_to_v4(connection)
    finally:
        connection.close()


class DatabaseMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "jobs.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_v1_database_migrates_to_v2_without_losing_queued_job(self) -> None:
        create_v1_database(self.path)
        store = ScanJobStore(self.path)
        record = store.get(JOB_ID)
        self.assertIs(record.state, ScanJobState.QUEUED)
        self.assertEqual(record.revision, 4)
        connection = sqlite3.connect(self.path)
        try:
            version = connection.execute(
                "SELECT value FROM service_metadata WHERE key = 'schema_version'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(version, (str(DATABASE_SCHEMA_VERSION),))

    def test_legacy_running_job_is_requeued_during_migration(self) -> None:
        create_v1_database(self.path, state=ScanJobState.RUNNING)
        store = ScanJobStore(self.path)
        record = store.get(JOB_ID)
        self.assertIs(record.state, ScanJobState.QUEUED)
        self.assertIsNone(record.started_at)
        self.assertEqual(record.revision, 5)

    def test_legacy_running_cancellation_becomes_terminal(self) -> None:
        create_v1_database(
            self.path,
            state=ScanJobState.RUNNING,
            cancellation_requested=True,
        )
        store = ScanJobStore(self.path)
        record = store.get(JOB_ID)
        self.assertIs(record.state, ScanJobState.CANCELLED)
        self.assertTrue(record.cancellation_requested)
        self.assertIsNotNone(record.completed_at)
        self.assertEqual(record.revision, 5)

    def test_schedule_table_exists_after_migration(self) -> None:
        create_v1_database(self.path)
        ScanJobStore(self.path)
        connection = sqlite3.connect(self.path)
        try:
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'scan_schedules'"
            ).fetchone()
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(scan_schedules)"
                )
            }
        finally:
            connection.close()
        self.assertEqual(table, ("scan_schedules",))
        self.assertTrue(
            {
                "schedule_id",
                "organization_id",
                "next_run_at",
                "last_job_id",
                "last_error_code",
            }.issubset(columns)
        )

    def test_reopening_current_database_is_idempotent(self) -> None:
        first = ScanJobStore(self.path)
        second = ScanJobStore(self.path)
        self.assertEqual(first.path, second.path)

    def test_pagination_secret_and_feed_indexes_exist_after_migration(self) -> None:
        create_v1_database(self.path)
        store = ScanJobStore(self.path)
        key = store.cursor_signing_key()
        self.assertGreaterEqual(len(key), 32)
        connection = sqlite3.connect(self.path)
        try:
            secret = connection.execute(
                "SELECT value FROM service_secrets WHERE key = 'pagination_cursor_hmac'"
            ).fetchone()
            indexes = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
        finally:
            connection.close()
        self.assertIsNotNone(secret)
        self.assertIn("idx_scan_jobs_organization_feed", indexes)
        self.assertIn("idx_scan_schedules_organization_feed", indexes)

    def test_reopening_database_preserves_cursor_key(self) -> None:
        first = ScanJobStore(self.path).cursor_signing_key()
        second = ScanJobStore(self.path).cursor_signing_key()
        self.assertEqual(first, second)

    def test_v4_database_migrates_transactionally_through_trustscan_to_schema_v6(self) -> None:
        create_v4_database(self.path)
        before = sqlite3.connect(self.path)
        try:
            self.assertEqual(
                before.execute(
                    "SELECT value FROM service_metadata WHERE key = 'schema_version'"
                ).fetchone(),
                ("4",),
            )
            self.assertIsNone(
                before.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'scan_permits'"
                ).fetchone()
            )
        finally:
            before.close()
        store = ScanJobStore(self.path)
        self.assertEqual(len(store.trustscan_signing_private_key()), 32)
        self.assertIsNone(store.get_job_permit_binding(JOB_ID))
        after = sqlite3.connect(self.path)
        try:
            self.assertEqual(
                after.execute(
                    "SELECT value FROM service_metadata WHERE key = 'schema_version'"
                ).fetchone(),
                ("6",),
            )
            integrity = after.execute("PRAGMA integrity_check").fetchone()
        finally:
            after.close()
        self.assertEqual(integrity, ("ok",))

    def test_trustscan_schema_and_private_signing_key_exist_after_migration(self) -> None:
        create_v1_database(self.path)
        store = ScanJobStore(self.path)
        first_key = store.trustscan_signing_private_key()
        second_key = ScanJobStore(self.path).trustscan_signing_private_key()
        self.assertEqual(first_key, second_key)
        self.assertEqual(len(first_key), 32)
        connection = sqlite3.connect(self.path)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            indexes = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
            secret = connection.execute(
                "SELECT value FROM service_secrets WHERE key = 'trustscan_ed25519_private_key_v1'"
            ).fetchone()
            version = connection.execute(
                "SELECT value FROM service_metadata WHERE key = 'schema_version'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(version, (str(DATABASE_SCHEMA_VERSION),))
        self.assertTrue(
            {
                "scan_permits",
                "job_permits",
                "schedule_permits",
                "job_safety_receipts",
            }.issubset(tables)
        )
        self.assertTrue(
            {
                "idx_scan_permits_organization",
                "idx_scan_permits_authorization",
                "idx_job_permits_permit",
                "idx_schedule_permits_permit",
            }.issubset(indexes)
        )
        self.assertIsNotNone(secret)

    def test_future_schema_version_is_rejected(self) -> None:
        create_v1_database(self.path)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE service_metadata SET value = '999' WHERE key = 'schema_version'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(JobStoreError) as context:
            ScanJobStore(self.path)
        self.assertEqual(context.exception.code, "job_store_schema_unsupported")


if __name__ == "__main__":
    unittest.main()
