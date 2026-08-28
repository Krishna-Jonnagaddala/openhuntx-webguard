"""PostgreSQL connection-pool behavior tests (Slice 12 requirement
12): rollback after an exception, connection release back to the
pool, concurrent reads/writes, and no leaked connections after
repeated borrow/release cycles. Requires a real database
(`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`).
"""

from __future__ import annotations

import os
import threading
import unittest
from datetime import datetime, timezone
from uuid import uuid4

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
# No hardcoded default DSN: WEBGUARD_RUN_INTEGRATION=1 alone is not
# sufficient to run these -- the CI job that sets it also runs the
# Juice Shop lab tests, which need no PostgreSQL at all, so treating
# that flag as "a Postgres instance exists" produced a real CI failure
# (a 5-second pool-timeout error, not a clean skip) the first time this
# suite ran in a job with no Postgres service container. Requiring the
# DSN to be explicitly set is also more honest than a hardcoded
# fallback that might silently point at the wrong instance.
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class PostgresConnectionPoolTests(unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool

        self.pool = WebGuardPostgresPool(
            POSTGRES_TEST_DSN, minimum_connections=2, maximum_connections=5
        )
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")

    def test_check_connectivity_succeeds_against_a_real_database(self) -> None:
        self.pool.check_connectivity()

    def test_exception_inside_borrowed_connection_rolls_back(self) -> None:
        org_id = str(uuid4())
        with self.assertRaises(RuntimeError):
            with self.pool.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO organizations (organization_id, name, name_key, status, created_at)
                    VALUES (%s, 'Rollback Test', 'rollback-test', 'active', %s)
                    """,
                    (org_id, datetime.now(timezone.utc)),
                )
                raise RuntimeError("simulated failure mid-transaction")

        with self.pool.connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM organizations WHERE organization_id = %s", (org_id,)
            ).fetchone()
        self.assertIsNone(row, "a rolled-back insert must not be visible afterwards")

    def test_application_exception_propagates_unmodified(self) -> None:
        """A domain exception raised by code running inside the
        borrowed-connection block must never be normalized into a
        generic database error -- see the regression this guards
        against in postgres_pool.py's own docstring."""

        class _DomainError(ValueError):
            pass

        with self.assertRaises(_DomainError):
            with self.pool.connection() as connection:
                connection.execute("SELECT 1")
                raise _DomainError("application-level failure, not a driver failure")

    def test_connection_is_released_after_each_use(self) -> None:
        initial = self.pool.statistics["pool_available"]
        for _ in range(20):
            with self.pool.connection() as connection:
                connection.execute("SELECT 1")
        self.assertEqual(self.pool.statistics["pool_available"], initial)

    def test_connection_is_released_after_an_exception(self) -> None:
        initial = self.pool.statistics["pool_available"]
        for _ in range(10):
            try:
                with self.pool.connection() as connection:
                    connection.execute("SELECT 1")
                    raise RuntimeError("forced failure")
            except RuntimeError:
                pass
        self.assertEqual(self.pool.statistics["pool_available"], initial)

    def test_concurrent_reads_and_writes_do_not_deadlock_or_leak(self) -> None:
        errors: list[Exception] = []
        organization_ids = [str(uuid4()) for _ in range(20)]

        def _writer(organization_id: str) -> None:
            try:
                with self.pool.connection() as connection:
                    connection.execute(
                        """
                        INSERT INTO organizations (organization_id, name, name_key, status, created_at)
                        VALUES (%s, %s, %s, 'active', %s)
                        """,
                        (
                            organization_id,
                            f"org-{organization_id}",
                            f"org-{organization_id}",
                            datetime.now(timezone.utc),
                        ),
                    )
                with self.pool.connection() as connection:
                    connection.execute(
                        "SELECT * FROM organizations WHERE organization_id = %s",
                        (organization_id,),
                    ).fetchone()
            except Exception as exc:  # noqa: BLE001 - collected, asserted below
                errors.append(exc)

        threads = [threading.Thread(target=_writer, args=(oid,)) for oid in organization_ids]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(errors, [])
        with self.pool.connection() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM organizations WHERE organization_id = ANY(%s)",
                (organization_ids,),
            ).fetchone()[0]
        self.assertEqual(count, len(organization_ids))


if __name__ == "__main__":
    unittest.main()
