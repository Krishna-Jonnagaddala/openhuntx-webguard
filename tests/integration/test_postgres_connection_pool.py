"""PostgreSQL connection-pool behavior tests (Slice 12 requirement
12): rollback after an exception, connection release back to the
pool, concurrent reads/writes, and no leaked connections after
repeated borrow/release cycles. Requires a real database
(`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`).

`TenantContextPoolTests` below covers P1-2's tenant-context plumbing
(docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md) -- tenant_connection()
and set_tenant_context() -- against a real backend connection, proving
the actual transaction-local GUC and pool-reuse behavior a fake
connection object cannot stand in for. This is plumbing-only proof:
no row-level-security policy exists yet, and these tests make no
tenant-isolation claim beyond "the GUC this future policy will read is
set and cleared correctly."
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


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class TenantContextPoolTests(unittest.TestCase):
    """Pool size deliberately 1 throughout this class -- every test
    below depends on the SAME physical backend connection being reused
    across separate borrows, which is exactly the scenario a future
    row-level-security policy's safety depends on: a pooled connection
    must never carry one tenant's context into the next borrower.
    """

    def setUp(self) -> None:
        from webguard_api.postgres_pool import TENANT_CONTEXT_GUC, WebGuardPostgresPool

        self.guc = TENANT_CONTEXT_GUC
        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, minimum_connections=1, maximum_connections=1)
        self.addCleanup(self.pool.close)

    def _current_guc_value(self, connection) -> str:
        return connection.execute("SELECT current_setting(%s, true)", (self.guc,)).fetchone()[0]

    def _backend_pid(self, connection) -> int:
        return connection.execute("SELECT pg_backend_pid()").fetchone()[0]

    def test_tenant_connection_sets_the_guc_to_the_given_organization(self) -> None:
        org_a = str(uuid4())
        with self.pool.tenant_connection(org_a) as connection:
            self.assertEqual(self._current_guc_value(connection), org_a)

    def test_no_context_after_tenant_connection_on_the_same_physical_connection(self) -> None:
        """Proves the security property directly: a previous tenant's
        UUID must not remain active on the next plain borrow. Does not
        assert whether PostgreSQL represents the reverted GUC as NULL
        or an empty string -- only that it is not the prior tenant's
        value."""

        org_a = str(uuid4())
        with self.pool.tenant_connection(org_a) as connection:
            pid_a = self._backend_pid(connection)

        with self.pool.connection() as connection:
            raw_value = self._current_guc_value(connection)
            pid_after = self._backend_pid(connection)

        self.assertNotEqual(raw_value, org_a, "the previous tenant's UUID must not remain active")
        self.assertEqual(pid_after, pid_a, "pool size 1 must reuse the same physical backend connection")

    def test_tenant_a_then_tenant_b_on_the_same_physical_connection(self) -> None:
        org_a = str(uuid4())
        org_b = str(uuid4())

        with self.pool.tenant_connection(org_a) as connection:
            pid_a = self._backend_pid(connection)

        with self.pool.tenant_connection(org_b) as connection:
            raw_value = self._current_guc_value(connection)
            pid_b = self._backend_pid(connection)

        self.assertEqual(raw_value, org_b)
        self.assertNotEqual(raw_value, org_a, "tenant A's context must not leak into tenant B's borrow")
        self.assertEqual(pid_b, pid_a, "pool size 1 must reuse the same physical backend connection")

    def test_rollback_then_tenant_b_on_the_same_physical_connection(self) -> None:
        org_a = str(uuid4())
        org_b = str(uuid4())

        with self.pool.tenant_connection(org_a) as connection:
            pid_before = self._backend_pid(connection)

        with self.assertRaises(RuntimeError):
            with self.pool.tenant_connection(org_a) as connection:
                connection.execute("SELECT 1")
                raise RuntimeError("simulated failure mid-transaction")

        with self.pool.connection() as connection:
            raw_value_after_rollback = self._current_guc_value(connection)

        with self.pool.tenant_connection(org_b) as connection:
            raw_value_b = self._current_guc_value(connection)
            pid_after = self._backend_pid(connection)

        self.assertNotEqual(
            raw_value_after_rollback, org_a, "a rolled-back tenant context must not remain active"
        )
        self.assertEqual(raw_value_b, org_b)
        self.assertEqual(pid_after, pid_before, "pool size 1 must reuse the same physical backend connection")

    def test_set_tenant_context_binds_late_in_an_existing_transaction(self) -> None:
        """Proves the second primitive: the trusted organization
        becoming known partway through an already-open transaction
        (the shape authenticate_token/authenticate_session/
        consume_identity_token will eventually need -- not wired to
        any of them in this change)."""

        from webguard_api.postgres_pool import set_tenant_context

        org_a = str(uuid4())
        with self.pool.connection() as connection:
            pid_start = self._backend_pid(connection)
            self.assertNotEqual(
                self._current_guc_value(connection), org_a, "no tenant context should exist yet"
            )

            set_tenant_context(connection, org_a)

            self.assertEqual(self._current_guc_value(connection), org_a)
            self.assertEqual(self._backend_pid(connection), pid_start, "must be the same connection, not a new one")

            connection.execute("SELECT 1")
            self.assertEqual(
                self._current_guc_value(connection), org_a, "context must persist for the rest of the transaction"
            )

        with self.pool.connection() as connection:
            self.assertNotEqual(
                self._current_guc_value(connection), org_a, "context must not survive past the transaction's end"
            )

    def test_tenant_context_survives_a_nested_transaction_savepoint(self) -> None:
        """Mirrors the actual nested-transaction pattern this codebase
        uses today (postgres_identity.py's create_principal,
        postgres_jobs.py's claim/lease paths: `with connection.transaction():`
        inside an already-borrowed connection) -- not an invented
        nesting shape."""

        org_a = str(uuid4())
        with self.pool.tenant_connection(org_a) as connection:
            self.assertEqual(self._current_guc_value(connection), org_a)
            with connection.transaction():
                connection.execute("SELECT 1")
                self.assertEqual(
                    self._current_guc_value(connection), org_a, "context must hold inside a savepoint"
                )
            self.assertEqual(
                self._current_guc_value(connection), org_a, "context must hold after a savepoint completes"
            )

    def test_invalid_organization_id_fails_before_any_sql_and_before_borrowing(self) -> None:
        initial_available = self.pool.statistics["pool_available"]
        with self.assertRaises(ValueError):
            with self.pool.tenant_connection("definitely-not-a-uuid"):
                pass  # pragma: no cover - must never be reached
        self.assertEqual(
            self.pool.statistics["pool_available"], initial_available, "no connection should have been borrowed"
        )


if __name__ == "__main__":
    unittest.main()
