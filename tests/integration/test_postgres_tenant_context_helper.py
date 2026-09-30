"""Real-PostgreSQL proof of P1-2's database-side tenant-context helper
(docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): infra/postgres/
migrations/0012_tenant_context_interpretation.sql's
public.webguard_current_tenant() function.

This is Phase B of the P1-2 plumbing: the helper is inert. No table
has row-level security enabled, no policy references it, and no
application code calls it. These tests exercise it directly, as SQL,
proving its own interpretation behavior (valid/unset/empty/malformed/
whitespace) and, together with tests/integration/test_postgres_connection_pool.py's
existing tenant_connection()/set_tenant_context() proofs, that it
reads the exact same transaction-local GUC those set, correctly, on a
reused physical connection.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`) with migrations already applied.
"""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

HELPER_CALL = "SELECT public.webguard_current_tenant()"
GUC_NAME = "webguard.current_organization_id"


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class TenantContextHelperTests(unittest.TestCase):
    """Pool size 1 throughout, matching test_postgres_connection_pool.py's
    TenantContextPoolTests: the reuse scenarios below depend on the
    same physical backend connection carrying no context forward
    between borrowers."""

    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, minimum_connections=1, maximum_connections=1)
        self.addCleanup(self.pool.close)

    def _call_helper(self, connection):
        return connection.execute(HELPER_CALL).fetchone()[0]

    def _backend_pid(self, connection) -> int:
        return connection.execute("SELECT pg_backend_pid()").fetchone()[0]

    def _set_raw_guc(self, connection, value: str) -> None:
        connection.execute("SELECT set_config(%s, %s, true)", (GUC_NAME, value))

    # -- Section 8 scenarios ------------------------------------------------

    def test_scenario_a_guc_never_set_returns_null(self) -> None:
        with self.pool.connection() as connection:
            self.assertIsNone(self._call_helper(connection))

    def test_scenario_b_valid_uuid_returns_that_uuid(self) -> None:
        org_a = str(uuid4())
        with self.pool.tenant_connection(org_a) as connection:
            result = self._call_helper(connection)
        self.assertEqual(str(result), org_a)

    def test_scenario_c_empty_string_returns_null(self) -> None:
        with self.pool.connection() as connection:
            self._set_raw_guc(connection, "")
            self.assertIsNone(self._call_helper(connection))

    def test_scenario_d_malformed_value_returns_null(self) -> None:
        with self.pool.connection() as connection:
            self._set_raw_guc(connection, "definitely-not-a-uuid")
            self.assertIsNone(self._call_helper(connection))

    def test_scenario_e_whitespace_returns_null(self) -> None:
        with self.pool.connection() as connection:
            self._set_raw_guc(connection, "   ")
            self.assertIsNone(self._call_helper(connection))

    def test_scenario_f_tenant_a_then_no_context_on_same_physical_connection(self) -> None:
        org_a = str(uuid4())
        with self.pool.tenant_connection(org_a) as connection:
            pid_a = self._backend_pid(connection)

        with self.pool.connection() as connection:
            result = self._call_helper(connection)
            pid_after = self._backend_pid(connection)

        self.assertIsNone(result, "the helper must not report a previous tenant once its transaction has ended")
        self.assertEqual(pid_after, pid_a, "pool size 1 must reuse the same physical backend connection")

    def test_scenario_g_tenant_a_then_tenant_b_on_same_physical_connection(self) -> None:
        org_a = str(uuid4())
        org_b = str(uuid4())

        with self.pool.tenant_connection(org_a) as connection:
            result_a = self._call_helper(connection)
            pid_a = self._backend_pid(connection)

        with self.pool.tenant_connection(org_b) as connection:
            result_b = self._call_helper(connection)
            pid_b = self._backend_pid(connection)

        self.assertEqual(str(result_a), org_a)
        self.assertEqual(str(result_b), org_b)
        self.assertNotEqual(str(result_b), org_a, "tenant A must never leak into tenant B's borrow")
        self.assertEqual(pid_b, pid_a, "pool size 1 must reuse the same physical backend connection")

if __name__ == "__main__":
    unittest.main()
