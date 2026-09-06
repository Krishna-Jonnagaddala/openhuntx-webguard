"""Unit tests for postgres_pool.py's tenant-context plumbing (P1-2,
docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): set_tenant_context()
and WebGuardPostgresPool.tenant_connection(). Neither primitive is
wired into any repository call site yet -- these tests prove the
primitives are correct in isolation, with a fake connection object
standing in for a real database, since a real WebGuardPostgresPool
needs a real DSN to construct at all.

Real-Postgres proof of the actual GUC/transaction/pool-reuse behavior
(the properties that actually matter for tenant isolation) lives in
tests/integration/test_postgres_connection_pool.py -- this file does
not attempt to simulate PostgreSQL's own session-variable or
transaction semantics with a fake.
"""

from __future__ import annotations

import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock
from uuid import uuid4

import psycopg

from webguard_api.db_errors import DatabaseError
from webguard_api.postgres_pool import (
    TENANT_CONTEXT_GUC,
    WebGuardPostgresPool,
    set_tenant_context,
)


class _FakeConnection:
    """Records every execute() call; stands in for psycopg.Connection
    without needing a real database."""

    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple | None]] = []
        self.commit_called = False
        self.rollback_called = False
        self.closed = False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        return MagicMock()

    def commit(self) -> None:
        self.commit_called = True

    def rollback(self) -> None:
        self.rollback_called = True

    def close(self) -> None:
        self.closed = True


class SetTenantContextTests(unittest.TestCase):
    def test_canonical_string_uuid_is_accepted(self) -> None:
        connection = _FakeConnection()
        organization_id = str(uuid4())
        set_tenant_context(connection, organization_id)
        self.assertEqual(len(connection.executed), 1)
        _, params = connection.executed[0]
        self.assertEqual(params, (TENANT_CONTEXT_GUC, organization_id))

    def test_uuid_instance_is_accepted(self) -> None:
        connection = _FakeConnection()
        organization_id = uuid4()
        set_tenant_context(connection, organization_id)
        _, params = connection.executed[0]
        self.assertEqual(params, (TENANT_CONTEXT_GUC, str(organization_id)))

    def test_uses_parameter_binding_not_string_interpolation(self) -> None:
        connection = _FakeConnection()
        organization_id = str(uuid4())
        set_tenant_context(connection, organization_id)
        sql, params = connection.executed[0]
        self.assertNotIn(
            organization_id, sql, "organization_id must never be interpolated into the SQL text"
        )
        self.assertEqual(sql.count("%s"), 2, "both the GUC name and the value must be bound parameters")
        self.assertEqual(params, (TENANT_CONTEXT_GUC, organization_id))

    def test_calls_set_config_with_is_local_true(self) -> None:
        connection = _FakeConnection()
        set_tenant_context(connection, str(uuid4()))
        sql, _ = connection.executed[0]
        self.assertIn("set_config", sql)
        self.assertIn("true", sql, "the third set_config argument must be the literal true (transaction-local)")

    def test_malformed_uuid_is_rejected_before_any_sql_executes(self) -> None:
        connection = _FakeConnection()
        with self.assertRaises(ValueError):
            set_tenant_context(connection, "definitely-not-a-uuid")
        self.assertEqual(connection.executed, [], "no SQL may run for a malformed organization_id")

    def test_non_string_non_uuid_is_rejected(self) -> None:
        connection = _FakeConnection()
        with self.assertRaises(ValueError):
            set_tenant_context(connection, 12345)  # type: ignore[arg-type]
        self.assertEqual(connection.executed, [])

    def test_does_not_commit_rollback_or_close_the_connection(self) -> None:
        connection = _FakeConnection()
        set_tenant_context(connection, str(uuid4()))
        self.assertFalse(connection.commit_called)
        self.assertFalse(connection.rollback_called)
        self.assertFalse(connection.closed)


class TenantConnectionDelegationTests(unittest.TestCase):
    """Proves tenant_connection()'s own wrapping logic (ordering,
    timeout forwarding, exception propagation) using a faked
    connection() method -- not a real pool. Does not attempt to prove
    real transaction/GUC behavior; see the real-Postgres suite for
    that."""

    def _pool_with_fake_connection(self, fake_connection: _FakeConnection) -> WebGuardPostgresPool:
        pool = object.__new__(WebGuardPostgresPool)
        calls: list[float | None] = []

        @contextmanager
        def fake_connection_cm(*, timeout_seconds=None):
            calls.append(timeout_seconds)
            yield fake_connection

        fake_connection_cm.calls = calls
        pool.connection = fake_connection_cm  # type: ignore[method-assign]
        return pool

    def test_delegates_through_existing_connection_method(self) -> None:
        fake = _FakeConnection()
        pool = self._pool_with_fake_connection(fake)
        with pool.tenant_connection(str(uuid4())) as connection:
            self.assertIs(connection, fake)
        self.assertEqual(len(pool.connection.calls), 1)

    def test_sets_context_before_yielding(self) -> None:
        fake = _FakeConnection()
        pool = self._pool_with_fake_connection(fake)
        organization_id = str(uuid4())
        with pool.tenant_connection(organization_id) as connection:
            self.assertEqual(
                len(connection.executed), 1, "tenant context must already be set by the time the body runs"
            )
            _, params = connection.executed[0]
            self.assertEqual(params, (TENANT_CONTEXT_GUC, organization_id))

    def test_passes_timeout_seconds_through(self) -> None:
        fake = _FakeConnection()
        pool = self._pool_with_fake_connection(fake)
        with pool.tenant_connection(str(uuid4()), timeout_seconds=2.5):
            pass
        self.assertEqual(pool.connection.calls, [2.5])

    def test_default_timeout_is_none(self) -> None:
        fake = _FakeConnection()
        pool = self._pool_with_fake_connection(fake)
        with pool.tenant_connection(str(uuid4())):
            pass
        self.assertEqual(pool.connection.calls, [None])

    def test_malformed_uuid_rejected_before_borrowing_a_connection(self) -> None:
        fake = _FakeConnection()
        pool = self._pool_with_fake_connection(fake)
        with self.assertRaises(ValueError):
            with pool.tenant_connection("not-a-uuid"):
                pass  # pragma: no cover - must never be reached
        self.assertEqual(pool.connection.calls, [], "no connection should be borrowed for a doomed call")

    def test_exception_in_body_propagates_unmodified(self) -> None:
        fake = _FakeConnection()
        pool = self._pool_with_fake_connection(fake)

        class _DomainError(RuntimeError):
            pass

        with self.assertRaises(_DomainError):
            with pool.tenant_connection(str(uuid4())) as connection:
                connection.execute("SELECT 1")
                raise _DomainError("application-level failure, not a driver failure")


class TenantConnectionErrorNormalizationTests(unittest.TestCase):
    """tenant_connection() reuses connection() entirely for pool
    checkout -- this proves it does not bypass or duplicate
    connection()'s own psycopg.Error -> DatabaseError normalization,
    using the real connection() implementation against a fake
    underlying ConnectionPool (no real database needed to prove a
    raised psycopg.Error is normalized)."""

    def test_psycopg_error_from_the_underlying_pool_is_still_normalized(self) -> None:
        pool = object.__new__(WebGuardPostgresPool)

        class _FailingUnderlyingPool:
            @contextmanager
            def connection(self, *, timeout=None):
                raise psycopg.OperationalError("simulated connection failure")
                yield  # pragma: no cover - unreachable, required for generator shape

        pool._pool = _FailingUnderlyingPool()

        with self.assertRaises(DatabaseError):
            with pool.tenant_connection(str(uuid4())):
                pass  # pragma: no cover - must never be reached


if __name__ == "__main__":
    unittest.main()
