"""PostgreSQL connection pooling (Slice 12 requirement 12).

Wraps ``psycopg_pool.ConnectionPool`` -- deliberately not ad-hoc
``psycopg.connect()`` calls scattered through repository code, which
was exactly the risk this requirement names ("resolve ad-hoc-
connection risk"). Every repository in this package borrows a
connection through :meth:`WebGuardPostgresPool.connection`, a context
manager that guarantees:

- the connection is returned to the pool on the way out, success or
  exception, so a raised error can never leak a held connection;
- an exception inside the ``with`` block rolls back whatever
  transaction state was open before the connection returns to the
  pool, so a half-finished transaction is never left implicitly
  committed or silently reused by the next borrower;
- every raw ``psycopg.Error`` is translated to this package's own
  normalized failure taxonomy (``db_errors``) before it leaves the
  context manager -- repository code never has to remember to do this
  itself at every call site.

P1-2 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md) tenant-context
plumbing: :meth:`WebGuardPostgresPool.tenant_connection` and
:func:`set_tenant_context` set a transaction-local Postgres session
variable (``TENANT_CONTEXT_GUC``) that a future row-level-security
policy will read. Neither is wired into any repository call site by
this change -- no migration exists yet to create such a policy, no
database role changes have been made, and no security guarantee
beyond "a caller can establish trustworthy tenant context on a
connection" is claimed by this module alone.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg_pool import ConnectionPool

from .db_errors import normalize

DEFAULT_MINIMUM_CONNECTIONS = 1
DEFAULT_MAXIMUM_CONNECTIONS = 10
DEFAULT_CONNECTION_TIMEOUT_SECONDS = 5.0

# P1-2 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): the GUC name
# a future row-level-security policy will read via current_setting(...).
# Fixed here, once, so the pool and every future policy/helper agree on
# the exact name without repeating a string literal at each call site.
TENANT_CONTEXT_GUC = "webguard.current_organization_id"


def _canonical_organization_id(organization_id: str | uuid.UUID) -> str:
    """Validates ``organization_id`` as a real UUID and returns its
    canonical string form. Raises ``ValueError`` -- loudly, in Python,
    before anything reaches Postgres -- for anything else, including a
    plausible-looking but malformed string. This is a deliberate
    application-layer check, not the same thing as the database-level
    fail-closed behavior a future RLS policy will also have: an
    invalid organization_id here is a programming error and must be
    caught immediately, not silently treated as "no tenant."

    Accepts either a ``uuid.UUID`` instance or a string, matching how
    callers already hold this value elsewhere in this codebase (an
    ``AuthContext``'s own ``organization_id`` is a plain string; a
    resolved scope may already carry a parsed value).
    """

    if isinstance(organization_id, uuid.UUID):
        return str(organization_id)
    try:
        return str(uuid.UUID(organization_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(
            f"organization_id must be a valid UUID, got {organization_id!r}."
        ) from exc


def set_tenant_context(connection: psycopg.Connection, organization_id: str | uuid.UUID) -> None:
    """Sets a transaction-local tenant-context GUC on an
    already-open connection, for the specific case where the trusted
    organization becomes known partway through an existing
    transaction -- a pre-auth resolve-then-mutate flow (token/session/
    identity-token verification, where the organization is not known
    until after a first read succeeds) is the reason this exists as a
    primitive distinct from :meth:`WebGuardPostgresPool.tenant_connection`,
    which requires the organization to already be known at checkout
    time. Neither primitive is wired into any repository call site in
    this change -- this is plumbing only.

    Does not commit, roll back, open another connection, or close the
    supplied one -- it issues exactly one statement on the connection
    it is given and returns; the caller's own transaction/connection
    lifecycle is entirely unaffected. The GUC is transaction-local
    (``set_config``'s third argument, ``true``), so it reverts on its
    own the instant this transaction ends, whether by commit or
    rollback -- nothing here ever resets it manually, and nothing
    needs to.

    ``organization_id`` must already be a trusted, server-derived
    value -- never a raw caller-supplied string -- and is validated as
    a real UUID before it is ever sent to Postgres, so a malformed
    value fails here, in Python, rather than becoming an untrusted or
    default tenant context at the database layer.
    """

    tenant_id = _canonical_organization_id(organization_id)
    connection.execute(
        "SELECT set_config(%s, %s, true)",
        (TENANT_CONTEXT_GUC, tenant_id),
    )


class WebGuardPostgresPool:
    """Owns one ``ConnectionPool`` for the API process's lifetime.
    Construct exactly one instance per process (mirroring
    ``CallbackRepository``'s "one shared instance" precedent) and pass
    it into every Postgres repository that needs a connection."""

    def __init__(
        self,
        dsn: str,
        *,
        minimum_connections: int = DEFAULT_MINIMUM_CONNECTIONS,
        maximum_connections: int = DEFAULT_MAXIMUM_CONNECTIONS,
        connection_timeout_seconds: float = DEFAULT_CONNECTION_TIMEOUT_SECONDS,
    ) -> None:
        if maximum_connections < minimum_connections:
            raise ValueError("maximum_connections must be >= minimum_connections")
        self._pool = ConnectionPool(
            conninfo=dsn,
            min_size=minimum_connections,
            max_size=maximum_connections,
            timeout=connection_timeout_seconds,
            open=True,
        )

    @contextmanager
    def connection(self, *, timeout_seconds: float | None = None) -> Iterator[psycopg.Connection]:
        """Only ``psycopg.Error`` (including pool exhaustion/timeout,
        which ``psycopg_pool.PoolTimeout`` subclasses) is normalized
        here. Anything else raised inside the ``with`` block --
        including every repository's own domain exceptions
        (``IdentityStoreError`` and friends) -- is deliberately left
        untouched and propagates as-is; this context manager's job is
        translating *driver* failures, never masking application-level
        ones raised by code that happens to run inside it.

        ``timeout_seconds`` (P1-B2, docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        ``None`` (the default) preserves this pool's own configured
        checkout timeout exactly, for every caller that doesn't pass
        it -- every repository, every existing test, every business-
        request DB operation. Only a caller that explicitly needs a
        *shorter* bound for a single checkout (a health/readiness
        probe -- see ``check_connectivity``) passes one, using
        ``psycopg_pool.ConnectionPool.connection``'s own existing
        per-call ``timeout`` parameter -- not a second pool, not a
        change to this pool's own configured default."""

        try:
            with self._pool.connection(timeout=timeout_seconds) as connection:
                yield connection
        except psycopg.Error as exc:
            raise normalize(exc) from exc

    @contextmanager
    def tenant_connection(
        self, organization_id: str | uuid.UUID, *, timeout_seconds: float | None = None
    ) -> Iterator[psycopg.Connection]:
        """Like :meth:`connection`, but establishes transaction-local
        tenant context immediately after borrowing, before the caller
        ever sees the connection -- for the case where the trusted
        organization is already known at checkout time (an
        ``AuthContext``'s own organization, a job's already-resolved
        scope, a schedule's own row). Not wired into any repository
        call site by this change; this method exists as plumbing for a
        future row-level-security policy phase (P1-2) to use.

        ``organization_id`` is validated as a real UUID before this
        method ever borrows a connection from the pool, so a malformed
        value fails immediately and cheaply, without occupying a pool
        slot for a call that could never succeed.

        Reuses :meth:`connection` entirely for the actual pool
        checkout/return, ``psycopg.Error`` normalization, and
        per-checkout transaction scope -- this method adds exactly one
        statement (the tenant-context ``set_config`` call, via
        :func:`set_tenant_context`) inside that same transaction,
        before yielding. Because that GUC is transaction-local, and
        this method's own ``with`` block (via :meth:`connection`) is
        itself the transaction boundary, the tenant context is cleared
        automatically the instant the transaction ends -- there is no
        manual reset here, and none is needed.
        """

        tenant_id = _canonical_organization_id(organization_id)
        with self.connection(timeout_seconds=timeout_seconds) as connection:
            set_tenant_context(connection, tenant_id)
            yield connection

    def check_connectivity(self, *, timeout_seconds: float | None = None) -> None:
        """Used by the readiness endpoint (requirement 14) -- a cheap
        round trip proving the pool can actually reach the database
        right now, not just that it was reachable at process start.

        ``timeout_seconds``: ``None`` (the default) uses this pool's
        own configured checkout timeout, unchanged -- every pre-P1-B2
        caller of this method keeps its exact existing behavior. A
        health/readiness caller may pass a shorter bound explicitly
        (see cli.py's health-server wiring) so one probe during a real
        outage cannot occupy a request thread for the full ordinary
        timeout; this never affects any other caller sharing the same
        pool, including P1-12's own callback-observation ingestion
        path."""

        with self.connection(timeout_seconds=timeout_seconds) as connection:
            connection.execute("SELECT 1")

    def close(self) -> None:
        self._pool.close()

    @property
    def statistics(self) -> dict[str, int]:
        """Pool occupancy for diagnostics -- deliberately excludes the
        DSN or any connection parameter (requirement 13: never expose
        connection strings)."""

        stats = self._pool.get_stats()
        return {
            "pool_size": stats.get("pool_size", 0),
            "pool_available": stats.get("pool_available", 0),
            "requests_waiting": stats.get("requests_waiting", 0),
        }


__all__ = [
    "DEFAULT_CONNECTION_TIMEOUT_SECONDS",
    "DEFAULT_MAXIMUM_CONNECTIONS",
    "DEFAULT_MINIMUM_CONNECTIONS",
    "TENANT_CONTEXT_GUC",
    "WebGuardPostgresPool",
    "set_tenant_context",
]
