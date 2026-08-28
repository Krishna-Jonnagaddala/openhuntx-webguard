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
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg_pool import ConnectionPool

from .db_errors import normalize

DEFAULT_MINIMUM_CONNECTIONS = 1
DEFAULT_MAXIMUM_CONNECTIONS = 10
DEFAULT_CONNECTION_TIMEOUT_SECONDS = 5.0


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
    def connection(self) -> Iterator[psycopg.Connection]:
        """Only ``psycopg.Error`` (including pool exhaustion/timeout,
        which ``psycopg_pool.PoolTimeout`` subclasses) is normalized
        here. Anything else raised inside the ``with`` block --
        including every repository's own domain exceptions
        (``IdentityStoreError`` and friends) -- is deliberately left
        untouched and propagates as-is; this context manager's job is
        translating *driver* failures, never masking application-level
        ones raised by code that happens to run inside it."""

        try:
            with self._pool.connection() as connection:
                yield connection
        except psycopg.Error as exc:
            raise normalize(exc) from exc

    def check_connectivity(self) -> None:
        """Used by the readiness endpoint (requirement 14) -- a cheap
        round trip proving the pool can actually reach the database
        right now, not just that it was reachable at process start."""

        with self.connection() as connection:
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
    "WebGuardPostgresPool",
]
