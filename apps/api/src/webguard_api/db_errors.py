"""Normalized PostgreSQL failure taxonomy (Slice 12 requirement 13).

Every Postgres repository in this package catches raw ``psycopg``
exceptions at its own boundary and re-raises one of the types below --
callers (including anything that could end up serialized into an API
response) never see a raw driver exception, a connection string, or
SQL text. This mirrors the existing discipline elsewhere in this
codebase (``IdentityStoreError``, ``JobStoreError``, ...): a small,
closed set of ``(code, message)`` failures, not a leaky abstraction
over the underlying driver.
"""

from __future__ import annotations

import psycopg
import psycopg.errors


class DatabaseError(RuntimeError):
    """Base class for every normalized database failure. Never
    constructed with a raw driver exception's string representation --
    callers must pass a fixed, reviewed message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class DatabaseUnavailableError(DatabaseError):
    """The database could not be reached at all (connection refused,
    DNS failure, pool exhausted)."""


class DatabaseTimeoutError(DatabaseError):
    """A statement or connection attempt exceeded its deadline."""


class DatabaseConflictError(DatabaseError):
    """A retryable conflict: serialization failure or deadlock under
    concurrent transactions. Safe for a caller to retry the whole
    transaction from the start."""


class DatabaseIntegrityError(DatabaseError):
    """A constraint was violated (unique, foreign key, check) --
    generally not retryable without changing the input."""


class DatabaseNotFoundError(DatabaseError):
    """The requested row does not exist (or, for a tenant-scoped
    lookup, does not exist *for the caller's organization* -- the
    identical signal as a genuinely unknown row, by design)."""


class DatabaseAuthorizationDeniedError(DatabaseError):
    """A database-enforced authorization control rejected the
    operation (e.g. a role/permission the connecting user lacks) --
    distinct from application-layer authorization, which is handled
    above this layer and is mandatory regardless of what the database
    itself enforces."""


class DatabaseMigrationError(DatabaseError):
    """The schema is missing, outdated, or inconsistent with what this
    code expects -- surfaced distinctly from a generic unavailability
    so operators can tell "can't connect" from "connected, but the
    schema is wrong" at a glance."""


def normalize(exc: Exception) -> DatabaseError:
    """Maps a raw ``psycopg`` exception to one normalized type. Never
    includes the original exception's message verbatim (it may
    contain SQL text or, for some driver errors, connection
    parameters) -- only a fixed, reviewed message per category."""

    if isinstance(exc, psycopg.errors.SerializationFailure):
        return DatabaseConflictError(
            "database_conflict",
            "The operation could not complete due to a concurrent conflict. Retry it.",
        )
    if isinstance(exc, psycopg.errors.DeadlockDetected):
        return DatabaseConflictError(
            "database_conflict",
            "The operation could not complete due to a concurrent conflict. Retry it.",
        )
    if isinstance(exc, psycopg.errors.UniqueViolation):
        return DatabaseIntegrityError(
            "database_integrity_violation",
            "The operation violates a uniqueness constraint.",
        )
    if isinstance(exc, psycopg.errors.ForeignKeyViolation):
        return DatabaseIntegrityError(
            "database_integrity_violation",
            "The operation references a row that does not exist.",
        )
    if isinstance(exc, psycopg.errors.CheckViolation):
        return DatabaseIntegrityError(
            "database_integrity_violation",
            "The operation violates a data constraint.",
        )
    if isinstance(exc, psycopg.errors.IntegrityError):
        return DatabaseIntegrityError(
            "database_integrity_violation",
            "The operation violates a database constraint.",
        )
    if isinstance(exc, psycopg.errors.InsufficientPrivilege):
        return DatabaseAuthorizationDeniedError(
            "database_authorization_denied",
            "The database connection is not permitted to perform this operation.",
        )
    if isinstance(exc, psycopg.errors.UndefinedTable) or isinstance(
        exc, psycopg.errors.UndefinedColumn
    ):
        return DatabaseMigrationError(
            "database_schema_mismatch",
            "The database schema does not match what this service expects. Run migrations.",
        )
    if isinstance(exc, psycopg.OperationalError):
        message = str(exc).lower()
        if "timeout" in message or "timed out" in message:
            return DatabaseTimeoutError(
                "database_timeout",
                "The database did not respond in time.",
            )
        return DatabaseUnavailableError(
            "database_unavailable",
            "The database is currently unavailable.",
        )
    if isinstance(exc, TimeoutError):
        return DatabaseTimeoutError(
            "database_timeout",
            "The database did not respond in time.",
        )
    return DatabaseUnavailableError(
        "database_unavailable",
        "The database operation failed unexpectedly.",
    )


__all__ = [
    "DatabaseAuthorizationDeniedError",
    "DatabaseConflictError",
    "DatabaseError",
    "DatabaseIntegrityError",
    "DatabaseMigrationError",
    "DatabaseNotFoundError",
    "DatabaseTimeoutError",
    "DatabaseUnavailableError",
    "normalize",
]
