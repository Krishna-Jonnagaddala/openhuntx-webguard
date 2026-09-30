#!/usr/bin/env python3
"""Deterministic, ordered, checksum-verified PostgreSQL schema
migration runner (Slice 12 requirement 7).

Not Alembic, not SQLAlchemy: this project has never used an ORM
(everything else is raw ``sqlite3``), so this runner follows the same
raw-SQL convention -- numbered ``.sql`` files under
``infra/postgres/migrations/``, applied in filename order, tracked in
a ``schema_migrations`` table this script itself creates and owns.

Safety properties:

- **Deterministic and ordered**: migrations apply in ascending
  filename order (``0001_...``, ``0002_...``); a gap or out-of-order
  file is refused rather than silently reordered.
- **Reviewable**: every migration is a plain, git-diffable ``.sql``
  file -- nothing here generates or infers schema from Python models.
- **Safe against accidental destructive migration**: once a migration
  has been recorded as applied, this script refuses to re-apply it
  even if invoked again, and refuses to proceed at all if an already-
  applied file's content has changed on disk since it was applied
  (its recorded checksum would no longer match) -- editing history
  after the fact fails closed rather than silently re-running
  something already-applied databases never expected to see twice.
- **CI-testable from zero**: run against a freshly created, empty
  database, this script *is* the "create schema from scratch" path;
  run again with no new files, it is a safe no-op.

Connection parameters come from ``WEBGUARD_DATABASE_URL`` (a standard
``postgresql://`` DSN) so this script never needs its own bespoke
argument surface for host/port/user/password.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "infra" / "postgres" / "migrations"


class MigrationError(RuntimeError):
    pass


def _discover_migrations() -> list[Path]:
    if not MIGRATIONS_DIR.is_dir():
        raise MigrationError(f"migrations directory not found: {MIGRATIONS_DIR}")
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        raise MigrationError(f"no migration files found in {MIGRATIONS_DIR}")
    seen_versions: set[str] = set()
    for path in files:
        version = path.stem.split("_", 1)[0]
        if not version.isdigit():
            raise MigrationError(
                f"migration file {path.name} does not start with a numeric version"
            )
        if version in seen_versions:
            raise MigrationError(f"duplicate migration version: {version}")
        seen_versions.add(version)
    ordered = sorted(files, key=lambda path: int(path.stem.split("_", 1)[0]))
    expected = [str(i + 1).zfill(len(ordered[0].stem.split("_", 1)[0])) for i in range(len(ordered))]
    actual = [path.stem.split("_", 1)[0] for path in ordered]
    if actual != expected:
        raise MigrationError(
            f"migration versions are not a contiguous sequence starting at 1: {actual}"
        )
    return ordered


def _checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ensure_tracking_table(connection: psycopg.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )


def run_migrations(dsn: str, *, dry_run: bool = False) -> list[str]:
    """Applies every not-yet-applied migration in order. Returns the
    list of migration filenames actually applied (empty if already
    up to date). Raises MigrationError on any inconsistency."""

    migrations = _discover_migrations()
    applied: list[str] = []

    with psycopg.connect(dsn, autocommit=False) as connection:
        _ensure_tracking_table(connection)
        connection.commit()

        existing = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT version, checksum FROM schema_migrations"
            ).fetchall()
        }

        for path in migrations:
            version = path.stem.split("_", 1)[0]
            checksum = _checksum(path)
            if version in existing:
                if existing[version] != checksum:
                    raise MigrationError(
                        f"migration {path.name} has changed on disk since it was "
                        f"applied (recorded checksum {existing[version][:12]}... does "
                        f"not match current {checksum[:12]}...); edit a new migration "
                        "instead of changing an already-applied one"
                    )
                continue

            if dry_run:
                applied.append(path.name)
                continue

            try:
                with connection.transaction():
                    connection.execute(path.read_text(encoding="utf-8"))
                    connection.execute(
                        """
                        INSERT INTO schema_migrations (version, filename, checksum)
                        VALUES (%s, %s, %s)
                        """,
                        (version, path.name, checksum),
                    )
            except psycopg.Error as exc:
                raise MigrationError(
                    f"migration {path.name} failed to apply: {exc}"
                ) from exc
            applied.append(path.name)

    return applied


def main() -> int:
    dsn = os.environ.get("WEBGUARD_DATABASE_URL")
    if not dsn:
        print(
            "WEBGUARD_DATABASE_URL is not set; refusing to guess a connection target.",
            file=sys.stderr,
        )
        return 2
    dry_run = "--dry-run" in sys.argv[1:]
    try:
        applied = run_migrations(dsn, dry_run=dry_run)
    except MigrationError as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        return 1
    if not applied:
        print("Database schema is already up to date.")
    else:
        verb = "Would apply" if dry_run else "Applied"
        for filename in applied:
            print(f"{verb}: {filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
