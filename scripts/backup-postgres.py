#!/usr/bin/env python3
"""Locally executable PostgreSQL data backup (P1-8 preparation).

This is the mechanics half of `docs/production/BACKUP_RESTORE.md`'s
still-outstanding restore-testing requirement: that document correctly
states no backup has ever been taken and no restore has ever been
tested, because no production RDS instance exists yet to test against.
That remains true after this script -- it cannot produce or validate
an RDS snapshot, a real RPO/RTO measurement, or anything else that
needs applied AWS infrastructure. What it CAN do, today, against any
already-migrated PostgreSQL database (this developer's own local
instance, a disposable CI instance, or eventually a real staging
instance), is prove the one thing that is not infrastructure-specific:
that this schema's actual data can be dumped and later restored
without loss, in a way runnable identically everywhere psycopg already
runs, with no dependency on the `pg_dump`/`pg_restore` client binaries
being installed on the host running it.

Format: one plain-text COPY file per table (PostgreSQL's own COPY TO
STDOUT text format, byte-identical to what psql's own backslash-copy
meta-command would produce), plus a JSON manifest recording the table list, each
table's row count, and when the backup was taken. This is deliberately
NOT pg_dump's own custom/directory format -- writing plain COPY text
means the files here are inspectable with a text editor and need no
special tool to read, at the cost of not capturing schema DDL (schema
is `infra/postgres/migrations/`'s job, tracked and applied separately
by `run-postgres-migrations.py`; this script is data-only by design,
matching how a restore is meant to run: onto an already-migrated,
already-empty target, never as a schema-creation mechanism of its own).

Connection parameters come from `WEBGUARD_DATABASE_URL`, matching
`run-postgres-migrations.py`'s own convention.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg


class BackupError(RuntimeError):
    pass


# schema_migrations is infrastructure-internal, not customer/product
# data: its rows are a derived consequence of which migration files
# have been applied, not something a restore should ever reproduce
# independently of actually running those same files (run-postgres-
# migrations.py). Backing it up here would let a restored row set
# disagree with what the target database's own migration runner
# actually recorded for itself, exactly the "restore to a point before
# a migration was applied silently disagreeing with the live schema"
# risk docs/production/BACKUP_RESTORE.md's own restore-testing
# checklist already names as something to check for, not create.
_EXCLUDED_TABLES = frozenset({"schema_migrations"})


def _table_names(connection: psycopg.Connection) -> list[str]:
    rows = connection.execute(
        """
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name
        """
    ).fetchall()
    return [str(row[0]) for row in rows if str(row[0]) not in _EXCLUDED_TABLES]


def backup_database(dsn: str, output_directory: Path) -> dict:
    """Dumps every base table in the `public` schema to
    `output_directory/<table>.copy` and writes `manifest.json`
    alongside them. Refuses to overwrite an existing, non-empty output
    directory -- a backup is evidence; silently clobbering a previous
    one defeats the point of taking it."""

    if output_directory.exists() and any(output_directory.iterdir()):
        raise BackupError(f"output directory is not empty: {output_directory}")
    output_directory.mkdir(parents=True, exist_ok=True)

    manifest: dict = {
        "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "tables": {},
    }

    with psycopg.connect(dsn) as connection:
        tables = _table_names(connection)
        if not tables:
            raise BackupError("no base tables found in the public schema -- is the schema migrated?")
        for table in tables:
            row_count = 0
            destination = output_directory / f"{table}.copy"
            with destination.open("wb") as handle:
                with connection.cursor().copy(f"COPY {table} TO STDOUT") as copy:  # noqa: S608
                    for chunk in copy:
                        handle.write(bytes(chunk))
                        row_count += bytes(chunk).count(b"\n")
            manifest["tables"][table] = row_count

    manifest_path = output_directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    dsn = os.environ.get("WEBGUARD_DATABASE_URL")
    if not dsn:
        print("WEBGUARD_DATABASE_URL is not set; refusing to guess a connection target.", file=sys.stderr)
        return 2
    args = sys.argv[1:]
    if len(args) != 1:
        print("Usage: backup-postgres.py <output-directory>", file=sys.stderr)
        return 2
    output_directory = Path(args[0])
    try:
        manifest = backup_database(dsn, output_directory)
    except BackupError as exc:
        print(f"Backup failed: {exc}", file=sys.stderr)
        return 1
    total_rows = sum(manifest["tables"].values())
    print(f"Backed up {len(manifest['tables'])} tables, {total_rows} rows total, to {output_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
