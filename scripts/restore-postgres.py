#!/usr/bin/env python3
"""Locally executable PostgreSQL data restore, the counterpart to
`backup-postgres.py` (P1-8 preparation -- see that script's own module
docstring for what this pair does and does not prove).

Restores data-only, onto a target database that must already have this
project's current schema applied (`run-postgres-migrations.py`), never
as a schema-creation mechanism of its own -- this mirrors exactly how
`docs/production/BACKUP_RESTORE.md`'s own restore-testing checklist
describes a real restore: migrate first, then load data, then verify.

Refuses by default to load into any table that already has rows, to
make an accidental restore-onto-live-data mistake loud instead of a
silent duplicate-row mess. `--truncate-first` opts into the alternative
(explicitly wipe each target table immediately before loading it),
which is what re-running a restore rehearsal against the same
target repeatedly actually needs -- never the default, always a
deliberate flag.

Loads with `session_replication_role` set to `replica` for the
duration of the restore, PostgreSQL's own standard mechanism for
disabling foreign-key and trigger enforcement during a bulk data load
(the same thing `pg_restore` relies on internally); this means table
load order does not need to respect foreign-key dependencies. The
session role is always reset back to `origin` afterward, including on
a failed load, so a partial/aborted restore never leaves the
connection's role silently changed for whatever runs next on it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import psycopg


class RestoreError(RuntimeError):
    pass


def _existing_row_count(connection: psycopg.Connection, table: str) -> int:
    return connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608


def restore_database(dsn: str, input_directory: Path, *, truncate_first: bool) -> dict:
    manifest_path = input_directory / "manifest.json"
    if not manifest_path.is_file():
        raise RestoreError(f"no manifest.json found in {input_directory}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    tables: dict[str, int] = manifest["tables"]

    with psycopg.connect(dsn) as connection:
        if not truncate_first:
            non_empty = [
                table for table in tables if _existing_row_count(connection, table) > 0
            ]
            if non_empty:
                raise RestoreError(
                    "refusing to restore into non-empty tables without --truncate-first: "
                    + ", ".join(sorted(non_empty))
                )

        connection.execute("SET session_replication_role = replica")
        try:
            if truncate_first:
                # All tables in ONE TRUNCATE statement, before any load
                # starts -- never one at a time inside the load loop.
                # TRUNCATE ... CASCADE cascades to every table that
                # references the one named, regardless of
                # session_replication_role (that setting only affects
                # constraint checking during INSERT/COPY, not
                # TRUNCATE's own cascade). Truncating table N after
                # table N-1 has already been loaded would silently wipe
                # N-1's just-restored rows the moment N cascades to it
                # -- this bit this script during its own development,
                # caught by comparing restored row content against the
                # source rather than trusting the row-count check
                # alone (which passes at each individual table's own
                # load time, before a later table's cascade wipes it).
                connection.execute(f"TRUNCATE {', '.join(tables)} CASCADE")  # noqa: S608
            restored: dict[str, int] = {}
            for table, expected_rows in tables.items():
                source = input_directory / f"{table}.copy"
                if not source.is_file():
                    raise RestoreError(f"backup is missing its dump file for table {table}: {source}")
                with source.open("rb") as handle:
                    with connection.cursor().copy(f"COPY {table} FROM STDIN") as copy:  # noqa: S608
                        while chunk := handle.read(65536):
                            copy.write(chunk)
                actual_rows = _existing_row_count(connection, table)
                restored[table] = actual_rows
                if actual_rows != expected_rows:
                    raise RestoreError(
                        f"row-count mismatch immediately after loading {table}: "
                        f"backup recorded {expected_rows}, table now has {actual_rows}"
                    )

            # A second pass, after every table has been loaded: this is
            # what actually catches a later table's own load (or its
            # own now-removed TRUNCATE) silently disturbing an earlier
            # one, which the per-table check above cannot -- it only
            # ever proves a table was correct at the moment it was
            # itself loaded, not that it stayed correct afterward.
            final_counts = {table: _existing_row_count(connection, table) for table in tables}
            disturbed = {
                table: (expected_rows, final_counts[table])
                for table, expected_rows in tables.items()
                if final_counts[table] != expected_rows
            }
            if disturbed:
                detail = ", ".join(
                    f"{table} (expected {expected}, final {final})"
                    for table, (expected, final) in sorted(disturbed.items())
                )
                raise RestoreError(
                    f"row counts changed after their own load completed, some later step "
                    f"disturbed already-restored data: {detail}"
                )
            restored = final_counts
        finally:
            connection.execute("SET session_replication_role = origin")
        connection.commit()
    return restored


def main() -> int:
    dsn = os.environ.get("WEBGUARD_DATABASE_URL")
    if not dsn:
        print("WEBGUARD_DATABASE_URL is not set; refusing to guess a connection target.", file=sys.stderr)
        return 2
    args = sys.argv[1:]
    truncate_first = "--truncate-first" in args
    positional = [arg for arg in args if not arg.startswith("--")]
    if len(positional) != 1:
        print("Usage: restore-postgres.py <input-directory> [--truncate-first]", file=sys.stderr)
        return 2
    input_directory = Path(positional[0])
    try:
        restored = restore_database(dsn, input_directory, truncate_first=truncate_first)
    except RestoreError as exc:
        print(f"Restore failed: {exc}", file=sys.stderr)
        return 1
    total_rows = sum(restored.values())
    print(f"Restored {len(restored)} tables, {total_rows} rows total, from {input_directory}")
    print("Row counts match the backup manifest exactly for every table.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
