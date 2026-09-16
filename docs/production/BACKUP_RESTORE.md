# Backup and Restore Requirements (Slice 12 requirement 18)

## Status

This document specifies backup, retention, point-in-time-recovery,
encryption, and restore-testing requirements for the production
PostgreSQL deployment designed in `infra/terraform/`. **No backup has
been taken and no restore has been tested** -- there is no deployed
production database yet to back up. This is a design specification for
the deployment that will exist once `infra/terraform/postgres.tf` is
actually applied, written now so the requirement is decided
deliberately rather than improvised during an actual incident.

A backup strategy is not considered proven until restore is tested in
the later deployed environment -- nothing in this document should be
read as "backups are handled," only as "here is what handling them
correctly requires."

## What needs to be backed up

| Data | Where it lives | Backup mechanism |
|---|---|---|
| Everything in `infra/postgres/migrations/`'s schema (organizations, principals, memberships, api_tokens, targets, callback_registrations/observations, security_audit_events, plus every deferred-repository table) | RDS PostgreSQL | RDS automated backups + snapshots (below) |
| TrustScan permit signing key | AWS KMS (once `KmsSigningProvider` is the active signer) | KMS key material is never exportable by design -- see `docs/production/PROVIDER_EVALUATION.md`; this is a durability *feature*, not a gap: AWS itself is responsible for the key's durability, and disaster recovery for a lost/compromised key is *rotation* (issue a new key, mark the old one retired-then-disabled via `SigningKeyRegistry`), not restoration of the same key material |
| Report/artifact files | Local filesystem today; object storage (S3) once provisioned | Out of this document's scope until S3 is actually provisioned (`docs/production/INFRASTRUCTURE_REQUIREMENTS.md`'s "what NOT to build first") |
| `schema_migrations` tracking table | Inside the same RDS instance | Covered by the same RDS backup mechanism as everything else -- it is an ordinary table, not special-cased |

## Automated backups (RDS)

- **Mechanism**: RDS automated backups, enabled via
  `backup_retention_period > 0` in `infra/terraform/postgres.tf`
  (`var.postgres_backup_retention_days`, default 7 days, RDS maximum
  35). Automated backups run daily during `backup_window` and capture
  transaction logs continuously in between, which is what makes
  point-in-time recovery possible (see below) -- there is no separate
  toggle for PITR in RDS; it is implicit in having automated backups
  enabled at all.
- **Retention**: 7 days by default. This is a starting point, not a
  compliance-reviewed number -- revisit once a real customer contract
  or regulatory requirement (data-retention policy, incident
  investigation window) sets an actual floor.
- **Encryption**: `storage_encrypted = true` with a dedicated
  `aws_kms_key.rds_storage_encryption` (see `postgres.tf`) -- backups
  inherit the source volume's encryption automatically; there is no
  separate "encrypt the backup" step to configure.

## Point-in-time recovery (PITR)

RDS PostgreSQL supports restoring to any point within the backup
retention window (down to the second, in practice) whenever automated
backups are enabled. **RPO** (recovery point objective) under this
design is effectively the transaction-log shipping interval RDS
manages internally -- typically well under 5 minutes, not a value this
project's own code controls. **RTO** (recovery time objective) for a
PITR restore is dominated by how long RDS takes to provision a new
instance from the backup and replay logs to the target point -- this
scales with database size and is not knowable precisely without
actually testing it against real data volume (see "Restore testing"
below).

A PITR restore in RDS always creates a **new** DB instance -- it does
not restore in place. Recovering from an incident therefore means: (1)
restore to a new instance at the desired point in time, (2) validate
the restored data, (3) update `WEBGUARD_DATABASE_URL` (and any DNS/
connection-string indirection in front of it) to point at the new
instance, (4) decommission the old one once the cutover is confirmed
safe. This sequence itself has never been executed or timed in this
project -- see "Restore testing."

## Manual snapshots

Automated backups are deleted when the RDS instance itself is deleted
(unless `skip_final_snapshot = false`, which `postgres.tf` already
sets, taking one final snapshot on deletion). For any deliberate,
longer-lived retention point (before a risky migration, before a major
version upgrade), take an explicit manual `aws rds create-db-snapshot`
-- manual snapshots persist independently of the instance's lifecycle
and of the `backup_retention_days` window, and should be tagged with
the reason they were taken.

## Local restore mechanics rehearsal (2026-09-16, locally executable today)

**This is not the restore test below** -- it proves the data-level
mechanics work, not that RDS/PITR/RTO/RPO do. `scripts/backup-postgres.py`
and `scripts/restore-postgres.py` are a locally executable, psycopg-only
backup/restore pair (no dependency on the `pg_dump`/`pg_restore` client
binaries being installed anywhere), runnable against any already-migrated
PostgreSQL instance -- a developer's own local database today, a
disposable CI instance, or eventually a real staging/production one.
`schema_migrations` is deliberately excluded from the dump: it is
derived from which migration files have run, not customer data, and
restoring it independently of actually running those files risks the
exact "restored state disagrees with the live schema" risk the restore
checklist below warns about.

Performed and verified against this developer's own local database
(33 tables, 696 rows, a trivial development-scale dataset, not
representative of any real data volume):

1. Backed up every table to a plain-text COPY dump plus a JSON
   manifest (row counts per table).
2. Restored into a separately migrated and tenant-isolation-bootstrapped
   target database.
3. Verified every restored table's row count matched the manifest
   both immediately after its own load and again after every other
   table had also been loaded (the second check exists because this
   rehearsal caught a real bug during its own development: an early
   version issued `TRUNCATE <table> CASCADE` one table at a time
   inside the load loop, so truncating a later table such as
   `organizations` silently cascaded to wipe `findings` and
   `coverage_records` that an earlier loop iteration had already
   restored, even though the row-count check for those earlier tables
   passed at the moment they were themselves loaded. Fixed by issuing
   one single `TRUNCATE` naming every table together, before any table
   is loaded, so no table is ever truncated after another has already
   received its data).
4. Verified full row-for-row content equality (not just counts)
   between source and restored database across all 33 tables.
5. Ran the full `tests/contract` suite (99/99) against the restored
   database to confirm schema constraints, tenant-isolation roles, and
   RLS policy definitions all survive a restore intact.
6. Confirmed `run-postgres-migrations.py --dry-run` reports the
   restored database as already up to date, proving the deliberate
   exclusion of `schema_migrations` from the data restore does not
   leave the target's own migration bookkeeping confused.
7. Timed the round trip: backup 0.32s, restore 0.23s, for this
   trivial dataset. This number says nothing about RDS-scale timing
   and must not be read as an RTO estimate -- recorded only so a
   future, larger-scale rehearsal has a baseline to compare against.

**What this does and does not close**: this proves the data-level
backup/restore mechanics are correct against real PostgreSQL, and it
caught and fixed one genuine bug in the process. It does not touch
P1-8's actual closure requirement below -- RDS snapshot behavior,
PITR, real RTO/RPO, and the cutover sequence all still require a real,
applied AWS environment this project does not have. P1-8 remains
`NOT_STARTED` for exactly that reason, unchanged by this rehearsal.

## Restore testing

**Not yet performed against real infrastructure** (see the local
mechanics rehearsal immediately above for what has been verified
without it). A backup strategy this document calls "proven"
requires, at minimum:

1. Restoring a real (or realistically-sized synthetic) snapshot to a
   new RDS instance in a non-production account/VPC.
2. Running `scripts/run-postgres-migrations.py`'s dry-run mode against
   the restored instance to confirm the `schema_migrations` table's
   recorded state matches what the restored data actually contains
   (a restore to a point *before* a migration was applied would
   otherwise silently disagree with the live schema).
3. Running the contract test suites in `tests/contract/` against the
   restored instance (pointing `WEBGUARD_POSTGRES_TEST_DSN` at it) to
   confirm the restored data is queryable and tenant-isolation
   invariants still hold -- a restore that silently corrupts foreign
   keys or indexes should fail these tests, not surface only in
   production.
4. Recording the actual wall-clock time the restore took, to replace
   this document's "not knowable precisely" RTO estimate with a real
   measured number.

None of this can happen until `infra/terraform/` is actually applied
to a real AWS account -- this document exists so that when it is, the
exact steps above are already decided rather than designed under
incident pressure.

## What this document deliberately does not cover

- Backup/restore for Redis, S3, or any other not-yet-provisioned
  component (`docs/production/INFRASTRUCTURE_REQUIREMENTS.md`'s "what
  NOT to build first" applies here too).
- A specific RPO/RTO *commitment* to customers -- that is a product/
  business decision this document does not make, only the technical
  numbers a real test would produce to inform it.
