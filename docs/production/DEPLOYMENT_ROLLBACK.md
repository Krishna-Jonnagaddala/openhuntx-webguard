# Deployment rollback procedure

## Status

**Written and rehearsed against a real, disposable local Postgres 16.10 instance (2026-09-23), not deployed, not yet rehearsed against a real RDS instance.** `docs/audit/production-gap-matrix.md`'s "Incident/rollback procedures: NOT STARTED" row is closed by this document for the *procedure*; the row's own scope never required a real AWS environment, and this document does not claim one. See "What this document does not cover" below for what still does need a real environment.

## The one fact that shapes everything below

`scripts/run-postgres-migrations.py` is **forward-only**. There is no down-migration file, no "undo" command, and no code path that reverses an already-applied `.sql` file. This is a deliberate design choice (the script's own docstring: "Safe against accidental destructive migration... editing history after the fact fails closed"), not an oversight, but it means **a schema migration cannot itself be rolled back**. Every case below follows from that one fact.

## Case 1: bad application code, no schema migration

The common case. Redeploy the previous known-good application version (previous container image / previous git SHA's build). No database action of any kind.

- **Safe, unconditionally.** The schema did not change, so the old code's assumptions about it are still correct.
- Configuration: if the bad deploy also changed an environment variable (e.g. a `WEBGUARD_ENABLED_MODULES` value, a rate-limit constant), revert that alongside the code. Application config and code should be rolled back together, not independently, or the "previous known-good" combination is never actually reconstructed.
- Signing-key compatibility: unaffected. `SigningKeyRegistry` resolves a permit's algorithm by the `signing_key_id` carried on the permit itself (see `docs/production/TRUSTSCAN_PRODUCTION_SIGNING.md`'s 2026-09-23 addendum), never by which code version is currently running, so a permit issued by the "bad" version still verifies correctly after rolling the code back, and vice versa. Rolling back application code never invalidates already-issued permits or safety receipts.

## Case 2: bad application code, WITH a schema migration that is backward-compatible

A migration is backward-compatible if the *old* code, unaware of the change, continues to work correctly against the *new* schema, e.g. a new nullable column, a new table, a new index. Confirm this deliberately before relying on it: read the migration file and ask "does anything the old code does violate a new constraint, or a new NOT NULL column with no default?"

- Redeploy the previous application code. Leave the schema migration applied (there is no down-migration to run even if you wanted to).
- **Safe, if the compatibility check above genuinely holds.** No data loss: nothing written after the migration needs to be discarded, because the old code and the new schema coexist correctly.

## Case 3: bad application code, WITH a schema migration that is NOT backward-compatible

Rehearsed for real below. This is the unsafe case: rolling back code alone breaks, because the old code cannot satisfy a new constraint the new schema now enforces (a NOT NULL column with no usable default is the sharpest version of this, but a renamed/dropped column or a narrowed CHECK constraint has the identical shape). **Recovery must use restore-from-backup, not a code-only rollback**, and that restore has a real, quantifiable cost: every write made between the migration and the restore is lost.

### Rehearsal (2026-09-23, local disposable Postgres, not RDS)

1. Created a disposable database, applied all 17 tracked migrations plus the full tenant-isolation bootstrap chain (roles/ACL/function-ACL/control-functions/RLS/runtime-grant): the "pre-deploy" state a real environment would be in.
2. Created one organization ("Rollback Rehearsal Org") through the real `PostgresIdentityRepository`, representing pre-existing customer data.
3. Backed it up: `scripts/backup-postgres.py <dir>` → 33 tables, 6 rows, `manifest.json` recorded.
4. Simulated the bad migration directly (not added to the tracked `infra/postgres/migrations/` set, since this rehearsal's schema change was never meant to ship): `ALTER TABLE organizations ADD COLUMN rehearsal_bad_column text NOT NULL` with no default, after backfilling existing rows, the sharpest form of a non-backward-compatible change.
5. Simulated a customer signing up **during** the bad deploy: inserted a second organization, providing the new column directly (only the *new* code path would know how).
6. Confirmed old code genuinely breaks against the new schema: called the real `PostgresIdentityRepository.create_organization` (which does not know about `rehearsal_bad_column`) against the still-migrated database. It failed, but not with an obviously diagnostic error. **Real, worth stating plainly for anyone diagnosing an incident under pressure**: the failure surfaced as `IdentityStoreError(code="organization_conflict", "An organization with that identifier or name already exists.")`, because `create_organization`'s exception handling normalizes every `IntegrityError` (unique violation, not-null violation, or otherwise) into the same generic conflict message. An operator seeing this error during a real incident would be misled toward "duplicate name" and away from the real cause, "the schema and the code have drifted." If you see this error immediately after a deploy that included a migration, check the migration's own compatibility before assuming a naming collision.
7. Executed the actual rollback: created a **second, fresh** database, applied only the original 17 tracked migrations plus the bootstrap chain (matching the pre-migration state exactly, since there is no way to un-apply the ad-hoc `ALTER TABLE` on the first database in place), then `scripts/restore-postgres.py <dir> --truncate-first` the step-3 backup into it.
8. Confirmed the result: the restored database contains exactly "Rollback Rehearsal Org": the customer who signed up during the bad deploy (step 5) is **not present**; that data is genuinely, permanently gone. Confirmed old code now works normally against the restored database (a fresh `create_organization` call succeeded with no error).
9. Cleaned up both disposable databases.

### What this proves, and what it costs

- Restoring from a pre-migration backup **is** a safe way to recover from a non-backward-compatible migration, once you also apply only the pre-migration schema to the restore target (never restore old data in place into a database that still has the new, incompatible schema: that combination was never tested here because it is not the correct target; if attempted, expect it to either fail outright or silently misbehave, depending on which columns the restore does and does not populate).
- The cost is **everything written between the migration going live and the restore completing**, with no partial recovery: this rehearsal lost exactly one organization, a real production incident would lose every read/write across every table in that window. There is no way around this without a slower, warmer failover strategy (e.g. dual-write or logical replication to a lagged replica) that this project does not build or claim today.
- The generic-error pitfall in step 6 is real and worth fixing independently of this document (`create_organization`'s exception normalization could distinguish a name collision from any other integrity violation), but doing so is a separate, small code change, not part of this rehearsal's own scope.

## When rollback is unsafe and recovery must use another procedure

- **A migration has already been running long enough that "everything since the migration" is not an acceptable loss.** Case 3's restore-from-backup discards it unconditionally; if that window contains anything the business cannot lose, the correct move is a **forward-fixing migration** (a new, reviewed `.sql` file that adapts the schema without touching the incompatible rows, e.g. making a NOT NULL column nullable again, or backfilling it from existing data) plus a **forward-fixing code deploy**, not a rollback. This is slower and requires a real review, which is the point: it trades speed for not discarding data.
- **The signing key active at deploy time was retired or disabled between the bad deploy and the rollback.** `SigningKeyRegistry.set_status` can mark a key `disabled` (verification fails outright, `trustscan_signing_key_disabled`), which is irreversible by rolling back application code: if an operator disabled a key in direct response to a suspected compromise, rolling the application back does not un-disable it, and should not: that specific action requires the same explicit, reviewed key-management decision either way, not an accidental side effect of an unrelated rollback.
- **The restore target is the same database the bad migration ran against, in place, without first ensuring its schema matches the backup's own pre-migration state.** Not rehearsed as a working path here (see step 7 above); treat it as unsafe until proven otherwise, and use a fresh restore target instead.

## What this document does not cover

- A real RDS snapshot-restore, with its own timing and PITR mechanics: `docs/production/BACKUP_RESTORE.md` already states this honestly as not yet exercised (P1-8, `NOT_STARTED`). This document's own rehearsal proves the *procedure and its data-loss shape* against real Postgres and the real backup/restore scripts; it does not and cannot prove RDS-specific timing.
- Rolling back the frontend static build independently of the API: this project builds and deploys them as one release unit per `docs/production/WEBGUARD_RELEASE_CHECKLIST.md`'s own selected configuration, so "roll back the API but not the frontend" is out of scope until a deployment pipeline that splits them exists.
- Automatic/scripted rollback tooling: every step above was run by hand, deliberately, to prove the procedure works before any part of it is automated.
