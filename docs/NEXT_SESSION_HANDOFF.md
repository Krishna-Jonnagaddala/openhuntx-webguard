# Next Session Handoff

Rewritten 2026-09-12 after Phase H closed. Read this before resuming; reconcile against Git before trusting anything below that could have changed. The version of this file written 2026-09-11 (at the very start of mandate execution) is superseded entirely; nothing in it should be treated as current.

## Current state

```
origin/main: 9df82b0498f5ffda35b9c43d81ea5750e5aea294 (Phase H complete)
No open PRs from this mandate's work as of this checkpoint.
Original checkout: /Users/krishna/Documents/Portfolio, now synced to origin/main
  (was 33 commits behind for most of this session; fast-forwarded this
  checkpoint). A stale, pre-Phase-D-correction copy of the RLS policies SQL,
  its test file, and a one-line CI diff were stashed rather than discarded
  (`git stash list`, entry "stale-pre-phase-d-rls-precursor-20260912") since
  they were confirmed byte-for-byte superseded by what's already on
  origin/main. Safe to drop once the user confirms; not dropped unilaterally.
  The unrelated sentinel-incident-investigation-lab/ directory (its own,
  separate git repository) still sits untracked here. Leave it alone.
```

## What this session did

1. Continued and completed Phase H (mandate §7): converted every ordinary PostgreSQL repository method across all 13 `postgres_*.py` files to run under its correct restricted tenant-data role, closing the runtime-conversion half of P1-2. PRs #30 through #47, all merged. See `docs/PROJECT_EXECUTION_LEDGER.md`'s Phase H section for the full per-PR account, including the runtime role-switching mechanism this required building from scratch (none existed before PR #30) and the 9 genuine, documented gaps left open (missing ACL grants or missing control-function support, not wiring oversights).
2. Hit and resolved a GitHub Actions billing lapse mid-arc (account payments/spending limit, not a code issue): the user fixed it directly, and CI resumed cleanly afterward.
3. Synced the original, long-stale main checkout to `origin/main` and reconciled its leftover uncommitted files (see "Current state" above).
4. Refreshed `docs/PROJECT_EXECUTION_LEDGER.md`, `docs/PRODUCT_VISION_TRACEABILITY.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/RELEASE_READINESS.md`, and this file to reflect Phase H's completion and two P1 closures (P1-6, P1-7) that had landed but were never reflected back into the living tracker (`docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md`) or these rollups. Open P1 count corrected: 6 to 4.

## What is NOT done (do not assume otherwise)

- RLS is still not `FORCE`-enabled on any table in any real environment. Phase G's policies and Phase H's runtime role-switching are both proven only against a real *disposable* Postgres (CI, local sandbox). P1-2 stays open on this basis alone.
- Update, 2026-09-17: the 9 Phase H method-level gaps listed below (this entry's own prior text, unedited above) are now closed at the code level, on branch `feat/p1-2-phase-h-gap-closure` (not yet merged, pending review given the security sensitivity of the new `callback_receiver` role): `get_password_hash` (new `webguard_control.resolve_password_hash`), `consume_identity_token` (widened `resolve_identity_token`, +`created_at`), `get_job_permit_binding`/`get_scope` (new `worker_function_owner` functions; `get` itself correctly left unconverted, see the ledger entry), `get_schedule_permit_binding` (new `scheduler_function_owner` function), `enqueue_due_schedule` (widened, +30 columns, plus a small supporting function for the request-fingerprint computation), `record_observation` (a new, genuinely separate LOGIN role, `callback_receiver`, EXECUTE on exactly one function and nothing else), `revoke_registration` (re-verified, still zero callers, correctly left open). Full account, exact function names/grants, and the callback-receiver adversarial pass: `docs/PROJECT_EXECUTION_LEDGER.md`'s "P1-2 Phase H, remaining method-level gaps closed" entry. This closes the code prerequisites for P1-2's runtime half; it does NOT close P1-2 itself. RLS+`FORCE` activation in a real, persistent environment is still untouched (see the bullet above), and a latent, out-of-scope gap in `set_password_hash` (never calls `set_tenant_context`, so it will fail closed once RLS is force-enabled) was found and flagged, not fixed, during this pass.
- The 9 Phase H gaps (as they stood before the 2026-09-17 update above) were real, not wiring oversights, and needed a design decision before they could close: `get_password_hash`/`consume_identity_token` (need a new principal_id-keyed or created_at-extended control function), `get_scope`/`get_job_permit_binding`/`get` in `postgres_jobs.py` and `get_schedule_permit_binding` in `postgres_schedules.py` (worker/scheduler has zero ACL grant on the table each needs), `enqueue_due_schedule` (control function's return columns too narrow for this method's contract), `record_observation` (Phase F deliberately granted EXECUTE to no role, pending a pre-auth identity design), `revoke_registration` (zero live callers, so no UPDATE grant was ever issued). None of these were fixed unilaterally; each needed the same design scrutiny Phase F's original 13 functions got, which is what the 2026-09-17 pass above did.
- P1-8 (backup/restore) and P1-9 (CloudHSM hardware) remain untouched, both genuinely blocked on external access this mandate doesn't grant.
- P1-12-R1 (sustained callback-outage evidence loss) remains open, deferred pending an explicit secondary-durability architecture decision, not a bug fix.
- The `require_bound` cross-tenant ID-existence oracle (found during Phase H's own classification pass, PR #29) remains open: mitigated by UUID4 entropy, not fixed. Needs its own dedicated PR with regression tests if the user wants it closed.
- Pillars 3, 5-10 of the product vision (attestation, Coverage Truth Map, Assessment Ledger, remediation evidence, standards exports, policy packs, data sovereignty) are still `NOT_STARTED`, confirmed by direct repository search, not assumption.

## Immediate next action

Two independent paths are open; neither blocks the other:

1. **RLS+FORCE activation in a real, non-disposable environment.** This is the one remaining piece of P1-2 and the release-candidate gate (`docs/RELEASE_READINESS.md`). It requires infrastructure access this mandate does not grant on its own (no production infrastructure changes, no public service exposure), so ask the user explicitly before starting this, rather than assuming a staging environment exists or may be touched.
2. **Coverage Truth Map** (`docs/PRODUCT_VISION_TRACEABILITY.md` pillar 5) is the Competitive Research document's own stated first differentiator, and `docs/IMPLEMENTATION_STATUS.md` already names it the highest-leverage work now that Phase H is done. Nothing here has been scoped yet beyond that one-line confirmation that it's unbuilt. Before writing any code, do for this pillar what Phase H's own first PR did for tenant-context conversion: a real discovery/inventory pass (what scan/crawl/finding state already exists that a coverage model could be built on top of, e.g. `crawl_scans.py`/`reporting.py`; what a `(asset, operation, identity, test class, version)` coverage record actually needs to capture; whether it's a new table, a derived view, or an event-sourced projection) written into the ledger before any implementation PR, not started cold.

## Open questions for the user, not yet asked because none currently block independent work

- Whether to pursue RLS+FORCE activation now (needs an explicit environment/authorization answer) or treat Coverage Truth Map discovery as the next priority instead (needs no new authorization, matches the roadmap's own stated sequencing).
- Whether to close the `require_bound` oracle finding, and whether the 9 Phase H gaps are worth a dedicated design pass now or should wait.
- Whether the stashed pre-Phase-D-correction files (see "Current state") can be dropped outright, or should be kept a while longer.
