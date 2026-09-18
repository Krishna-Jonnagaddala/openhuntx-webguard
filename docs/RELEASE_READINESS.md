# Release Readiness

Six separate verdicts (mandate §25). These are not interchangeable — do not report a higher gate as met because a lower one passed. Grounded in `docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md`'s own GO/NO-GO verdicts, not re-derived from scratch, since those verdicts remain unchanged evidence pending Phase H and the P0/P1 closures already reflected in the mutable tracker.

## Engineering progress

Implemented and verified: P0-1, P0-2 (baseline audit, closed), P1-1, P1-3, P1-4, P1-5, P1-6, P1-7, P1-10, P1-11 (tracker, closed), Phase A-G tenant-isolation data-layer plumbing (verified), Phase H runtime tenant-context conversion (implemented, proven against a real disposable Postgres, PRs #30-#47). RLS policies now also cover the three tenant tables added since Phase H (`coverage_records`, `module_entitlements`, `scoped_control_implementations`), closing that specific gap; a new adversarial test proves precisely what RLS+`FORCE` does and does not protect against (see P1-2's own ledger note). One further Phase H method-level gap closed 2026-09-16 (`organization_id_for_job`, PR #64). Correction, 2026-09-17: that entry's "eight remain open" was imprecise, not merely rounded. `get_scope`/`organization_id_for_job` had been tracked as one combined row despite being two separate methods, so the real count after PR #64 was 9 remaining, not 8 (see `docs/PROJECT_EXECUTION_LEDGER.md`'s "P1-2 Phase H, remaining method-level gaps closed" entry for the exact grep evidence). 7 of the 9 are converted at the code level on branch `feat/p1-2-phase-h-gap-closure` (not yet merged): `get_password_hash`/`consume_identity_token` (new/widened `identity_function_owner` functions), `get_job_permit_binding`/`get_scope` (new `worker_function_owner` functions), `get_schedule_permit_binding`/`enqueue_due_schedule` (new/widened `scheduler_function_owner` functions), `record_observation` (a new, genuinely separate LOGIN role, `callback_receiver`, granted EXECUTE on exactly one function and nothing else). The other 2, `get` and `revoke_registration`, are correctly left unconverted, not fixed: both re-verified to have zero live production callers. Say "7 converted, 2 correctly deferred," not "9 closed." A further, separately-discovered gap (2026-09-18): exercising the real service layer end to end under real forced RLS showed registration/login themselves failing first, because `get_principal` and five sibling methods (`touch_last_login`, `set_principal_email_verified`, `invalidate_identity_tokens`, `list_tokens_for_principal`, `revoke_token_owned`) had the identical missing-tenant-context gap as `set_password_hash` (below); all 7 (including `set_password_hash`) are now fixed and proven through real registration/login/password-change/reset/invitation flows with legitimately-issued tokens (`docs/PROJECT_EXECUTION_LEDGER.md`'s 2026-09-18 addendum). This demonstrates the code prerequisites for P1-2's runtime half end to end against disposable, forced-RLS PostgreSQL; it still does not close P1-2 itself, see the next sentence. P1-12-R1 gained a real-Postgres regression test the same PR proving a polling database error never returns the same shape as a genuine absent callback observation, closing the specific evidence gap without claiming the broader finding is closed by that alone. In progress: P1-2's remaining half, RLS+`FORCE` activation in a real, persistent environment (not yet attempted anywhere), procedure documented (`docs/production/RLS_STAGING_ACTIVATION.md`). Blocked: P1-9. Deferred with reason: P1-12-R1, P1-8. Traced and severity-graded, decision unmade: P1-13 (object storage and `secret_provider.py` both isolate tenants correctly today by construction only, with no independent second layer; see `docs/PROJECT_EXECUTION_LEDGER.md`'s P1-13 row for the full trace).

Open P1 total is now **5**, not 4: P1-2, P1-8, P1-9, P1-12-R1 (the original baseline's remaining open items) plus P1-13 (identified 2026-09-14, independent of the original August baseline audit). Any prior statement of "4 open" predates P1-13's identification.

## Software release candidate

**Not met, but closer.** A release candidate requires a declared scope with its gates green and limitations explicit. Phase H (runtime tenant-context conversion) is now complete and proven against a real disposable Postgres, but P1-2 remains open: RLS itself is not `FORCE`-enabled in any real, non-disposable environment, so the tenant-isolation claim is proven in test, not yet in production topology. This is still a meaningful, not cosmetic, gap for a product whose core promise includes tenant isolation.

## Staging validated

**Conditional GO, per the baseline audit's own original verdict**, contingent on P0-1/P0-2 (closed) and now also contingent on P1-2's remaining RLS-activation half. The baseline audit judged P1-1 through P1-4 "strongly recommended before staging" as observability/isolation gaps; all four are now closed at the code/test level, but P1-2's RLS+`FORCE` activation has not been exercised against a real deployment. Staging deployment should not be represented as validating tenant isolation until that activation is verified there.

## Production ready

**NOT MET**, unchanged from the baseline audit's own NO-GO: no evidence any infrastructure has been applied to a real cloud account, no backup/restore ever exercised (P1-8), no CloudHSM hardware validation (P1-9). These are proven-absent, not merely undocumented.

## Production deployed

**NOT MET** — no deployment has occurred (consistent with "production ready" above; deployment cannot precede readiness).

## Full vision complete

**NOT MET.** Per `docs/PRODUCT_VISION_TRACEABILITY.md`: 2 of 10 WebGuard pillars substantially implemented (Permit, Safety Receipt), 2 implemented-unverified beyond that (per-action enforcement: Phase H's runtime wiring is done, RLS+FORCE activation is not; Coverage Truth Map v1: populates 3 of its own 6 vision states, tenant-scoped paginated read API since Phase 4, no report surface), 6 not started (attestation, Assessment Ledger, remediation evidence, standards-interop exports, policy packs, data sovereignty). This ratio is reported against the explicit ten-pillar inventory, not an invented percentage.

This verdict covers WebGuard's own ten-pillar vision only, per this document's own baseline-audit scope. It does not speak to SOC or Compliance completeness: those two modules have their own, much earlier-stage status, tracked in `docs/PRODUCT_VISION_TRACEABILITY.md`'s "Platform expansion" section and `docs/RELEASE_EVIDENCE.md`, not folded into this WebGuard-scoped verdict.

## Immediate blockers to the next gate (release candidate)

1. RLS+`FORCE` activation in a real, non-disposable environment (closes P1-2's remaining half; Phase H's own runtime conversion is done). `docs/production/RLS_STAGING_ACTIVATION.md` (2026-09-16) is the written procedure; it still needs a real environment to run against and an owner's authorization to run it.
2. Real-runtime adversarial proof of tenant isolation under non-superuser credentials in that same real environment (the same document's acceptance-checks section is what that proof would consist of)

This file was last reconciled against actual repository state on 2026-09-16 (previously 2026-09-15). See the OpenHuntX Scope & Progress Audit, 2026-09-14, for the evidence-backed review this reconciliation is based on, and `docs/PROJECT_EXECUTION_LEDGER.md`'s "OpenHuntX Scope & Progress Audit and continuation" entry for what has changed since.

P1-6 and P1-7 are closed (PRs #17, #19). P1-8 and P1-9 block **production ready**, not a release candidate or staging validation, since they require an applied environment and physical hardware respectively that a release candidate does not need.
