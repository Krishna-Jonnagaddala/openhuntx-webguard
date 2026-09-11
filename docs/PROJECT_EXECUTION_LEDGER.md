# Project Execution Ledger

Durable, requirement-level tracking for OpenHuntX WebGuard engineering work, per the Claude Master Completion Mandate (2026-09-11). This is a coordination document, not the authoritative vulnerability record — that remains `docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md` and `docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md` (immutable). This ledger links to that evidence rather than duplicating it.

Status values: NOT_STARTED, IN_PROGRESS, IMPLEMENTED_UNVERIFIED, VERIFIED, BLOCKED_EXTERNAL, DEFERRED_WITH_REASON.

## Canonical baseline

```
Commit: 88dd4927d0960ea516f72242986f1dd995bc08a3
Verified: 2026-09-11, by direct git fetch + rev-parse, not trusted from a prior report.
origin/main == this commit: YES
Open P1 total: 6 (P1-2, P1-6, P1-7, P1-8, P1-9, P1-12-R1) -- verified against
  docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md's own "CURRENT P1
  ACCOUNTING" section directly, not the mandate's paraphrase of it.
```

## Test-quality findings (not P1/audit items, recorded for continuity)

**Flaky test fixed, 2026-09-11**: `tests/unit/test_customer_auth.py`'s
`test_no_json_response_ever_contains_the_raw_session_or_csrf_secret`
extracted the session secret with `rsplit("_", 1)[-1]` instead of the
production parser's own `split("_", 2)[-1]` (`identity.py`'s
`_parse_prefixed_secret`). Since the secret is `token_urlsafe(32)`
output and its base64url alphabet legitimately includes `_`, this
could (and once did, live on `main`, CI run `34592378065`, Python
3.13.14 only) extract a single trailing character as the "secret" and
then fail because that character coincidentally appeared inside a
randomly generated UUID elsewhere in the same JSON response. Fixed in
PR #21 to match the production parser exactly, which makes it
mathematically impossible to cut into the secret regardless of its
content (not merely less likely) -- verified with 30 repeated runs.
Recorded here because it explains a real red `main` CI run that had
nothing to do with the PR that triggered it (PR #20, doc-only), so a
future session doesn't waste time re-diagnosing it.

## Requirement rows

| ID | Source | Intended behavior | Status | Code/contracts | Tests/evidence | Dependency | Milestone | Acceptance condition |
|---|---|---|---|---|---|---|---|---|
| A-G | Baseline audit P1-2 | Tenant-context plumbing through dormant RLS policies | VERIFIED | `infra/postgres/bootstrap/tenant_isolation_*.sql` | 129/129 combined Postgres suite, CI run 34506680942 | none | Phase A-G | Reconfirmed live at `da5da85`; see final P1-C2-G report in session transcript |
| P1-6 | Baseline audit | Commit `.terraform.lock.hcl`, stop gitignoring it | VERIFIED | `.gitignore`, `infra/terraform/.terraform.lock.hcl` | PR #17, commit `c4132e5`, merged, CI fully green (10/10 jobs) | none | opportunistic fix | Met |
| P1-2 | Baseline audit | RLS structurally blocked: no tenant-context GUC checkout/reset hook at runtime | IN_PROGRESS (policies defined, runtime not converted) | A-G bootstrap SQL exists; `postgres_pool.py`'s tenant-context helper exists (Phase B) but ordinary repository callers don't yet set it before every query | Dormant-state proven (29/29 Phase G); runtime conversion (Phase H) not started | Phase H completion | Real runtime paths set tenant context; enforced isolation survives adversarial test; RLS+FORCE activated in a real (non-disposable) environment with evidence |
| P1-7 | Baseline audit | `TrustScanSigner.sign()`/`sign_safety_receipt()` hardcode `signature_algorithm="Ed25519"` regardless of actual provider | IMPLEMENTED_UNVERIFIED | `apps/api/src/webguard_api/permits.py`, `webguard_contracts/scan_permits.py`, `webguard_contracts/safety_receipts.py` | New `tests/unit/test_p1_7_signature_algorithm_metadata.py`, 8/8 pass (real ECDSA_SHA_256 sign/verify/tamper round trip); full signing suite 45/45; backend unit 1799/1799; PR #19, commit `ae5ea72`, CI pending | none | independent fix | Algorithm field is now provider-derived (`self._registry.active.algorithm`); local + KMS paths both tested; verification stays bound to key/algorithm (unchanged, resolves via registry not self-report) -- moves to VERIFIED once PR #19 CI confirms and is merged |
| P1-8 | Baseline audit | Backup/restore never tested against any environment | NOT_STARTED | Terraform toggles exist; no EFS/persistent-volume resource | none | requires an actual applied environment | deferred to staging | Real backup/restore exercise, integrity verified, RTO/RPO measured |
| P1-9 | Baseline audit | CloudHSM PKCS#11 `EC_POINT` encoding unverified against real hardware | BLOCKED_EXTERNAL | `kms` path is the tested fallback; CloudHSM code exists, unexercised | none against real hardware | real CloudHSM module/hardware access | N/A until hardware available | Genuine hardware validation of key extraction, identity, signing, independent verification |
| P1-12-R1 | Post-audit residual | Sustained callback-service PostgreSQL outage can lose durable SSRF evidence (proven: yields false NOT_VULNERABLE, not INCONCLUSIVE) | DEFERRED_WITH_REASON | `callback_server.py`, `postgres_callback_service.py` | Proven residual: `test_no_fabricated_confirmation_when_persistence_never_recovers` | requires an explicit secondary-durability architecture decision (not a bug fix) | future architecture slice | Durable secondary store or documented, accepted, explicitly-surfaced limitation |
| Phase H | Mandate §7 | Convert ordinary PostgreSQL repository callers to set tenant context before query; classify pre-auth/cross-tenant/callback paths separately | IN_PROGRESS (classification/inventory sub-phase complete: 13 of 13 files classified; conversion sub-phase not started) | 13 `postgres_*.py` repository files, ~115 public methods, all classified 2026-09-11: `postgres_identity.py` (25), `postgres_jobs.py` (30), `postgres_schedules.py` (11), `postgres_sessions.py` (6), `postgres_callback_service.py` (4), `postgres_callback_broker.py` (5), `postgres_targets.py` (6), `postgres_authentication_contexts.py` (6), `postgres_authorization_comparison.py` (6), `postgres_findings.py` (5), `postgres_reports.py` (3), `postgres_scans.py` (5), `postgres_target_verification.py` (4) — see "Phase H classification: all 13 repository files complete" below for the full tally and open items | none yet for the conversion sub-phase; classification is documentation-only | P1-2 closure depends on this | multi-session | Every ordinary tenant-data method sets context before query; adversarial cross-tenant test passes under real runtime credentials |

## Phase H: repository inventory (discovery, 2026-09-11)

Structural pass only — file, class, and public method names, extracted directly from source. Per-method classification (tenant source, principal source, current pool/role, desired capability, transaction boundary, control-function need, error semantics, test coverage) is the next pass and is NOT yet done; do not treat the presence of a method here as evidence its tenant scoping has been reviewed.

| File | Class | Public method count |
|---|---|---|
| `postgres_authentication_contexts.py` | `PostgresAuthenticationContextRepository` | 6 |
| `postgres_authorization_comparison.py` | `PostgresAuthorizationComparisonPlanRepository` | 6 |
| `postgres_callback_broker.py` | `PostgresCallbackBroker` | 5 |
| `postgres_callback_service.py` | `PostgresCallbackRegistrationRepository` | 4 |
| `postgres_findings.py` | `PostgresFindingRepository` | 5 |
| `postgres_identity.py` | `PostgresIdentityRepository` | 25 |
| `postgres_jobs.py` | `PostgresJobRepository` | 30 |
| `postgres_reports.py` | `PostgresReportRepository` | 3 |
| `postgres_scans.py` | `PostgresScanRepository` | 5 |
| `postgres_schedules.py` | `PostgresScheduleRepository` | 10 |
| `postgres_sessions.py` | `PostgresSessionRepository` | 6 |
| `postgres_target_verification.py` | `PostgresTargetVerificationRepository` | 4 |
| `postgres_targets.py` | `PostgresTargetRepository` | 6 |

13 repository files, ~115 public methods total (note: `postgres_jobs.py` re-exposes several schedule methods as thin delegates to `postgres_schedules.py` — actual distinct implementations are fewer; this will be resolved in the classification pass, not double-counted in Phase H's own completion metric).

## Phase H: `postgres_identity.py` classification (complete, 2026-09-11)

25 methods, `PostgresIdentityRepository`. Legend: **Ordinary** = ordinary tenant-scoped data path (set tenant context from a known organization_id before query); **Pre-auth** = identity resolution before any tenant context can exist, candidate for a narrow `identity_function_owner` control function (the same category Phase D/E/F/G's own comments repeatedly flagged as "a future resolver's domain"); **Admin** = CLI/operator-only, never reachable from the API `serve` process; **Self-scoped** = takes no organization_id parameter because the caller already supplies a value that cannot be attacker-influenced (an authenticated session's own `principal_id`, not a URL parameter).

| Method | Tables | Tenant source | Current role/ACL | Classification | Note |
|---|---|---|---|---|---|
| `create_organization` | organizations | the new `organization_id` itself | `api_tenant_data` SELECT/INSERT | Ordinary (self-tenant registration) | Same pattern Phase G's own test already proves: context = the row's own new id |
| `get_organization` | organizations | `organization_id` param | `api_tenant_data` SELECT | Ordinary | |
| `create_principal` | principals, memberships | `organization_id` param | `api_tenant_data` SELECT/INSERT/UPDATE | Ordinary | One `connection.transaction()` block already — good shape for adding tenant context once |
| `get_principal` | principals | **none** — no org parameter at all | `api_tenant_data` SELECT | **Pre-auth** | Called from `assign_authorization` specifically to discover a principal's own org; cannot itself be tenant-scoped since discovering the tenant is the point |
| `get_principal_by_email` | principals | **none** | `api_tenant_data` SELECT | **Pre-auth** | The login-by-email lookup; textbook pre-auth resolver |
| `get_principal_scoped` | principals | `organization_id` param, checked in Python after an unscoped `get_principal` read | `api_tenant_data` SELECT | Ordinary (app-level check today) | Phase H should move the org predicate into the SQL `WHERE`, not just the post-hoc Python check, once RLS is live |
| `list_principals` | principals | `organization_id` param | `api_tenant_data` SELECT | Ordinary | |
| `update_principal_role` | principals | `organization_id` param (P1-C1 already added it to the `UPDATE`'s own `WHERE`) | `api_tenant_data` SELECT/UPDATE | Ordinary | Two separate connection checkouts (`get_principal_scoped` then `UPDATE`), not one transaction — set context on both |
| `set_principal_active` | principals | same as above | `api_tenant_data` SELECT/UPDATE | Ordinary | Same two-checkout note |
| `set_principal_email_verified` | principals | **none** | `api_tenant_data` UPDATE | **Self-scoped** | Called only after `consume_identity_token` already resolved this exact `principal_id`; no org parameter to set context from without a signature change |
| `touch_last_login` | principals | **none** | `api_tenant_data` UPDATE | **Self-scoped** | Called post-authentication once org is already established by the caller; same signature gap |
| `set_password_hash` | password_credentials | derived via `principal_id` -> `principals.organization_id` | `api_tenant_data` INSERT/UPDATE, narrow `SELECT(principal_id)` (P1-2 Phase-D correction) | Ordinary (derived chain) | Already covered by Phase G's `wg_api_password_credentials_select`/insert/update policies |
| `get_password_hash` | password_credentials | **none** | **not granted to `api_tenant_data` at all** (Phase D correction confirmed `DatabaseAuthorizationDeniedError`) | **Pre-auth** | The password-verification step during login, before any session exists; this is the resolver Phase D/E's own comments have referenced throughout as "a future identity function owner's resolver domain" |
| `create_identity_token` | identity_tokens | `organization_id` param | `api_tenant_data` INSERT | Ordinary | |
| `consume_identity_token` | identity_tokens | **none** — resolves org FROM the token row itself | `api_tenant_data` narrow `SELECT`/`UPDATE` (P1-2 Phase-D correction); full 8-column read here exceeds the granted columns | **Pre-auth** | Confirmed in this session's own Phase-D correction work: the method's internal SELECT already exceeds what `api_tenant_data` may read; explicitly deferred there as "later repository-conversion phase" -- this is that phase |
| `invalidate_identity_tokens` | identity_tokens | derived via `principal_id` | `api_tenant_data` narrow `SELECT`/`UPDATE` (P1-2 Phase-D correction) | Ordinary (derived chain) | Already covered |
| `list_tokens_for_principal` | api_tokens | **none** in SQL | `api_tenant_data` SELECT | **Self-scoped** | Verified via caller: `service.py:3142`'s `list_api_keys` passes `context.principal_id` (the authenticated caller's own id, never a URL parameter) — "Self-service by design" per that file's own comment. Not a live gap; still needs org-context wiring since the repository method itself has no org input |
| `revoke_token_owned` | api_tokens | **none in SQL** — ownership checked in Python (`row[2] != principal_id`) | `api_tenant_data` SELECT/UPDATE | Ordinary (app-level check today) | Matches the baseline audit's own P3 technical-debt note about SQL-scoped vs. caller-scoped enforcement being inconsistent project-wide |
| `create_token` | principals, organizations, api_tokens | derived via `principal.organization_id` | `api_tenant_data` SELECT/INSERT | Ordinary (derived) | Three separate connection checkouts (two internal `get_principal`/`get_organization` calls plus its own INSERT) — Phase H's "prove pool reuse isolation" requirement applies directly here |
| `authenticate_token` | api_tokens, principals, organizations | **none** — resolves org FROM the token row itself | `api_tenant_data` SELECT/UPDATE | **Pre-auth** | The API-token authentication path; single most security-critical pre-auth path in this file |
| `revoke_token` | api_tokens | **none at all** | `api_tenant_data` SELECT/UPDATE | **Admin** | Verified sole caller: `cli.py:338`, the `token revoke` operator subcommand. Same documented pattern as `assign_authorization` -- never reachable from the API `serve` process. Investigated this session specifically because the missing check looked concerning in isolation; resolved, not a gap |
| `assign_authorization` | principals (read), organization_authorizations (write) | `organization_id` param, validated against the read principal's own org | `api_tenant_data` has SELECT only on `organization_authorizations`; INSERT is explicitly withheld per `tenant_isolation_acl.sql`'s own header comment | **Admin** | Documented in-file already: `cli.py`'s `authorization assign` subcommand is the only caller |
| `authorization_is_assigned` | organization_authorizations | `organization_id` param | `api_tenant_data` SELECT | Ordinary | |
| `list_assigned_authorization_ids` | organization_authorizations | `organization_id` param | `api_tenant_data` SELECT | Ordinary | |
| `record_audit_event` | security_audit_events | `event.organization_id` (embedded in the passed dataclass) | `api_tenant_data` SELECT/INSERT | Ordinary | |
| `list_audit_events_page` / `list_audit_events` | security_audit_events | `organization_id` param | `api_tenant_data` SELECT | Ordinary | |

**Summary for this file**: 16 Ordinary, 5 Pre-auth (`get_principal`, `get_principal_by_email`, `get_password_hash`, `consume_identity_token`, `authenticate_token`), 2 Admin (`revoke_token`, `assign_authorization` — both already documented, both investigated and confirmed CLI-only), 2 Self-scoped-but-no-org-parameter (`set_principal_email_verified`, `touch_last_login`, plus `list_tokens_for_principal` makes 3 — all three need a signature review, not a control function, since their caller already holds the right identifier and just needs to pass it through).

The 5 Pre-auth methods are the concrete list Phase H's "narrow functions for pre-tenant identity lookups" requirement (mandate §7) needs. **Correction after checking `postgres_jobs.py` (below): these functions already exist.** Phase F did not just build 13 generic control functions — its own SQL comments explicitly name the exact Python method each one replaces. See "Major finding" below before assuming Phase H means designing anything new.

## Major finding: Phase F already built Phase H's control functions (2026-09-11)

`infra/postgres/bootstrap/tenant_isolation_control_functions.sql` defines exactly the resolvers this file's own 5 Pre-auth methods (and `postgres_jobs.py`'s cross-tenant lease/schedule methods) need — each with a code comment stating "current source is `<file>.py`'s `<method>()`" and reproducing that method's exact predicate/CAS/validation logic in `SECURITY DEFINER` SQL, already tested 43/43 (`test_postgres_control_functions.py`). This was not visible from `postgres_identity.py` alone; it only became clear once `postgres_jobs.py`'s lease methods were checked against the same file.

| Python method | Control function | Granted to | Note |
|---|---|---|---|
| `postgres_identity.py`'s `authenticate_token` | `webguard_control.resolve_api_token(uuid)` | `api_tenant_data` | |
| `postgres_sessions.py`'s `authenticate_session` **plus** `auth.py`'s `BrowserSessionAuthenticator.authenticate()`'s own `get_principal()`/`get_organization()` calls right after it | `webguard_control.resolve_browser_session(uuid)` | `api_tenant_data` | Same LEFT JOIN shape as `resolve_api_token`: returns session/principal/organization fields unconditionally so the caller checks expiry/revocation itself. `csrf_hash` is included (the CSRF check itself stays in Python); `user_agent`/`ip_address`/`last_used_at` are omitted (audit-only, no read decision needs them) |
| `postgres_identity.py`'s `get_principal_by_email` **and** `get_password_hash` | `webguard_control.resolve_principal_by_email(text)` | `api_tenant_data` | **one function replaces both** — returns `password_hash` directly alongside principal/organization fields, exactly the "login" resolver shape a caller needs in one round trip |
| `postgres_identity.py`'s `consume_identity_token` | `webguard_control.resolve_identity_token(uuid)` | `api_tenant_data` | Deliberately narrower than the other three (identity_tokens only) — its own comment confirms every current caller fetches principal/organization separately, through the ordinary tenant role, after the token resolves which `organization_id` to set as context |
| `postgres_jobs.py`'s `claim_next_leased` | `webguard_control.claim_next_job(text, numeric, timestamptz)` | `worker_tenant_data` | Preserves the exact claimable-row predicate, `ORDER BY`, `FOR UPDATE SKIP LOCKED`, and CAS `UPDATE` |
| `postgres_jobs.py`'s `recover_expired_leases` | `webguard_control.recover_expired_leases(timestamptz, integer)` | `worker_tenant_data` | |
| `postgres_jobs.py`'s `renew_lease` | `webguard_control.renew_lease(uuid, text, text, timestamptz, numeric)` | `worker_tenant_data` | |
| `postgres_jobs.py`'s `get_scope` / `organization_id_for_job` | `webguard_control.resolve_job_organization(uuid)` | `worker_tenant_data` | |
| `postgres_jobs.py`'s `_terminal_update` (via `finish_result_leased`/`fail_leased`/`cancel_running_leased`) | `webguard_control.terminal_transition(...)` | `worker_tenant_data` | Reproduces the exact 7-step atomic sequence (fetch, confirm RUNNING, lease check, CAS update, conditional `scan_records` reconciliation, conditional safety-receipt insert, readback), including the safety-receipt path/digest format validation |
| `postgres_schedules.py`'s `list_due_schedules` | `webguard_control.list_due_schedules(timestamptz, integer)` | `scheduler_tenant_data` | Cross-tenant poll for every organization's due schedules at once — inherently unscoped by design, not a gap |
| `postgres_schedules.py`'s `enqueue_due_schedule` | `webguard_control.enqueue_due_schedule(...)` | `scheduler_tenant_data` | |
| `postgres_schedules.py`'s `block_due_schedule` | `webguard_control.block_due_schedule(uuid, integer, text, timestamptz)` | `scheduler_tenant_data` | |
| `postgres_callback_service.py`'s `PostgresCallbackRegistrationRepository.record_observation` | `webguard_control.resolve_and_record_callback_observation(...)` | (not yet checked — `postgres_callback_broker.py`/`postgres_callback_service.py` not yet classified) | Deliberately ONE atomic function, not split into resolve-then-record: splitting would reopen the exact TOCTOU window ("is this token still valid" vs. "record it was used") the current single-transaction Python method already closes. Returns a single boolean, collapsing unknown/expired/revoked into the same outcome, matching the current code's own oracle-avoidance (already covered by this session's P1-12 work) |

**What this changes about Phase H's actual scope**: the mandate's own framing ("design ... narrow functions for pre-tenant identity lookups and legitimate worker/scheduler control") reads as a design task. It mostly is not — the design, the SQL, and the test coverage already exist and are already merged (Phase F, this session, commit range `bc44177` and earlier). What remains for every method in the table above is **rewiring**: replace the Python method's raw SQL with a call to the matching `webguard_control` function through the appropriate role's connection, then prove the swap is behaviorally identical (same errors, same concurrency guarantees, same return shape) under a real non-superuser runtime credential. That is still real, non-trivial work — each swap needs its own adversarial proof — but it is a materially smaller and better-specified task than designing these functions from scratch would have been. Re-verify this holds before assuming it for the remaining 11 files; it might not extend as cleanly to files with no obvious control-function counterpart (e.g. `postgres_findings.py`, `postgres_target_verification.py`, `postgres_reports.py`, `postgres_targets.py`, `postgres_authentication_contexts.py`, `postgres_authorization_comparison.py`, `postgres_scans.py` — none of these appeared in Phase F's function list, so they are likely genuinely-ordinary tenant-data files needing only the "set context before query" treatment, not a resolver).

## Phase H: `postgres_jobs.py` classification (complete, 2026-09-11)

`PostgresJobRepository`, 30 public methods (module docstring's own count is higher because several are thin one-line delegates to `PostgresScheduleRepository` — see below). Legend matches the `postgres_identity.py` section above, plus **Worker-internal** = unscoped by design because its only caller is the worker/executor operating on a job it already holds an independently-verified lease/binding for (the cross-tenant worker-control category, not a gap).

### Schedule delegates (10 methods) — not classified here

`create_schedule`, `get_schedule_scoped`, `list_schedules_scoped_page`, `pause_schedule_scoped`, `resume_schedule_scoped`, `get_schedule_permit_binding`, `get_schedule_permit_binding_scoped`, `list_due_schedules`, `enqueue_due_schedule`, `block_due_schedule` are one-line delegations to `PostgresScheduleRepository` (`self._schedules`). Real classification belongs to `postgres_schedules.py`'s own Phase H pass, not duplicated here — matches the inventory's own note that these must not be double-counted.

### Permits and job-permit bindings

| Method | Tables | Tenant source | Current role/ACL | Classification | Note |
|---|---|---|---|---|---|
| `create_scan_permit` | scan_permits | `claims.organization_id` (embedded in the permit) | `api_tenant_data` INSERT | Ordinary | |
| `get_scan_permit` | scan_permits | **none** | `api_tenant_data` SELECT | Worker-internal | Only called from within this file: after `create_scan_permit`'s own insert, and after `revoke_scan_permit_scoped`'s own scoped check — both already-verified-safe re-reads, never externally reachable unscoped |
| `get_scan_permit_scoped` | scan_permits | `organization_id` param | `api_tenant_data` SELECT | Ordinary | Already SQL-scoped (P1-C1) |
| `revoke_scan_permit_scoped` | scan_permits | `organization_id` param | `api_tenant_data` SELECT/UPDATE | Ordinary | Already SQL-scoped (P1-C1) |
| `get_job_permit_binding` | job_permits | **none** | `api_tenant_data` SELECT | Worker-internal | Explicitly documented in-file as "retained for internal/system callers that already hold an independently-verified job_id." Verified callers: `executor.py` (twice, with the worker's own claimed `record.job_id`) and `submit()`'s own idempotency check (an already-looked-up job_id) |
| `get_job_permit_binding_scoped` | job_permits, scan_jobs (joined) | `organization_id` param | `api_tenant_data` SELECT | Ordinary | Already SQL-scoped via JOIN (P1-C1) — the customer/service-facing equivalent |
| `get_job_safety_receipt_scoped` | job_safety_receipts, scan_jobs (joined) | `organization_id` param | `api_tenant_data` SELECT | Ordinary | Already SQL-scoped via JOIN (P1-C1) |

### Job CRUD and lifecycle

| Method | Tables | Tenant source | Current role/ACL | Classification | Note |
|---|---|---|---|---|---|
| `submit` | scan_jobs, job_permits | `organization_id` param, **optional** (both `organization_id`/`submitted_by` None together is a valid, supported state) | `api_tenant_data` SELECT/INSERT | Ordinary (self-tenant registration variant) | Its own pre-insert idempotency-key lookup is deliberately global/unscoped (must be, to detect a key reused across organizations at all), with an explicit app-level cross-tenant conflict check afterward (`"used outside this organization"`) — a correctness requirement, not a gap; flagged so it is not mistaken for one during conversion |
| `get` | scan_jobs | **none** | `api_tenant_data` SELECT | Worker-internal | Verified sole caller (transitively): `is_cancellation_requested`, itself only called from `worker.py` with the worker's own claimed job. No `service.py` caller found by search |
| `get_scope` / `organization_id_for_job` | scan_jobs | **none** — this IS the resolver | `api_tenant_data` SELECT | **Pre-auth-equivalent resolver** (worker/cross-tenant class) | Has an exact control-function counterpart already built: `webguard_control.resolve_job_organization(uuid)`, granted to `worker_tenant_data` |
| `get_scoped` | scan_jobs | `organization_id` param | `api_tenant_data` SELECT | Ordinary | Already SQL-scoped (P1-C1), documented as "the primary tenant-facing job lookup" |
| `list_jobs_scoped_page` | scan_jobs | `organization_id` param | `api_tenant_data` SELECT | Ordinary | |
| `request_cancellation_scoped` / `request_cancellation` | scan_jobs | `organization_id` param on the `_scoped` wrapper; the bare method it calls has **no org predicate in its own `UPDATE`** | `api_tenant_data` SELECT/UPDATE | Ordinary, but **defense-in-depth gap** | `request_cancellation_scoped` checks org via a separate `get_scoped()` call, then invokes `request_cancellation` (a second, separate connection checkout) whose own `UPDATE ... WHERE job_id = %s AND revision = %s` never re-checks `organization_id`. Not exploitable today only because `scan_jobs.organization_id` is immutable post-creation (same invariant `postgres_identity.py`'s own comments state for `principals`/`scan_jobs`) — but `postgres_identity.py`'s `update_principal_role`/`set_principal_active` already received the equivalent fix (P1-C1: org folded directly into the `UPDATE`'s own `WHERE`) and this method did not. Worth the same fix for symmetry and because Phase H's real-runtime-credential conversion removes the "we control every caller" assumption this currently leans on |
| `is_cancellation_requested` | scan_jobs | **none** | `api_tenant_data` SELECT | Worker-internal | Verified sole caller: `worker.py:403`, with the worker's own claimed `record.job_id` |

### Leases — cross-tenant worker control plane

| Method | Tables | Tenant source | Current role/ACL | Classification | Control-function counterpart |
|---|---|---|---|---|---|
| `claim_next_leased` | scan_jobs, job_permits, scan_permits, organization_authorizations (all read cross-tenant by design) | **none — intentionally cross-tenant**: a worker claims the next queued job for ANY organization | `worker_tenant_data`, running this exact multi-table query directly today | **Cross-tenant worker control** | `webguard_control.claim_next_job(text, numeric, timestamptz)` — already built, already granted to `worker_tenant_data`, already tested |
| `renew_lease` | scan_jobs | **none** — lease-token/worker-id pair is the authority, not organization | `worker_tenant_data` SELECT/UPDATE | Cross-tenant worker control | `webguard_control.renew_lease(uuid, text, text, timestamptz, numeric)` |
| `recover_expired_leases` | scan_jobs, scan_records | **none — intentionally cross-tenant**: recovery sweeps expired leases for every organization at once | `worker_tenant_data` | Cross-tenant worker control | `webguard_control.recover_expired_leases(timestamptz, integer)` |
| `finish_result` / `finish_result_leased` / `fail_leased` / `cancel_running_leased` / `cancel_running` (all route through `_terminal_update`) | scan_jobs, scan_records, job_safety_receipts | **none** — lease-token/worker-id pair is the authority | `worker_tenant_data` SELECT/UPDATE/INSERT | Cross-tenant worker control | `webguard_control.terminal_transition(...)` — reproduces the exact 7-step atomic sequence including the safety-receipt format validation |

**Summary for this file**: 13 Ordinary (2 with the P1-C1 pattern already fully applied at SQL level: `get_scoped`, `get_job_permit_binding_scoped`, `get_job_safety_receipt_scoped`, `get_scan_permit_scoped`, `revoke_scan_permit_scoped`; 1 flagged for a defense-in-depth gap: `request_cancellation`/`_scoped`), 4 Worker-internal (verified against actual callers, not assumed: `get_scan_permit`, `get_job_permit_binding`, `get`, `is_cancellation_requested`), 8 Cross-tenant worker control (all 8 already have a tested `webguard_control` counterpart), 10 schedule delegates (deferred to `postgres_schedules.py`'s own pass).

## Phase H: `postgres_schedules.py` classification (complete, 2026-09-11)

`PostgresScheduleRepository`, 11 public methods (10 of which `postgres_jobs.py` delegates to by name — see that file's own section; `list_schedules_scoped` is the one method with no delegate, called directly against this class only).

| Method | Tables | Tenant source | Current role/ACL | Classification | Note |
|---|---|---|---|---|---|
| `create_schedule` | scan_schedules, schedule_permits | `organization_id` param (embedded) | `scheduler_tenant_data`/`api_tenant_data` (whichever role actually calls this — not yet cross-checked against `tenant_isolation_acl.sql`'s exact grant table) | Ordinary (self-tenant registration variant) | |
| `get_schedule_scoped` | scan_schedules | `organization_id` param | same | Ordinary | Already SQL-scoped |
| `list_schedules_scoped_page` | scan_schedules | `organization_id` param | same | Ordinary | Already SQL-scoped |
| `list_schedules_scoped` | scan_schedules | `organization_id` param | same | Ordinary | Already SQL-scoped; the one method with no `postgres_jobs.py` delegate |
| `pause_schedule_scoped` | scan_schedules | `organization_id` param, folded into `_set_schedule_state`'s own `UPDATE ... WHERE ... AND organization_id = %s AND revision = %s` | same | Ordinary | Already SQL-scoped **and** already has the P1-C1-style atomic-predicate treatment `postgres_jobs.py`'s `request_cancellation` is missing — this file did it right |
| `resume_schedule_scoped` | scan_schedules | same as above | same | Ordinary | Same atomic-predicate treatment |
| `get_schedule_permit_binding` | schedule_permits | **none** | same | Scheduler-internal | Explicitly documented "retained for internal/system callers." Verified sole external caller: `scheduler.py:177`, with `schedule.schedule_id` from the scheduler's own cross-tenant `list_due_schedules()` poll — a trusted, non-attacker-influenced identifier, same pattern as `postgres_jobs.py`'s `get_scan_permit`/`get_job_permit_binding` |
| `get_schedule_permit_binding_scoped` | schedule_permits, scan_schedules (joined) | `organization_id` param | same | Ordinary | Already SQL-scoped via JOIN (P1-C1) |
| `list_due_schedules` | scan_schedules | **none — intentionally cross-tenant**: polls every organization's due schedules at once | runs the raw multi-tenant query directly today | **Cross-tenant scheduler control** | `webguard_control.list_due_schedules(timestamptz, integer)` — already built, already granted to `scheduler_tenant_data`, already tested |
| `enqueue_due_schedule` | scan_schedules, organization_authorizations, schedule_permits, scan_permits, scan_jobs, job_permits | **none in its own initial read** (`WHERE schedule_id = %s FOR UPDATE`, no org predicate) — `organization_id` is derived from the row once read, matching the `schedule_id`'s trusted cross-tenant-poll origin (same reasoning as `get_schedule_permit_binding` above, not a separate gap) | same | Cross-tenant scheduler control | `webguard_control.enqueue_due_schedule(...)` |
| `block_due_schedule` | scan_schedules | **none** — same trusted-origin reasoning | same | Cross-tenant scheduler control | `webguard_control.block_due_schedule(uuid, integer, text, timestamptz)` |

**Summary for this file**: 8 Ordinary (2 of which — `pause_schedule_scoped`/`resume_schedule_scoped` — already have the atomic organization-scoped `UPDATE` predicate that `postgres_jobs.py`'s `request_cancellation` still lacks, worth pointing conversion work at as the reference implementation), 1 Scheduler-internal (verified against its actual caller), 3 Cross-tenant scheduler control (all 3 already have a tested `webguard_control` counterpart).

Combined with `postgres_jobs.py` and `postgres_identity.py`: all 13 `webguard_control` functions Phase F built now have a confirmed source method, read directly from the SQL file's own comments (3 identity resolvers, 1 session resolver, 5 job-lease functions, 3 schedule functions, 1 callback function). What's still pending is the *other* methods in `postgres_sessions.py` and `postgres_callback_broker.py`/`postgres_callback_service.py` — those two files' own full classification passes haven't happened yet, only the one method each that a control function already covers.

## Phase H: `postgres_sessions.py` classification (complete, 2026-09-11)

`PostgresSessionRepository`, 6 public methods.

| Method | Tables | Tenant source | Current role/ACL | Classification | Note |
|---|---|---|---|---|---|
| `create_session` | browser_sessions | `organization_id` param (embedded) | `api_tenant_data` INSERT | Ordinary (self-tenant registration variant) | |
| `authenticate_session` | browser_sessions | **none** — session_id is the only key, parsed from the token itself; org is discovered from the row | `api_tenant_data` full-row SELECT today | **Pre-auth resolver** | Exact control-function counterpart already built: `webguard_control.resolve_browser_session(uuid)`, granted to `api_tenant_data`. Its own SQL comment names both this method and `auth.py`'s `BrowserSessionAuthenticator.authenticate()`'s subsequent `get_principal()`/`get_organization()` calls as combined source |
| `get_session` | browser_sessions | **none** | `api_tenant_data` SELECT | Self-scoped | Verified sole caller: `service.py:2330`'s `get_session_info`, called with `context.token_id` — the caller's own already-authenticated session id, never a URL parameter. Same "no org parameter to set context from" signature gap as `postgres_identity.py`'s `list_tokens_for_principal`/`touch_last_login` |
| `revoke_session` | browser_sessions | `principal_id` param, folded directly into the `UPDATE`'s own `WHERE` (P1-C1) | `api_tenant_data` UPDATE | Ordinary | Deliberately scoped by `principal_id`, not `organization_id` — its own docstring explains why: a session belongs to exactly one principal, there is no "admin force-revoke a teammate's session" concept anywhere in this codebase, and scoping by org instead would incorrectly let any same-org principal revoke another's session. Already the atomic, no-TOCTOU shape |
| `revoke_all_sessions_for_principal` | browser_sessions | `principal_id` param | `api_tenant_data` UPDATE | Ordinary | Same principal-scoping reasoning as `revoke_session` |
| `list_sessions_for_principal` | browser_sessions | `principal_id` param | `api_tenant_data` SELECT | Ordinary | Same reasoning |

**Summary for this file**: 4 Ordinary (3 of which are deliberately principal-scoped rather than organization-scoped, with an explicit, already-correct rationale — this file has zero identified gaps), 1 Pre-auth resolver (control function already built and tested), 1 Self-scoped (verified against its actual caller, needs the same kind of signature review as the identity-file findings, not a control function).

This is the cleanest file classified so far: no defense-in-depth gaps, no unverified assumptions about callers, and its own pre-existing docstrings already explain the scoping choices in the same terms Phase H needs.

## Phase H: `postgres_callback_service.py` and `postgres_callback_broker.py` classification (complete, 2026-09-11)

Both files together, since `PostgresCallbackBroker` (the broker) is a thin adapter over `PostgresCallbackRegistrationRepository` (the durable repository) — most of its methods are one-line delegations, matching the same delegate pattern `postgres_jobs.py` uses for `postgres_schedules.py`.

### `postgres_callback_service.py` — `PostgresCallbackRegistrationRepository`, 4 methods

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `register` | callback_registrations | `organization_id` param (embedded) | Ordinary (self-tenant registration variant) | Its own pre-INSERT `COUNT(*)` abuse-limit check is also `organization_id`-scoped — a soft, best-effort cap, not a hard-serialized one (already documented in-file as an accepted trade-off against lock contention) |
| `get_registration` | callback_registrations | `organization_id` param | Ordinary | Already SQL-scoped (`WHERE token_value = %s AND organization_id = %s`) |
| `revoke_registration` | callback_registrations | `organization_id` param | Ordinary | Already SQL-scoped, single atomic `UPDATE ... RETURNING` — no separate read-then-write step at all, arguably the cleanest write shape found in any file so far |
| `record_observation` | callback_registrations (read), callback_observations (write) | **none** — `token_value` is the only key | **Callback token resolution** (the mandate's own named category, distinct from pre-auth/cross-tenant-worker) | Exact control-function counterpart already built: `webguard_control.resolve_and_record_callback_observation(...)`. Deliberately kept as ONE atomic function/method rather than split into resolve-then-record — splitting would reopen the exact TOCTOU window ("is this token still valid" vs. "record that it was used") this project's own P1-12 work already closed. Safe unscoped-by-design: `token_value` is a `secrets.token_urlsafe(32)` high-entropy secret, not enumerable, so there is no practical cross-tenant probing surface even though the SQL carries no organization predicate |

### `postgres_callback_broker.py` — `PostgresCallbackBroker`, 5 methods (+ `policy` property, not a DB operation)

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `register` | (delegates to repository's `register`) | `organization_id` param | Ordinary (delegate) | Adds no SQL of its own; wraps the durable repository's return value into the scanner-layer `CallbackToken` shape |
| `wait_for_observation` | callback_registrations (via `get_registration`), callback_observations (via `_latest_observation`) | `organization_id` param, checked **once, before polling begins** | Ordinary, with an already-correct ownership pre-check | Calls `self._repository.get_registration(token.value, organization_id=organization_id)` first — a mismatch raises `CallbackServiceError` outright (a genuine integrity violation, not a soft failure) — then polls `_latest_observation(token.value)` in a loop that itself carries no organization predicate. Safe because ownership was already proven before the loop starts and `token_value` is high-entropy, not because the poll query is scoped |
| `_latest_observation` (private) | callback_observations | **none** | N/A (private, not independently reachable) | Only ever called from within `wait_for_observation`, after that method's own ownership check already passed |
| `revoke_registration` | (delegates to repository's `revoke_registration`) | `organization_id` param | Ordinary (delegate) | |
| `record_observation` | (delegates to repository's `record_observation`) | **none** | Callback token resolution (delegate) | Same classification as the repository method it wraps |

**Summary for these two files**: 6 Ordinary (3 genuinely new SQL in the repository, 3 delegates in the broker; zero defense-in-depth gaps — `revoke_registration`'s atomic `UPDATE ... RETURNING` and `wait_for_observation`'s check-before-poll pattern are both already the correct shape), 2 Callback token resolution (1 genuinely new in the repository, already covered by a tested control function; 1 delegate in the broker), 1 property/no-op, 1 private helper not independently classifiable.

All 13 `webguard_control` functions Phase F built are now fully accounted for across their 5 confirmed source files (`postgres_identity.py` ×3, `postgres_sessions.py` ×1, `postgres_jobs.py` ×5, `postgres_schedules.py` ×3, `postgres_callback_service.py` ×1). The remaining 7 files with no entry in Phase F's function list (`postgres_authentication_contexts.py`, `postgres_authorization_comparison.py`, `postgres_findings.py`, `postgres_reports.py`, `postgres_scans.py`, `postgres_target_verification.py`, `postgres_targets.py`) were hypothesized to be genuinely-ordinary tenant-data files needing only the "set tenant context before query" treatment, no resolver — `postgres_targets.py` (below) is the first of the 7 actually checked, and confirms it.

## Phase H: `postgres_targets.py` classification (complete, 2026-09-11)

`PostgresTargetRepository`, 6 public methods. First confirmation of the "genuinely ordinary, no resolver needed" hypothesis for the 7 files with no Phase F control-function counterpart.

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `create_target` | targets | `organization_id` param (embedded) | Ordinary (self-tenant registration variant) | |
| `get_target` | targets | `organization_id` param | Ordinary | Already SQL-scoped |
| `list_targets` | targets | `organization_id` param | Ordinary | Already SQL-scoped |
| `list_targets_scoped_page` | targets | `organization_id` param | Ordinary | Already SQL-scoped |
| `update_target` | targets | `organization_id` param | Ordinary | Atomic single-statement `UPDATE ... RETURNING`, same clean shape as `postgres_callback_service.py`'s `revoke_registration` |
| `archive_target` | targets | `organization_id` param | Ordinary | Same atomic `UPDATE ... RETURNING` shape |

**Summary for this file**: 6 Ordinary, 0 exceptions of any kind — every method takes `organization_id` as an explicit parameter and uses it directly in its own SQL predicate. Zero pre-auth, zero cross-tenant, zero unscoped methods, zero flagged gaps. This is the simplest file classified so far and the first genuine confirmation that a file absent from Phase F's control-function list really does need nothing more than the tenant-context-setting treatment — 6 of 7 remaining files to check before treating that as settled project-wide.

## Phase H: `postgres_authentication_contexts.py` classification (complete, 2026-09-11)

`PostgresAuthenticationContextRepository`, 6 public methods. Second of the 7 files with no Phase F control-function counterpart.

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `create` | authentication_contexts | `organization_id` param (embedded) | Ordinary (self-tenant registration variant) | Returns `self.get_metadata(effective_id)` — an unscoped post-write read of the row it just inserted itself, not a caller-supplied ID |
| `get_metadata` | authentication_contexts | **none** — unscoped by ID alone | Ordinary, but callers must be trusted (see note) | Verified against every actual caller in the repository: `apps/api/src/webguard_api/*.py` has exactly 3 bare `.get_metadata(` call sites, all inside this same class (`create`'s and `revoke`'s own post-write re-reads, and `require_bound`'s initial fetch). No external file calls this method directly |
| `revoke` | authentication_contexts | **none** — unscoped by ID alone | Dead code externally | A repo-wide grep for `.revoke(` (excluding `revoke_scoped`/`revoke_session`/`revoke_token`/`revoke_registration`/`revoke_all`/`revoke_scan_permit`) found zero callers anywhere in `apps/api/src/webguard_api/`. `revoke_authentication_context` in `service.py` calls `revoke_scoped`, not this method. Not a gap since nothing reaches it, but worth flagging as removable if a future cleanup pass wants to shrink this class's public surface |
| `get_metadata_scoped` | authentication_contexts | `organization_id` param | Ordinary | Already SQL-scoped (P1-C1): a wrong-org lookup and a nonexistent ID raise the identical `authentication_context_not_found` error, verified by reading the method's own predicate directly (`WHERE authentication_context_id = %s AND organization_id = %s`) |
| `revoke_scoped` | authentication_contexts | `organization_id` param | Ordinary | Same atomic-predicate shape as `get_metadata_scoped`; its own re-read after the `UPDATE` calls `get_metadata_scoped`, not the bare method |
| `require_bound` | authentication_contexts | `organization_id` param, checked in Python after an unscoped `get_metadata` read | Ordinary, but **see finding below** | The docstrings on this file's own `get_metadata_scoped`/`revoke_scoped` claim `require_bound`'s callers only ever pass "a trusted, previously org-validated reference (a permit or comparison plan), not directly from an untrusted caller." Verified against the actual call sites: that claim is false for two of them. See "Finding: `require_bound`'s cross-tenant ID-existence oracle" below |

**Summary for this file**: 4 Ordinary with correct SQL-level scoping (`create`, `get_metadata_scoped`, `revoke_scoped`, and `get_metadata`/`revoke`'s own internal self-reads), 1 externally-dead method (`revoke`, zero real callers), 1 method (`require_bound`) whose safety rests on a documented assumption about its callers that does not hold at two real call sites — not a defense-in-depth gap in this file's own code, but a documentation-accuracy problem this classification pass caught by checking the claim against actual callers instead of trusting the docstring.

## Phase H: `postgres_authorization_comparison.py` classification (complete, 2026-09-11)

`PostgresAuthorizationComparisonPlanRepository`, 6 public methods. Same shape as `postgres_authentication_contexts.py` in every respect — `create`/`get`/`revoke`/`get_scoped`/`revoke_scoped`/`require_bound`, with `get_scoped`'s and `revoke_scoped`'s own docstrings citing `PostgresAuthenticationContextRepository`'s docstrings directly rather than restating them.

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `create` | authorization_comparison_plans | `organization_id` param (embedded) | Ordinary (self-tenant registration variant) | |
| `get` | authorization_comparison_plans | **none** | Ordinary, but callers must be trusted (see note) | Same 3-internal-caller pattern as `postgres_authentication_contexts.py`'s `get_metadata`: `create`'s and `revoke`'s own post-write re-reads, and `require_bound`'s initial fetch |
| `revoke` | authorization_comparison_plans | **none** | Dead code externally | Same verification: `revoke_authorization_comparison_plan` in `service.py` calls `revoke_scoped`, not this method. Zero external callers found |
| `get_scoped` | authorization_comparison_plans | `organization_id` param | Ordinary | Already SQL-scoped (P1-C1) |
| `revoke_scoped` | authorization_comparison_plans | `organization_id` param | Ordinary | Same atomic-predicate shape |
| `require_bound` | authorization_comparison_plans | `organization_id` param, checked in Python after an unscoped `get` read | Ordinary, but **see finding below** | One of the two directly-untrusted call sites for this pattern (`issue_permit`'s `submission.authorization_comparison_plan_id`) reaches this exact method |

**Summary for this file**: identical shape to `postgres_authentication_contexts.py` — 4 correctly SQL-scoped Ordinary methods, 1 externally-dead method, 1 method carrying the same require_bound finding below. This file's own module docstring is also stale: it says "Status: POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED... this class is not part of this slice's live execution path," but `production_startup.py`'s own module docstring lists "authorization comparison plans" under "Live as of this slice," and `build_production_components` constructs and wires `PostgresAuthorizationComparisonPlanRepository` directly into `WebGuardJobService`. Corrected in this PR since the classification work is what surfaced it.

Both files now bring the confirmed-ordinary count (files absent from Phase F's control-function list, needing only tenant-context-setting, no resolver) to 3 of 7: `postgres_targets.py`, `postgres_authentication_contexts.py`, `postgres_authorization_comparison.py`. 4 remain unchecked: `postgres_findings.py`, `postgres_reports.py`, `postgres_scans.py`, `postgres_target_verification.py`.

## Finding: `require_bound`'s cross-tenant ID-existence oracle (2026-09-11)

Both `PostgresAuthenticationContextRepository.require_bound` and `PostgresAuthorizationComparisonPlanRepository.require_bound` fetch a record by ID with no organization predicate (`get_metadata`/`get`), then compare `record.organization_id` against the caller's `organization_id` in Python, raising a distinct error code for "not found" versus "found, wrong org." The docstrings on the neighboring `get_metadata_scoped`/`get_scoped` methods justify this by claiming `require_bound` is only ever reached with "a trusted, previously org-validated reference (a permit or comparison plan), not directly from an untrusted caller." Checked against the actual call sites, that claim holds for one of three and not the other two:

- `service.py`'s `issue_permit` calls `authentication_contexts.require_bound(submission.authentication_context_id, ...)` and `authorization_comparison_plans.require_bound(submission.authorization_comparison_plan_id, ...)` with IDs read straight out of `load_trustscan_permit_submission_json(body)` — the caller's own HTTP request body. Untrusted.
- `service.py`'s `register_authorization_comparison_plan` calls `authentication_contexts.require_bound(context_id, ...)` for both `body["primary_context_id"]` and `body["secondary_context_id"]` — also straight from the request body. Untrusted.
- `executor.py`'s `_apply_authorization_comparison` calls both `require_bound` methods with IDs read from an already-registered `AuthorizationComparisonPlanRecord` (`plan.primary_context_id`, `plan.secondary_context_id`, and `comparison_plan_id` itself bound to a signed permit claim). This one matches the docstring's claim.

Practical effect: any authenticated principal, from any organization, can submit an arbitrary UUID as `authentication_context_id`, `authorization_comparison_plan_id`, `primary_context_id`, or `secondary_context_id` in a permit-issuance or comparison-plan-registration request and learn, from the returned error code, whether that UUID exists as a real row in *any* organization's data, not just their own (`..._not_found` vs. `..._organization_mismatch`) — the exact "distinguishable existence oracle" `get_metadata_scoped`'s own docstring says the P1-C1 fix was built to prevent, reappearing at a call site that fix didn't cover.

This is not the same severity as a true IDOR: `authentication_context_id` and `comparison_plan_id` are `uuid4()` values (122 bits of random entropy), so an attacker has nothing to enumerate against without already possessing a candidate ID from some other source — the same non-enumerability argument this codebase already relies on for `postgres_callback_service.py`'s token-based lookups. It is real, though: it means an attacker who obtains a context or plan ID belonging to another tenant (leaked in a log line, a support ticket, a URL, a referrer header) can confirm cross-tenant existence and active/expired/revoked status of that specific record without ever authenticating as that tenant, which a fully SQL-scoped predicate would prevent outright regardless of how the ID was obtained.

Not fixed in this PR: changing `require_bound`'s error semantics or its callers' exception handling is a runtime-behavior change, not a documentation fix, and deserves its own PR with its own test coverage (matching how every other P1-C1-style fix in this codebase shipped with a dedicated regression test proving the two error paths become indistinguishable). Recorded here, honestly, rather than folded into a docs-only PR or left for a future session to rediscover from scratch.

## Phase H: `postgres_findings.py`, `postgres_reports.py`, `postgres_scans.py`, `postgres_target_verification.py` classification (complete, 2026-09-11)

The last four files with no Phase F control-function counterpart. All four confirm the "genuinely ordinary" hypothesis with zero exceptions — no pre-auth method, no cross-tenant method, no unscoped write.

### `postgres_findings.py` — `PostgresFindingRepository`, 5 methods

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `record_finding` | findings, finding_events | `organization_id` param (embedded) | Ordinary | Atomic `INSERT ... ON CONFLICT (organization_id, fingerprint) DO UPDATE`, so the tenant-scoped uniqueness constraint itself prevents cross-tenant collision, not just the predicate |
| `get_finding_scoped` | findings | `organization_id` param | Ordinary | Already SQL-scoped |
| `list_findings_scoped_page` | findings | `organization_id` param | Ordinary | Already SQL-scoped |
| `update_status` | findings, finding_events | `organization_id` param | Ordinary | The idempotent no-op branch (`new_status is current_status`) re-reads by `finding_id` alone with no organization predicate — safe because that ID was already proven to belong to this organization by the scoped `SELECT` three lines above, in the same connection, same transaction; not a separate untrusted lookup |
| `list_events_scoped` | findings (existence check), finding_events | `organization_id` param | Ordinary | Existence check against `findings` is scoped before reading `finding_events`, which has no `organization_id` column of its own |

### `postgres_reports.py` — `PostgresReportRepository`, 3 methods

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `create_report` | reports | `organization_id` param (embedded) | Ordinary | Returns `self.get_report_scoped(...)`, not an unscoped read |
| `get_report_scoped` | reports | `organization_id` param | Ordinary | Already SQL-scoped |
| `list_reports_scoped_page` | reports | `organization_id` param | Ordinary | Already SQL-scoped |

### `postgres_scans.py` — `PostgresScanRepository`, 5 methods

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `create_scan` | scan_records | `organization_id` param (embedded) | Ordinary | Returns `self.get_scan_scoped(...)`, not an unscoped read |
| `complete_scan` | scan_records | `organization_id` param | Ordinary | Atomic `UPDATE ... RETURNING`, same shape as `postgres_targets.py`'s `update_target` |
| `get_scan_scoped` | scan_records | `organization_id` param | Ordinary | Already SQL-scoped |
| `list_scans_scoped` | scan_records | `organization_id` param | Ordinary | Already SQL-scoped |
| `list_scans_scoped_page` | scan_records | `organization_id` param | Ordinary | Already SQL-scoped |

### `postgres_target_verification.py` — `PostgresTargetVerificationRepository`, 4 methods

| Method | Tables | Tenant source | Classification | Note |
|---|---|---|---|---|
| `initiate` | target_verifications | `organization_id` param (embedded) | Ordinary | The verification token itself is never persisted as a real column (design predates and is unrelated to tenant scoping — see file's own module docstring); stored only as an `evidence` placeholder string |
| `get_current` | target_verifications | `organization_id` param | Ordinary | Already SQL-scoped; returns `None` rather than raising when nothing matches, a deliberate "is there a current verification" query shape, not a scoping difference from the other methods |
| `get_pending_token` | target_verifications | `organization_id` param | Ordinary | Already SQL-scoped |
| `record_result` | target_verifications | `organization_id` param | Ordinary | Atomic `UPDATE ... RETURNING` |

**Summary for these four files**: 17 Ordinary methods, 0 exceptions of any kind. Every method that reads or writes takes `organization_id` explicitly and uses it directly in its own SQL predicate; every write that returns a record does so through either an atomic `UPDATE ... RETURNING` or a scoped re-read of a row it just inserted itself.

## Phase H classification: all 13 repository files complete (2026-09-11)

Final tally across all 13 `postgres_*.py` files (~115 public methods, ~105 distinct once schedule delegates are excluded):

- **6 files needed and already have a Phase F control-function counterpart**: `postgres_identity.py` (3 resolvers), `postgres_sessions.py` (1 resolver), `postgres_jobs.py` (5 cross-tenant worker-control functions), `postgres_schedules.py` (3 cross-tenant scheduler-control functions), `postgres_callback_service.py` (1 callback-token resolver). All 13 `webguard_control` functions Phase F built are accounted for against a named source method — none left over, none missing a match.
- **7 files are genuinely ordinary, no resolver needed**: `postgres_targets.py`, `postgres_authentication_contexts.py`, `postgres_authorization_comparison.py`, `postgres_findings.py`, `postgres_reports.py`, `postgres_scans.py`, `postgres_target_verification.py`. Every method in every one of these takes `organization_id` (or, for `postgres_sessions.py`'s deliberately principal-scoped subset, `principal_id`) as an explicit parameter and uses it directly in its own SQL predicate.
- **`postgres_callback_broker.py`** is a thin adapter over `postgres_callback_service.py`, classified alongside it, contributing no new SQL of its own beyond `wait_for_observation`'s check-before-poll pattern.

What remains open going into the actual Phase H *conversion* work (rewiring these repositories to run under a real non-superuser role and set tenant context before every query, per Mandate §7):

1. **Rewire the 6 pre-auth/cross-tenant/callback methods** listed under "Major finding" above to call their matching `webguard_control` function instead of raw SQL, then adversarially prove each swap is behaviorally identical under real runtime credentials (same errors, same concurrency guarantees, same return shape).
2. **Add tenant-context-setting to every Ordinary method** across all 13 files before its query runs, so RLS (already defined, dormant since Phase A-G) actually activates instead of running under a role that bypasses it.
3. **Three concrete, already-identified gaps to fix, none newly discovered by this final pass**:
   - `postgres_jobs.py`'s `request_cancellation` lacks the atomic `organization_id` predicate its own `_scoped` wrapper implies (defense-in-depth only, not exploitable today, but inconsistent with the fix already applied to `postgres_identity.py`'s `update_principal_role`/`set_principal_active` and `postgres_schedules.py`'s `_set_schedule_state`).
   - `require_bound`'s cross-tenant ID-existence oracle on `postgres_authentication_contexts.py` and `postgres_authorization_comparison.py` (documented above), which needs its own PR with dedicated regression tests, not a bundled fix.
   - A handful of self-scoped methods with no `organization_id` parameter at all (`postgres_identity.py`'s `set_principal_email_verified`/`touch_last_login`/`list_tokens_for_principal`, `postgres_sessions.py`'s `get_session`) need a signature review to accept and use an org/principal identifier for context-setting, even though none of them has a live scoping gap today.
4. **RLS+FORCE activation in a real, non-disposable environment with evidence** — the actual runtime proof P1-2 needs, which cannot happen inside a worktree or CI's disposable test database alone.

Item 1 and 2 are genuinely large, multi-file, multi-PR engineering work — not something this ledger can mark VERIFIED by documentation alone. This closes the classification/inventory half of Phase H; the conversion half starts from this document.

## Phase H conversion: runtime role-switching mechanism + first rewired method (2026-09-11)

Before this, "convert an ordinary/pre-auth method" read like a Python-only rewiring task. It isn't. Tracing the actual runtime path found that `api_tenant_data`/`worker_tenant_data`/`scheduler_tenant_data` are `NOLOGIN` roles by design (`tenant_isolation_roles.sql`), and no file anywhere granted the real application role membership into them. Every WebGuard process today connects and queries as one role: `webguard`, the literal username `infra/terraform/postgres.tf` provisions on RDS (`username = "webguard"`) and the same name CI's `WEBGUARD_DATABASE_URL`/`WEBGUARD_POSTGRES_TEST_DSN` use. Since Phase G's own RLS-policy file documents that a table's owner bypasses RLS unless `FORCE ROW LEVEL SECURITY` is also applied, and no policy exists for the literal role name `webguard`, enabling RLS while every query still ran as `webguard` would either do nothing (no FORCE) or break every query outright (FORCE, zero matching policy, default-deny). RLS enforcement is not reachable by editing repository methods alone: it needs the live process to actually assume a restricted role for the query it's running.

This was surfaced to the user directly rather than designed and shipped silently, since it's a foundational decision about how the running service authenticates to Postgres with app-wide blast radius if done wrong. Decision: build and prove the mechanism against the disposable CI/dev Postgres sandbox only; applying it to any real, deployed database is a separate, explicit step for later.

**What was built:**

- `infra/postgres/bootstrap/tenant_isolation_runtime_grant.sql`: `GRANT api_tenant_data TO webguard;` (plus the worker/scheduler equivalents). Membership only, never LOGIN/SUPERUSER, never a revocation of anything `webguard` already has. It adds one option (the ability to voluntarily `SET ROLE` into a narrower identity for one query), consistent with how every other tenant-isolation bootstrap file in this project has worked: SQL only, applied and torn down inside a disposable test database, never touching a real environment.
- `postgres_pool.py`'s `role_scoped_connection(role)`: runs `SET LOCAL ROLE` (transaction-scoped, auto-reverting, same lifecycle as `set_tenant_context`'s GUC) after validating `role` against a fixed three-value set. `SET ROLE` has no parameterized form, so this validation is what stands in for a bind parameter, matching `_canonical_organization_id`'s existing defensive shape in the same file.
- `postgres_identity.py`'s `authenticate_token` rewired: the pre-auth resolve step (token id and secret only, no tenant known yet) now runs under `api_tenant_data` and calls `webguard_control.resolve_api_token` instead of three raw `SELECT`s. The moment the control function resolves a real `organization_id`, the rest of the method (the full principal/organization reads and the `last_used_at` write) runs as an ordinary, now-tenant-scoped query on the same connection via `set_tenant_context`. This is the pattern `resolve_identity_token`'s own SQL comment already prescribed for this class of method. Public return contract (`tuple[ApiTokenMetadata, Principal, Organization]`, every field populated with real data, none fabricated) is unchanged: `resolve_api_token` deliberately omits `label`/`created_at` (Section 13 output minimization, per its own comment), so those two fields are fetched with one small additional tenant-scoped query rather than left blank or guessed.
- `tests/contract/test_identity_repository_contract.py`'s Postgres fixture now applies the full role/ACL/function-ACL/control-function/runtime-grant bootstrap in `setUpClass` (mirroring `test_postgres_control_functions.py`'s own `_apply_full_bootstrap`/`_drop_bootstrap_roles` pattern exactly). Without it, `SET LOCAL ROLE api_tenant_data` fails the first time this suite's existing `authenticate_token` test cases run.

**What was proven, against the real disposable CI/dev Postgres (not mocked):**

- The full existing contract-test suite (59 tests across `tests/contract`), the full existing Postgres integration sequence (`test_postgres_connection_pool` through `test_postgres_sessions`, matching `.github/workflows/ci.yml`'s own order exactly), and the full 1799-test unit suite all pass unmodified in behavior. `authenticate_token`'s observable contract (return values, error codes, error ordering) is unchanged for every existing test case, including the two that exercise it directly (`test_token_issue_authenticate_and_revoke_lifecycle`, `test_wrong_secret_is_rejected`).
- After the runtime grant is applied, `SET LOCAL ROLE api_tenant_data` succeeds and `current_user` genuinely changes (verified directly: `current_user=api_tenant_data, session_user=webguard`).
- Under that role, a raw `SELECT password_hash FROM password_credentials` (the withheld-by-design table `get_password_hash` still needs a resolver for) fails with `InsufficientPrivilege: permission denied for table password_credentials`, proving the restricted role is genuinely restricted, not restricted in name only.

**What was not, and could not honestly be, proven here**: whether the runtime grant is load-bearing. In this project's CI/dev sandbox, `webguard` is the official Postgres Docker image's `POSTGRES_USER`, which is a true superuser, and a Postgres superuser can `SET ROLE` to any role regardless of membership grants. Testing "does `SET ROLE api_tenant_data` fail before the grant is applied" in this sandbox returns "no, it already works," which is accurate but not representative: AWS RDS's master user is `rds_superuser`, not a literal `SUPERUSER`, and does not carry this bypass. The grant is real, necessary infrastructure for an actual deployment; this sandbox's own elevated test role just can't be used to adversarially demonstrate that necessity. Recorded here precisely rather than glossed over.

**Deliberately not done in this slice**: RLS is not enabled or forced on any table (still separate, later, explicit work per P1-2's own acceptance criteria). The runtime grant has not been applied to any real environment. The other two pre-auth resolvers approved alongside this one (`get_principal_by_email`+`get_password_hash` -> `resolve_principal_by_email`, `consume_identity_token` -> `resolve_identity_token`) are follow-up work using this same now-proven mechanism, not yet done.

## Phase H conversion: second slice, `get_principal_by_email` converted, two new gaps found (2026-09-11)

Continuing from the runtime role-switching mechanism proven in the previous PR, this slice attempted all three remaining pre-auth resolvers approved earlier: `get_principal_by_email`/`get_password_hash` (via `resolve_principal_by_email`) and `consume_identity_token` (via `resolve_identity_token`). One converted cleanly; two turned out to have real, ACL-level blockers the classification pass could not have caught by reading code alone, since they only surface when a query actually tries to run under the restricted role.

**Converted**: `get_principal_by_email` now resolves under `api_tenant_data` via `webguard_control.resolve_principal_by_email`, then reads the full `principals` row (every field its three callers need, including `email`, which the control function does not return) as an ordinary tenant-scoped query once `organization_id` is known. Same pattern as `authenticate_token`. This worked cleanly because `principals` and `organizations` both carry full table-level `SELECT` grants to `api_tenant_data` already, so the follow-up read has nowhere to fail.

**Not converted, `get_password_hash`**: no control function is keyed by a bare `principal_id`. All 13 of Phase F's functions resolve by token, session, or email; `get_password_hash`'s second caller (`service.py`'s `change_password`, using `context.principal_id` from an already-authenticated session, not an email) has no matching resolver shape even in principle. `password_credentials` has zero `SELECT` granted to `api_tenant_data` at all (Phase D's own correction), so this method's raw query works today purely because every process still connects as `webguard`, unrestricted. Documented precisely in the method's own docstring; not fixed here, since closing it needs a new `SECURITY DEFINER` function with the same design review Phase F's other 13 got.

**Not converted, `consume_identity_token`**: this one looked convertible (a resolver exists, `resolve_identity_token`, and it already validates everything this method checks) until the same resolve-then-refetch pattern that worked for the other two hit a real permission error against the actual sandbox Postgres: `tenant_isolation_acl.sql` grants `api_tenant_data` only a 4-column `SELECT` on `identity_tokens` (`token_id, principal_id, purpose, used_at`), not `created_at` and not `organization_id`. There is no ordinary query under this role that can read `created_at` back for the return value, or scope the post-resolution `UPDATE` by `organization_id` the way `authenticate_token`'s `last_used_at` write now does. Attempted the conversion, ran it against real Postgres, watched it fail with `permission denied for table identity_tokens`, then reverted to the original raw SQL rather than leave a broken implementation in place. Documented in the method's own docstring: closing this needs `resolve_identity_token`'s own `RETURNS TABLE` extended to include `created_at`, a change to Phase F's already-reviewed SQL, not a wiring change made unilaterally here.

**New test coverage added** (neither method had any real-Postgres test coverage before this slice): `test_get_principal_by_email_matches_and_returns_none_for_unknown` and `test_consume_identity_token_lifecycle` in `tests/contract/test_identity_repository_contract.py`, run against both backends. The second one exercises the unconverted method's existing correctness (wrong purpose, forged secret, expiry, already-used), which is worth having regardless of the conversion outcome.

**Proven against real disposable Postgres**: the full contract suite (63 tests, up from 59), the full Postgres integration sequence including `test_postgres_identity_credentials_write_shape.py` (which independently proves `api_tenant_data`'s exact column grants on `password_credentials`/`identity_tokens`), and the full 1799-test unit suite all pass.

This closes out the three pre-auth resolvers approved in the previous slice: one fully converted (`authenticate_token`, prior PR), one fully converted this slice (`get_principal_by_email`), and two genuine gaps found and documented rather than forced (`get_password_hash`, `consume_identity_token`). The remaining Phase H conversion work (the cross-tenant worker/scheduler control functions in `postgres_jobs.py`/`postgres_schedules.py`, the callback resolver in `postgres_callback_service.py`, and tenant-context-setting for every ordinary method across all 13 files) has not started.

## Deployment ordering constraint discovered by this PR's own CI failure (2026-09-11)

The "Frontend browser E2E (Playwright)" job failed on this PR with four registration/login flows all stuck at the same point (no Dashboard heading after sign-in). Root cause, confirmed by reproducing it locally: that job's Postgres only ever runs `scripts/run-postgres-migrations.py` (schema only), never the tenant-isolation role/ACL/function bootstrap. Since `get_principal_by_email` (and `authenticate_token`, merged in the prior PR) now hard-require `api_tenant_data` to exist via `role_scoped_connection`, every `register_account`/`login` call against that unbootstrapped database raised `DatabaseUnavailableError` and the whole E2E flow broke.

This is not just a CI gap. It is real, and it generalizes: **any environment running this code, including real production, will have every registration, login, and API-token authentication fail outright the moment it handles its first request, unless `tenant_isolation_roles.sql`, `tenant_isolation_acl.sql`, `tenant_isolation_function_acl.sql`, `tenant_isolation_control_functions.sql`, and `tenant_isolation_runtime_grant.sql` have already been applied to that database, in that order.** Production has not had this bootstrap applied (confirmed in the prior PR's own ledger entry). Deploying `main` as it now stands, without applying that chain first, means a full authentication outage on the very first request.

Fixed in CI: added an "Apply tenant-isolation runtime bootstrap" step to the Playwright E2E job, applying the same five files in the same order `tests/contract/test_identity_repository_contract.py`'s own `setUpClass` already does. Verified by reproducing the exact failure locally (`get_principal_by_email` against an unbootstrapped database raises; against a bootstrapped one, it returns cleanly) before and after the fix.

Not fixed, and not something to fix unilaterally: this ordering constraint needs to be part of whatever process eventually deploys this code to a real environment. Recorded here in the strongest terms this ledger uses, since two merged PRs (#30, #31) already carry this property and a future session or a human deploying `main` needs to see this before doing so, not discover it from a production incident.

## Phase H conversion: third slice, postgres_jobs.py's worker-lease methods (2026-09-11)

Converted `claim_next_leased`, `renew_lease`, and `recover_expired_leases` to run entirely through their existing `webguard_control` functions under `worker_tenant_data`. Different shape from the identity conversions: `worker_tenant_data` has zero table-level grant on `scan_jobs` at all (confirmed by reading `tenant_isolation_acl.sql`'s own worker section), so there is no "resolve via function, then ordinary refetch" fallback available here the way there was for `principals`/`organizations`. Every one of these three methods now has to go through its control function completely, for every field, not just the pre-tenant-context part.

That constraint turned out to be a clean fit: all three control functions' own `RETURNS TABLE` shapes already cover each Python method's full contract (`claim_next_job` returns the exact 19 `ScanJobRecord` fields plus `worker_id`/`lease_token`/`lease_expires_at`/`attempt_count`; `renew_lease` adds an `outcome` discriminator column since a SQL function can't raise three distinct `JobStoreError` codes the way Python can; `recover_expired_leases` returns the exact `(requeued, cancelled, failed)` triple). No follow-up query was needed for any of the three, unlike every identity-layer conversion so far.

**One real bug caught by testing against actual Postgres, not assumed correct from reading the SQL**: `claim_next_job`/`renew_lease` both take `p_lease_seconds numeric`. Passing a Python `float` sends it to Postgres as `double precision`, and Postgres does not implicitly cast `double precision` to `numeric` for function-overload resolution, so the first real test run failed with `UndefinedFunction: function webguard_control.claim_next_job(unknown, double precision, timestamp with time zone) does not exist`. Fixed by adding an explicit `::numeric` cast in the call site's own SQL text, matching the exact convention `tests/integration/test_postgres_control_functions.py` already uses for these same two functions.

**Not converted, `get_scope` (and `organization_id_for_job`, its own thin wrapper)**: `resolve_job_organization` exists and covers exactly what `get_scope`'s one live caller (`executor.py`) actually reads (`organization_id` alone), but `get_scope`'s own contract also returns `submitted_by`, which the function does not, and there is no ordinary-grant fallback to fill that gap the way `authenticate_token`'s follow-up query could. Documented in the method's own docstring. `organization_id_for_job` itself has zero external callers anywhere in the repository, so converting it standalone would have no caller to prove the conversion against.

**Test infrastructure**: none of `tests/contract/test_job_scan_finding_repository_contract.py`, `tests/integration/test_postgres_tenant_isolation_slice13.py`, `tests/integration/test_postgres_worker_crash_recovery.py`, `tests/integration/test_postgres_worker_outage_resilience.py`, or `tests/integration/test_production_runtime_completion_e2e.py` applied the tenant-isolation bootstrap before this change, since none of them previously needed it. All five now do, in `setUpClass`, matching the identical pattern from the previous two PRs. `test_postgres_worker_outage_resilience.py` (real `docker stop`/`start` against a named container) was fixed for consistency but not run locally, to avoid disrupting a real running container; its underlying mechanism (`claim_next_leased` + `recover_expired_leases` interacting under simulated failure) is already proven by `test_postgres_worker_crash_recovery.py`'s 9 passing tests, which exercise the same code path without the container-lifecycle risk.

**Proven against real disposable Postgres**: full contract suite (63/63), full Postgres integration sequence including the concurrent-claim atomicity test and the crash-recovery suite (9/9), the production-realistic `build_production_components` E2E (4/4), and the full 1799-test unit suite. Adversarial check: under `worker_tenant_data`, a raw `SELECT job_id FROM scan_jobs` fails with `permission denied`; `webguard_control.claim_next_job` under the identical restricted connection succeeds cleanly.

Remaining Phase H worker/scheduler conversion work: `_terminal_update` (via `finish_result_leased`/`fail_leased`/`cancel_running_leased`) and its safety-receipt issuance path, `postgres_schedules.py`'s three cross-tenant scheduler functions, and `postgres_callback_service.py`'s callback resolver. None started.

## Phase H conversion: fourth slice, terminal_transition and safety-receipt issuance (2026-09-11)

Converted `_terminal_update` (the shared implementation behind `finish_result`, `finish_result_leased`, `fail_leased`, `cancel_running_leased`, and `cancel_running`) to run entirely through `webguard_control.terminal_transition` under `worker_tenant_data`. This is the method that issues safety receipts, the signed proof artifact this project's whole safety model rests on, so it got the same careful, line-by-line comparison against the SQL function as every prior conversion, not a faster pass because the pattern was already proven three times before.

The function's own SQL comment documents one visible behavioral reordering worth restating here: the original Python validated the safety-receipt format (path-traversal check, hex-digest check) at the very end, right before the `INSERT`, after the lease/CAS work had already succeeded. The function validates that format up front, before touching the row at all. Both orderings are observably identical, since a failure either way aborts the whole invocation with zero writes (one Postgres transaction, one Python `with` block whose exception triggers a full rollback). Phase F's own review already reasoned through this when the function was built; this conversion just relies on that existing reasoning rather than re-litigating it.

`terminal_transition` reports twelve distinct non-success outcomes plus `ok` through its own `outcome` column (a SQL function cannot raise Python's `JobStoreError` subclasses). Mapped each to its exact original error code and message: `not_found`, `invalid_state`, `lease_required`, `lease_expired`, `transition_conflict`, `safety_receipt_reference_invalid`, `safety_receipt_digest_invalid`, and a `lease_lost` catch-all covering the three outcomes (`lease_lost` itself, `worker_id_invalid`, `receipt_metadata_invalid`, `lease_credentials_invalid`) that are unreachable from this call site because Python already validates the identical conditions before ever reaching the database.

With this conversion, `_require_active_lease` (the helper `renew_lease`'s own earlier conversion had already stopped calling) had no callers left at all. Deleted it rather than leave dead code behind, and corrected the module's own docstring, which still named it as the concurrency model's lease-validation mechanism.

**Proven against real disposable Postgres**: full contract suite (63/63), full Postgres integration sequence including the crash-recovery suite and the `build_production_components` E2E, and the full 1799-test unit suite, all unchanged in behavior. Adversarial check: a raw `INSERT` into `job_safety_receipts` fails under `worker_tenant_data` with permission denied; `webguard_control.terminal_transition` succeeds under the identical restricted connection and correctly reports `not_found` for an unknown job.

This closes out every method in `postgres_jobs.py` that has a Phase F control-function counterpart. Remaining Phase H worker/scheduler conversion work: `postgres_schedules.py`'s three cross-tenant scheduler functions (`list_due_schedules`, `enqueue_due_schedule`, `block_due_schedule`) and `postgres_callback_service.py`'s callback resolver (`record_observation`).

## Phase H conversion: fifth slice, postgres_schedules.py's scheduler functions (2026-09-11)

Converted `list_due_schedules` and `block_due_schedule` to run entirely through their existing `webguard_control` functions under `scheduler_tenant_data`, which (like `worker_tenant_data` on `scan_jobs`) has zero table-level grant on `scan_schedules` at all. Both functions' return columns match `_COLUMNS` exactly, so both converted cleanly with no follow-up query, the same shape as `postgres_jobs.py`'s `claim_next_leased`/`recover_expired_leases`.

**Not converted, `enqueue_due_schedule`**: this is a new, different kind of gap from the ones found so far. `webguard_control.enqueue_due_schedule` exists and reproduces the method's exact sequence, but its own `RETURNS TABLE` is a deliberately minimized 8-column summary (`outcome`, `schedule_id`, `schedule_state`, `schedule_revision`, `schedule_next_run_at`, `job_id`, `job_state`, `job_submitted_at`), not the full `ScanScheduleRecord`/`ScanJobRecord` pair this Python method's own contract promises. Checked the one real caller (`scheduler.py`'s `run_once`): it discards the schedule record entirely and reads only `job_record.job_id` from the job record, so the function's summary is already sufficient in practice, exactly like `authenticate_token`'s discovery that its own caller used far fewer fields than the full return type. The difference here: `scheduler_tenant_data` has zero table-level grant on `scan_schedules`, `scan_jobs`, `schedule_permits`, or `job_permits`, so there's no ordinary-refetch fallback available at all to reconstruct the missing fields, the same wall `postgres_jobs.py`'s `get_scope` hit. Closing this needs either widening the function's return columns (a change to Phase F's already-reviewed SQL) or narrowing this method's own return contract to match its one real caller, both real design decisions and neither made unilaterally here. Documented in the method's own docstring.

**New test coverage**: neither `list_due_schedules` nor `block_due_schedule` had any real-Postgres test coverage calling them as Python methods before this change (`test_postgres_tenant_isolation_slice13.py` constructs `PostgresScheduleRepository` but never calls either; `test_postgres_control_functions.py` tests the SQL functions directly, not the Python wiring). Added `tests/integration/test_postgres_schedule_repository_wiring.py`, five new tests proving both methods work end to end against real Postgres: due/not-due filtering, the limit parameter, pausing with an error code, and both `None`-on-no-match cases (revision mismatch, unknown schedule id).

**Proven against real disposable Postgres**: full contract suite (63/63), full Postgres integration sequence including the new wiring test and the `build_production_components` E2E, and the full 1799-test unit suite. Adversarial check: a raw `SELECT schedule_id FROM scan_schedules` fails under `scheduler_tenant_data` with permission denied; `webguard_control.list_due_schedules` succeeds under the identical restricted connection.

Remaining Phase H worker/scheduler conversion work: `postgres_callback_service.py`'s callback resolver (`record_observation`). After that, every method with an existing Phase F control-function counterpart will have been either converted or precisely documented as blocked, closing the "rewire existing functions" half of Phase H's conversion work; adding tenant-context-setting to the ~90 genuinely-ordinary methods across all 13 files has not started.

## Milestone history (reconstructed from Git + tracker, not fabricated)

| Milestone | Evidence |
|---|---|
| 1.25 | Reporting hotfix (referenced in mandate; not independently re-verified this session) |
| 1.26 | Service queue (referenced in mandate; not independently re-verified this session) |
| 1.27 | Organizations/RBAC (referenced in mandate and old README; superseded by later identity work) |
| 1.31 | TrustScan Scan Permit v1 |
| 1.32 | Runtime safety enforcement, Safety Receipt v1 |
| P0 remediation | `a26b99a`, `0114d56`, disabled-key fix `d94b96c`, closure `c13ccb9` |
| P1-A | `ccf05d1` (A1), `ee3c2c2` (A2, closes P1-5) |
| P1-1 closure | `fa94d7c`, audit record `b412e8b` |
| P1-3 closure | `a2f385b` |
| P1-4 closure | `2ba35a1`, tracking `38ee4b4` |
| P1-10/P1-11 closure, P1-12 partial | tracked in `WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md`, commit `b5d3bb9` |
| Phase A-G (tenant isolation) | `af5cb58` through `da5da85`, this session |
| P1-6 fix | PR #17 merged as `c4132e5` |
| Ledger docs established | PR #18 merged as `871a220` |
| P1-7 fix | PR #19 merged as `47da741` |
| Phase H identity classification | PR #20 merged as `5df6f1d` |
| Flaky test fix (`test_customer_auth.py`) | PR #21, branch `fix/flaky-session-secret-extraction`, commit `7fc07e4`, CI pending |

1.25/1.26/1.27 milestone claims are carried forward from the mandate as-supplied; this session did not independently re-derive their exact commits. Flagged here rather than silently treated as verified.
