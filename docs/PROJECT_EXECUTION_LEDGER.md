# Project Execution Ledger

Durable, requirement-level tracking for OpenHuntX WebGuard engineering work, per the Claude Master Completion Mandate (2026-09-11). This is a coordination document, not the authoritative vulnerability record — that remains `docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md` and `docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md` (immutable). This ledger links to that evidence rather than duplicating it.

Status values: NOT_STARTED, IN_PROGRESS, IMPLEMENTED_UNVERIFIED, VERIFIED, BLOCKED_EXTERNAL, DEFERRED_WITH_REASON.

## Canonical baseline

```
Commit: f77d3651f62b442be97b4f33d7020ad4d094e1bf
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
| Phase H | Mandate §7 | Convert ordinary PostgreSQL repository callers to set tenant context before query; classify pre-auth/cross-tenant/callback paths separately | IN_PROGRESS (7 of 13 files classified; major scope correction found, see below) | 13 `postgres_*.py` repository files, ~115 public methods enumerated 2026-09-11; `postgres_identity.py` (25), `postgres_jobs.py` (30), `postgres_schedules.py` (11), `postgres_sessions.py` (6), `postgres_callback_service.py` (4), `postgres_callback_broker.py` (5), `postgres_targets.py` (6) fully classified 2026-09-11 (see below) | none yet — classification in progress, conversion not started | P1-2 closure depends on this | multi-session | Every ordinary tenant-data method sets context before query; adversarial cross-tenant test passes under real runtime credentials |

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
