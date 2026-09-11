# Project Execution Ledger

Durable, requirement-level tracking for OpenHuntX WebGuard engineering work, per the Claude Master Completion Mandate (2026-09-11). This is a coordination document, not the authoritative vulnerability record — that remains `docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md` and `docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md` (immutable). This ledger links to that evidence rather than duplicating it.

Status values: NOT_STARTED, IN_PROGRESS, IMPLEMENTED_UNVERIFIED, VERIFIED, BLOCKED_EXTERNAL, DEFERRED_WITH_REASON.

## Canonical baseline

```
Commit: 5df6f1d94ae66767d2d1953f3e1ba30d264ea57d
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
| Phase H | Mandate §7 | Convert ordinary PostgreSQL repository callers to set tenant context before query; classify pre-auth/cross-tenant/callback paths separately | IN_PROGRESS (1 of 13 files classified) | 13 `postgres_*.py` repository files, ~115 public methods enumerated 2026-09-11; `postgres_identity.py` (25 methods) fully classified 2026-09-11 (see below) | none yet — classification in progress, conversion not started | P1-2 closure depends on this | multi-session | Every ordinary tenant-data method sets context before query; adversarial cross-tenant test passes under real runtime credentials |

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

The 5 Pre-auth methods are the concrete list Phase H's "narrow functions for pre-tenant identity lookups" requirement (mandate §7) needs to design control functions for. This matches, rather than contradicts, this session's own Phase D/E/F/G work: every one of them was already flagged in-line, by name, as a future resolver's domain during that work — Phase H is that future.

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
