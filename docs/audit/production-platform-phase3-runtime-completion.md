# Production Platform, Phase III: Runtime Completion (Slice 14)

## 0. Scope confirmation

Slice 13 proved the live PostgreSQL-backed core pipeline (organization → target → authorization → permit → scan → job → worker → Scanner v1 → finding persistence → `/v1/...` retrieval) while leaving schedules, authentication contexts, authorization comparison plans, and report metadata **POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED**. This slice closes every one of those deferrals. As of this slice, the production runtime path (`webguard-api serve/worker/scheduler --environment production`) live-wires:

organizations/principals/memberships, targets, authorizations, scans, jobs, findings (unchanged from Slice 13) **plus, new this slice:** schedules, authentication-context metadata, authorization-comparison plans, and report metadata.

Scanner v1 remains feature-frozen: no detector logic changed. No dashboard work was started; the frontend contract doc (§20) documents what exists for a future dashboard to build against, it does not build one.

## 1. Authentication-context live-wiring and the SecretProvider abstraction (requirement 1)

**The gap**: `PostgresAuthenticationContextRepository` (Slice 13) stores metadata only and has no `get_secret` method by design. Every place in `executor.py` that resolved authenticated-scanning secret material called `authentication_contexts.get_secret(id)` directly: a hard dependency on the in-memory repository's shape that would have raised `AttributeError` the first time anyone attempted authenticated scanning in production.

**The fix**: `secret_provider.py` introduces a `SecretProvider` protocol, mirroring `signing.py`'s `SigningProvider` pattern exactly:

- `LocalSecretProvider`: wraps whatever `authentication_contexts` repository is active; delegates to its `get_secret` if present (unchanged local/dev/lab behavior), or raises a clear `secret_provider_not_configured` error if not (production, no real provider configured), fail-closed by construction, never a silent fallback to storage that does not exist.
- `SecretsManagerSecretProvider`: signs through an injected, duck-typed client matching `boto3`'s Secrets Manager shape (`get_secret_value(SecretId=...) -> {"SecretString": ...}`), never importing `boto3` directly, identical in spirit to `KmsSigningProvider`.

`AuthenticationContextRecord` gained a `secret_reference_id` field (threaded through both backends); `ScanJobExecutor`'s three authenticated-scanning call sites (`_apply_active_detection`, `_apply_authorization_comparison`, `_apply_ssrf_callback_detection`) now call `secret_provider.resolve(record.secret_reference_id or context_id)` instead of `authentication_contexts.get_secret(context_id)` directly. `ProductionServiceConfig.secret_provider` is a new, **optional** field (`WEBGUARD_SECRET_PROVIDER`, accepted value `"aws_secrets_manager"` or unset): deliberately optional, because most production deployments never use authenticated scanning and should not be forced to configure AWS Secrets Manager credentials to start.

**A second, related bug found and fixed**: `WebGuardJobService.register_authentication_context()` (the `POST /v1/authentication-contexts` handler) unconditionally called `self.authentication_contexts.create(..., secret=material, ...)`: a signature only the in-memory repository has. In production this would have failed the first real invocation. Fixed: the service now branches on `hasattr(self.authentication_contexts, "get_secret")` (the same local-vs-production test `LocalSecretProvider` uses): local/dev/lab still accepts raw credential fields inline; production requires `secret_reference_id` and explicitly rejects raw credential fields (`authentication_context_raw_secret_not_accepted`) rather than silently discarding them.

**Verification**: `tests/integration/test_production_runtime_completion_e2e.py::test_authenticated_production_scan_resolves_secret_via_secrets_manager` proves the full chain against real PostgreSQL with a fake-but-real `SecretsManagerClientProtocol` implementation: a bearer-token-gated fixture only reflects its vulnerable parameter when the resolved secret's token is actually presented, so a finding existing is direct proof the resolution genuinely happened, not merely that the unauthenticated path still works.

## 2. Authorization-comparison plan live-wiring (requirement 2)

`PostgresAuthorizationComparisonPlanRepository` is now constructed in `build_production_components` and injected into both `WebGuardJobService` (for `POST /v1/authorization-comparisons` and its revoke route) and `ScanJobExecutor` (for permit-time plan resolution): a drop-in replacement for the in-memory repository, same interface, no executor code changed beyond passing the new instance through.

**A real bug found and fixed**: `PostgresAuthorizationComparisonPlanRepository._record_from_row()` returned `primary_context_id`/`secondary_context_id` as raw `uuid.UUID` objects (psycopg's native type for `UUID`-typed columns) instead of strings: every other UUID-typed column in this class was correctly wrapped in `str()`, these two were not. This crashed the *first* real end-to-end comparison-plan request (`POST /v1/authorization-comparisons` → `TypeError: Object of type UUID is not JSON serializable`): a bug Slice 13's own tests never caught because no test previously exercised the full create → HTTP-serialize round trip against real Postgres for this entity. Fixed by wrapping both fields in `str()`, matching every other ID field in the file.

**Verification**: `test_production_idor_comparison_persists_cwe_639_finding` proves the full production IDOR workflow: two identities, two authentication contexts (`secret_reference_id` only), a persisted comparison plan, the unchanged Slice 8/9 differential engine, and two independently `CONFIRMED` CWE-639 findings (one per cross-identity direction) retrieved through `GET /v1/findings`. No direct victim-identifier injection: `resource_scope` is explicit, operator-supplied endpoints, exactly as the plan model has always required.

## 3. Schedule live-wiring (requirement 3)

`ScanScheduleCoordinator` is now constructed in `build_production_components` against `PostgresJobRepository` (which delegates every schedule-shaped method: `create_schedule`, `get_schedule_scoped`, `list_schedules_scoped_page`, `pause_schedule_scoped`, `resume_schedule_scoped`, `get_schedule_permit_binding`, and the three new materialization methods below, to one internal `PostgresScheduleRepository` instance, so there is exactly one real SQL implementation, not two). `cli.py`'s `webguard-api serve --environment production` now starts a real scheduler thread; `webguard-api scheduler --environment production` runs it standalone. Neither fails closed anymore: both were the deliberate Slice 13 boundary, now closed.

`create`/`list`/`get`/`pause`/`resume` were already fully built (Slice 13); this slice adds the three methods a live scheduler process actually needs, none of which existed for PostgreSQL before: `list_due_schedules`, `enqueue_due_schedule`, `block_due_schedule`. Added to `PostgresScheduleRepository`, ported faithfully from `ScanJobStore`'s proven SQLite logic (`SELECT ... FOR UPDATE` row lock, the same revision-CAS, the same `scan_jobs`/`job_permits` insert shape `submit()` itself uses, **the identical normal job objects a user-triggered submission creates**, not a parallel path).

## 4. Schedule duplicate prevention (requirement 4)

Two independent database guarantees, not one, make double-materializing a due occurrence impossible:

1. **Revision CAS**: `enqueue_due_schedule` reads the schedule row with `FOR UPDATE`, and its final `UPDATE ... WHERE revision = %s AND state = 'active'` only succeeds if nothing else touched the row since the read. A losing concurrent transaction affects zero rows and returns `None` ("raced"), exactly like `PostgresJobRepository`'s own job-claim CAS.
2. **`scan_jobs.idempotency_key`'s database-level `UNIQUE` index** (migration 0005, pre-existing): the job inserted for one occurrence uses `f"schedule:{schedule_id}:{scheduled_for}"` as its idempotency key. Even in a scenario the revision CAS alone did not fully prevent, the second insert would fail the unique constraint: genuine defense in depth, not reliance on a single mechanism.

**Verification**: `test_production_schedule_materializes_exactly_one_job_under_concurrent_scheduler_ticks` races three real threads calling `scheduler.run_once()` simultaneously against one due schedule and asserts exactly one materializes (`sum(winners) == 1`), then proves the materialized job is claimable and executes to completion through the unchanged worker/executor path.

**What this does not solve, stated honestly**: a full highly-available scheduler (multiple scheduler *processes* agreeing on which schedules each owns, rather than safely colliding and letting the database reject the loser) is a distinct, unsolved problem. Today's guarantee is "any number of scheduler processes may poll concurrently and never double-materialize an occurrence," which is what this requirement asks for; it is not "exactly one process does the polling," which is a leader-election problem requiring Redis or another distributed-lock mechanism (§19).

## 5. Report metadata live-wiring (requirement 5)

`PostgresReportRepository` is constructed in `build_production_components` and injected into `WebGuardJobService`. New HTTP surface: `POST /v1/reports` (registers a completed scan's existing report artifact as a tracked entity; it does not render a new report body; Scanner v1's report format is unchanged and frozen), `GET /v1/reports`, `GET /v1/reports/{id}`. `ReportRecord` gained a `completed_at` field (migration 0009) distinct from `created_at`, and both backends gained `list_reports_scoped_page` (replacing the unpaginated `list_reports_scoped`, which had no caller outside one now-updated test).

`create_report()`'s checksum is computed from the artifact's **actual bytes** via the injected `ArtifactStore` (§6), never a client-supplied value: a report's integrity claim is only as good as what actually reads the file.

## 6. Artifact-storage contract (requirement 6)

`artifact_store.py`: a narrow `ArtifactStore` protocol (`put`, `get_reference`, `exists`, `delete`, `checksum`, nothing else, per this slice's own instruction against speculative surface). `LocalArtifactStore` is a real, fully-implemented backend (owner-only permissions, symlink rejection, path-containment checks, the same safety posture `executor.py`'s pre-existing artifact-writing code has always used, now named and reusable). `ObjectStorageArtifactStore` exists to validate the interface is genuinely implementable by a non-filesystem backend: every method is fully specified and raises `object_storage_not_implemented`, honestly, rather than a silent no-op or an incomplete S3 integration this slice's scope does not call for.

**`build_production_components` never constructs `LocalArtifactStore` for production**: it constructs `ObjectStorageArtifactStore`, meaning every report-artifact operation in a real production deployment fails closed with a clear, named error until Slice 15 builds real object storage. This is deliberate, not an oversight: requirement 5 states plainly "production must not pretend a local filesystem path is durable cloud storage," and this is what actually enforcing that looks like in code, not just in a comment. `test_production_report_metadata_persists_checksum_and_reference` asserts this directly (`components.service.artifact_store.checksum(...)` raises `object_storage_not_implemented` before the test substitutes a local store for its own controlled purposes) before proceeding with the rest of the report E2E.

## 7. Cross-repository transaction remediation (requirement 7)

Three named invariants, assessed and resolved on their own merits rather than uniformly wrapped in a heavyweight abstraction:

- **"A submitted scan cannot exist without its initial job"**: already enforced at the schema level: `scan_records.job_id UUID REFERENCES scan_jobs(job_id)` (migration 0004), proven directly by a new test (`test_scan_record_cannot_reference_a_nonexistent_job`) asserting the foreign key rejects an orphan insert with `DatabaseIntegrityError`. No code change was needed; the invariant already held, it just was not tested explicitly before.
- **"A successful terminal job cannot leave the scan permanently RUNNING"** and **"cancellation state cannot disagree across job and scan"**: `PostgresJobRepository._terminal_update()` (the single internal method `finish_result_leased`/`fail_leased`/`cancel_running_leased`/`cancel_running` all funnel through) now runs one additional `UPDATE scan_records SET status = %s, completed_at = COALESCE(completed_at, %s) WHERE job_id = %s AND completed_at IS NULL` **in the same transaction** as the job's own terminal write, for `FAILED`/`CANCELLED` outcomes. `recover_expired_leases()`'s own auto-cancel and auto-fail-on-exhausted-attempts branches (already inside one shared transaction) gained the identical statement. A `SUCCEEDED` job needs no such reconciliation: `complete_scan()` already runs, in its own short transaction, inside `execute()` before the worker ever calls `finish_result_leased`. By the time a job can reach `SUCCEEDED`, its scan row is already accurately completed.

This achieves genuine same-transaction atomicity for these two specific, bounded invariants **without** a cross-repository unit-of-work abstraction, a shared-connection parameter threaded through every repository method, or exposing raw database connections in business logic: the reconciliation is one extra SQL statement against a table `PostgresJobRepository` already has pool access to, written and committed inside a method that was already a single transaction. A full unit-of-work abstraction remains reserved for a genuine need spanning more than two tables or more than one repository class's own transaction boundary: none of this slice's invariants required that, so none was built speculatively.

**Verification**: `test_failing_a_job_reconciles_its_incomplete_scan_record` and `test_cancelling_a_job_reconciles_its_incomplete_scan_record` (new Postgres contract tests) prove both reconciliation paths directly against real transactions.

## 8. Crash consistency (requirement 8)

Deterministic recovery, scenario by scenario:

| Scenario | Recovery |
|---|---|
| API dies after scan insert but before job insert | Not reachable in this architecture: a job is always submitted (and exists) before any scan row is created: a scan is created by the *worker*, after claiming an already-existing job (see `docs/ARCHITECTURE.md` §7's job-vs-scan distinction). The FK constraint (§7) makes the literal inverse ("scan exists, job does not") structurally impossible. |
| Worker dies before completion | The job's lease expires; `recover_expired_leases()` (Slice 13, unchanged) either requeues it (attempts remain: a fresh `execute()` call creates a new scan row for the retry, and the abandoned prior scan row, if one existed, remains an accurate historical record of a real, incomplete attempt) or marks it `FAILED` (attempts exhausted), reconciling any still-incomplete scan row to `failed` in the same transaction (§7). |
| Worker dies after findings persist | Findings are already durably recorded (`record_finding`'s atomic `ON CONFLICT` upsert, Slice 13) and are never lost or duplicated by a subsequent retry: re-detection on retry updates `last_seen`, not a second row. The scan row for that specific attempt reconciles to `failed` exactly as above; the findings it discovered remain, correctly attributed to the scan that actually found them. |
| DB exception during terminal transition | `_terminal_update()`'s own connection-context-manager rollback (Slice 12's proven generic mechanism, `test_exception_inside_borrowed_connection_rolls_back`) ensures nothing partially commits: the job remains `RUNNING` with its lease intact until it naturally expires and the row above applies. |
| Process restarts after lease expiry | Identical to "worker dies before completion" above: lease expiry is process-identity-agnostic; a different process instance performing `recover_expired_leases()` behaves identically to the same process restarting. |
| Scheduler dies during materialization | `enqueue_due_schedule` performs its schedule-row CAS and job/permit inserts inside **one** `pool.connection()` transaction: a crash mid-materialization means the whole statement either committed or rolled back as a unit; there is no partial-materialization state to recover from, by construction. |

No new recovery infrastructure was built for this requirement specifically: every scenario above resolves via a combination of Slice 12/13's existing lease-expiry recovery and this slice's new terminal-state reconciliation (§7). "No scan/job should remain permanently orphaned without a recovery path" is satisfied because every terminal state a job can reach either already implies its scan is consistent (`SUCCEEDED`) or now actively reconciles it (`FAILED`/`CANCELLED`).

## 9. Finding lifecycle via API (requirement 9)

`POST /v1/findings/{id}/status`: body `{"status": "confirmed"|"false_positive"|"accepted_risk"|"resolved", "reason": "<optional>"}`. `reopened` is rejected outright with a dedicated `finding_status_not_client_settable` error before it ever reaches the transition-validity check: it remains reachable only by scanner re-detection (`finding_store.py`'s existing re-detection rule, unchanged). Tenant-scoped (`organization_id` checked before any transition), RBAC-controlled (`ApiPermission.FINDING_UPDATE`; OWNER/ADMINISTRATOR/ANALYST, not VIEWER, a new permission, added to `_ROLE_PERMISSIONS`), audited (`_audit(...)` on every attempt, success or denial), and idempotent (a repeated identical status is a 200 no-op: no duplicate history entry, no error). No field but `status`/`reason` is ever accepted; a client cannot rewrite detector evidence, severity, or any other finding field through this route.

## 10. Finding history (requirement 10)

New append-only `finding_events` table (migration 0009): `event_id`, `finding_id`, `organization_id`, `previous_status`, `new_status`, `reason`, `changed_by` (principal ID, `NULL` for the one scanner-driven transition), `created_at`. Application code only ever `INSERT`s into this table: no `UPDATE`, no `DELETE`. An incorrect entry is corrected by appending a new one, never by rewriting history. Both the operator-driven path (`update_status`) and the scanner-driven path (`record_finding`'s resolved→reopened transition) write exactly one event per actual status change, in the same transaction as the status change itself (both backends: `InMemoryFindingRepository`'s in-process lock, `PostgresFindingRepository`'s single connection checkout). `GET /v1/findings/{id}/events` exposes the full chronological history.

## 11. Production API completeness review (requirement 11)

Reviewed against the entity list requirement 11 names. Live and PostgreSQL-backed: organizations, principals/RBAC, API tokens (all pre-existing, unchanged), targets, authorizations, scans (**new HTTP surface this slice**: `GET /v1/scans`, `GET /v1/scans/{id}`; the repository existed since Slice 13 but had no route), jobs/status, findings, finding lifecycle (new), schedules, authentication-context metadata, comparison plans, report metadata (new), audit. No route was redesigned for aesthetic consistency; the two additions beyond the slice's named requirements (`/v1/scans`, and pagination free-form filters, §12) were made because they were genuine, load-bearing gaps discovered while implementing the named requirements: a "Scans" UI page (named explicitly in the frontend contract, §20) had no endpoint to read from at all before this slice, and several documented filters (finding severity/CWE/asset, schedule target, report scan_id) had no query-parameter path to reach them. Both gaps are documented precisely in `docs/product/WEB_APP_API_CONTRACT_V1.md`, including the ones **not** closed this slice (Dashboard, Assets, Team, API Keys, Settings all remain internal/CLI-only: named as real gaps, not silently deferred).

## 12. Pagination and filtering (requirement 12)

`pagination.py`'s `parse_page_request` gained a `free_form_filters` parameter alongside the existing enum-only `allowed_filters`: a filter name whose legitimate values cannot be enumerated in advance (a scan ID, a CWE identifier, a target URL) is now accepted as any bounded (≤2048 chars), control-character-free string, rather than being unimplementable within the existing enum-only design. Both filter kinds are canonicalized into the identical `(key, value)` tuple shape before signing, so the existing signed-cursor protections apply uniformly: a cursor issued under one filter set fails closed if replayed under a different one, tampered, or issued to a different organization, exactly as before. This was proven generically already (`test_phase2_cursor_tenant_isolation.py`, unmodified) and confirmed to still hold by the full unit-suite regression run (§21).

New filters, all requirement-12-named: scans by `target` (free-form) and `status` (enum); findings by `severity` (enum), `cwe_id`/`asset`/`scan_id` (free-form; `status` was already enum-filterable since Slice 13); schedules by `target` (free-form; `state` already enum-filterable); reports by `scan_id` (free-form). Audit log filtering (`outcome`) was already complete and unchanged.

## 13-16. Production E2E proofs (requirements 13-16)

`tests/integration/test_production_runtime_completion_e2e.py`, four tests, all against real PostgreSQL with zero AWS/public infrastructure (KMS and, new this slice, Secrets Manager both substituted with cryptographically-real or behaviorally-real fakes):

- **Requirement 13** (`test_authenticated_production_scan_resolves_secret_via_secrets_manager`): org → authorize target → authentication-context metadata (`secret_reference_id` only) → `SecretsManagerSecretProvider` resolution → authenticated scan → finding → Postgres persistence → API retrieval.
- **Requirement 14** (`test_production_idor_comparison_persists_cwe_639_finding`): two identities → two authentication contexts → persisted comparison plan → unchanged Slice 8/9 differential engine → CWE-639 findings (both cross-identity directions independently confirmed) → API retrieval. Reuses the exact fixture (`_IdorFixtureHandler`) already proven correct in `test_idor_authorization_e2e_lab.py` rather than inventing a new one.
- **Requirement 15** (`test_production_schedule_materializes_exactly_one_job_under_concurrent_scheduler_ticks`): persisted schedule → due occurrence → exactly one job materialized under three concurrent scheduler ticks → real worker claim → scan execution → completion, proving §3/§4 together end-to-end.
- **Requirement 16** (`test_production_report_metadata_persists_checksum_and_reference`): completed scan → report requested → metadata persisted → checksum/reference retrievable via API, using a locally-substituted `LocalArtifactStore` for the test's own controlled purposes, with the actual production default (`ObjectStorageArtifactStore`, failing closed) asserted directly beforehand.

## 17. TrustScan production signing (requirement 17)

Decided in a dedicated document: `docs/production/TRUSTSCAN_PRODUCTION_SIGNING.md`. Recommendation: **AWS CloudHSM-backed Ed25519** as the v1 production launch path (preserves the existing permit format and verification code entirely; genuine HSM-backed custody; real but justified cost). AWS KMS's `ECDSA_SHA_256` migration (already built as `KmsSigningProvider`) remains a credible, cheaper fallback if CloudHSM's cost proves prohibitive, explicitly requiring its own future reviewed/regression-tested slice rather than being adopted by default. A dedicated internal signing service (Option B) was considered and rejected as dominated by CloudHSM: strictly more operational surface for strictly less assurance. **No permit algorithm was changed this slice**; `LocalDevelopmentSigner`/Ed25519 remains the only wired signer everywhere, local and production alike.

## 18. Row-level security (requirement 18)

**Still deferred: the Slice 13 precondition is not yet met, and this slice did not manufacture a reason to claim otherwise.** Slice 13 named a specific, concrete blocker: `WebGuardPostgresPool` reuses connections across unrelated requests without resetting session-scoped state (a tenant-context GUC) on checkout, and RLS policies added without first fixing that would introduce a *new* cross-tenant leakage vector (a pooled connection silently retaining a prior request's tenant context) rather than closing one.

This slice's own transaction work (§7) deliberately did **not** build a connection-checkout hook or a session-scoped tenant-context mechanism: the reconciliation fix needed only one extra statement inside an already-open transaction, not a new connection-lifecycle abstraction. Because that groundwork still does not exist, the three-part precondition Slice 13 set (checkout hook setting/clearing `app.org_id`; fail-closed-on-unset-GUC proven before any policy rollout; per-table gated rollout only after the hook is proven safe under real pool reuse) remains entirely unmet. Implementing RLS now would still be superficial: a policy layered on a connection model that cannot yet guarantee which tenant's context is actually set. Application-layer enforcement (every repository method requires and checks `organization_id` explicitly, now proven for seven additional entities this slice: schedules, authentication contexts, comparison plans, reports, plus the three new invariant tests in §7) remains the correct, sole enforced boundary. The remaining blocker is unchanged and precise: build the pool-checkout hook first, prove it under real concurrent pool reuse, and only then revisit RLS as a defense-in-depth layer on top of, never instead of, application-layer checks.

## 19. Redis readiness (requirement 19)

**No second real consumer emerged this slice; Redis is not added.** Reassessing the four previously-named future roles against what this slice actually built:

- **Schedule duplicate prevention** (the role most likely to have created a real Redis need) was fully solved by PostgreSQL alone (§4): a revision CAS plus a database-level unique constraint, no distributed lock required. This is a concrete, negative data point: a scenario that looked like it might need Redis coordination did not.
- **Callback correlation** remains exactly where Slice 10/13 left it: `InMemoryCallbackBroker`, in-process, unchanged. No code this slice moved callback correlation across process boundaries.
- **Cross-instance rate limiting** and **worker queue/dispatch efficiency** remain unneeded: this slice did not introduce a second production API instance or observe queue-polling load as an actual problem.
- **Distributed locks for HA scheduling** (multiple scheduler *processes* agreeing on ownership, as opposed to safely colliding, §3/§4) remains the one role with a plausible future trigger, but no code this slice built actually needs it, since "any number of scheduler processes may run concurrently without corrupting data" was achieved without it.

Per this project's own standing rule, Redis is added when a second concrete consumer exists, not when a plausible future one is named again. That threshold was not crossed this slice. `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`'s Redis section is left as Slice 13 stated it, with this slice's finding (schedule dedup did not need it) noted as evidence, not a reason to remove the roles that remain plausible.

## 20. Frontend API contract (requirement 20)

`docs/product/WEB_APP_API_CONTRACT_V1.md`. Documents every `/v1/...` endpoint live as of this slice against the UI surfaces the brief names (Dashboard, Assets, Scans, Findings, Finding detail/lifecycle, Schedules, Reports, Team, API Keys, Audit Log, Settings), marked `STABLE_V1`/`EXPERIMENTAL`/`INTERNAL` per section. States plainly, not silently, which named surfaces have no backing endpoint yet: Dashboard (no aggregate endpoint: compose from list endpoints, or defer, since dashboard-shaped work is explicitly out of scope), Assets/targets (repository exists, no HTTP route), Team/members and API Keys (CLI/repository-only, no HTTP route), Settings (no endpoint), and report download (`report_ref` is an internal reference, not a fetchable URL: object storage, §6, is the actual prerequisite).

## 21. Scanner v1 regression (requirement 21)

Full suite re-run after every change this slice:

- **Unit**: 1,477 tests (1,471 carried over + 6 new: 5 finding-lifecycle/scan/report HTTP tests plus RBAC permission-set updates), all passing.
- **Contract**: 59 tests (56 carried over + 3 new: the two terminal-state scan-reconciliation proofs and the scan-record FK-constraint proof), all passing against both SQLite/in-memory and PostgreSQL backends.
- **Integration**: full suite including every pre-existing XSS/SQLi/IDOR-BOLA/SSRF/authenticated-crawl/authenticated-discovery/TLS/permit-service/Juice-Shop lab test unchanged and passing, the Slice 13 tenant-isolation suite (one test updated for `report_store`'s new paginated method name, no behavior change, a rename-follow-through), the Slice 13 production E2E test (still passing, now exercising a service constructed with every new component wired in), and this slice's own 4 new production E2E tests.

No scanner detection logic was touched. The two real bugs found this slice (the `register_authentication_context` production-path gap, §1; the comparison-plan UUID-serialization bug, §2) were both in *this slice's own new code paths*, not regressions in previously-shipped, previously-tested behavior: caught by writing genuine end-to-end tests against the actual new code, not by inspection.

## 22. Security gates (requirement 22)

`./scripts/run-security-gates.sh` (secret scan + Ruff static analysis + locked-dependency advisory audit), `python scripts/verify-supply-chain-pins.py`, `python scripts/verify-governance-docs.py`, and `python -m compileall` across all source and test trees: all run against the real, unmodified gates, no manual substitute, per this slice's own explicit instruction.

## 23. Documentation (requirement 23)

This document. `docs/production/TRUSTSCAN_PRODUCTION_SIGNING.md` and `docs/product/WEB_APP_API_CONTRACT_V1.md` (new). `docs/ARCHITECTURE.md` and `docs/production/INFRASTRUCTURE_REQUIREMENTS.md` updated from implementation evidence only (§24 below covers the specific edits).

## 24. Known limitations carried forward

- Dashboard, Assets/targets HTTP routes, Team/members HTTP routes, API Keys HTTP routes, Settings, and report download/object-storage are all named, real gaps (§11, §20), not silently missing.
- RLS remains deferred with the identical, unmet precondition Slice 13 named (§18); this slice did not build the connection-checkout hook that would make revisiting it meaningful.
- Redis remains unadded (§19): no second real consumer exists yet.
- The TrustScan production signing decision (§17) is a decision, not an implementation: CloudHSM key custody is not provisioned; `LocalDevelopmentSigner`/Ed25519 remains the only wired signer everywhere.
- Cross-repository atomicity beyond the two invariants this slice closed (§7) remains scoped, not general: a genuine unit-of-work abstraction is reserved for a future need that spans more than the two tables this slice's reconciliation already covers.
- A full highly-available scheduler (leader election across scheduler processes, as opposed to safe concurrent polling) remains unsolved, honestly (§3/§4/§19).
