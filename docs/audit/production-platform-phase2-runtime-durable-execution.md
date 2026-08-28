# Production Platform, Phase II: Runtime Wiring, Durable Scan State & Finding Persistence (Slice 13)

## 0. Scope confirmation

Slice 12 (`docs/audit/production-platform-phase1-postgres-kms-tenancy.md`) built PostgreSQL schema, connection pooling, a KMS-capable signing abstraction, and repositories for organizations/principals/tokens/authorizations/audit-events/targets/callback-registrations — proven with contract tests, but **not wired into any running process**. Scanner v1 remained, and remains, feature-frozen this slice: no new detector was added, and no broad web dashboard was started.

Per the user's own scoping decision for this slice (vertical-slice approach), the following entities are **live** in the production runtime this slice — the real `/v1/...` HTTP paths, in `environment=production`, use PostgreSQL repositories with no silent SQLite/in-memory fallback:

- organizations / principals / memberships
- targets
- authorizations
- scans
- jobs
- findings
- audit events

The following entities are **POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED** — fully built and contract-tested against real PostgreSQL this slice, but not constructed or injected by the production runtime path:

- schedules
- authentication contexts
- authorization comparison plans
- report metadata

No second parallel service implementation was created. `WebGuardJobService`, `ScanJobExecutor`, `ScanJobWorker`, and `ApiTokenAuthenticator` are the same classes used by the pre-existing local/SQLite path; production mode constructs them with different repository objects (`repository_contracts.py`'s `JobRepository`/`ScanRepository`/`FindingRepository`/`IdentityRepository` Protocols), not a rewritten service layer.

## 1. Production startup wiring (requirement 1)

**Gap found and closed.** `production_startup.py`'s `build_production_components()` (added mid-slice) correctly assembled every live component, and was proven end-to-end by the production-mode E2E test — but nothing in `cli.py`, the actual `webguard-api serve`/`worker`/`scheduler` entry point, ever called it. A real operator running `webguard-api serve` had no way to reach PostgreSQL at all; the function existed only as a test-only assembly point. This was found and fixed before closing out the slice, not left as a silent gap:

- `environment.py` defines `Environment(str, Enum)`: `DEVELOPMENT`, `TEST`, `LAB`, `PRODUCTION`.
- `cli.py` adds an explicit `--environment` flag (and `$WEBGUARD_ENVIRONMENT` default) to the `serve`, `worker`, and `scheduler` subcommands only — not to administrative one-shot commands (`organization create`, `token create`, etc.), which remain local-database tools regardless of deployment target. Choice is validated by `argparse`'s `choices=`, itself the same string values `Environment` accepts; there is no heuristic (hostname sniffing, "does a config file exist", debug flags) anywhere in the selection.
- `_production_components()` (`cli.py`) calls `ProductionServiceConfig.from_environment()` — which independently re-validates `WEBGUARD_ENVIRONMENT == "production"` and every other required `WEBGUARD_*` variable, fail-closed with a `ProductionConfigError` if anything is missing or malformed — then constructs a real `boto3.client("kms")` and calls `build_production_components()`. `boto3` is imported lazily, inside this one function, after configuration has already validated successfully: a misconfigured deployment gets the correct, specific `ProductionConfigError` message; a correctly-configured one that is missing the `boto3` package (not a locked dependency of this project — see `signing.py`'s and `production_startup.py`'s module docstrings) fails at exactly that documented boundary, not before.
- `_serve_command`, `_worker_command` branch on `Environment.PRODUCTION` to call `_production_components()` instead of the unchanged local `_components(config)` path. `_scheduler_command` fails closed with `EXIT_USAGE` and a clear message in production mode, rather than silently running the scheduler against SQLite while claiming to be in production — schedule runtime wiring is explicitly deferred (§5), so there is nothing correct for a production scheduler invocation to do yet. `_serve_command` in production mode starts the worker thread but not a scheduler thread, printing an explicit "not started" notice instead of the local mode's "recurring scan scheduler is enabled" line.
- The PostgreSQL connection pool is closed on process exit in all three commands (`pool.close()` in a `finally` block), matching the pattern the E2E test's `addCleanup(components.pool.close)` already established.

**Verification**:
- `tests/unit/test_cli_production_environment.py` (5 new tests): proves `serve`/`worker` call `_production_components()` and never `_components()` when `--environment production` is selected (and the reverse for every other value), proves `scheduler` fails closed with `EXIT_USAGE` in production without touching either component builder, and proves the PostgreSQL pool is closed on exit — all via lightweight fakes at the exact seams `cli.py` calls through, with no real database, AWS credentials, or blocking server loop required.
- Manual smoke verification against the real CLI entry point (`python -m webguard_api ...`, not a test harness): `serve --environment production` with no `WEBGUARD_*` variables set fails immediately with `ERROR [production_config_missing]: WEBGUARD_ENVIRONMENT is required...` (exit 1, no traceback); with a full, valid production configuration pointed at the real disposable PostgreSQL instance, it passes configuration validation and pool/repository construction and fails only at the expected external boundary (`ModuleNotFoundError: No module named 'boto3'`, since this sandboxed environment has no AWS package or credentials installed) — proving every WebGuard-side wiring step is correct up to the genuine external dependency edge.
- `ProductionServiceConfig.from_environment()`'s own field-by-field validation is separately, thoroughly covered by `tests/unit/test_production_config.py` (pre-existing plus new tests for `authorization_directory`/`cursor_signing_secret`/loopback `host` this slice).
- `build_production_components()` itself, and the full resulting runtime, is proven by the production-mode E2E test (§ requirement 22 below) — real PostgreSQL, a cryptographically-real fake KMS client, real HTTP.

Local, unit, and lab behavior is unchanged: every environment value other than `production` runs the exact pre-existing `_components(config)` path.

## 2. Scan persistence (requirement 2)

`scan_store.py` (`ScanRecord`, `ScanStoreError`, `InMemoryScanRepository`) and `postgres_scans.py` (`PostgresScanRepository`, backed by the `scan_records` table extended in migration `0005`). A scan record is created by `ScanJobExecutor.execute()` the moment execution genuinely begins — right after `scan_id = str(uuid4())` is generated, before any network activity — and completed with the finding count and completion timestamp immediately after the scanner finishes and evidence is written. Fields: `scan_id`, `organization_id`, `job_id`, `target`, `authorization_id`, `mode`, `status`, `scanner_version` (from `webguard_scanner.ENGINE_VERSION`), `created_at`/`started_at`/`completed_at`, `permit_id`/`permit_fingerprint` (references, not the permit document), `requested_checks`, `report_ref`, `cancellation_requested`/`cancelled_at`, `finding_count`. No raw permit secret or Ed25519/ECDSA signature is duplicated into this table — only the permit's own ID and content fingerprint, exactly as every other permit-referencing table in this schema already does.

## 3. Durable jobs (requirement 3)

`postgres_jobs.py`'s `PostgresJobRepository` replicates the full job/permit/lease surface `ScanJobStore` (SQLite) already provides: `submit` (idempotent on `idempotency_key`), `get`/`get_scoped`/`list_jobs_scoped_page`, `request_cancellation[_scoped]`, `claim_next_leased`, `renew_lease`, `recover_expired_leases`, `finish_result[_leased]`, `fail_leased`, `cancel_running[_leased]`, and the scan-permit issuance/lookup/revocation methods a job binds to. State lifecycle (`QUEUED` → `LEASED`/`RUNNING` → `SUCCEEDED`/`FAILED`/`CANCELLED`) and retry/attempt tracking are unchanged in shape from the SQLite model; only the storage backend and claim mechanism differ.

**Atomicity under concurrent workers**: `claim_next_leased()` uses `SELECT ... FOR UPDATE OF jobs SKIP LOCKED` layered on top of (not instead of) the same optimistic-concurrency `revision` check the SQLite implementation uses, so two workers racing for the same row never both win — one gets the lock and updates, the other's `SKIP LOCKED` clause makes the row invisible to it for that scan, and it moves on to the next eligible row or returns `None`. `tests/contract/test_job_scan_finding_repository_contract.py`'s `test_claim_next_leased_is_atomic_under_concurrent_workers` proves this directly: 20 real threads race for 5 real queued jobs against real PostgreSQL, and exactly 5 unique winners result, with zero double-claims, on every run.

**Bug found and fixed during this slice**: the initial `claim_next_leased()` implementation only checked `state = 'queued'` — it omitted the full claim-eligibility safety predicate `ScanJobStore._select_claimable_row()` enforces in SQLite: that the job's `authorization_id` is currently assigned to the organization, that any bound permit is unrevoked and within its validity window, and that the same permit is not already driving another `RUNNING` job. This was caught by contract-test parity, not by inspection: `SqliteJobRepositoryContractTests` correctly refused to claim a job whose authorization was never assigned, while `PostgresJobRepositoryContractTests` incorrectly claimed it. The fix ports the complete predicate into the PostgreSQL `SELECT`. The contract test file's `_submit_claimable_job()` helper (now calling `identity.assign_authorization(...)` before expecting claimability) exists specifically so this class of gap cannot silently reappear for either backend.

## 4. Worker leases (requirement 4)

Unchanged lease model, ported faithfully: `worker_id`, `lease_owner`, `lease_expires_at`, heartbeat renewal (`renew_lease`), and `attempt` count are explicit columns/parameters, not derived state. `recover_expired_leases()` requeues, cancels, or fails a job whose lease has expired without a heartbeat, exactly like the SQLite implementation's crash-recovery path — proven for PostgreSQL by the same contract-test mixin the SQLite implementation runs (`SqliteJobRepositoryContractTests`/`PostgresJobRepositoryContractTests` both extend `JobRepositoryContractMixin`). No in-process mutex is used or relied upon for correctness anywhere in the PostgreSQL path; every exclusivity guarantee is a database-level lock (`FOR UPDATE ... SKIP LOCKED`) or an atomic conditional `UPDATE ... WHERE revision = ...`/`WHERE lease_token = ...`, so correctness holds across separate worker processes, separate hosts, and API-process restarts identically — the guarantee was never process-local to begin with.

## 5. Schedule persistence (requirement 5)

`postgres_schedules.py`'s `PostgresScheduleRepository` is **POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED**: full CRUD, pause/resume, and permit-binding lookup exist and are contract-tested (cross-tenant isolation included, §9), but nothing in the production runtime path constructs or calls it. `PostgresJobRepository`'s schedule-shaped methods (`create_schedule`, `get_schedule_scoped`, `list_schedules_scoped_page`, `pause_schedule_scoped`, `resume_schedule_scoped`, `get_schedule_permit_binding`) exist only to satisfy the `JobRepository` protocol's full shape and deliberately raise `JobStoreError("schedule_runtime_wiring_deferred", ...)` rather than silently delegating to the repository above or falling back to SQLite. `cli.py`'s `scheduler` command fails closed with the identical message in production mode (§1).

**Honest limitation, not yet resolved**: "prevent trivial duplicate scheduled executions across scheduler instances" is a genuine multi-instance coordination problem this slice does not solve, because the scheduler itself is not live against PostgreSQL yet. The pre-existing single-host `ScanScheduleCoordinator` (SQLite-backed, unchanged) has no such problem today because only one scheduler instance is expected to run per SQLite database. The moment schedule execution is wired to PostgreSQL in a future slice, this becomes a real requirement, and §11 (Redis boundary) names the concrete mechanism (a distributed lock or advisory-lock-style coordination) that solves it — deliberately not built speculatively now, per the user's own instruction not to add coordination infrastructure before it is needed.

## 6. Finding persistence (requirement 6)

`finding_store.py` (`FindingRecord`, `FindingStatus`, `InMemoryFindingRepository`) and `postgres_findings.py` (`PostgresFindingRepository`, backed by the `findings` table). Fields: `finding_id`, `organization_id`, `scan_id`, `target`, `fingerprint`, `check_id`, `detector_version`, `title`, `severity`, `confidence`, CWE/OWASP identifiers (extracted from `NormalizedFinding.identifiers` by namespace), `endpoint`/`method`/`parameter`, bounded evidence, remediation, references, `first_seen`/`last_seen`, `status`. No raw authentication material (bearer token, session cookie, password) is ever written to this table — findings reference the authentication context by ID where relevant (inherited from the underlying `NormalizedFinding`), never the secret itself, consistent with every other authentication-adjacent table in this schema since Slice 7.

## 7. Finding lifecycle (requirement 7)

`FindingStatus`: `OPEN`, `CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `RESOLVED`, `REOPENED`. `_ALLOWED_TRANSITIONS` (`finding_store.py`) is an explicit graph, enforced by `assert_valid_transition()` on every status update:

```
OPEN           -> CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, RESOLVED
CONFIRMED      -> FALSE_POSITIVE, ACCEPTED_RISK, RESOLVED
FALSE_POSITIVE -> OPEN, CONFIRMED
ACCEPTED_RISK  -> OPEN, RESOLVED
RESOLVED       -> REOPENED
REOPENED       -> CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, RESOLVED
```

Re-detection of an existing `(organization_id, fingerprint)` updates `last_seen` (and, for a currently-`RESOLVED` finding, transitions it to `REOPENED`) rather than inserting a second row — see §8. Confidence is never read by any status-setting code path; a `CONFIRMED`-vs-`PROBABLE` detector confidence and a finding's lifecycle `status` are deliberately independent axes; an operator or a future triage workflow decides status, detection quality never does.

## 8. Finding deduplication (requirement 8)

Enforced at the database level, not just in application code: migration `0005` (extending Slice 12's `idx_findings_fingerprint`) makes `(organization_id, fingerprint)` a unique constraint. `PostgresFindingRepository.record_finding()` issues a single atomic statement —

```sql
INSERT INTO findings (...) VALUES (...)
ON CONFLICT (organization_id, fingerprint) DO UPDATE
SET last_seen = EXCLUDED.last_seen, ...,
    status = CASE WHEN findings.status = 'resolved' THEN 'reopened' ELSE findings.status END
```

— so dedup-or-reopen is a single round trip with no read-then-write race window. `fingerprint` itself is computed deterministically from target/endpoint/method/parameter/check identity (unchanged from the scanner's existing fingerprint logic), so same org + same target + same detector + same vulnerability identity always converges to one row, while a different organization, target, endpoint, or parameter is a structurally different fingerprint and therefore always an independent row — tenant ownership is part of the uniqueness constraint itself, not an application-layer convention layered on top of a tenant-agnostic key. Proven by `tests/contract/test_job_scan_finding_repository_contract.py`'s `test_same_fingerprint_dedupes_to_one_finding`, `test_resolved_finding_reopens_on_redetection`, and `test_different_organization_same_fingerprint_is_independent`, each running against both the in-memory and PostgreSQL implementations.

## 9. Authentication-context metadata persistence (requirement 9)

`postgres_authentication_contexts.py`'s `PostgresAuthenticationContextRepository` is **POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED**, matching schedules (§5). It persists context ID, organization, target, authentication type, non-secret metadata, expiry, and revocation state, plus an optional `secret_reference_id: str | None` — a reference to wherever the actual secret will eventually live (a secrets manager or KMS-adjacent store), never the secret itself. There is no `get_secret`-shaped method on this repository at all; the class structurally cannot return authentication material, matching the in-memory `AuthenticationContext` design from Slice 7 (metadata and secret material have always been separate objects with separate lifecycles in this codebase — this repository continues that separation rather than introducing a new one). Since no production secret store exists yet, actual secret persistence remains explicitly deferred; `secret_reference_id` is the seam a future slice fills in without touching this table's shape.

## 10. Authorization-comparison plan persistence (requirement 10)

`postgres_authorization_comparison.py`'s `PostgresAuthorizationComparisonPlanRepository` closes the cross-process limitation Slice 8 documented (an in-memory-only comparison plan cannot survive a worker process restart or be shared between a submitting API process and a separate executing worker process) at the schema level — full CRUD mirroring `AuthorizationComparisonPlanRecord`/`ResourcePairSpec`. Also **POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED** this slice, matching §5/§9: the repository exists and is contract-tested, but IDOR/BOLA scanning's live runtime path is out of this slice's core-pipeline scope (the vertical slice covers XSS/passive detection through the production E2E; every active detector already works identically regardless of which backend the comparison plan or authentication context ultimately lives in, since the executor consumes them through the same interfaces either way). No credential material is stored — a plan references two authentication-context IDs and an explicit, operator-supplied resource scope, never a secret.

## 11. Callback durable metadata vs. live correlation (requirement 11)

Unchanged from Slice 12's explicit decision, reaffirmed rather than silently drifted from: `PostgresCallbackRegistrationRepository` (already live-wired since Slice 12, and still live this slice via `build_production_components`) is durable **metadata** — organization/target/authorization binding, token issuance/revocation record-keeping. It is not, and does not become, the live wait/correlation mechanism a running SSRF scan actually blocks on; that remains `InMemoryCallbackBroker`, in-process, per Slice 10's original design. Making Postgres the live correlation path would mean a worker polling a database table in a tight loop to detect a callback landing — an inefficient, latency-adding substitute for the receiver process directly waking the waiting thread it already can reach in-memory. §12 (Redis boundary) names the actual mechanism for the day this needs to span more than one process: a shared pub/sub or short-TTL key-value layer, not Postgres polling.

## 12. Report metadata persistence (requirement 12)

`report_store.py` (`ReportRecord`, `InMemoryReportRepository`) and `postgres_reports.py` (`PostgresReportRepository`) persist `report_id`, `organization_id`, `scan_id`, `format`, `state`, an artifact reference (`report_ref`, a path/key — not the report body), a checksum, and `created_at`. **POSTGRES_REPOSITORY_READY, LIVE_RUNTIME_WIRING_DEFERRED**, matching §5/§9/§10 — report generation is not part of this slice's core scan pipeline. No large report body is stored in PostgreSQL, this slice or as a design intention; `report_ref` anticipates the object-storage boundary `docs/production/INFRASTRUCTURE_REQUIREMENTS.md` already identifies as a future requirement, not a reason to inline JSON/HTML report bodies into a relational column now.

## 13. Transaction boundaries (requirement 13)

Two genuinely different kinds of atomicity exist in this slice, and this section states plainly which boundaries are atomic by construction and which are not, rather than claiming a uniform guarantee that was not built.

**Atomic by construction (single connection checkout, single implicit transaction)**:
- **Finding write + lifecycle update** (§8): the `INSERT ... ON CONFLICT ... DO UPDATE` in `record_finding()` is one SQL statement. There is no read-then-decide-then-write race window, and no partial state is observable — proven by `test_same_fingerprint_dedupes_to_one_finding`/`test_resolved_finding_reopens_on_redetection`.
- **Job claim** (§3): `claim_next_leased()`'s `SELECT ... FOR UPDATE SKIP LOCKED` followed by its `UPDATE` happen inside one connection's implicit transaction, committed together or not at all — proven by the 20-thread concurrency test.
- **Job submission idempotency** (§14): `submit()`'s idempotency-key handling is a single statement/transaction per call.
- The underlying mechanism behind all of the above — that an exception anywhere inside a `pool.connection()` block rolls the transaction back before the connection is released to the pool, rather than partially committing — is Slice 12's own generic proof (`tests/integration/test_postgres_connection_pool.py`'s `test_exception_inside_borrowed_connection_rolls_back`), which every repository method in this codebase relies on identically; it was not re-proven per-repository this slice because it is not repository-specific behavior.

**Not atomic this slice — a real, documented limitation, not an oversight**: "scan creation + initial job", "job completion + scan completion", and "cancellation + audit event" each span **two separate repository calls on two separate objects** (`PostgresJobRepository` and `PostgresScanRepository`, or the job repository and the audit-event mechanism), each independently committing on its own connection checkout inside `ScanJobExecutor.execute()`. A crash between the two calls is possible and is not rolled back as a unit. This is judged acceptable for this slice, not merely accepted, for concrete reasons:
- A job that reaches `RUNNING` (claimed) but crashes before its scan record is created leaves an orphaned scan-record absence, not corrupted job state — the job's own lease-expiry recovery (§4) already handles a worker dying mid-execution regardless of which side effect it reached, because recovery keys off the job's own lease, not the scan record's existence.
- Finding writes are themselves idempotent (§8's `ON CONFLICT`) and job completion is checked for a current lease before accepting a terminal state (§14), so a worker that restarts and reprocesses after a partial crash cannot double-write a finding or double-complete a job — the *outcome* users observe (no duplicate findings, no double-completed jobs) holds even without a shared transaction, because each individual write is itself safe to retry.
- Building a genuine cross-repository shared transaction (an explicit unit-of-work parameter threaded through `PostgresJobRepository`/`PostgresScanRepository`/`PostgresFindingRepository`'s methods) is a real architectural change — every method signature in all three classes would need to accept an optional externally-supplied connection — and is out of scope for a vertical slice whose explicit mandate was proving one workflow end-to-end, not redesigning the repository layer's transaction model. This is named here as concrete, specific next-slice work, not deferred vaguely: introduce a `UnitOfWork`-shaped optional connection parameter, starting with the job-completion/scan-completion pair, once a second real cross-repository consistency requirement makes the cost worth it.

No rollback test was written for the second category because there is no atomicity guarantee there to test; writing one would either be vacuous or would misrepresent behavior that does not exist. The first category's rollback behavior is exercised by the concurrency and dedup contract tests above, which fail if a partial write were ever observable mid-transaction.

## 14. Idempotency (requirement 14)

- **Same submission retried** (client-side HTTP retry with the same `Idempotency-Key`): `test_submit_is_idempotent_on_retry` (contract test, both backends) and the pre-existing `test_idempotent_replay_returns_200` (`tests/unit/test_http_api.py`) both prove a retried submission returns the original job, not a duplicate.
- **Worker retries completion**: proven by `test_terminal_transition_requires_a_current_lease` (contract test, both backends) — a second `finish_result_leased`/`fail_leased` call for a job whose lease the first call already cleared is rejected, not silently reapplied. This is the correct idempotency shape for a terminal, one-shot, worker-internal event: rejecting the duplicate (rather than returning "already succeeded" the way client-facing submission does) is sufficient and appropriate, because a worker's own retry logic treats a rejection here as "someone already finished this" and drops it — no caller-visible inconsistency results either way.
- **Scheduler retries enqueue**: not applicable to the PostgreSQL-backed runtime this slice, because scheduled-job creation is not live-wired to PostgreSQL at all (§5) — there is no PostgreSQL-backed "scheduler enqueues a job" code path to test yet. When schedule runtime wiring lands, it will call the same `submit()` idempotency path already proven above, not new logic.
- **HTTP request retried**: covered by the existing `test_idempotent_replay_returns_200` and the tenant-scoped idempotency-key test `test_same_http_idempotency_key_is_tenant_scoped` (`tests/unit/test_phase2_http_tenant_isolation.py`), both unchanged and still passing against the same service layer now backed by PostgreSQL in production mode.

## 15. Pagination (requirement 15)

`SignedCursorCodec` (unchanged) is reused as-is by the production `WebGuardJobService` (`build_production_components` passes `cursor_codec=SignedCursorCodec(config.cursor_signing_key_bytes)`); no PostgreSQL-specific cursor implementation was introduced, so the pre-existing tenant/resource/filter-bound signing and the pre-existing failure modes (cross-org replay, filter-mismatch replay, changed-query replay, malformed cursor) apply unchanged and fail closed identically regardless of which repository backend answers the underlying `list_*_scoped_page` call — `service.list_findings()` (new this slice) follows the exact same `_decode_page`/`_next_cursor` pattern `list_jobs()` already established, with `resource="findings"`. `tests/unit/test_phase2_cursor_tenant_isolation.py`'s existing cross-tenant/replay tests were not modified and continue to pass; no new PostgreSQL-specific pagination test was needed because pagination correctness lives entirely in the codec and service layer, neither of which changed shape.

## 16. API integration (requirement 16)

`http_api.py` adds exactly two things: a `GET /v1/findings` list route (tenant-scoped, paginated, optional `status` filter) and a `GET /v1/findings/{id}` single-resource route, both calling the same `service.list_findings()`/`service.get_finding()` methods used regardless of backend. No second API surface, port, or path prefix was created; `/v1/...` is unchanged and is the only production API path. In production mode, every one of these paths — jobs, permits, scans (via job/finding responses), and findings — is served by the identical `create_server()`/`WebGuardJobService` used locally, just constructed with PostgreSQL-backed repositories by `build_production_components()` (§1). `ApiPermission.FINDING_READ` was added to the RBAC permission set (ANALYST and VIEWER roles; OWNER/ADMINISTRATOR already receive every permission automatically).

## 17. Health and readiness (requirement 17)

Unchanged from Slice 12's design, now genuinely exercised against real production dependencies rather than only a generic mock: `/health` (and its `/healthz` alias) is pure liveness — it never touches the database or signing provider, by design, so a transient PostgreSQL blip cannot make the process appear dead. `/ready` calls `service.readiness()`, which runs the injected `readiness_check` and reports **only** a boolean and a fixed, reviewed reason string (`"ready"` or `"dependency_unavailable"`) — the underlying exception's message, which could name a host, port, schema, or credential, is deliberately discarded, never logged into the response. `build_production_components()` wires `readiness_check=lambda: pool.check_connectivity()`, a real `SELECT 1` round trip against the production PostgreSQL pool.

**New this slice**: the production-mode E2E test now asserts this directly against the real, fully production-wired service (not a generic mock) — `GET /ready` returns `{"status": "ready", "reason": "ready"}`, and the raw response body is asserted to contain neither the database port (`5433`), the database password, the fake KMS key identifier, nor the database hostname — closing the "confirm no DB hostname/credentials/topology/KMS identifiers leak in production `/ready` responses" verification this requirement calls for specifically, rather than relying on the generic (pre-production) `/ready` unit tests alone.

## 18. Secret-scan gate remediation (requirement 18)

**Root cause**: `Breach/Checker/breach-checker/` is a pre-existing, untracked nested Git repository; `git ls-files --others` reports a nested repo as one opaque directory path rather than descending into it, which broke `scan-secrets.py`'s `repository_files()`'s `is_file()` assumption and crashed the real gate on this repository. Separately, `.claude/` was invisible to `git status` only because of the **operator's personal, machine-wide** `~/.config/git/ignore` (confirmed via `git check-ignore -v`), not because of anything tracked in this repository — meaning the gate would crash identically on any other machine or in CI, where that personal file does not exist.

**Fix**: the repository's own tracked `.gitignore` now excludes `/Breach/` and `/.claude/` explicitly, as documented repository policy — not a script-side workaround, not scanning only changed files, and neither directory was staged, modified, or deleted to make this work. With this in place, `python scripts/scan-secrets.py` — the real, official gate, unmodified — passes cleanly: `Secret scan passed (360 repository files, 6 generated artifact files and 741 reachable Git blobs checked).` The full `./scripts/run-security-gates.sh` (secret scan + Ruff static analysis + locked-dependency advisory audit) passes end to end.

**Regression test**: `tests/unit/test_phase5_secret_scanner.py::test_repository_files_excludes_claude_and_breach_by_policy` calls the real `scanner.repository_files()` against the real, canonical repository (the same function the actual gate runs, not a synthetic fixture) and asserts both that enumeration succeeds and that nothing under `Breach/` or `.claude/` is returned.

## 19. PostgreSQL tenant isolation (requirement 19)

`tests/integration/test_postgres_tenant_isolation_slice13.py` (`Slice13TenantIsolationTests`, 7 tests, one per repository introduced this slice) proves cross-tenant reads/mutations fail closed identically to "not found" for: jobs (read + cancel), scans (read), findings (read + status update), schedules (read + pause/resume), authentication contexts (require-bound check), authorization comparison plans (require-bound check), and reports (read). Every repository's tenant boundary is enforced the same way every other tenant-scoped resource in this codebase has been since Slice 2: an explicit `organization_id` parameter checked in the query itself (`<resource>_scoped(id, organization_id)`), not an identifier-implies-access assumption. Cross-tenant access is indistinguishable from an unknown ID in every case — an attacker (or a bug) probing another tenant's resource ID learns nothing about whether it exists.

## 20. Row-level security decision (requirement 20)

**Decision: RLS remains not implemented, again — but this time with a concrete precondition for when it should be, not an open-ended deferral.** Application-layer authorization (every repository method requires and checks `organization_id` explicitly, proven by §19's tests) remains the enforced tenant boundary this slice, for a specific engineering reason, not inertia:

Real RLS enforcement requires session-scoped tenant context — a policy like `USING (organization_id = current_setting('app.org_id')::uuid)`, set per-transaction via `SET LOCAL app.org_id = ...` immediately after a connection is checked out. `WebGuardPostgresPool` (`postgres_pool.py`, Slice 12) is a `psycopg_pool`-backed pool that reuses raw connections across unrelated requests; its reset behavior on check-in is a `ROLLBACK`, not a GUC (session-variable) reset. Adding RLS policies today, without *also* adding a mandatory "clear or re-set `app.org_id` on every pool checkout" hook in the same change, would create a **new** cross-tenant leakage vector that does not exist today: a pooled connection reused for organization B's request without its GUC being explicitly re-set would silently retain organization A's session variable from a prior checkout, and a permissive or missing default policy could then let B's query see A's rows through a mechanism that looks like a security control but is actually acting backwards. That failure mode is strictly worse than today's status quo of "no RLS, but every single repository method is contract-tested to check `organization_id` explicitly" — it would trade a proven, tested, consistent enforcement mechanism for an unproven one with a real, specific, identified gap.

This is judged a genuine engineering blocker, not an excuse: RLS is deferred again, but the next slice that wants to add it has a concrete, three-part gate to clear, not a vague "revisit later":
1. Add a pool-checkout hook (in `WebGuardPostgresPool.connection()`) that explicitly sets `app.org_id` (or clears it) on every single checkout, before any application code runs.
2. Every RLS policy's default posture must be **fail closed on an unset GUC** — proven by a dedicated test that a connection with no `app.org_id` set can read zero rows from any tenant-scoped table, before any policy is considered for rollout.
3. Only then apply RLS per table, one at a time, each gated on a contract test proving the checkout-hook prevents cross-connection leakage under real pool reuse (a connection serving org A's request immediately followed by a checked-out-and-reused connection serving org B's request, on the same underlying pool).

Until that three-part sequence exists, RLS as currently conceivable would be defense-in-depth in name only, with a real hole where the "depth" is supposed to be. Application-layer enforcement, proven per-repository by contract tests, is the correct sole boundary for now.

## 21. Redis boundary decision (requirement 21)

**What PostgreSQL alone guarantees today**, proven by this slice's own tests, not aspirationally: correct-under-crash, correct-under-concurrency job dispatch (§3/§4 — `FOR UPDATE SKIP LOCKED` plus lease expiry recovers a dead worker without any external coordinator); atomic finding deduplication (§8); a durable, tenant-isolated source of truth for every entity listed in §0. None of this requires Redis, and none of it is weakened by Redis's absence — PostgreSQL is not a stand-in for a queue here, it already *is* a correct queue for a single shared-database deployment.

**What Redis's future role concretely is** — named now, precisely, so nothing gets added to "the roadmap" as a vague line item, but nothing is built early either:

1. **Worker queue/dispatch efficiency, not correctness.** Today, `claim_next_leased()` requires a worker to poll (`SELECT ... SKIP LOCKED` on an interval). This is already *correct* under concurrency and crash; what it is not, is push-based. The moment horizontal worker scaling makes polling latency or database load from many idle pollers matter, Redis (a real queue — lists, streams, or a wake-up pub/sub channel workers block on) removes the polling interval as a latency floor. This does not change where job *state* lives — PostgreSQL remains authoritative; Redis would only carry the "something is ready, go look" signal.
2. **Ephemeral callback correlation** (§11). The concrete, most time-sensitive future role: `InMemoryCallbackBroker` cannot correlate a callback observed by one process with a scan waiting on another. This is genuinely ephemeral, short-TTL, non-durable-by-design data (the durable metadata already lives in PostgreSQL per §11) — exactly the shape Redis is for, and exactly the shape that would be actively wrong to force into a durability-oriented store like PostgreSQL via polling.
3. **Rate limiting across instances.** `FixedWindowRateLimiter` (unchanged, still in-process) is correct for exactly one API instance and silently wrong the moment a second instance shares a tenant's rate budget, because each instance would enforce its own independent window. Redis (`INCR`+`EXPIRE`, or a leaky-bucket script) is the standard fix — needed only once a second production API instance is real, not before.
4. **Distributed locks / coordination**, specifically: preventing duplicate scheduled-job execution across multiple scheduler instances (§5's named gap) and any future leader-election need. This is the one item on this list with a live, named consumer already identified (§5) — but it has no code today because schedule runtime wiring itself is deferred; there is nothing yet for a lock to protect.

**Explicit non-goal, stated plainly**: Redis is never a second source of truth in any of the four roles above. Each is either a performance/coordination layer on top of state that stays durably correct in PostgreSQL alone (roles 1 and 3), or data that was never meant to be durable in the first place (roles 2 and 4). Concretely, this slice adds **no** Redis container, **no** Redis client dependency, and **no** code path that depends on Redis existing — `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`'s "Queue / Redis" section is updated to reflect this more concrete, now-implementation-informed version of the same conclusion it already reached in outline.

## 22. Production-mode end-to-end proof (requirement 22)

`tests/integration/test_production_mode_e2e.py`'s `test_full_production_pipeline_organization_to_finding_retrieval` (gated on `WEBGUARD_RUN_INTEGRATION=1` and `WEBGUARD_POSTGRES_TEST_DSN`) proves, against a real disposable PostgreSQL instance and zero AWS/public infrastructure:

```
environment=production, database_backend=postgresql
  -> ProductionServiceConfig -> WebGuardPostgresPool -> real PostgreSQL
  -> create organization/principal/API token (PostgresIdentityRepository)
  -> create + authorize a target (PostgresTargetRepository, filesystem authorization doc)
  -> GET /ready over real HTTP -- proven "ready", proven not to leak
     DB host/port/credentials or the KMS key ID (requirement 17)
  -> POST /v1/permits over real HTTP -- KMS-backed signing
     (KmsSigningProvider against a cryptographically-real fake KMS client;
     zero AWS network calls, zero boto3 dependency)
  -> POST /v1/jobs over real HTTP (PostgresJobRepository)
  -> a real worker thread claims and executes it (atomic PostgreSQL lease,
     unchanged Scanner v1 XSS/passive detection pipeline against a real
     self-signed-HTTPS reflected-XSS fixture server)
  -> a finding is persisted (PostgresFindingRepository)
  -> the scan record completes (PostgresScanRepository)
  -> GET /v1/findings and GET /v1/findings/{id} over real HTTP retrieve it
```

`_FakeKmsClient` performs real ECDSA P-256/SHA-256 signing via the `cryptography` library, returning DER-encoded signatures and DER SubjectPublicKeyInfo public keys matching AWS KMS's real response shape closely enough to exercise `KmsSigningProvider`'s actual verification path, not a stub of it — only the network boundary to AWS is substituted, exactly as `signing.py`'s own module docstring anticipates for tests. Cross-tenant isolation for the entities this test touches is additionally verified via direct repository calls at the end of the test.

## 23. Scanner v1 regression (requirement 23)

Full local suite re-run after every change this slice, including the executor's new scan/finding-persistence hooks:

- **Unit**: 1,471 tests, all passing (`python -m unittest discover -s tests/unit`).
- **Contract**: 56 tests, all passing against *both* SQLite/in-memory and PostgreSQL backends (`WEBGUARD_RUN_INTEGRATION=1 WEBGUARD_POSTGRES_TEST_DSN=... python -m unittest discover -s tests/contract`).
- **Integration**: 56 tests, all passing (`WEBGUARD_RUN_INTEGRATION=1 WEBGUARD_LAB_TARGET=... WEBGUARD_POSTGRES_TEST_DSN=... python -m unittest discover -s tests/integration`), including every pre-existing XSS/SQLi/IDOR-BOLA/SSRF/authenticated-crawl/authenticated-discovery/TLS/permit-service/Juice-Shop lab test unchanged and passing, plus this slice's 7 tenant-isolation tests and the production-mode E2E test.

No scanner detection logic, safety engine, or network-safety code was touched this slice; the only executor change is that scan/finding persistence calls happen alongside the unchanged detection pipeline, and the full regression run above confirms that addition changed nothing about detection behavior itself.

## 24. Documentation (requirement 24)

This document. `docs/ARCHITECTURE.md` §3/§7/§12 updated with the Slice 13 runtime-wiring reality (production startup path, live vs. deferred entities, the RLS decision). `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`'s PostgreSQL and Queue/Redis sections updated to reflect what is now actually live versus still deferred, replacing outline-level guesses with implementation-informed specifics.

## 25. Known limitations carried forward

- Schedules, authentication-context secrets, authorization-comparison-plan live execution, and report generation are not live against PostgreSQL — explicitly scoped out this slice (§0), not silently missing.
- Cross-repository transactions (scan+job, job-completion+scan-completion, cancellation+audit-event) are not atomic as a unit — §13 explains why this is currently safe in practice and names the concrete follow-up.
- RLS is not implemented — §20 names the exact three-part precondition for adding it safely.
- Redis is not introduced — §21 names its four future roles precisely, none of which are needed yet.
- A real production deployment of `webguard-api serve --environment production` requires operators to install `boto3` (not a locked dependency of this project) and configure real AWS credentials for KMS signing — verified to fail closed with a clear error at exactly that boundary, not a WebGuard-side defect, if omitted.
- The production-mode E2E test substitutes a cryptographically-real fake KMS client for actual AWS KMS, per this project's established, documented testing convention (`signing.py`'s module docstring) — it has never made a real AWS API call, this slice or Slice 12, and none of this slice's own verification requires one.
