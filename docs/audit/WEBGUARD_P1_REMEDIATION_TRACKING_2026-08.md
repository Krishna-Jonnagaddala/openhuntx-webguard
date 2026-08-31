# WebGuard P1 Remediation Tracking — 2026-08

This is a living tracking document for P1 remediation work, layered on
top of the immutable baseline audit and the closed P0 remediation. It
is **not** part of either immutable record:

- [WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md](WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md) — immutable pre-remediation baseline. Never edited.
- [WEBGUARD_P0_REMEDIATION_2026-08.md](WEBGUARD_P0_REMEDIATION_2026-08.md) — P0 closure record. Never edited after the fact.

This document is updated as P1 batches complete and as new
post-audit findings are discovered during that work.

---

## BATCH A — Runtime resilience (CLOSED)

**Scope**: A1 (callback observation polling failure handling), A2
(PostgreSQL-backed worker crash / lease-expiry recovery proof).

**Commits**:
- `ccf05d1` — *fix(ssrf): degrade callback-store outages safely* (A1)
- `ee3c2c2` — *test(jobs): prove postgres worker lease recovery* (A2)

**Status**: Both committed and pushed to `main`; `HEAD == origin/main` confirmed at `ee3c2c2`. Full regression green (see the batch's own delivered report for the complete matrix). Approved.

---

## BASELINE P1 FINDINGS

**BASELINE P1 = 9** (P1-1 through P1-9, from the immutable baseline audit — unchanged, still open, counted separately from anything below). See [WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md](WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md) for the original findings; none of them are rewritten here.

## POST-AUDIT P1 FINDING

### P1-10 — Worker terminal-state persistence can kill worker during sustained PostgreSQL outage

Discovered during Batch A's A1 remediation review — not part of the original 9 baseline P1 findings. Do not read this as having existed in, or been missed by, the original audit's P1 list; it is a distinct, later discovery, tracked under its own ID.

**Remediation commit**: `eddc7c8` — *fix(worker): survive transient postgres outages*.

#### ORIGINAL DISCOVERY

```
executor raises while Postgres remains unavailable
  → worker catches exception
  → worker attempts _fail(...)
  → fail_leased() requires Postgres
  → Postgres call fails
  → persistence exception escapes
  → run_once()/run_forever worker loop may terminate
  → leased job can remain RUNNING until later recovery
```

Live-reproduced during Batch A's own A1 investigation: a real permit→job→worker flow, Postgres stopped mid-execution long enough to span both the original failure and the worker's own attempt to record it. Captured traceback: `psycopg_pool.PoolTimeout` → `DatabaseUnavailableError` escaping `PostgresJobRepository.fail_leased()` → `_terminal_update()`, uncaught by `run_once()`'s `except JobStoreError as store_error:` (wrong exception type — `DatabaseUnavailableError` is not a `JobStoreError`), propagating out of `run_forever()` entirely (`Exception in thread Thread-2 (run_forever):`). Job row confirmed stuck `state="running"`.

#### PRE-CLAIM OUTAGE REPRODUCTION

Before implementing anything, this batch's own dedicated investigation reproduced one additional case live: Postgres unavailable *before* `recover_expired_leases()`/`claim_next_leased()` even run — i.e. before any job is touched at all. Confirmed the identical exception-boundary gap exists there too, earlier than originally scoped, and confirmed a `webguard-api serve`-style `run_forever()` thread started while Postgres was already down never resumed processing even after Postgres came back — the same instance stayed dead until manually restarted. This was folded into P1-10's scope per instruction ("the same worker/job-store outage class"), not treated as a separate finding.

Six scenarios reproduced live in total against real, disposable Postgres containers (`docker stop`/`docker start`) before any code change: the pre-claim case, `run_forever()` dying on a startup-time outage, executor-raises-during-outage, executor-succeeds-but-`_finish_result()`-fails, cancellation-persistence-during-outage, and heartbeat/monitor-thread death (`>>> THREAD DIED: webguard-lease-XXXX: DatabaseUnavailableError` — previously an unexplained artifact in Batch A's own logs, now attributed precisely).

#### ROOT CAUSE

`DatabaseError` (raised by `WebGuardPostgresPool`'s own 5-second connection-checkout timeout when Postgres is unreachable) is a `RuntimeError` subclass, structurally unrelated to `JobStoreError` (a `ValueError` subclass) — every exception handler in `worker.py` that catches `JobStoreError` (or, worse, nothing at all) therefore let a raw `DatabaseError` escape uncaught at four independent sites: terminal-state persistence (`_finish_result`/`_fail`/`_cancel`), the heartbeat/cancellation-check loop, and the pre-claim calls at the top of `run_once()`. Worst case: `_fail()` itself needing Postgres to record a failure that Postgres-unavailability *caused* turned one outage into a dead worker thread trying to report itself.

#### DEPLOYMENT-MODE IMPACT

Confirmed by direct code read (`cli.py`): in `webguard-api serve` (combined API+worker+scheduler), `run_forever` ran on its own thread — only that thread died, silently, with no restart trigger; the process looked healthy throughout. In standalone `webguard-api worker` mode, `run_forever` runs on the **main thread** with no enclosing handler for `DatabaseError` anywhere up to `main()` — the whole process crashed (self-healing only if a supervisor restarted it).

#### IMPLEMENTATION

Three independent resilience additions to `apps/api/src/webguard_api/worker.py`, no other production file changed, no lease/CAS/`SKIP LOCKED` SQL touched:

1. **Terminal-state persistence** (`_finish_result`/`_fail`/`_cancel`, via a new shared `_persist_terminal_state` helper): bounded retry on `DatabaseError` only — a semantic `JobStoreError` (`job_lease_lost` and friends) still fails immediately, unchanged. On exhaustion, returns `False` rather than raising or recursing into another terminal-write attempt — the job is left exactly where it durably already is.
2. **`monitor_job()` heartbeat/cancellation loop**: `DatabaseError` no longer ends the thread — it skips that cycle with a short backoff (`heartbeat_retry_backoff_seconds`) and keeps monitoring on schedule. Genuine `JobStoreError` (lease actually lost) is unchanged.
3. **`run_forever()`'s own loop boundary**: catches `DatabaseError` specifically (never a blanket `Exception`) around `run_once()`, backs off via `stop_event.wait(poll_seconds)` (so shutdown is never delayed), and lets the next iteration retry naturally — this is what makes the pre-claim case survivable without needing a separate retry-of-retries inside `run_once()` itself.

#### TERMINAL RETRY POLICY

`DEFAULT_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS = 3`, `DEFAULT_TERMINAL_PERSISTENCE_RETRY_BACKOFF_SECONDS = 1.0`, `DEFAULT_HEARTBEAT_RETRY_BACKOFF_SECONDS = 1.0` — all three constructor-overridable (matching the existing `lease_seconds`/`heartbeat_seconds`/`poll_seconds` pattern), plus an injectable `sleep` callable for fast, deterministic unit testing.

**Accurate invariant** (corrected from an earlier draft of this document, which incorrectly claimed the retry budget "always sits comfortably inside the lease" — it does not, and the design does not depend on that being true):

- Terminal-persistence retries are bounded (a small, fixed attempt count and backoff — never unbounded, never a busy-loop).
- Retries never weaken lease-token/revision CAS ownership checks — `_terminal_update()` is byte-for-byte unchanged.
- Terminal persistence can begin late in an already-running lease interval, and each retry attempt can itself take up to the connection pool's own 5-second checkout timeout — under a sufficiently long outage, **the lease genuinely can expire while a retry sequence is still in progress.** The retry budget is not sized to prevent this; it is not meant to.
- If another worker reclaims the job before this worker's retry sequence finishes, the original worker's eventual terminal write is rejected by the existing, unmodified lease/state/revision protections (`job_lease_lost`, or `job_state_transition_invalid` if the job already reached a terminal state by then).
- **Therefore correctness is preserved even when retry duration overlaps lease expiry** — the CAS is what guarantees safety, not the retry budget's relationship to `lease_seconds`.
- The cost of that overlap is a possible duplicate execution, never a corrupted or double-persisted result: at most one terminal write can ever survive (see DUPLICATE-EXECUTION LIMITATION).

`run_forever()`'s own outage backoff is a separate, deliberately unbounded-in-duration policy (retries for as long as `stop_event` isn't set — correct behavior for "wait out an outage of unknown length"), bounded only in rate (never busy-loops).

#### RUN_FOREVER RESILIENCE

See IMPLEMENTATION item 3. Live-proven: the same `run_forever()` instance — no restart — survives a startup-time outage and automatically resumes processing once Postgres returns.

#### HEARTBEAT RESILIENCE

See IMPLEMENTATION item 2. Live-proven: a transient renewal failure no longer ends the monitor thread; the main worker loop is unaffected regardless.

#### FAIL PATH

Live-proven: executor raises while Postgres is down → `_fail()`'s retries exhaust → `run_once()` returns normally (no raise) → job left `RUNNING`, `error_code` empty (never falsely marked failed).

#### FINISH PATH

Live-proven: executor succeeds, Postgres down during `_finish_result()` → retries exhaust → job left `RUNNING`, `result_status` empty — never falsely reported completed, never routed into `_fail()`.

#### CANCEL PATH

Live-proven (real outage, not code-only): cancellation requested, Postgres down during `_cancel()` → worker survives → job left `RUNNING` — CANCELLED is never fabricated if it was never durably persisted.

#### RECOVERY MODEL

No new recovery mechanism — an abandoned attempt is left `RUNNING` with its already-durable lease, reclaimed by the existing, already-proven `recover_expired_leases()` (Batch A2) once that lease naturally expires (or, per TERMINAL RETRY POLICY above, once it expires mid-retry). Live-proven this batch: abandonment → `recover_expired_leases()` requeues → a second worker reclaims → exactly one winner (10-thread race) → the original, now-stale worker's own later completion attempt is rejected by the unchanged CAS.

#### LEASE/CAS SAFETY

Unmodified. `FOR UPDATE SKIP LOCKED`, lease-token/revision CAS, and `_terminal_update()`'s state/lease checks are byte-for-byte unchanged — confirmed by diff (only `worker.py` changed) and by re-running Batch A2's full crash-recovery suite unmodified (9/9 pass).

#### DUPLICATE-EXECUTION LIMITATION

Live-proven contained, not eliminated: if a heartbeat outage lets a lease lapse mid-execution, a second worker can genuinely re-execute the same job concurrently with the first. The CAS guarantees only one terminal result ever persists; the tenant-scoped finding upsert leaves exactly one row even if both workers recorded the identical finding. The cost is wasted duplicate scanning work, not incorrect persisted state.

#### TEST EVIDENCE

- `tests/unit/test_worker_outage_resilience.py` (new, 10 tests, fast/deterministic via a real SQLite-backed store with specific methods monkeypatched and an injected fake `sleep`): exact bounded retry count, configured backoff duration honored, no retry on semantic `JobStoreError`, no recursive failure-persistence, success-path exhaustion never falls back to `_fail()`, `run_forever()` survives and keeps retrying past repeated pre-claim failures, backoff is not a busy-loop, `stop_event` remains responsive during the outage backoff, monitor thread survives a transient renewal failure. Reverting the fix (`git stash`) makes all 10 fail.
- `tests/integration/test_postgres_worker_outage_resilience.py` (new, 12 tests, real Postgres, real `docker stop`/`start`): every required scenario A–P, including the pre-claim case, same-instance startup-outage recovery without restart, executor-raises/finish-result/cancellation persistence during real outages, heartbeat survival, recovery-within-budget, lease-expiry reclaim after abandonment, multi-worker-one-winner, stale-worker rejection, duplicate-execution/finding-dedup intact, and a later unrelated job processing normally once Postgres returns. 12/12 pass, confirmed on two independently fresh containers.

#### REMAINING LIMITATIONS

1. A long DB outage during execution may allow the lease to lapse and a second worker to perform duplicate scanning work.
2. Existing CAS/state/revision checks guarantee at most one valid persisted terminal result.
3. Finding dedup protects identical persisted findings where applicable.
4. The heartbeat does not currently propagate a proactive "lease uncertain" signal to the executing scanner (deliberate — the existing CAS already protects correctness at the final write regardless; adding this would be the "major executor-cancellation redesign" the remediation instructions explicitly said not to attempt in this batch).
5. `--once` mode may still expose a raw DB-unavailability traceback during pre-claim failure (a one-shot invocation legitimately should report the failure rather than retry forever; it is just not yet wrapped in this codebase's coded-error convention).
6. Structured logging and service health/readiness remain absent pending P1-B — an operator still cannot *observe* that a worker absorbed an outage, only that it no longer dies from one.

#### STATUS: CLOSED

POST-AUDIT OPEN P1 count for P1-10 is now **0**. History above is preserved, not erased.

---

### P1-11 — Scheduler run_forever() can be killed by a transient PostgreSQL outage

Discovered while auditing runtime resilience after P1-10 closed — P1-10 was explicitly scoped to `worker.py` only, and `scheduler.py`'s `ScanScheduleCoordinator.run_forever()` turned out to have the identical, unfixed class of defect. Not part of the original 9 baseline P1 findings.

**Remediation commit**: `41ea1b5` — *fix(scheduler): survive transient postgres outages*.

#### ORIGINAL DISCOVERY

```
run_forever() → run_once() → list_due_schedules() / enqueue_due_schedule()
  → PostgreSQL unavailable
  → DatabaseError raised
  → run_forever() has no exception handling at all
  → loop terminates permanently
```

Confirmed by direct code read: `run_forever()` was `while not stop_event.is_set(): self.run_once(); stop_event.wait(self.poll_seconds)` — zero exception handling, structurally identical to `worker.py`'s pre-P1-10 `run_forever()`.

#### ROOT CAUSE

Same taxonomy mismatch as P1-10: `DatabaseError` (`RuntimeError` subclass) is structurally unrelated to `JobStoreError` (`ValueError` subclass). `run_once()` never wrapped its calls to `list_due_schedules()`/`enqueue_due_schedule()` in anything that would catch `DatabaseError`, so it always propagated straight out of `run_forever()`.

#### STANDALONE IMPACT

`_scheduler_command()` (`cli.py`) calls `scheduler.run_forever(stop_event)` directly on the main thread, no enclosing handler. Live-reproduced: a real subprocess launched against an already-stopped Postgres exited with code 1 and a full `DatabaseUnavailableError` traceback on stderr. Needs an external supervisor to recover.

#### SERVE-MODE IMPACT

`_serve_command()` runs the scheduler on a `daemon=True` background thread (`threading.Thread(target=scheduler.run_forever, ...)`). Live-reproduced: an uncaught `DatabaseError` killed only that thread (Python's default `threading.excepthook` logged it and the thread ended); the HTTP API and worker thread kept running normally, but recurring schedule materialization silently stopped forever with no operator-visible symptom beyond one stderr traceback.

#### STARTUP-OUTAGE REPRODUCTION

Live test: started `run_forever()` on a background thread against an already-stopped Postgres. Pre-fix, the thread died on its first iteration and never resumed even after Postgres came back — the same instance stayed dead until manually restarted, exactly mirroring P1-10's own pre-claim-outage finding for the worker. Post-fix, the same thread survives the outage and resumes on its own, materializing a real, previously-seeded, fully TrustScan-permit-validated due occurrence with no restart of any kind.

#### ATOMICITY ANALYSIS

This mattered more here than it did for the worker: `enqueue_due_schedule()` performs a row lock, several validation reads, a `scan_jobs` INSERT, a `job_permits` INSERT, and a `scan_schedules` UPDATE (revision CAS) — all inside one `with self._pool.connection() as connection:` block with **no explicit `.transaction()` wrapper**. Whether that block alone provides atomic commit-or-rollback was not assumed; it was checked against `psycopg_pool.ConnectionPool.connection()`'s own source (it wraps the borrowed connection in `with conn:` — `psycopg.Connection`'s own context manager, which commits on clean exit and rolls back on any exception) and confirmed this codebase never sets `autocommit=True` anywhere, so every call to `enqueue_due_schedule()` runs inside one implicit transaction by default.

#### FAULT-INJECTION PROOF

Empirically verified against real, disposable PostgreSQL with two live fault injections on a fully-seeded schedule (real organization/principal/authorization/permit/binding), re-run on completely fresh infrastructure immediately before this commit:

- **Fault A** — connection failure injected immediately before the `scan_schedules` UPDATE, after the `scan_jobs`/`job_permits` INSERTs had already run: `scan_jobs` count, `job_permits` count, `scan_schedules.revision`, and `scan_schedules.next_run_at` all confirmed **unchanged** afterward.
- **Fault B** — connection failure injected immediately after the `scan_schedules` UPDATE succeeded, before the connection block's implicit commit: all four of the same values confirmed **unchanged** afterward.

Both fault points roll back completely — no orphan job can exist without a matching schedule advance, and no schedule can advance without its job, in either direction.

#### IMPLEMENTATION

One file changed: `apps/api/src/webguard_api/scheduler.py`. `run_forever()` now wraps `self.run_once()` in `try/except DatabaseError`, backing off via the existing `stop_event.wait(self.poll_seconds)` and continuing the loop. No changes to `run_once()`, `enqueue_due_schedule()`, or any repository SQL. Deliberately not a copy of `worker.py`'s pattern: no nested bounded-retry-with-backoff helper (unlike `worker.py`'s `_persist_terminal_state`), because the proven atomicity above means a failed attempt has nothing partially written to retry-in-place — the outer poll loop re-driving the whole batch on the next cycle is sufficient. Only `DatabaseError` is caught; `JobStoreError` and any unexpected exception still propagate and end the loop (verified live).

#### RETRY POLICY

Reuses `self.poll_seconds` as the backoff interval via the existing `stop_event.wait(...)` call, mirroring worker.py's own top-level boundary. No new constant introduced. No unbounded retry: each iteration is one bounded attempt, gated by the connection pool's own 5-second checkout timeout.

#### STOP-EVENT BEHAVIOR

Verified live: `stop_event.set()` during an active outage-backoff wait interrupts it immediately rather than blocking for the full `poll_seconds` (tested with a 10-second poll interval; returned in well under 3 seconds).

#### REVISION/CAS PROOF

Untouched by this change, and verified unaffected: revision starts at 0, increments to exactly 1 on the one successful enqueue, and a stale-revision retry attempt correctly returns `None`. Live concurrent-race test (two `ScanScheduleCoordinator` instances racing `run_once()` for the same due occurrence, one race staged immediately after a Postgres restart): exactly one job and one revision advance resulted; the loser cleanly returned `None` via the CAS.

#### IDEMPOTENCY PROOF

Untouched by this change. The unique idempotency-key index behind the revision CAS remains the second protection layer for duplicate-occurrence prevention; not exercised differently by this fix.

#### FULL REGRESSION

Run against completely fresh, disposable infrastructure (a new Postgres container and a new pinned Juice Shop container, neither reused from the fault-injection investigation), immediately before this commit:

- Migrations from zero: 11/11 applied cleanly.
- Backend unit (`tests/unit`): **1619/1619 pass**.
- Backend contract against real PostgreSQL (`tests/contract`, `WEBGUARD_RUN_INTEGRATION=1` + `WEBGUARD_POSTGRES_TEST_DSN` set so the Postgres-backed cases actually execute rather than skip): **59/59 pass, 0 skipped**.
- Backend integration including Juice Shop (`tests/integration`): **111/111 pass** — covers the new P1-11 scheduler outage suite (17/17), the existing P1-10 worker outage suite, the A2 worker crash/lease-recovery suite (`test_postgres_worker_crash_recovery.py`), the production SSRF callback E2E suite (`test_production_ssrf_callback_e2e.py`), the TrustScan permit-service lab, the signing-service E2E suite, and the full set of Scanner v1 lab tests (crawler, TLS analyzer, safe-HTTP, crawl-scan, professional-report, IDOR/Juice-Shop-authenticated-discovery).
- P1-11 scheduler outage suite standalone re-run (`tests/integration/test_postgres_scheduler_outage_resilience.py`): **17/17 pass**.
- Scheduler concurrency/idempotency: covered by the above (P1-11 suite scenarios 13-15) plus `tests/unit/test_phase2_cross_tenant_schedules.py` and `tests/unit/test_schedule_store.py` within the unit pass.
- Job/executor regression: covered by the unit pass (`test_job_executor.py`, `test_job_executor_active_detection.py`, `test_phase4_executor_authority.py`, `test_job_leases.py`).
- Callback tenant isolation: covered by `tests/unit/test_callback_service.py` (unit pass) and `tests/contract/test_callback_registration_repository_contract.py` (contract pass).
- Signing-service regression: covered by the unit pass (`test_trustscan_signing.py`, `test_signing_provider.py`, `test_cloudhsm_signing.py`, `test_signing_service_cli_production_gate.py`) and the integration pass (`test_signing_service_e2e.py`).
- TrustScan regression: covered by the unit pass (all `test_trustscan_*`/`test_*permit*` files) and the integration pass (`test_trustscan_permit_service_lab.py`).
- Frontend typecheck (`tsc -b`): pass.
- Frontend build (`tsc -b && vite build`): pass.
- Frontend lint (`oxlint`): pass (pre-existing warnings only, no errors, none introduced by this change).
- Vitest: **39/39 pass**.
- Playwright (run only after the backend integration pass had fully finished, never concurrently against the same database): **4/4 pass**.
- Secret scan, Ruff security checks (`--select S`), dependency audit (`scripts/run-security-gates.sh`): all pass.
- Supply-chain pin verification (`scripts/verify-supply-chain-pins.py`) and security-governance document verification (`scripts/verify-governance-docs.py`): both pass.
- `terraform fmt -check -recursive`, `terraform init -backend=false`, `terraform validate`: all pass.
- Trivy IaC config scan (`infra/`, CRITICAL/HIGH): 0 misconfigurations.
- `git diff --check`: clean throughout.
- Both empirical atomicity fault injections (see FAULT-INJECTION PROOF) re-run on this same fresh infrastructure immediately before commit: both confirmed atomic.

#### REMAINING LIMITATIONS

1. The standalone-process test drives `ScanScheduleCoordinator.run_forever()` directly rather than the full `webguard-api scheduler` CLI entrypoint with production secrets/signing-service bootstrap — sound because `_scheduler_command()`'s only logic around `run_forever()` is "call it directly, no try/except," which the test reproduces exactly; the argparse/bootstrap layer is untouched by this fix.
2. Combined `serve`-mode thread isolation was validated by reproducing `cli.py`'s exact `daemon=True, target=run_forever` thread construction, not by running a full `serve` process with a live HTTP server — a deliberate generalization from directly-tested Python threading semantics (an uncaught exception on one thread cannot propagate to another thread or the process), not an unverified assumption.
3. Backoff reuses `poll_seconds` rather than a distinct outage constant, matching `worker.py`'s own choice — a very short `poll_seconds` configuration retries an outage just as fast as it polls normally; not a new risk, since that is also true of every other iteration already.
4. Structured logging and service health/readiness remain absent pending P1-B — an operator still cannot *observe* that the scheduler absorbed an outage, only that it no longer dies from one.

#### STATUS: CLOSED

POST-AUDIT OPEN P1 count for P1-11 is now **0**.

## CURRENT P1 ACCOUNTING

- BASELINE OPEN P1: 9 (P1-1 through P1-9, unchanged, still open — see the immutable baseline audit)
- POST-AUDIT P1-10: CLOSED
- POST-AUDIT P1-11: CLOSED
- OPEN POST-AUDIT P1: 0
- CURRENT OPEN P1 TOTAL: 9
