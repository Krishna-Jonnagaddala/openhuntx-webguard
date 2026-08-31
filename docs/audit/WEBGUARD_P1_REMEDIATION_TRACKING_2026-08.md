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
