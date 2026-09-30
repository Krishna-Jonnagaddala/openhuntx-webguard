# WebGuard P1 Remediation Tracking: 2026-08

This is a living tracking document for P1 remediation work, layered on
top of the immutable baseline audit and the closed P0 remediation. It
is **not** part of either immutable record:

- [WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md](WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): immutable pre-remediation baseline. Never edited.
- [WEBGUARD_P0_REMEDIATION_2026-08.md](WEBGUARD_P0_REMEDIATION_2026-08.md): P0 closure record. Never edited after the fact.

This document is updated as P1 batches complete and as new
post-audit findings are discovered during that work.

---

## BATCH A: Runtime resilience (CLOSED)

**Scope**: A1 (callback observation polling failure handling), A2
(PostgreSQL-backed worker crash / lease-expiry recovery proof).

**Commits**:
- `ccf05d1`: *fix(ssrf): degrade callback-store outages safely* (A1)
- `ee3c2c2`: *test(jobs): prove postgres worker lease recovery* (A2)

**Status**: Both committed and pushed to `main`; `HEAD == origin/main` confirmed at `ee3c2c2`. Full regression green (see the batch's own delivered report for the complete matrix). Approved.

---

## BASELINE P1 FINDINGS

**P1 FINDINGS AT BASELINE AUDIT = 9** (P1-1 through P1-9: this historical count is immutable and is never rewritten; see [WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md](WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md) for the original findings, unchanged, never edited). Remediation status of each is tracked here, in this mutable document, without altering that historical baseline count.

**CLOSED BASELINE P1: P1-5.** P1-5 was "no test in this repository exercises PostgreSQL-backed worker-crash/lease-expiry recovery... implemented-but-unproven" (baseline audit, line 294). Closed by Batch A's A2 work: `tests/integration/test_postgres_worker_crash_recovery.py` (commit `ee3c2c2`), 9 test methods, real PostgreSQL, already committed and part of every full-regression pass since: worker-A-disappears/worker-B-reclaims, claim-before/after-lease-expiry, stale-worker rejection, CAS-revision protection, no-duplicate-finding-on-recovered-retry, terminal-consistency-after-attempts-exhausted, cancellation-during-lease-becomes-cancelled-on-recovery, many-workers-racing-produces-one-winner. This closure was accurate at the time A2 completed but was not reflected in this document's running accounting until now. It is corrected here, not backdated into the immutable baseline audit.

**CLOSED BASELINE P1: P1-3.** P1-3 was the baseline audit's structured/operational logging gap: no consistent, machine-parseable operational log stream across `api`/`worker`/`scheduler`/`callback-service`/`signing-service`, only ad hoc or absent logging. Closed by the P1-B1 batch below.

**CLOSED BASELINE P1: P1-4.** P1-4 was the baseline audit's process health/readiness gap: no liveness or readiness signal for `api`/`worker`/`scheduler`/`callback-service`/`signing-service`, so an operator (or an orchestrator) had no way to detect a stalled process or a lost database dependency short of watching for silence. Closed by the P1-B2 batch below.

**CLOSED BASELINE P1: P1-1.** P1-1 was the baseline audit's repository-level tenant-isolation gap (line 290 of the baseline audit): `authentication_contexts`, `authorization_comparison_plans`, and `browser_sessions` had zero tenant/principal enforcement at the SQL/repository layer, with correctness depending entirely on `service.py` checking first. Closed by the P1-C1 batch below.

**CLOSED BASELINE P1: P1-6.** P1-6 was `.terraform.lock.hcl` gitignored instead of committed, so `terraform apply` could pick a different provider build across machines/CI runs with no diff to review. Fixed by regenerating the lockfile via `terraform init` on the CI-pinned Terraform version (1.16.0), confirming it byte-identical to the file already present locally, and removing the stray `.gitignore` line. PR #17, merged as `c4132e5`, CI fully green (10/10 jobs).

**CLOSED BASELINE P1: P1-7.** P1-7 was `TrustScanSigner.sign()`/`sign_safety_receipt()` hardcoding `signature_algorithm="Ed25519"` in the returned metadata regardless of which provider actually signed (local Ed25519, KMS ECDSA_SHA_256, or CloudHSM), so a permit or safety receipt signed by a non-Ed25519 provider carried a false algorithm label. Fixed by deriving the field from `self._registry.active.algorithm` (the provider's own reported algorithm) instead of a literal. Verification stays bound to key/algorithm exactly as before (resolved through the registry, never through the self-reported field), so this is a metadata-accuracy fix, not a verification-logic change. `tests/unit/test_p1_7_signature_algorithm_metadata.py` (8/8, real local and KMS sign/verify/tamper round trips); full signing suite 45/45; backend unit 1799/1799. PR #19, merged as `47da741`, CI fully green (10/10 jobs).

**CURRENT OPEN BASELINE P1: 3** (P1-2, P1-8, P1-9; P1-1, P1-3, P1-4, P1-5, P1-6, and P1-7 closed, as above).

### P1-3: Structured logging / operational log stream

**Remediation commit**: `a2f385b`, *feat(logging): add structured runtime observability*.

**STATUS: CLOSED.**

#### LOGGING ARCHITECTURE

New module `apps/api/src/webguard_api/structured_logging.py`, built on Python's standard `logging.Logger`/`logging.StreamHandler`/a custom `logging.Formatter`, not a bespoke stdout writer. Thread-safety comes from `StreamHandler.emit()`'s own internal lock (relied on, not reimplemented), which is what makes the module safe across worker/scheduler background threads and per-connection HTTP handler threads at once. One dedicated logger (`webguard.structured`, `propagate=False`) so nothing else in a process's logging tree gets swept in by accident. One JSON object per physical output line (NDJSON). `configure_structured_logging(service=...)` runs once per process, before that process's runtime loop starts; `log_event(...)` is the call-site API and is a safe no-op if configuration never ran (so the large pre-existing test suite, which constructs `ScanJobWorker`/`ScanScheduleCoordinator`/etc. directly, is unaffected).

The output boundary (not just `log_event()`) enforces the redaction contract. `_JsonLineFormatter.format()` independently re-derives `timestamp` (from `record.created`) and `level` (from `record.levelname`), and re-validates `service`/`event`/every field against the same central allowlist, regardless of what already happened upstream. A record that isn't a dict, or lacks a valid `service`/`event`/recognized level, is dropped by returning `None`, which `_StructuredStreamHandler.emit()` treats as "write nothing." A formatting or write failure never propagates. Proven directly by bypassing `log_event()` entirely: calling `logging.getLogger("webguard.structured")` directly with unsafe fields, an unknown-shaped payload, a plain string, and a custom object whose `__str__` returns a marked secret. None of it reaches the output.

#### REDACTION MODEL

Closed allowlist, checked by field NAME and VALUE SHAPE both: `request_id, organization_id, principal_id, scan_id, job_id, schedule_id, finding_id, worker_id, key_id, route_name, reason_code, error_code, exception_type, source_module, source_function, status_code, attempt, source_line, duration_ms, http_method`. Everything else is silently dropped, never raised (a logging-call mistake must never become a new failure in the code path being logged). Never present, by construction (none are allowlisted field names): `Authorization`, `Cookie`, session/CSRF/identity tokens, raw callback tokens, passwords, database DSNs, request/response bodies, signing message/signature bytes, CloudHSM PINs/private keys/provider secrets, arbitrary exception `str()`/`repr()`, absolute filesystem paths. Exception diagnostics (`exception_type`, `source_module`, `source_function`, `source_line`) are extracted by walking the traceback to its innermost frame and reading `frame.f_globals["__name__"]` (never `f_code.co_filename`), so a stack trace can never leak a path.

#### SERVICE IDENTITY

Every call site outside `mail.py`/`service.py` passes its own explicit `service=`: `worker.py` → `"worker"` (10 call sites), `scheduler.py` → `"scheduler"` (6), `callback_server.py` → `"callback-service"` (3), `signing_service.py` → `"signing-service"` (5), `http_api.py` → `"api"` (4). This is deliberate, rather than relying on whatever `configure_structured_logging()` set for the whole process. No thread-local state, no per-thread loggers/handlers, same single logger/handler/stream throughout. This is what makes the combined `webguard-api serve` process (configured once as `service="api"`) correctly label its embedded worker's `job_claimed` as `worker` and its embedded scheduler's `schedule_materialized` as `scheduler`, instead of mislabeling every embedded event `api`. `mail.py`/`service.py` deliberately have no fixed identity of their own and inherit whichever process they run in, which is correct for both.

#### OUTAGE EVENTS

Edge-triggered, not per-poll-cycle: `worker.py`/`scheduler.py` each track a single boolean (`_in_database_outage`) touched only by their own `run_forever()` thread, producing exactly one `database_outage_detected` and one `database_outage_recovered` per outage episode. Proven both with fast fake-DB-error injection and against real, genuine PostgreSQL outages (real `docker stop`/`start`) layered as additive test methods onto the existing P1-10/P1-11 suites, none of which altered those suites' own pre-existing assertions or runtime semantics. `callback_observation_persistence_retry`/`_recovered`/`_exhausted` layer identically onto P1-12's existing bounded-retry loop, with `_exhausted` carrying the fixed `error_code="callback_observation_persistence_unavailable"`: this is P1-12-R1's own operational signal.

**P1-12-R1 is now operationally observable** through `callback_observation_persistence_exhausted`: an operator watching the structured stream can now see a sustained-outage callback loss happen, in real time, rather than only inferring it after the fact from a missing finding. **This does not functionally solve P1-12-R1**: no observation is recovered, no fabricated confirmation is prevented that wasn't already prevented, nothing about the false-NOT_VULNERABLE outcome changes. **P1-12 remains PARTIAL/open**, unchanged by this batch.

#### DEVELOPMENT MAIL

`DevelopmentMailProvider.send()`'s original stdlib-logger call (which wrote the complete message body, including a real one-time verification/reset/invitation token, to the application log) was removed entirely during pre-commit review, not weakened or level-adjusted. A pre-commit check correctly rejected the first cut of this work, which had left that call in place on the reasoning that it was currently inert (nothing in this codebase calls `logging.basicConfig()`, so the call happened to be filtered by the stdlib default `WARNING` level). That is not a security property, since any future change enabling logging would have silently reopened the leak. `DevelopmentMailProvider.send()` is now a documented no-op. `InMemoryMailProvider` (already existing, unmodified) remains the safe, explicit inspection seam for tests and local development: it captures every message programmatically (`messages_to`/`latest_to`) and can mirror it to a JSON Lines file, exactly as the Playwright browser E2E suite already relies on. Plain `webguard-api serve` local-dev usage has a resulting, documented, non-security **LOCAL-DEVELOPMENT UX LIMITATION**: an operator has no console-visible way to read a verification/reset/invitation link unless they explicitly construct the service with `InMemoryMailProvider(sink_path=...)` themselves. Deliberately left open rather than closed by weakening the redaction boundary.

#### VERIFICATION

- Structured logging (core + bypass + combined-serve-identity + standalone + mail-root-logger-leakage + all five per-service call-site test files): **53/53 pass**.
- Backend unit (`tests/unit`): **1701/1701 pass**.
- Real-outage logging suites (P1-10/P1-11/P1-12, real Postgres, genuine `docker stop`/`start`, additive assertions layered on unmodified pre-existing tests): **37/37 pass**.
- Backend contract (real PostgreSQL): **59/59 pass**.
- Backend integration incl. Juice Shop: **121/121 pass**.
- Frontend build (`tsc -b && vite build`): **PASS**.
- Vitest: **39/39 pass**.
- Playwright: **4/4 pass**.
- Security gates (secret scan, Ruff `--select S`, dependency audit): **PASS**.
- Terraform (`fmt -check`, `init -backend=false`, `validate`): **PASS**.
- Trivy IaC (`infra/`, CRITICAL/HIGH): **0 misconfigurations**.
- `git diff --check`: **clean**.
- Root-logger-enabled token leakage regression (deliberately configures the ROOT logger to `DEBUG` with its own capturing handler, sends a marked fake one-time token through `DevelopmentMailProvider.send()`, asserts the marker absent from captured root output/stdout/stderr/the structured stream): **PASS**.
- Raw runtime stdlib logging calls remaining anywhere in `apps/api/src/webguard_api` (`git grep -e 'logging\.getLogger' -e '_logger\.' -e '\blogger\.'`): **zero** (the one remaining match is inside an explanatory comment, not executable code).

#### REMAINING LIMITATIONS

1. No `route_name` template on API events yet (would need deriving one safely across ~40 inline route branches without raw-path leakage, judged out of proportion for this batch).
2. No `request_id`↔`job_id` correlation bridge on job-creation API responses yet.
3. Worker's `monitor_job()` heartbeat-`DatabaseError` path doesn't yet participate in the top-level `database_outage_detected`/`_recovered` transition event (scoped to `run_forever()` only, documented in-code as deliberate).
4. LOCAL-DEVELOPMENT UX LIMITATION (see DEVELOPMENT MAIL above): non-security.
5. Health/readiness (P1-4) was open at the time this section was written; see the P1-4 section immediately below, now closed by P1-B2.

### P1-4: Process health/readiness

**Remediation commit**: `2ba35a1`, *feat(health): add runtime liveness and readiness monitoring*.

**STATUS: CLOSED.**

#### SHARED INTERNAL HEALTH SERVER

New `apps/api/src/webguard_api/health_server.py`: one `HealthServer` class, reusing the exact `ThreadingHTTPServer` + explicit `start()`/`stop()` daemon-thread idiom already used identically by `http_api.py::create_server`, `callback_server.py::CallbackHttpReceiver`, and `signing_service.py::SigningServiceServer`: the same pattern, not a new one. Used standalone by `worker`/`scheduler`/`callback-service`/`signing-service`; the main API keeps its existing in-band `/healthz`/`/health`/`/ready`, no new port. Hardcoded to bind `127.0.0.1` only: no host is ever configurable, anywhere in this module or its callers, since these listeners answer with no authentication at all (their bodies never carry anything worth protecting). Exactly two routes, `/healthz` and `/ready`; unknown paths get a fixed `404`, non-GET a fixed `405`. Response bodies are a closed, fixed shape (`{"status":"ok"}` or `{"status":"not_ready","reason":"<fixed_code>"}`) with `Content-Type: application/json`, `Cache-Control: no-store`, and an explicit `Content-Length`. Never a stack trace, hostname, DSN, port, database name, token, key ID, PIN, or absolute path. A liveness/readiness callback that raises unexpectedly is caught and reported as the fixed reason `health_check_failed`; its safe diagnostic metadata (P1-B1's own `exception_type`/`source_module`/`source_function`/`source_line`, never `str(exc)`/`repr(exc)`) goes only to the structured log, never into the HTTP response.

#### LIVENESS VS READINESS

Liveness answers "is this process's own loop/listener still functioning," independent of external dependency state where that's the correct question (worker/scheduler: is the loop still turning; callback/signing: is the listener still running). Readiness additionally requires the real dependency to be reachable. This distinction is enforced structurally, not just documented: `/healthz` never touches a Postgres pool at all for worker/scheduler/callback/signing.

#### WORKER

`ScanJobWorker._last_progress_monotonic`, touched at every `run_forever()` iteration (idle, processed, outage-backoff) and every `monitor_job()` heartbeat cycle: the second source is what keeps a long-running scan from ever looking stalled just because `run_forever()` hasn't returned from `run_once()` yet, proven with a real 0.4s simulated job against a real thread. `progress_stale_after_seconds = max(poll_seconds×6, 3.0, 7.0)`: the `7.0` (`DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS`) term was added after a real-outage re-measurement caught the original two-term formula (validated only against a fake, instant `DatabaseError`) understating the true worst-case gap. During a genuine outage, `run_once()`'s own first DB call is itself bound by the *ordinary* ~5s pool checkout timeout (which this batch deliberately never shortens), so the real gap between touches can approach 5s+poll_seconds, not poll_seconds alone. Re-verified against a real ~9s outage, sampled every second: `/healthz` stayed `200` throughout. Readiness = `progress_healthy()` AND a real `pool.check_connectivity(timeout_seconds=1.0)` call: the health-specific bound, not the ordinary 5s one (see POSTGRES HEALTH PROBE below).

#### SCHEDULER

Identical shape, adapted: `_last_progress_monotonic` touched once per `_run_forever()` iteration AND (a pre-commit correction) once per schedule `run_once()` actually reaches inside its own per-schedule loop, since a single `run_once()` call processing a large, legitimately slow batch (many due schedules, each materialization taking real time) was proven, with a real deterministic per-schedule delay, to otherwise go stale mid-batch. Never touched for a call that hasn't returned (`list_due_schedules()` itself, or one schedule's own hung DB call, still correctly reads as stale; no fake timer thread was used to paper over this). Same `7.0s` DB-outage floor and same real-outage re-verification, twice: once immediately after the fix (a real ~9s outage, sampled every second, all `200`), and again in the final pre-commit round against completely fresh disposable Postgres, where `/ready`'s `503` responses carried reason `scheduler_dependency_unavailable` (not `scheduler_progress_stalled`) on every one of 10 samples (median 1006.0ms, max 1072.4ms), proving the real dependency probe is genuinely reached, not short-circuited by a stale progress check.

#### CALLBACK

Liveness reflects `CallbackHttpReceiver.is_running` (`self._thread is not None and self._thread.is_alive()`, a boolean only, never the `Thread` object), a pre-commit correction from an earlier draft that only checked whether the *separate* health listener itself was answering, which would have reported healthy even with a crashed or never-started public listener. Readiness fails whenever liveness fails, then checks the SAME Postgres pool object callback persistence already uses (confirmed by tracing the actual code, not assumed) with its existing, unmodified `WEBGUARD_CALLBACK_SERVICE_DB_CHECKOUT_TIMEOUT_SECONDS` (0.25s default), deliberately never lengthened to the 1.0s health-specific bound used elsewhere. The public callback protocol listener gained zero new routes: proven both by unit-level route-inventory tests (`/healthz`/`/ready` through the public listener produce the byte-identical uniform `204` any other unknown-token path would) and by a real-subprocess integration test showing the identical response during a genuine outage. Production-wiring latency measured through the actual `webguard-api callback-service` subprocess: `/ready` during a real outage bounded at median 254.6ms/max 257.5ms, matching its 0.25s configuration, not the 1.0s or 5s bounds used elsewhere. **P1-12-R1 remains functionally OPEN**: this batch makes the sustained-outage loss observable (already true since P1-B1's `callback_observation_persistence_exhausted`); it does not solve it.

#### SIGNING

Liveness reflects `SigningServiceServer.is_running`, same pattern and same pre-commit correction as callback. Readiness reuses `SigningKeyRegistry.ensure_active_key_signable()` (the exact check the real `/v1/sign` path already runs before every signature), proven to trigger zero synthetic sign operations and to never expose `key_id` or key material in the health response body.

#### COMBINED SERVE

`create_server`/`build_handler` gained `additional_readiness_checks: Sequence[Callable[[], tuple[bool, str]]] = ()`, empty by default, proven byte-for-byte identical to pre-P1-B2 `/ready` behavior for a standalone API-only process. `_serve_command` composes, in fixed precedence: API dependency (`service.readiness()`, evaluated first, unconditionally) → worker progress → worker dependency → scheduler progress → scheduler dependency, each only reached if everything before it passed. Never `Thread.is_alive()` for worker/scheduler (explicitly reserved for callback/signing's simpler listener-lifecycle case only). The API's own `service.readiness_check` is reassigned (only when a real Postgres pool exists) to the same 1.0s health-specific bound, closing the gap where it would otherwise have kept blocking ~5s regardless of how fast the composed checks were. Proven: `/healthz` stays `200` even while `/ready` correctly fails on a stalled embedded worker: the core P1-4 claim, that "the HTTP server answering" can never mask a wedged embedded component.

#### POSTGRES HEALTH PROBE

`WebGuardPostgresPool.connection()`/`check_connectivity()` gained an optional, keyword-only `timeout_seconds: float | None = None`: `None` (the default, used by every pre-existing caller and every ordinary business/job/schedule DB operation) preserves the pool's own configured timeout exactly, passed straight through to `psycopg_pool.ConnectionPool.connection(timeout=...)`'s own existing per-call parameter, not a new mechanism. `DEFAULT_CONNECTION_TIMEOUT_SECONDS` (5.0) is untouched. New `WEBGUARD_HEALTH_DB_CHECKOUT_TIMEOUT_SECONDS` (default `1.0`, bounded `0.1..5.0`, validated) is passed only from the worker/scheduler/API(combined-serve) health-readiness closures, confirmed by grep: exactly three real call sites, all in `cli.py`'s health wiring, zero in any repository module. Callback deliberately keeps its own existing 0.25s configuration unchanged.

#### STRUCTURED TELEMETRY

Reuses P1-B1's `log_event`/`configure_structured_logging` directly: no second logging mechanism. Every internal `HealthServer`'s `/ready` transition is edge-triggered: proven that 5 consecutive failing probes during one continuous outage produce exactly one `readiness_failed`, and recovery-then-continued-healthy-probes produce exactly one `readiness_recovered`, never one event per probe. Each event carries only `service` + `reason_code` (plus safe exception metadata on the rare unexpected-failure path), verified to contain nothing else, including under a deliberately marked fake-secret-bearing exception message.

#### VERIFICATION EVIDENCE

- Backend unit: **1777/1777 pass**.
- Backend contract (fresh disposable Postgres): **59/59 pass**.
- Backend integration (fresh disposable Postgres + fresh pinned Juice Shop; includes P1-10/P1-11/P1-12 real-outage suites, the three P1-B2 health real-outage tests, production SSRF callback E2E, TrustScan, Scanner v1, signing service): **124/124 pass**.
- Scheduler real-outage final measurement (fresh disposable Postgres): `/healthz` 10/10 `200`, fast (0.4–2.1ms); `/ready` 10/10 `503` `scheduler_dependency_unavailable`, median 1006.0ms, max 1072.4ms; same process recovers to `200` after restart.
- Worker cross-check, same outage window: `/healthz` `200`, `/ready` `503` `worker_dependency_unavailable`, ~1.0s bounded.
- Callback production-wiring latency: `/ready` bounded ~0.25s during a real outage through the actual subprocess construction path; public protocol response byte-identical before/during/after.
- Concurrent readiness pressure (20 concurrent `/ready` during a real outage, worker and combined-serve): all complete, no traceback, no hang, process alive, `/healthz` still fast immediately after.
- Vite build: **PASS** (real `dist/` output). Vitest: **39/39 pass**, genuine canonical run. Playwright: **4/4 pass**.
- Secret scan / Ruff / dependency audit / Terraform / Trivy / `git diff --check`: all **PASS**.

#### REMAINING LIMITATIONS

1. No `route_name` template, no `request_id`↔`job_id` correlation bridge, unchanged carry-overs from P1-3.
2. Worker's `monitor_job()` heartbeat-`DatabaseError` path still doesn't feed the top-level `database_outage_detected`/`_recovered` event, unchanged, deliberate batch scoping.
3. LOCAL-DEVELOPMENT UX LIMITATION (P1-3): unchanged, non-security.
4. P1-12-R1 remains functionally open: health makes it observable, does not close it.
5. Four new loopback-only listening sockets (worker/scheduler/callback/signing, when run standalone): more surface even at zero-auth-zero-secret-body; a deliberate, reviewed trade-off, not an oversight.

### P1-1: Repository-level tenant isolation

**Remediation commit**: `fa94d7c` (*fix(tenancy): enforce repository-level tenant isolation*).

**STATUS: CLOSED.**

#### ORIGINAL WEAKNESS

Repository authorization was mostly tenant-aware already: most reads and writes carried an atomic `WHERE ... AND organization_id = %s` predicate. But several secondary-resource and mutation paths still depended on the caller (almost always `service.py`) having already validated tenant ownership, rather than the repository method enforcing it independently. That is a defense-in-depth gap, not evidence that an arbitrary client-supplied `organization_id` was ever trusted by the HTTP layer: nothing found here was reachable by sending a forged tenant ID over the wire. The risk was a missing second layer, not a broken first one.

Confirmed live, by direct code reading and real-Postgres reproduction, not assumed from the baseline audit's language alone:

- `revoke_session` took no ownership parameter at all. Any authenticated principal who obtained another principal's `session_id` could revoke that session.
- `authentication_contexts.get_metadata`/`revoke` and `authorization_comparison.get`/`revoke` fetched a record by ID first, then compared `organization_id` in Python. The one caller-facing HTTP endpoint using each pair (`revoke_authentication_context`, `revoke_authorization_comparison_plan`) did its own service-layer check before calling them, but the repository methods themselves had no independent backstop.
- `postgres_jobs.py`'s `get_scoped`, the primary tenant-facing job lookup used by nearly every job-reading endpoint, ran two separate unscoped queries and compared the result in Python rather than a single atomically-scoped query.
- `get_scan_permit_scoped` had the identical two-step shape.
- `job_permits`, `job_safety_receipts`, and `schedule_permits` carry no `organization_id` column of their own (they are pure ID-to-ID binding tables). `service.py`'s enrichment lookups (`_public`, `_schedule_public`, the job-result endpoint) called the fully unscoped versions of these lookups directly, relying only on already having fetched an org-scoped parent record first.
- `update_principal_role`/`set_principal_active` did call `get_principal_scoped` internally before mutating, so this one was never a bare service-layer-only check, but the `UPDATE` statement's own predicate didn't repeat `organization_id`. Correct only because `organization_id` is never mutated on `principals`, not because the write was self-scoped.

#### FIX

Every one of the above now enforces tenant ownership atomically inside the repository's own SQL predicate, in both backends (PostgreSQL and the SQLite/in-memory equivalents):

- `revoke_session(session_id, *, principal_id, now)`: `UPDATE browser_sessions SET revoked_at = %s WHERE session_id = %s AND principal_id = %s AND revoked_at IS NULL`. A wrong-principal call is a silent no-op, identical to revoking a session that never existed.
- New `get_metadata_scoped`/`revoke_scoped` (authentication contexts) and `get_scoped`/`revoke_scoped` (authorization comparison plans), each a single atomically-scoped query. `service.py`'s two HTTP-facing revoke endpoints now call these instead of the unscoped pair. The original unscoped `get_metadata`/`revoke`/`get`/`revoke` methods stay, used only internally (`create()`'s own post-insert fetch, `require_bound()`'s defense-in-depth mismatch check against an already-trusted reference), never by a caller-supplied ID from an HTTP request.
- `postgres_jobs.py::get_scoped` and `get_scan_permit_scoped` are now single atomically-scoped queries.
- New `get_job_permit_binding_scoped`, `get_schedule_permit_binding_scoped` (joining to `scan_jobs`/`job_scopes` and `scan_schedules`, the authoritative organization relations, since the binding tables themselves have no organization column). `service.py`'s enrichment paths now use these exclusively. The unscoped originals remain, used only by the worker's own idempotency/re-validation checks (`executor.py`) and the scheduler's own due-schedule loop (`scheduler.py`), both already operating on a job or schedule they hold through a system, not a customer, path.
- `get_job_safety_receipt` (unscoped) had no remaining caller anywhere once its one service-facing use moved to `get_job_safety_receipt_scoped`, and was removed outright, from both backends and the `JobRepository` protocol, rather than kept around for symmetry. Its five test callers were migrated to the scoped method.
- `update_principal_role`/`set_principal_active`: the `UPDATE` predicate now carries `organization_id` directly (`WHERE principal_id = %s AND organization_id = %s`) in both backends, so the mutation is self-scoped and doesn't rely on a separate preceding call or on `organization_id` staying immutable forever.

`organization_id_for_job(job_id)` was investigated as a possible sixth case (a bare `job_id` lookup returning tenant data) and an early pass in this batch misclassified it as dead code. It is not: it's wired into `ScanJobExecutor` as `organization_resolver` in both the production (`production_startup.py`) and CLI (`cli.py`) executor-construction paths, and determines whether report/audit/safety-receipt artifacts are written under a per-organization path or a flat one. It is called only by the worker on a job it is actively executing, never with a caller-supplied ID, and was left unchanged. The methodology gap that produced the original misclassification (grepping for `method_name(` rather than also checking for the method passed as a bare callback reference) was then used to re-check every other method in scope; nothing else was affected.

#### FINAL UNSCOPED-METHOD AUDIT

Every repository method that takes a bare resource ID without `organization_id`/`principal_id` in its own signature was classified into one of: system control-plane (lease-fenced worker/scheduler operations, or a demonstrated non-customer caller like the two permit-binding lookups above), token-capability (the callback token or an identity/reset token is itself the authorization), global identity (principal/organization self-lookups, called only with a server-derived ID), operator-only (the CLI's own `revoke_token`, run with direct database trust, not an `AuthContext`), or test-harness-only (a parallel, non-lease-fenced job-lifecycle API used by over thirty unit test files, never referenced by `service.py`). Zero methods remained classified as reachable from a customer/tenant-facing path without independent scoping.

#### CI

The real-Postgres tenant-isolation suite (`tests/integration/test_postgres_tenant_isolation_slice13.py`, extended from 7 to 14 test methods) and the session-repository suite (`tests/integration/test_postgres_sessions.py`) were never actually executed by CI before this batch: the `authorised-lab-integration` job never set `WEBGUARD_POSTGRES_TEST_DSN`, and `postgresql-integration` only ran `tests/contract` plus one explicitly named module. Both are now named explicitly in the `postgresql-integration` job's test step, which already carries the required environment variables.

A broader gap remains and is intentionally not fixed here: `postgresql-integration` still does not run several other real-Postgres/real-subprocess suites (`test_postgres_worker_outage_resilience.py`, `test_postgres_scheduler_outage_resilience.py`, `test_postgres_worker_crash_recovery.py`, `test_callback_service_outage_resilience.py`, and the production E2E family) in CI itself, though all of them pass locally (see VERIFICATION EVIDENCE below). That is a separate, larger CI-coverage question, not a P1-1 blocker.

#### VERIFICATION EVIDENCE

- Backend unit: **1777/1777 pass**.
- Backend contract (fresh disposable Postgres): **59/59 pass**.
- Tenant-isolation and session suites, real Postgres: **23/23 pass**, including new cross-tenant coverage for every fix above (reads and mutations, wrong-tenant always fails exactly like a nonexistent resource, never a distinguishable existence oracle, correct-tenant access still succeeds immediately afterward).
- P1-10 worker outage suite, real Postgres, dedicated disposable container: **14/14 pass**.
- P1-11 scheduler outage suite, same container, run serially after P1-10: **19/19 pass**.
- P1-12 callback outage suite, same container, run serially after P1-11: **7/7 pass**.
- Full backend integration (fresh disposable Postgres and Juice Shop, broad discovery): **132 discovered, 92 executed, 92 passed, 40 skipped, 0 failed, 0 errors**. The 40 skips are exactly the three outage suites above, gated on the disposable-container environment variables they don't have when run inside the broad discovery pass, not a broader gap; all three were separately run to completion above.
- Secret scan / Ruff `--select S` / dependency audit / `git diff --check`: all **PASS**.
- `.github/workflows/ci.yml`'s new lines parsed and confirmed with Ruby's `Psych` (a real YAML parser, not a visual read) to sit inside the correct job and inherit `WEBGUARD_RUN_INTEGRATION`/`WEBGUARD_POSTGRES_TEST_DSN`.

#### REMAINING LIMITATIONS

1. Callback registration cross-org behavior (`postgres_callback_service.py`) was confirmed correct by code reading (an existing, already-atomic `WHERE token_value = %s AND organization_id = %s` predicate); it did not get a new dedicated cross-tenant test in this batch, since it was not itself a fix.
2. The non-leased `claim_next`/`fail`/`finish_result`/`cancel_running` test-harness API family is real and heavily used, but undocumented at its own definition site as intentionally test-only; a future reader could mistake it for a live gap the way this batch's own audit initially did.
3. The broader CI-coverage gap named above (several real-Postgres/subprocess suites not merge-gating) remains open.

This closes P1-1 only. It does not close P1-2: nothing here is database-enforced. It remains application-selected SQL, now provably correct at every reachable entry point and continuously re-verified by CI going forward, exactly as it was before, just with the second layer P1-2 (row-level security) would add still not built.

## POST-AUDIT P1 FINDING

### P1-10: Worker terminal-state persistence can kill worker during sustained PostgreSQL outage

Discovered during Batch A's A1 remediation review, not part of the original 9 baseline P1 findings. Do not read this as having existed in, or been missed by, the original audit's P1 list; it is a distinct, later discovery, tracked under its own ID.

**Remediation commit**: `eddc7c8`, *fix(worker): survive transient postgres outages*.

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

Live-reproduced during Batch A's own A1 investigation: a real permit→job→worker flow, Postgres stopped mid-execution long enough to span both the original failure and the worker's own attempt to record it. Captured traceback: `psycopg_pool.PoolTimeout` → `DatabaseUnavailableError` escaping `PostgresJobRepository.fail_leased()` → `_terminal_update()`, uncaught by `run_once()`'s `except JobStoreError as store_error:` (wrong exception type: `DatabaseUnavailableError` is not a `JobStoreError`), propagating out of `run_forever()` entirely (`Exception in thread Thread-2 (run_forever):`). Job row confirmed stuck `state="running"`.

#### PRE-CLAIM OUTAGE REPRODUCTION

Before implementing anything, this batch's own dedicated investigation reproduced one additional case live: Postgres unavailable *before* `recover_expired_leases()`/`claim_next_leased()` even run, i.e. before any job is touched at all. Confirmed the identical exception-boundary gap exists there too, earlier than originally scoped, and confirmed a `webguard-api serve`-style `run_forever()` thread started while Postgres was already down never resumed processing even after Postgres came back: the same instance stayed dead until manually restarted. This was folded into P1-10's scope per instruction ("the same worker/job-store outage class"), not treated as a separate finding.

Six scenarios reproduced live in total against real, disposable Postgres containers (`docker stop`/`docker start`) before any code change: the pre-claim case, `run_forever()` dying on a startup-time outage, executor-raises-during-outage, executor-succeeds-but-`_finish_result()`-fails, cancellation-persistence-during-outage, and heartbeat/monitor-thread death (`>>> THREAD DIED: webguard-lease-XXXX: DatabaseUnavailableError`, previously an unexplained artifact in Batch A's own logs, now attributed precisely).

#### ROOT CAUSE

`DatabaseError` (raised by `WebGuardPostgresPool`'s own 5-second connection-checkout timeout when Postgres is unreachable) is a `RuntimeError` subclass, structurally unrelated to `JobStoreError` (a `ValueError` subclass): every exception handler in `worker.py` that catches `JobStoreError` (or, worse, nothing at all) therefore let a raw `DatabaseError` escape uncaught at four independent sites: terminal-state persistence (`_finish_result`/`_fail`/`_cancel`), the heartbeat/cancellation-check loop, and the pre-claim calls at the top of `run_once()`. Worst case: `_fail()` itself needing Postgres to record a failure that Postgres-unavailability *caused* turned one outage into a dead worker thread trying to report itself.

#### DEPLOYMENT-MODE IMPACT

Confirmed by direct code read (`cli.py`): in `webguard-api serve` (combined API+worker+scheduler), `run_forever` ran on its own thread: only that thread died, silently, with no restart trigger; the process looked healthy throughout. In standalone `webguard-api worker` mode, `run_forever` runs on the **main thread** with no enclosing handler for `DatabaseError` anywhere up to `main()`: the whole process crashed (self-healing only if a supervisor restarted it).

#### IMPLEMENTATION

Three independent resilience additions to `apps/api/src/webguard_api/worker.py`, no other production file changed, no lease/CAS/`SKIP LOCKED` SQL touched:

1. **Terminal-state persistence** (`_finish_result`/`_fail`/`_cancel`, via a new shared `_persist_terminal_state` helper): bounded retry on `DatabaseError` only: a semantic `JobStoreError` (`job_lease_lost` and friends) still fails immediately, unchanged. On exhaustion, returns `False` rather than raising or recursing into another terminal-write attempt: the job is left exactly where it durably already is.
2. **`monitor_job()` heartbeat/cancellation loop**: `DatabaseError` no longer ends the thread: it skips that cycle with a short backoff (`heartbeat_retry_backoff_seconds`) and keeps monitoring on schedule. Genuine `JobStoreError` (lease actually lost) is unchanged.
3. **`run_forever()`'s own loop boundary**: catches `DatabaseError` specifically (never a blanket `Exception`) around `run_once()`, backs off via `stop_event.wait(poll_seconds)` (so shutdown is never delayed), and lets the next iteration retry naturally: this is what makes the pre-claim case survivable without needing a separate retry-of-retries inside `run_once()` itself.

#### TERMINAL RETRY POLICY

`DEFAULT_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS = 3`, `DEFAULT_TERMINAL_PERSISTENCE_RETRY_BACKOFF_SECONDS = 1.0`, `DEFAULT_HEARTBEAT_RETRY_BACKOFF_SECONDS = 1.0`: all three constructor-overridable (matching the existing `lease_seconds`/`heartbeat_seconds`/`poll_seconds` pattern), plus an injectable `sleep` callable for fast, deterministic unit testing.

**Accurate invariant** (corrected from an earlier draft of this document, which incorrectly claimed the retry budget "always sits comfortably inside the lease": it does not, and the design does not depend on that being true):

- Terminal-persistence retries are bounded (a small, fixed attempt count and backoff, never unbounded, never a busy-loop).
- Retries never weaken lease-token/revision CAS ownership checks: `_terminal_update()` is byte-for-byte unchanged.
- Terminal persistence can begin late in an already-running lease interval, and each retry attempt can itself take up to the connection pool's own 5-second checkout timeout. Under a sufficiently long outage, **the lease genuinely can expire while a retry sequence is still in progress.** The retry budget is not sized to prevent this; it is not meant to.
- If another worker reclaims the job before this worker's retry sequence finishes, the original worker's eventual terminal write is rejected by the existing, unmodified lease/state/revision protections (`job_lease_lost`, or `job_state_transition_invalid` if the job already reached a terminal state by then).
- **Therefore correctness is preserved even when retry duration overlaps lease expiry**: the CAS is what guarantees safety, not the retry budget's relationship to `lease_seconds`.
- The cost of that overlap is a possible duplicate execution, never a corrupted or double-persisted result: at most one terminal write can ever survive (see DUPLICATE-EXECUTION LIMITATION).

`run_forever()`'s own outage backoff is a separate, deliberately unbounded-in-duration policy (retries for as long as `stop_event` isn't set, correct behavior for "wait out an outage of unknown length"), bounded only in rate (never busy-loops).

#### RUN_FOREVER RESILIENCE

See IMPLEMENTATION item 3. Live-proven: the same `run_forever()` instance (no restart) survives a startup-time outage and automatically resumes processing once Postgres returns.

#### HEARTBEAT RESILIENCE

See IMPLEMENTATION item 2. Live-proven: a transient renewal failure no longer ends the monitor thread; the main worker loop is unaffected regardless.

#### FAIL PATH

Live-proven: executor raises while Postgres is down → `_fail()`'s retries exhaust → `run_once()` returns normally (no raise) → job left `RUNNING`, `error_code` empty (never falsely marked failed).

#### FINISH PATH

Live-proven: executor succeeds, Postgres down during `_finish_result()` → retries exhaust → job left `RUNNING`, `result_status` empty, never falsely reported completed, never routed into `_fail()`.

#### CANCEL PATH

Live-proven (real outage, not code-only): cancellation requested, Postgres down during `_cancel()` → worker survives → job left `RUNNING`: CANCELLED is never fabricated if it was never durably persisted.

#### RECOVERY MODEL

No new recovery mechanism: an abandoned attempt is left `RUNNING` with its already-durable lease, reclaimed by the existing, already-proven `recover_expired_leases()` (Batch A2) once that lease naturally expires (or, per TERMINAL RETRY POLICY above, once it expires mid-retry). Live-proven this batch: abandonment → `recover_expired_leases()` requeues → a second worker reclaims → exactly one winner (10-thread race) → the original, now-stale worker's own later completion attempt is rejected by the unchanged CAS.

#### LEASE/CAS SAFETY

Unmodified. `FOR UPDATE SKIP LOCKED`, lease-token/revision CAS, and `_terminal_update()`'s state/lease checks are byte-for-byte unchanged: confirmed by diff (only `worker.py` changed) and by re-running Batch A2's full crash-recovery suite unmodified (9/9 pass).

#### DUPLICATE-EXECUTION LIMITATION

Live-proven contained, not eliminated: if a heartbeat outage lets a lease lapse mid-execution, a second worker can genuinely re-execute the same job concurrently with the first. The CAS guarantees only one terminal result ever persists; the tenant-scoped finding upsert leaves exactly one row even if both workers recorded the identical finding. The cost is wasted duplicate scanning work, not incorrect persisted state.

#### TEST EVIDENCE

- `tests/unit/test_worker_outage_resilience.py` (new, 10 tests, fast/deterministic via a real SQLite-backed store with specific methods monkeypatched and an injected fake `sleep`): exact bounded retry count, configured backoff duration honored, no retry on semantic `JobStoreError`, no recursive failure-persistence, success-path exhaustion never falls back to `_fail()`, `run_forever()` survives and keeps retrying past repeated pre-claim failures, backoff is not a busy-loop, `stop_event` remains responsive during the outage backoff, monitor thread survives a transient renewal failure. Reverting the fix (`git stash`) makes all 10 fail.
- `tests/integration/test_postgres_worker_outage_resilience.py` (new, 12 tests, real Postgres, real `docker stop`/`start`): every required scenario A–P, including the pre-claim case, same-instance startup-outage recovery without restart, executor-raises/finish-result/cancellation persistence during real outages, heartbeat survival, recovery-within-budget, lease-expiry reclaim after abandonment, multi-worker-one-winner, stale-worker rejection, duplicate-execution/finding-dedup intact, and a later unrelated job processing normally once Postgres returns. 12/12 pass, confirmed on two independently fresh containers.

#### REMAINING LIMITATIONS

1. A long DB outage during execution may allow the lease to lapse and a second worker to perform duplicate scanning work.
2. Existing CAS/state/revision checks guarantee at most one valid persisted terminal result.
3. Finding dedup protects identical persisted findings where applicable.
4. The heartbeat does not currently propagate a proactive "lease uncertain" signal to the executing scanner (deliberate: the existing CAS already protects correctness at the final write regardless; adding this would be the "major executor-cancellation redesign" the remediation instructions explicitly said not to attempt in this batch).
5. `--once` mode may still expose a raw DB-unavailability traceback during pre-claim failure (a one-shot invocation legitimately should report the failure rather than retry forever; it is just not yet wrapped in this codebase's coded-error convention).
6. Structured logging and service health/readiness remain absent pending P1-B: an operator still cannot *observe* that a worker absorbed an outage, only that it no longer dies from one.

#### STATUS: CLOSED

POST-AUDIT OPEN P1 count for P1-10 is now **0**. History above is preserved, not erased.

---

### P1-11: Scheduler run_forever() can be killed by a transient PostgreSQL outage

Discovered while auditing runtime resilience after P1-10 closed: P1-10 was explicitly scoped to `worker.py` only, and `scheduler.py`'s `ScanScheduleCoordinator.run_forever()` turned out to have the identical, unfixed class of defect. Not part of the original 9 baseline P1 findings.

**Remediation commit**: `41ea1b5`, *fix(scheduler): survive transient postgres outages*.

#### ORIGINAL DISCOVERY

```
run_forever() → run_once() → list_due_schedules() / enqueue_due_schedule()
  → PostgreSQL unavailable
  → DatabaseError raised
  → run_forever() has no exception handling at all
  → loop terminates permanently
```

Confirmed by direct code read: `run_forever()` was `while not stop_event.is_set(): self.run_once(); stop_event.wait(self.poll_seconds)`: zero exception handling, structurally identical to `worker.py`'s pre-P1-10 `run_forever()`.

#### ROOT CAUSE

Same taxonomy mismatch as P1-10: `DatabaseError` (`RuntimeError` subclass) is structurally unrelated to `JobStoreError` (`ValueError` subclass). `run_once()` never wrapped its calls to `list_due_schedules()`/`enqueue_due_schedule()` in anything that would catch `DatabaseError`, so it always propagated straight out of `run_forever()`.

#### STANDALONE IMPACT

`_scheduler_command()` (`cli.py`) calls `scheduler.run_forever(stop_event)` directly on the main thread, no enclosing handler. Live-reproduced: a real subprocess launched against an already-stopped Postgres exited with code 1 and a full `DatabaseUnavailableError` traceback on stderr. Needs an external supervisor to recover.

#### SERVE-MODE IMPACT

`_serve_command()` runs the scheduler on a `daemon=True` background thread (`threading.Thread(target=scheduler.run_forever, ...)`). Live-reproduced: an uncaught `DatabaseError` killed only that thread (Python's default `threading.excepthook` logged it and the thread ended); the HTTP API and worker thread kept running normally, but recurring schedule materialization silently stopped forever with no operator-visible symptom beyond one stderr traceback.

#### STARTUP-OUTAGE REPRODUCTION

Live test: started `run_forever()` on a background thread against an already-stopped Postgres. Pre-fix, the thread died on its first iteration and never resumed even after Postgres came back: the same instance stayed dead until manually restarted, exactly mirroring P1-10's own pre-claim-outage finding for the worker. Post-fix, the same thread survives the outage and resumes on its own, materializing a real, previously-seeded, fully TrustScan-permit-validated due occurrence with no restart of any kind.

#### ATOMICITY ANALYSIS

This mattered more here than it did for the worker: `enqueue_due_schedule()` performs a row lock, several validation reads, a `scan_jobs` INSERT, a `job_permits` INSERT, and a `scan_schedules` UPDATE (revision CAS): all inside one `with self._pool.connection() as connection:` block with **no explicit `.transaction()` wrapper**. Whether that block alone provides atomic commit-or-rollback was not assumed; it was checked against `psycopg_pool.ConnectionPool.connection()`'s own source (it wraps the borrowed connection in `with conn:`, `psycopg.Connection`'s own context manager, which commits on clean exit and rolls back on any exception) and confirmed this codebase never sets `autocommit=True` anywhere, so every call to `enqueue_due_schedule()` runs inside one implicit transaction by default.

#### FAULT-INJECTION PROOF

Empirically verified against real, disposable PostgreSQL with two live fault injections on a fully-seeded schedule (real organization/principal/authorization/permit/binding), re-run on completely fresh infrastructure immediately before this commit:

- **Fault A**: connection failure injected immediately before the `scan_schedules` UPDATE, after the `scan_jobs`/`job_permits` INSERTs had already run: `scan_jobs` count, `job_permits` count, `scan_schedules.revision`, and `scan_schedules.next_run_at` all confirmed **unchanged** afterward.
- **Fault B**: connection failure injected immediately after the `scan_schedules` UPDATE succeeded, before the connection block's implicit commit: all four of the same values confirmed **unchanged** afterward.

Both fault points roll back completely: no orphan job can exist without a matching schedule advance, and no schedule can advance without its job, in either direction.

#### IMPLEMENTATION

One file changed: `apps/api/src/webguard_api/scheduler.py`. `run_forever()` now wraps `self.run_once()` in `try/except DatabaseError`, backing off via the existing `stop_event.wait(self.poll_seconds)` and continuing the loop. No changes to `run_once()`, `enqueue_due_schedule()`, or any repository SQL. Deliberately not a copy of `worker.py`'s pattern: no nested bounded-retry-with-backoff helper (unlike `worker.py`'s `_persist_terminal_state`), because the proven atomicity above means a failed attempt has nothing partially written to retry-in-place: the outer poll loop re-driving the whole batch on the next cycle is sufficient. Only `DatabaseError` is caught; `JobStoreError` and any unexpected exception still propagate and end the loop (verified live).

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
- Backend integration including Juice Shop (`tests/integration`): **111/111 pass**: covers the new P1-11 scheduler outage suite (17/17), the existing P1-10 worker outage suite, the A2 worker crash/lease-recovery suite (`test_postgres_worker_crash_recovery.py`), the production SSRF callback E2E suite (`test_production_ssrf_callback_e2e.py`), the TrustScan permit-service lab, the signing-service E2E suite, and the full set of Scanner v1 lab tests (crawler, TLS analyzer, safe-HTTP, crawl-scan, professional-report, IDOR/Juice-Shop-authenticated-discovery).
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

1. The standalone-process test drives `ScanScheduleCoordinator.run_forever()` directly rather than the full `webguard-api scheduler` CLI entrypoint with production secrets/signing-service bootstrap. This is sound because `_scheduler_command()`'s only logic around `run_forever()` is "call it directly, no try/except," which the test reproduces exactly; the argparse/bootstrap layer is untouched by this fix.
2. Combined `serve`-mode thread isolation was validated by reproducing `cli.py`'s exact `daemon=True, target=run_forever` thread construction, not by running a full `serve` process with a live HTTP server. This is a deliberate generalization from directly-tested Python threading semantics (an uncaught exception on one thread cannot propagate to another thread or the process), not an unverified assumption.
3. Backoff reuses `poll_seconds` rather than a distinct outage constant, matching `worker.py`'s own choice: a very short `poll_seconds` configuration retries an outage just as fast as it polls normally; not a new risk, since that is also true of every other iteration already.
4. Structured logging and service health/readiness remain absent pending P1-B: an operator still cannot *observe* that the scheduler absorbed an outage, only that it no longer dies from one.

#### STATUS: CLOSED

POST-AUDIT OPEN P1 count for P1-11 is now **0**.

---

### P1-12: Callback observation loss and response-oracle during PostgreSQL outage

Discovered during the P1-11 investigation phase, as a narrow, separate question about the callback-service HTTP receiver's own outage behavior. Not part of the original 9 baseline P1 findings.

**OPEN FINDING COMMIT**: `09ce0f4`, *audit: record P1-12 callback outage finding*.
**REMEDIATION COMMIT**: `b5d3bb9`, *fix(callback): harden postgres outage handling and evidence timing*.
**STATUS**: **PARTIAL**. The response-oracle break, the connection-reset behavior, the brief-outage observation loss, and the persistence-latency confidence demotion are all closed. A sustained-outage observation-loss residual remains open, tracked below as P1-12-R1. Not deferred to a new finding ID (no P1-13): it is the known, expected remainder of P1-12 itself.

#### ROOT BEHAVIOR (proven live, real `webguard-api callback-service` subprocess + real disposable PostgreSQL)

```
callback HTTP request
  → CallbackHttpReceiver._handle()
  → record_observation()
  → PostgreSQL unavailable
  → DatabaseError escapes handler (no try/except anywhere in the call chain)
  → request thread terminates
  → connection closes without any HTTP response
  → observation is not persisted
```

`CallbackHttpReceiver._handle()` (`callback_server.py`) calls `repository.record_observation(...)` with no exception handling. `PostgresCallbackRegistrationRepository.record_observation()` (`postgres_callback_service.py`) can raise `DatabaseError` from its own unwrapped `with self._pool.connection()` read. The uncaught exception propagates into Python's default `socketserver`/`http.server` error handling, which logs and drops the connection before any status line is sent.

#### SECURITY/RELIABILITY CONSEQUENCES

1. A PostgreSQL outage becomes externally distinguishable from every other callback outcome: the client sees `RemoteDisconnected` (connection reset, no response) instead of the uniform `204 No Content` every other outcome produces.
2. This breaks the module's own documented uniform-response invariant ("a throttled caller must not be able to distinguish 'throttled' from 'recorded' from the response alone").
3. A genuine SSRF callback arriving during the outage window is silently lost: `record_observation()` never durably records it, and nothing retries.
4. The worker/detector can later see no observation even though the target actually made the callback.
5. This can cause an infrastructure-timing-dependent missed SSRF confirmation (a false negative on a real finding), with no operator-visible symptom.
6. The default `http.server` traceback (internal file paths, SQL structure, client address) reaches stderr on every DB-outage-triggered request.
7. No raw callback token value was observed in stderr in the live reproduction: the leak is internal-structure disclosure, not a secret leak.

Scoped honestly: because the failing read happens before any token-validity check, every token (valid, invalid, or expired) gets the identical connection-reset during an outage, so this leaks "the database is currently down" (an infrastructure fact), not any per-token correlation state. The narrower anti-oracle property (can a caller tell if *this specific* token was recorded) is not broken by this; the broader "always identical response, period" property is.

#### CLASSIFICATION

**POST-AUDIT P1.** Justified by the combination of (a) a demonstrated, reproducible break of a security-motivated design invariant, and (b) a silent, security-relevant functional-correctness gap (consequence 3-5 above) with no operator-visible signal, not merely a hardening nice-to-have.

#### COMPONENT STATUS

- RESPONSE ORACLE: **CLOSED**
- EXPECTED DATABASEERROR CONNECTION RESET: **CLOSED**
- BRIEF-OUTAGE CALLBACK LOSS: **CLOSED**
- PERSISTENCE-LATENCY CONFIDENCE DEMOTION: **CLOSED**
- CLOCK-SKEW MODEL: **CHARACTERIZED, NO APPLICATION-LEVEL TOLERANCE**
- P1-12-R1 SUSTAINED-OUTAGE CALLBACK LOSS: **OPEN**
- FALSE NOT_VULNERABLE AFTER LOST SUSTAINED-OUTAGE CALLBACK: **OPEN**
- **P1-12 OVERALL: PARTIAL**

#### RETRY DESIGN

- Callback-service connection checkout timeout: **0.25 seconds** default (`WEBGUARD_CALLBACK_SERVICE_DB_CHECKOUT_TIMEOUT_SECONDS`, scoped only to `webguard-api callback-service`'s own pool construction in `cli.py`).
- Maximum persistence attempts: **2** (`DEFAULT_RECORD_OBSERVATION_MAXIMUM_ATTEMPTS`, `callback_server.py`).
- Retry backoff: **0.1 seconds** (`DEFAULT_RECORD_OBSERVATION_RETRY_BACKOFF_SECONDS`).
- Approximate maximum DB-wait/backoff budget per request: **~0.6 seconds** (2 × 0.25s checkout + 1 × 0.1s backoff).
- Generic PostgreSQL connection-checkout timeout (`WebGuardPostgresPool`'s `DEFAULT_CONNECTION_TIMEOUT_SECONDS`): **unchanged**, still 5.0s, for every other caller (API, worker, scheduler).
- Retry owner: `CallbackHttpReceiver`'s own ingestion layer (`_record_observation_with_bounded_retry` in `callback_server.py`): not the generic repository, not a new service layer. Call-site audit found exactly one real production HTTP-ingestion call site (`_handle()` → the repository directly, no intermediate broker/service in that path), so the repository and the worker-side broker pass-through remain untouched and unretried, as does the contract-test suite that deliberately exercises the repository's raw behavior.
- Retry condition: `DatabaseError` only. A semantic outcome (invalid/expired/revoked/rate-limited token) is `record_observation()` legitimately returning `False`, never raising, never retried, regardless.
- `observed_at`: captured exactly once, in `_handle()`, at the moment the HTTP request arrives, before any persistence attempt; the identical value is reused, unchanged, across every retry attempt inside the helper.

#### TIME MODEL

- **Monotonic time** (`time.monotonic()`): sole authority for polling, waiting, and timeout termination in `wait_for_observation()`'s loop, untouched by this change, immune to wall-clock adjustment.
- **UTC wall time**: the worker's evidence-window anchor. Captured once (`wait_started_at_utc = datetime.now(timezone.utc)`) at the same instant as the monotonic baseline, then used to derive `primary_evidence_deadline_utc`/`grace_evidence_deadline_utc`.
- **Callback `observed_at`**: the evidence-arrival timestamp, written once by the callback-service process at HTTP receipt. Drives CONFIRMED/PROBABLE classification: compared against the UTC evidence deadlines above, never against monotonic time.
- **Database persistence time is NOT evidence time.** **Poll-discovery time is NOT evidence time.** Both were the previous (pre-P1-12) implicit behavior; both are now explicitly excluded from the classification comparison.
- **No application-level clock-skew tolerance exists.** The comparison is a bare inclusive `<=`/exclusive `>`, no epsilon.
- **Infrastructure assumption**: the worker host and the callback-service host maintain reasonably synchronized UTC clocks, the same assumption this codebase already makes for TrustScan permit validity windows (`not_before <= now < expires_at`, checked across the process that issued a permit and whatever process later validates it). No Terraform-provisioned compute exists yet to point to a specific SLA, but the existing networking/IAM/Postgres Terraform is AWS-oriented, and mainstream AWS compute (EC2/ECS/Fargate) synchronizes via Amazon Time Sync Service by default, typically to single-digit milliseconds.
- Near a timing boundary, host clock skew **may** change CONFIRMED ↔ PROBABLE. It does **not** fabricate a callback, remove a persisted callback, or change callback correlation (token/tenant scoping is entirely unrelated to this comparison).

**Characterization proof** (`ClockSkewBoundaryCharacterizationTests`, `tests/unit/test_postgres_callback_broker.py`, 6/6 pass):
- True arrival 50ms before the primary boundary, +100ms callback-service clock skew → stored `observed_at` reads past the boundary → **PROBABLE**.
- True arrival 50ms after the primary boundary, −100ms skew → stored `observed_at` reads before the boundary → **CONFIRMED**.
- True arrival comfortably inside primary (window midpoint), ±500ms skew → **CONFIRMED** both directions.
- True arrival comfortably inside grace (band midpoint), ±500ms skew → **PROBABLE** both directions.
- `observed_at` exactly on the primary deadline → **CONFIRMED** (inclusive).
- `observed_at` exactly on the grace deadline → **PROBABLE**, not dropped (inclusive).

±500ms is demonstrated safe only at these specific, boundary-distant points, not claimed as a general tolerance; the first two cases are the deliberate near-boundary counter-examples showing the opposite.

---

### P1-12-R1: Sustained-outage callback evidence loss

**Proven sequence** (real production architecture: worker → SSRF detector → real TLS fixture → real callback receiver → real PostgreSQL, fault-injected at the exact `INSERT INTO callback_observations` statement for the whole run):

```
real target callback
  → callback-service receives request
  → observed_at captured
  → PostgreSQL persistence unavailable longer than the bounded retry budget
  → external callback response remains uniform (204, unchanged)
  → no observation fabricated
  → no observation durably persisted
  → worker-side DB reads remain healthy (only the write path was faulted)
  → worker finds no callback row (a clean, error-free empty poll result)
  → no CallbackBrokerError/DatabaseError occurs on the worker's own read path
  → the existing INCONCLUSIVE safety path is never entered
  → SsrfDetectionOutcome.NOT_VULNERABLE is returned
```

Verified two ways: (1) end-to-end, `test_no_fabricated_confirmation_when_persistence_never_recovers` in `tests/integration/test_production_ssrf_callback_e2e.py`: no fabricated CONFIRMED/PROBABLE finding, zero observation rows for the run; (2) directly, by reproducing `ssrf_callback_detector.py`'s own decision branch with the exact tuple `wait_for_observation()` returns in this scenario (`None, False, False`): confirmed programmatically to resolve to `SsrfDetectionOutcome.NOT_VULNERABLE`, not `INCONCLUSIVE`.

**Classification: KNOWN FALSE-NEGATIVE RESIDUAL.** Not hidden, not minimized: a target that is genuinely vulnerable and genuinely calls back during a sustained outage can be scored NOT_VULNERABLE, indistinguishable at the API level from an actually-safe target.

#### WHY P1-12-R1 REMAINS OPEN

PostgreSQL is currently the sole durable callback-observation store. This remediation deliberately does **not** introduce a second one (no Redis, no SQS, no Kafka, no local-disk WAL, no other database, no authoritative volatile in-memory queue) because secondary callback durability is an architecture decision, not something to smuggle in as a side effect of an outage-hardening fix.

Increasing synchronous retries further is not a sufficient substitute, and was deliberately not done:
- It blocks `ThreadingHTTPServer` request threads for longer, increasing resource-exhaustion risk under a real outage combined with real traffic.
- It directly competes with, and can exceed, the SSRF detector's own 3s/5s observation window: a longer retry budget does not just risk lateness, it risks actively causing the CONFIRMED→PROBABLE (or worse) demotion this same remediation just closed for the brief-outage case.
- No synchronous retry budget, however large, can guarantee survival through an outage of arbitrary duration: only a durable secondary store (an explicit architecture decision, out of scope here) or observability into the gap (P1-B) can change that.

#### FINAL VERIFICATION EVIDENCE

- Backend unit: **1642/1642**.
- Backend contract (real PostgreSQL): **59/59**.
- Backend integration + Juice Shop: **117/117**.
- Callback classification test file (`test_postgres_callback_broker.py`, includes clock-skew characterization): **25/25**.
- Vitest, genuine current-tree run: **39/39**.
- Playwright: **4/4**.
- Security gates (secret scan, Ruff `--select S`, dependency audit): **PASS**.
- Terraform (`fmt -check`, `init -backend=false`, `validate`): **PASS**.
- Trivy IaC (`infra/`, CRITICAL/HIGH): **0 misconfigurations**.
- `git diff --check`: **clean**.

Production SSRF evidence preserved from this remediation's E2E proofs:
- Brief persistence failure (one forced connection error, resolves on retry) → observation recovered, original `observed_at` retained → **CONFIRMED CWE-918**.
- Sustained persistence failure (every attempt fails for the whole run) → no fabricated observation, zero observation rows → **NOT_VULNERABLE residual confirmed** (P1-12-R1, above).

## CURRENT P1 ACCOUNTING

- BASELINE P1 AT AUDIT: 9 (P1-1 through P1-9: immutable historical count, never altered)
- CLOSED BASELINE P1: P1-1, P1-3, P1-4, P1-5, P1-6, P1-7 (see BASELINE P1 FINDINGS above)
- CURRENT OPEN BASELINE P1: 3 (P1-2, P1-8, P1-9)
- CLOSED POST-AUDIT: P1-10, P1-11
- PARTIAL / OPEN POST-AUDIT: P1-12 (P1-12-R1 sustained-outage residual open within it, not a separate finding ID; operationally observable via `callback_observation_persistence_exhausted` and, since P1-B2, via `readiness_failed`, not functionally solved)
- CURRENT OPEN P1 TOTAL: 4

P1-2's own runtime-conversion half (Phase H: every ordinary PostgreSQL repository caller scoped to a restricted role before query) is complete as of PR #47 (`docs/PROJECT_EXECUTION_LEDGER.md`), proven against a real disposable Postgres. P1-2 stays open because RLS itself is not yet `FORCE`-enabled in any real, non-disposable environment; that activation is explicitly out of scope pending real infrastructure access.
