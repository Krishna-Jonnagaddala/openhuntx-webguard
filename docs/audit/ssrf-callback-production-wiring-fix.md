# SSRF-Callback Production Wiring Fix

A note on scope, stated up front: this document was requested with
several references that do not exist in this repository -- a "Slice
18" audit doc, a pre-existing `docs/production/CALLBACK_SERVICE_DEPLOYMENT.md`,
and an already-built `webguard-api callback-service` CLI command.
`git log --all` shows no Slice 18 work anywhere in this repository's
history at the time of this fix; the most recent completed slice is
Slice 17 (`aa0774f`). This document covers exactly what it says in the
title -- a targeted production-wiring bug fix discovered while
reasoning about Slice 18-shaped work, not a full Slice 18. The CLI
command and the deployment doc referenced above did not exist before
this fix; they are built as part of it (see §3-4) because the fix
cannot be deployed or proven end to end without them, not because a
broader Slice 18 was completed here.

## 1. The bug

`apps/api/src/webguard_api/production_startup.py` constructed
`PostgresCallbackRegistrationRepository(pool)` (Slice 12's durable
callback-registration *metadata* store) and passed it directly as
`ScanJobExecutor(callback_repository=..., ...)`. `executor.py`'s
`_apply_ssrf_callback_detection` immediately does
`callback_policy=callback_repository.policy` -- and
`PostgresCallbackRegistrationRepository` has no `.policy` attribute
(it was never designed to be the live broker; see its own module
docstring before this fix, which explicitly named this exact wiring as
future work). This raised `AttributeError` before a single callback
token was ever registered.

Confirmed two ways: by reading `postgres_callback_service.py` against
`executor.py`'s actual usage, and by a live Python REPL call against a
real Postgres instance showing `PostgresCallbackRegistrationRepository`
genuinely has no `.policy` and no `wait_for_observation()`, and that
its `register()` returns a `ScopedCallbackRegistration` with no `.url`
field -- the very next thing `ssrf_callback_detector.py` needs
(`mutate(template, template.parameter, token.url)`) would also have
failed had execution reached that far.

**Practical impact**: any production-mode scan whose TrustScan permit
included `active.ssrf.callback` crashed with an uncaught
`AttributeError` inside `ScanJobExecutor.execute()`. `ScanJobWorker.run_once()`'s
blanket `except Exception:` (worker.py) caught it and marked the job
FAILED rather than crashing the worker process -- so the observable
symptom was "the scan job fails with a generic internal error," not a
worker crash, but SSRF detection functionally never succeeded in
production. Pre-existing since Slice 12/13; not introduced by this
investigation.

## 2. Why a thin fix (just adding `.policy`) was not enough

Even patching `.policy` onto the repository would not have worked,
because of a second, structural gap: `wait_for_observation()` needs a
real-time signal that a callback arrived, and the only implementation
that existed (`InMemoryCallbackBroker`'s in-process dict +
`threading.Event`-style polling) requires the registering process and
the observing process to be the same process. That stopped being true
the moment a callback receiver becomes an independently deployable
component (`webguard-api callback-service`, built as part of this fix
-- see §4): the worker process that registers a token and the process
that receives the target's actual outbound HTTP request share no
Python memory. Any fix had to also answer "how does the worker learn
about an observation recorded by a different OS process," not just
"where does `.policy` come from."

## 3. The fix

New module `apps/api/src/webguard_api/postgres_callback_broker.py`,
`PostgresCallbackBroker`: an adapter wrapping
`PostgresCallbackRegistrationRepository` for durable storage, adding
exactly the three things the durable repository cannot provide by
itself --

1. `.policy` (a `CallbackPolicy`, poll interval widened to 0.25s from
   the in-memory default's 0.05s; the 3s/2s confirmed-vs-probable
   timing window is unchanged, since that is a security-relevant
   classification threshold, not an implementation detail).
2. `register()` returning a genuine `CallbackToken` (not a
   `ScopedCallbackRegistration`) with a real `.url`, built from an
   explicit `base_url` -- `production_startup.py` builds this as
   `https://{callback_service_hostname}/`, finally consuming
   `ProductionServiceConfig.callback_service_hostname`, which had been
   validated since that config type was introduced but never read by
   any code path.
3. `wait_for_observation()` polling `callback_observations` in
   PostgreSQL directly, instead of an in-process dict -- the piece
   that makes cross-process correlation actually work.

`production_startup.py` now constructs this broker and passes it as
`ScanJobExecutor`'s `callback_repository`; `executor.py`'s type hints
(`_ScanScopedCallbackBroker`, `_apply_ssrf_callback_detection`,
`ScanJobExecutor.__init__`) were updated to a new
`repository_contracts.TenantScopedCallbackBroker` protocol rather than
the concrete in-memory `CallbackRepository` class, since a Postgres-
backed broker is not that class and should not be typed as if it were.

`PostgresCallbackRegistrationRepository.register()` also gained
per-organization `maximum_active_registrations` enforcement -- the one
policy control its own module docstring named as not reproduced from
the in-memory broker. Scoped per-organization (not process-wide, the
way the in-memory broker scopes it) so one noisy-neighbor tenant cannot
exhaust a shared production budget affecting every other organization.
This is a best-effort count-then-insert, not a hard
serialization-guaranteed cap; see the module's updated docstring for
why that trade-off was made.

Local/dev/lab behavior is completely unchanged: `ScanJobExecutor`'s
default `callback_repository` (an in-memory `CallbackRepository`) is
untouched, and every existing local/lab SSRF test
(`test_ssrf_callback_e2e_lab.py`, `test_ssrf_callback_detector_live.py`)
passes unmodified.

## 4. `webguard-api callback-service`

A new, production-only CLI subcommand (`cli.py`) that runs
`CallbackHttpReceiver` (Slice 10's real `ThreadingHTTPServer` receiver,
previously only ever constructed directly by tests) as a standalone
process against a `PostgresCallbackRegistrationRepository` built from
`ProductionServiceConfig.from_environment()`'s `database_url`. This is
the minimum needed to make the wiring fix actually deployable and
testable end to end as two real, separately-runnable processes --
deliberately not the full public callback endpoint
(`docs/production/INFRASTRUCTURE_REQUIREMENTS.md`'s own "do not build
a public callback service before deciding the DNS/TLS/abuse-control
model" instruction is respected, not overridden): binding defaults to
loopback, and no rate limiting, TLS, or public hostname is built here.
See `docs/production/CALLBACK_SERVICE_DEPLOYMENT.md` for the full
deployment model and the explicit list of what remains unbuilt.

## 5. Verification

- `tests/integration/test_production_ssrf_callback_e2e.py` (new): a
  real production-mode scan, against a real disposable PostgreSQL
  instance, with a permit authorizing `active.ssrf.callback`, targeting
  the same vulnerable fixture `test_ssrf_callback_e2e_lab.py` already
  uses. The callback receiver is a genuinely separate
  `PostgresCallbackRegistrationRepository` instance bound to its own
  `CallbackHttpReceiver` socket -- structurally identical to what
  `webguard-api callback-service` does as a separate OS process,
  sharing nothing with the executor except the same PostgreSQL
  database. Asserts a CWE-918 finding is produced for the vulnerable
  endpoint and none for the safe/reflect-only endpoints on the
  identical fixture; a second test asserts a passive-only permit
  produces no SSRF finding at all. Both pass.
- Existing suites re-run and confirmed unaffected: the full
  `tests/contract/test_callback_registration_repository_contract.py`
  (in-memory and Postgres backends), `tests/unit/test_callback_service.py`,
  `tests/unit/test_production_config.py`, `tests/integration/test_production_mode_e2e.py`,
  `tests/integration/test_production_runtime_completion_e2e.py`,
  `tests/integration/test_ssrf_callback_e2e_lab.py`,
  `tests/integration/test_ssrf_callback_detector_live.py`,
  `tests/unit/test_job_executor.py`,
  `tests/unit/test_job_executor_active_detection.py`, and
  `tests/unit/test_phase4_executor_authority.py` — all pass.
- Manual smoke test: `webguard-api callback-service` started against a
  real Postgres instance, accepted an inbound callback request (204),
  and shut down cleanly on SIGTERM.

## 6. Known gaps, stated plainly

- No public hostname, TLS, reverse proxy, WAF, or rate limiting for
  `callback-service` -- unchanged from before this fix, and
  deliberately not attempted (see §4 and the deployment doc's §5).
- No physical cleanup of long-expired, never-observed
  `callback_registrations` rows. `expires_at` still governs whether a
  token can be used, but nothing deletes old rows; storage growth is
  unbounded absent a future reaper job.
- `maximum_active_registrations` enforcement is best-effort (a small
  race window under a heavy concurrent-registration burst), not a hard
  guarantee -- acceptable for a soft abuse control, not acceptable if
  this budget is ever relied on as a hard security invariant.
- `PostgresCallbackBroker.wait_for_observation`'s poll interval (0.25s)
  was chosen by reasoning about acceptable database load, not measured
  against a real deployment's actual callback-service network latency
  -- worth revisiting once real production traffic exists.
