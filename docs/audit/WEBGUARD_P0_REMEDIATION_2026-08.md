# WebGuard P0 Remediation Closure Report, 2026-08

## BASELINE AUDIT COMMIT

`f138f2acb2a270a5cb8a20636aa8af5737a44dd5` (*audit: record full pre-remediation WebGuard system assessment*) ([WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md](WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md)).

This baseline is immutable and has not been amended, rewritten, or modified by this remediation pass. It remains the pre-remediation record of truth; this document is a separate, later closure record layered on top of it.

---

## P0-1: Production SSRF callback execution

**Original finding** (audit, P0 FINDINGS): *"SSRF-callback detector is non-functional in production. `ScanJobExecutor` is wired to `PostgresCallbackRegistrationRepository`, an interface incompatible with what the SSRF detector's live broker role requires."*

**Original reproduction** (recorded in the audit, pre-remediation): a real permit + job + worker through the real production object graph, real fixture target → `state: "failed"`, `error.code: "worker_internal_error"`.

**Root cause**: `production_startup.py` constructed the raw `PostgresCallbackRegistrationRepository` (a durable *metadata* store) and passed it directly as `ScanJobExecutor`'s `callback_repository`. `executor.py`'s `_apply_ssrf_callback_detection` immediately accessed `callback_repository.policy` (an attribute the repository never had), raising `AttributeError` before a single callback token was ever registered. Even a thin fix (adding `.policy`) would still have failed: `wait_for_observation()` needs a live cross-process signal, and the only prior implementation (`InMemoryCallbackBroker`) assumes the registering and observing processes share Python memory, which stops being true the moment the callback receiver is a genuinely separate deployable process.

**Remediation commit**: `a26b99a` (*fix(ssrf): restore cross-process production callback correlation*).

**Separate-process architecture**:
```
Worker  →  PostgresCallbackBroker.register()
              → durable INSERT into callback_registrations (Postgres)
              → real CallbackToken with .url built from callback_service_hostname
Worker embeds that URL in the mutated SSRF-probe request → sent to target
Target (if vulnerable) makes an outbound request to that callback URL
              ↓ (real network hop, no shared memory)
Standalone `webguard-api callback-service` process (separate OS process)
  └─ CallbackHttpReceiver → PostgresCallbackRegistrationRepository.record_observation()
       → durable INSERT into callback_observations (Postgres)
Worker's PostgresCallbackBroker.wait_for_observation()
  → polls callback_observations every 0.25s
  → observation found within 3s → CONFIRMED CWE-918
```
`PostgresCallbackBroker` (new module `postgres_callback_broker.py`) is the adapter providing exactly the three things the raw repository lacked: `.policy`, a real `.url`-bearing `CallbackToken`, and a Postgres-polling `wait_for_observation()`. Correlation between the two processes happens exclusively through PostgreSQL: no shared Python object, no `threading.Event`, no in-memory broker crosses the process boundary. Local/dev/lab behavior (the in-memory `CallbackRepository`) is untouched.

**Closure reproduction**: run against the actual committed HEAD (`d94b96c`), not a working-tree snapshot. `webguard-api callback-service` started as a genuinely separate OS process (PID 6138), confirmed listening. A second, separate Python process (PID 6395) built the real production component graph, substituted the broker's `base_url` to point at that separate process, and drove a real permit → job → worker → findings flow over real HTTP against a genuinely SSRF-vulnerable fixture:
```
job: state="completed", error=null
finding: check_id=active.ssrf.callback.confirmed, cwe_id=CWE-918, severity=high
evidence: "...Callback observed at 2026-08-31T08:26:56.835237+00:00 via GET. Outcome: confirmed."
```

**Test evidence**: `tests/integration/test_production_ssrf_callback_e2e.py` (2/2: CONFIRMED CWE-918 for the vulnerable endpoint, no finding for a passive-only permit); callback tenant-isolation contract, both backends (12/12); TrustScan regression (48/48); Scanner v1 detector regression (91/91, confirming `executor.py`'s diff is type-annotation widening only, no detector logic changed); full backend integration suite including Juice Shop (73/73).

**STATUS: CLOSED**

---

## P0-2: Production signing-service fail-closed boundary

**Original finding** (audit, P0 FINDINGS): *"`webguard-api signing-service` has no fail-closed environment gate and defaults to a hardcoded development signing key... `key_source=development`, using `LocalDevelopmentSigner(bytes(range(32)))`."*

**Original reproduction**: `WEBGUARD_ENVIRONMENT=production` + only the bearer token set → process started and listened, serving real signed responses under `key_id: sha256:56475aa7...`, independently confirmed to be the exact public-key hash of `LocalDevelopmentSigner(bytes(range(32)))`, the fixed, source-visible development key.

**Root cause**: `_signing_service_command` (`cli.py`) had no `--environment`/`WEBGUARD_ENVIRONMENT` concept at all, unlike `serve`/`worker`/`scheduler`. `--key-source` defaulted to `"development"` unconditionally, with no gate checking deployment context.

**Remediation commit**: `0114d56` (*fix(signing): fail closed on development keys in production*).

**Fail-closed proof**: `--environment production` (explicit flag or `$WEBGUARD_ENVIRONMENT`) now refuses to start unless `--key-source cloudhsm` was also explicitly selected, checked as the first statement in `_signing_service_command`, before the bearer-token check, before any provider construction, before any socket bind. Re-reproduced against the committed HEAD:
```
ERROR [signing_service_development_key_forbidden_in_production]: --environment production
requires --key-source cloudhsm; the signing service will not start with --key-source
"development" in production.
exit: 1
```
Confirmed via `curl` that no socket was bound afterward. CloudHSM provider-construction failures (missing config, unavailable PKCS#11 module) are also now caught and converted to a clean coded failure rather than an uncaught traceback.

**Test evidence**: `tests/unit/test_signing_service_cli_production_gate.py` (9/9: production+no-flag, production+explicit-development, production+malformed-CloudHSM-config, production+unavailable-CloudHSM-provider all FAIL; development+development, test/lab+development, non-production+cloudhsm all PASS); `test_signing_service_e2e.py` (1/1).

**STATUS: CLOSED**

---

## ADDITIONAL SIGNING DEFECT: disabled active key could still sign

Discovered during P0-2's remediation review, not present in the original audit's P0/P1/P2/P3 findings: a separate, narrower defect in the signing-key lifecycle model.

**Defect**: `SigningKeyRegistry.set_status()` only ever affected the separate `_verification_keys` map, never `_active` (the live signer). `verify_by_key_id()` correctly rejected a disabled key during verification, but `signing_service.py`'s `POST /v1/sign` handler called `registry.active.sign(message)` unconditionally, with no check on the active key's own status. An operator disabling the currently-active key mid-rotation, or in response to a suspected compromise, had no effect on new signing: the endpoint kept signing with it.

**Root cause**: no code path connected `set_status()`'s effect on the active key's own registry entry back to the one method (`registry.active.sign`) that actually performs signing.

**Remediation commit**: `d94b96c` (*fix(signing): prevent disabled active key from signing*). New `SigningKeyRegistry.ensure_active_key_signable()` checks the active key's own status and raises `SigningProviderError("trustscan_signing_key_disabled", ...)` (the same code `verify_by_key_id` already uses), called from `/v1/sign` immediately before `registry.active.sign()`.

**HTTP-level proof**: `tests/unit/test_cloudhsm_signing.py::test_disabled_active_key_cannot_sign_over_http`, against a real, bound `ThreadingHTTPServer`: sign successfully (200) → `registry.set_status(key_id, "disabled")` → `POST /v1/sign` with the identical payload → rejected (500, `error.code: trustscan_signing_key_disabled`).

**Confirmed key-status behavior matrix**:

| Status | Sign (`/v1/sign`) | Verify (`verify_by_key_id`) |
|---|---|---|
| ACTIVE | permitted | permitted |
| RETIRED | permitted (only `set_status` to `"disabled"` on the *active* key blocks signing; retiring a *former* active key after rotation is the normal, intended path and does not affect the *new* active key's ability to sign) | permitted (this is the whole point of rotation: a permit signed under a now-retired key keeps verifying until it naturally expires) |
| DISABLED | **rejected** (`trustscan_signing_key_disabled`), newly fixed | rejected (`trustscan_signing_key_disabled`), pre-existing, unchanged |
| unknown key ID | n/a (signing always uses the registry's own active key, never a caller-supplied ID) | rejected (`trustscan_signing_key_unknown`), pre-existing, unchanged |

**STATUS: CLOSED**

---

## FULL REGRESSION MATRIX

Run against the actual committed HEAD (`d94b96c`), fresh disposable Postgres and Juice Shop containers (none reused from any prior run), Docker daemon restarted for this pass. Backend integration and Playwright were run strictly serially, never concurrently, against the shared Postgres instance.

| # | Check | Result |
|---|---|---|
| 1 | Migrations from zero | **11/11 applied** |
| 2 | Backend unit | **1596/1596 pass** |
| 3 | Backend contract (real PostgreSQL) | **59/59 pass** |
| 4 | Backend integration incl. Juice Shop | **73/73 pass** |
| 5 | Production SSRF cross-process E2E | **CONFIRMED CWE-918**, two genuinely separate OS processes |
| 6 | Callback tenant-isolation tests | **12/12 pass** (in-memory + Postgres backends) |
| 7 | Signing-service production-gate tests | **9/9 pass** |
| 8 | Disabled-active-key HTTP test | **1/1 pass** |
| 9 | Signing-service E2E | **1/1 pass** |
| 10 | TrustScan regression | **48/48 pass** |
| 11 | Scanner v1 regression | **91/91 pass** (SSRF detector + IDOR + SQLi + secret-scanner + active-detector-registry + cross-detector-authorization suites) |
| 12 | Frontend typecheck | **exit 0** |
| 13 | Frontend build | **exit 0** |
| 14 | Frontend lint | **exit 0** (oxlint, pre-existing warnings only, no errors) |
| 15 | Vitest | **39/39 pass**, 7 files |
| 16 | Playwright | **4/4 pass** (run alone, after the backend integration suite completed) |
| 17 | Secret scan | **passed**: 472 files, 6 artifacts, 1017 blobs |
| 18 | Ruff security checks | **all checks passed** |
| 19 | Dependency audit | **passed**: 12 locked packages |
| 20 | Supply-chain verification | **passed** |
| 21 | Governance verification | **passed** |
| 22 | `terraform fmt -check -diff` | **exit 0** |
| 23 | `terraform init -backend=false` | **success** |
| 24 | `terraform validate` | **success** |
| 25 | Trivy IaC | **0 misconfigurations** |
| 26 | `git diff --check` | **exit 0** |

No failures, no flakes, no reruns needed this pass: every suite passed on its first, isolated attempt. (Contrast with the earlier uncommitted-tree gate check, where running the integration suite concurrently with Playwright against the same database produced one transient `authorization_not_found` failure that did not reproduce in isolation; this pass avoided that entirely by strict serialization, per instruction; see TEST-ENVIRONMENT WEAKNESS below.)

## CURRENT OPEN P0 COUNT

**0.** Both baseline P0 findings are CLOSED.

## BASELINE P1 COUNT

**9** (P1-1 through P1-9, unchanged from the original audit, none remediated in this pass, per "Do not start P1 remediation").

## BASELINE P2 COUNT

**9** (P2-1 through P2-9, unchanged).

## BASELINE P3 COUNT

**11** (unnumbered bullet items, unchanged).

---

## NEWLY DISCOVERED POST-AUDIT FINDINGS

Not present in the original audit's P0/P1/P2/P3 lists. Recorded here separately and explicitly **not** merged into the baseline counts above.

**Callback hardening observations** (discovered during P0-1's remediation review; none block the P0-1 closure above, all remain open):

- **PostgreSQL failure during `wait_for_observation()`'s poll loop may fail the entire scan job.** Traced end-to-end: `PostgresCallbackBroker._latest_observation()` has no `try/except DatabaseError` around its poll query (unlike `register()`, which does); `_ScanScopedCallbackBroker.wait_for_observation()` (executor.py) is a bare passthrough with no exception handling; `run_ssrf_callback_detector`'s call site has no try/except around `wait_for_observation()` either; `_apply_ssrf_callback_detection` only catches `ActiveDetectionError`, which a raw `DatabaseError` is not. A transient Postgres outage occurring *after* registration but *during* the poll window would propagate unhandled up to `worker.py`'s blanket `except Exception:`, failing the **entire job** with `worker_internal_error`: not gracefully degrading just the one SSRF candidate to `INCONCLUSIVE`, the way a registration-time outage already does.
- **`maximum_active_registrations` enforcement is best-effort, not hard-serialized.** A count-then-insert check inside one connection, not a database-level constraint: a burst of concurrent registrations from one organization could transiently exceed the configured limit. Acceptable for a soft abuse control, not for a hard security invariant.
- **No reaper for expired, never-observed `callback_registrations` rows.** `expires_at` governs whether a token can still be used, but nothing deletes old rows: unbounded storage growth over time absent a future cleanup job.
- **Callback poll interval (0.25s) was chosen by reasoning about acceptable database load, not measured against a real deployment's actual callback-service network latency.** Worth revisiting once real production traffic exists.

**Test-environment weakness** (tracked separately from production defects: this is a test-infrastructure property, not a product defect):

- Running the backend integration suite concurrently with Playwright's own backend fixture against the *same* shared disposable Postgres instance produced one transient cross-suite failure (`test_signing_service_e2e.py`, `authorization_not_found`) that did not reproduce across 3 immediate isolated re-runs, nor in this pass's fully serialized run. The two suites are safe to run serially but are not currently safe to run concurrently against a shared database. CI does not hit this because each of its jobs provisions its own separate Postgres container; only a local session sharing one disposable instance across both suites can.

---

## STAGING VERDICT AFTER P0 CLOSURE

**Conditional GO**, same condition structure as the baseline audit minus the now-closed P0s: P1-1 through P1-4 (tenant-isolation defense-in-depth, RLS, observability) remain strongly recommended before staging, since staging is exactly where those gaps would otherwise go undetected until production. Nothing else in P1/P2/P3, nor any of the newly discovered post-audit findings above, should on its own block a staging deployment intended to validate the product against real (non-public) traffic.

## PRODUCTION VERDICT

**NO-GO.** The two P0 defects that were the audit's sole cited production blockers are now closed, but production readiness was never solely gated on those two findings. Independent of them, the baseline audit found no evidence that any infrastructure has ever been applied to a real cloud account, no evidence a backup has ever been taken or a restore ever tested, and no evidence CloudHSM has ever been exercised against real hardware (P1-9). None of that evidence has changed in this remediation pass: no real deployment, backup/restore, or CloudHSM-hardware proof was attempted or claimed here. Production must remain **NO-GO** until that real deployment proof exists, independent of P0/P1/P2/P3 code-level remediation.
