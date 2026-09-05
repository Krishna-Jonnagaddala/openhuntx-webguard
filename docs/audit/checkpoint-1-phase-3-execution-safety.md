# Audit Checkpoint 1, Phase 3: Execution Safety, Worker Leases & Scheduling

## Status

Completed.

Phase 3 assessed WebGuard's execution-safety boundaries, including:

- concurrent worker claims;
- lease fencing and recovery;
- stale-worker completion;
- cancellation races;
- TrustScan permit revocation and expiry;
- schedule materialisation;
- schedule pause and catch-up behaviour;
- runtime request-boundary enforcement;
- transaction rollback;
- worker exception handling;
- Safety Receipt persistence.

One security finding was confirmed during this phase:

- **P3-001 (Medium): TrustScan permit revocation was not enforced atomically at scheduler and worker-claim boundaries.**

P3-001 was remediated and regression-tested before Phase 3 closure.

No Critical or High severity findings were identified during Phase 3.

---

## Audit Scope

Phase 3 focused on the components responsible for turning authorised scan requests into actual scanner execution.

Primary areas reviewed:

- `ScanJobStore`;
- leased job claiming;
- lease renewal and recovery;
- stale-worker fencing;
- terminal state transitions;
- cancellation;
- recurring schedule materialisation;
- TrustScan permit bindings;
- TrustScan runtime-safety enforcement;
- worker error handling;
- transaction atomicity.

The audit intentionally used concurrent and failure-injection tests rather than relying only on sequential happy-path coverage.

---

## Phase 3A: Concurrency and Lease Races

Adversarial tests were added for:

1. two workers racing to claim one queued job;
2. two jobs bound to the same TrustScan permit racing for execution;
3. lease renewal racing with expired-lease recovery;
4. stale completion racing with lease recovery;
5. two scheduler instances racing to materialise the same due schedule;
6. TrustScan runtime concurrency enforcement across threads.

### Result

**6/6 tests passed.**

Verified invariants included:

- one queued job cannot be leased simultaneously by two workers;
- TrustScan Permit v1 concurrency remains limited to one active execution;
- expired leases cannot be renewed back into valid running state after recovery;
- stale completion cannot overwrite recovery;
- one schedule occurrence cannot be materialised twice;
- runtime concurrency enforcement is atomic within the execution engine.

No Phase 3A security finding was identified.

---

## Phase 3B: Revocation and Cancellation Races

Adversarial tests were added for:

- cancellation racing with worker claim;
- revoked permit before worker claim;
- permit revocation before the next outbound request;
- permit expiry before the next outbound request;
- permit revocation racing with schedule materialisation.

### Finding P3-001

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** TrustScan permit revocation was not enforced atomically at scheduler and worker-claim boundaries

### Initial behaviour

Two adversarial tests failed before remediation.

#### Worker claim boundary

A queued job already bound to a revoked TrustScan permit could still transition to:

`queued -> running`

The job was successfully leased even though its permit had been revoked.

#### Scheduler materialisation boundary

The scheduler could:

1. validate a TrustScan permit;
2. lose the race to a concurrent permit revocation;
3. still enqueue the scheduled job afterward.

This created a time-of-check/time-of-use gap between permit validation and persisted work creation.

### Security impact

The issue allowed revoked authorization state to cross orchestration boundaries.

The finding was classified as **Medium**, rather than High, because the scanner executor and TrustScan Runtime Safety Engine independently revalidated authorization and permit state before outbound requests.

During adversarial testing, runtime revocation and runtime expiry both remained fail-closed.

The audit therefore found no evidence that revoked execution could successfully send a subsequent outbound request through the tested runtime path.

### Remediation

Permit validity was moved into the transactional orchestration boundaries.

Worker job selection now requires the bound TrustScan permit to:

- exist;
- match the persisted permit fingerprint;
- not be revoked;
- have reached `not_before`;
- not have reached `expires_at`.

This check was applied to both:

- `claim_next()`;
- `claim_next_leased()`.

Schedule materialisation now rechecks the persisted permit inside the same transaction used to create the scheduled job.

If the permit is no longer current, no job is materialised.

### Security invariant after remediation

Once TrustScan permit revocation has committed:

- no new scheduled job may be materialised under that permit;
- no queued job may cross the worker-claim boundary under that permit;
- already-running execution independently revalidates permit state before outbound requests.

### Regression verification

Additional regression coverage confirmed that:

- revoked queued permits cannot be leased;
- expired queued permits cannot be leased;
- the legacy `claim_next()` path cannot bypass revocation;
- concurrent scheduler revocation cannot materialise work;
- runtime revocation blocks the next request;
- runtime expiry blocks the next request.

### Result

Final Phase 3B suite:

**7/7 tests passed.**

Combined Phase 3A + Phase 3B:

**13/13 tests passed.**

P3-001 is therefore recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 3C: Transaction Atomicity, Pause and Catch-Up

Failure-injection and race tests assessed:

- partial schedule materialisation;
- terminal transition plus Safety Receipt persistence;
- expired-lease batch recovery;
- paused schedule enforcement;
- pause racing with schedule enqueue;
- heavily overdue schedule catch-up.

SQLite triggers were deliberately used to abort transactions after execution had already entered state-changing paths.

### Verified invariants

Schedule materialisation rollback leaves no partial:

- job;
- job scope;
- permit binding;
- schedule advancement.

Terminal-transition rollback leaves the running job and lease intact if Safety Receipt persistence fails.

Expired-lease recovery rolls back the entire recovery batch if a failure occurs during the transaction.

Paused schedules do not materialise work.

If pause commits before schedule enqueue acquires its transaction, the scheduled job is not created.

A badly overdue schedule produces only the intended bounded single catch-up job and advances the next execution time into the future.

### Result

**6/6 tests passed.**

No Phase 3C security finding was identified.

---

## Phase 3D: Worker Failure and Exception Safety

Adversarial tests assessed:

- unexpected executor exceptions;
- controlled execution failures;
- Safety Receipt metadata propagation;
- cancellation racing with scanner failure;
- lease loss during successful execution;
- lease loss during failed execution;
- normal successful completion as a control case.

### Verified invariants

Unexpected executor exceptions are converted into:

`worker_internal_error`

with a generic persisted message.

Raw underlying exception contents are not persisted as the job error message.

Controlled `JobExecutionError` values preserve their controlled error code and Safety Receipt metadata.

When cancellation has been observed, cancellation wins over a competing controlled scanner error.

A worker that loses its lease cannot subsequently persist:

- success;
- failure;
- stale result references;
- stale error information.

Normal execution with a current valid lease still completes successfully.

### Result

**6/6 tests passed.**

No Phase 3D security finding was identified.

---

## Full Verification

Following remediation and adversarial testing, the full repository verification was executed.

### Unit tests

**988 tests passed.**

### Standard verification gate

`./scripts/verify.sh`

Result:

**PASS**

The verification gate also confirmed that integration tests remain opt-in by default.

Without explicit integration authorization:

**14 integration tests discovered, 14 safely skipped.**

### Authorised integration environment

The isolated OWASP Juice Shop lab was explicitly started and the integration environment enabled with:

- `WEBGUARD_RUN_INTEGRATION=1`;
- loopback-only authorised lab target.

Result:

**14/14 integration tests passed.**

The isolated container and Docker network were removed after the test run.

### Security gates

Secret scanning:

**PASS (208 repository files checked)**

Ruff/security checks:

**PASS**

Dependency advisory audit:

**PASS (6 exact locked packages checked)**

Overall WebGuard security gate:

**PASS**

---

## Findings Summary

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| P3-001 | Medium | TrustScan permit revocation was not enforced atomically at scheduler and worker-claim boundaries | Remediated |
| P3-002 | N/A | No additional Phase 3 finding assigned | N/A |

Phase 3 totals:

- Critical: 0
- High: 0
- Medium: 1
- Low: 0
- Informational: 0

Open Phase 3 findings:

**0**

---

## Residual Considerations

The tested execution model is the current SQLite-backed, single-host service architecture.

Phase 3 does not claim distributed cross-host coordination guarantees for future horizontally scaled runner deployments.

Before distributed or customer-hosted runner execution is introduced, equivalent fencing, permit concurrency, revocation propagation and scheduling guarantees must be designed for that execution model.

The broader Checkpoint 1 key-management limitation remains tracked separately and is not reclassified as a Phase 3 finding.

---

## Conclusion

WebGuard's execution path remained fail-closed under the tested worker, lease, scheduler, cancellation, runtime-safety, transaction-failure and exception scenarios after remediation of P3-001.

The Phase 3 regression tests are retained permanently to protect the corrected security invariants from future changes.

**Audit Checkpoint 1, Phase 3: COMPLETE**
