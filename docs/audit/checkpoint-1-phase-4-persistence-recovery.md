# Audit Checkpoint 1 — Phase 4: Persistence, Recovery & Authority Revalidation

## Status

Completed.

Phase 4 assessed WebGuard's persistence and recovery boundaries, including:

- database schema integrity;
- migration rollback and restart behaviour;
- malformed persisted state;
- identity and RBAC persistence;
- SQLite lock and crash recovery;
- queued-job and lease recovery;
- scheduler authority revalidation;
- worker-claim authority revalidation;
- executor runtime authority revalidation;
- persisted scalar validation;
- database resource lifecycle;
- static-analysis safety of persistence code.

Ten product findings were confirmed during this phase:

- **P4-001 — Medium — Current job-store schema version was trusted without structural validation.**
- **P4-002 — Low — Failed startup could mutate missing job-store schema metadata.**
- **P4-003 — Medium — Malformed persisted job, schedule, or permit state could escape controlled storage-error boundaries.**
- **P4-004 — Medium — IdentityStore could silently recreate missing security-critical identity/RBAC tables.**
- **P4-005 — Low — Missing identity schema metadata could be silently recreated or accepted.**
- **P4-006 — Medium — Malformed persisted identity state could escape controlled IdentityStore boundaries.**
- **P4-007 — Low — Generic SQLite operational failures could escape IdentityStore mutation boundaries as raw sqlite3 errors.**
- **P4-008 — High — Organization authorization revocation was not enforced across scheduler materialisation and worker execution boundaries.**
- **P4-009 — Medium — Persisted scalar validation was incomplete and could accept invalid boolean or integer values.**
- **P4-011 — Low — Dynamic SQL construction in identity schema validation triggered the static-analysis SQL-injection control.**

All confirmed findings were remediated and regression-tested before Phase 4 closure.

One additional candidate, **P4-010**, was investigated and dismissed as a product security finding after it was traced to test-only SQLite connection lifecycle handling.

No Critical severity findings were identified during Phase 4.

---

## Audit Scope

Phase 4 focused on the components responsible for preserving authorization, job state, schedules, leases, identity state, and recovery behaviour across process restarts and database failures.

Primary areas reviewed:

- `ScanJobStore`;
- `IdentityStore`;
- database initialization;
- schema version validation;
- schema migration;
- persisted record deserialization;
- SQLite lock handling;
- lease recovery;
- recurring schedule materialisation;
- organization authorization assignments;
- worker claim boundaries;
- executor runtime authorization checks;
- database transaction rollback;
- persisted scalar type validation;
- test and production database connection lifecycle.

The audit intentionally used malformed database state, direct SQLite corruption, lock injection, transaction failure injection, restart simulation, authorization revocation races, and static-analysis gates rather than relying only on normal persistence tests.

---

## Phase 4A — Schema Migration and Recovery

Adversarial tests assessed:

1. current-schema databases missing required tables;
2. invalid schema-version metadata;
3. failed startup with missing schema-version metadata;
4. migration rollback;
5. migration restart after failure;
6. migration idempotency.

### Finding P4-001

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Current job-store schema version was trusted without structural validation

### Initial behaviour

A database declaring the current job-store schema version could be accepted even when required tables were missing.

This allowed schema metadata to claim a valid current version while the physical database structure was incomplete.

### Security impact

Persistence integrity could not be trusted solely from the schema-version marker.

A structurally damaged current-version database could cross startup validation and fail later in less controlled execution paths.

### Remediation

Current-version databases are now structurally validated before use.

Required tables and columns are checked before the store is considered initialized.

### Finding P4-002

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Failed startup could mutate missing job-store schema metadata

### Initial behaviour

A failed initialization path could recreate missing schema metadata while determining whether the database was valid.

### Security impact

Startup validation was not completely side-effect free.

A damaged database could be altered even though startup ultimately failed.

### Remediation

Initialization now distinguishes new databases from previously existing databases and validates existing schema state without mutating it.

### Result

Phase 4A:

**6/6 tests passed.**

P4-001 and P4-002 are recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 4B — Persisted Job, Schedule and Permit Corruption

Adversarial database mutations assessed malformed:

- job state;
- job timestamps;
- schedule state;
- schedule timestamps;
- TrustScan permit revocation timestamps;
- revision values;
- truncated SQLite databases.

### Finding P4-003

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Malformed persisted operational state could escape controlled storage-error boundaries

### Initial behaviour

Malformed persisted values could trigger raw exceptions such as `ValueError` during record reconstruction or recovery.

### Security impact

Corrupt or adversarial persisted state could bypass the store's controlled error taxonomy.

That weakened fail-closed behaviour and could expose implementation exceptions to callers.

### Remediation

Persisted timestamps, states, integers, and record projections are now parsed through controlled validation boundaries.

Malformed persisted state is translated into deterministic `JobStoreError` outcomes.

Claim and recovery transactions also preserve rollback behaviour when persisted values are invalid.

### Result

Phase 4B:

**7/7 tests passed.**

P4-003 is recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 4C — Identity Persistence Integrity

The audit assessed:

- missing identity tables;
- missing identity schema metadata;
- malformed roles;
- malformed timestamps;
- current-version schema integrity.

### Finding P4-004

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** IdentityStore could silently recreate missing security-critical identity tables

### Initial behaviour

An already-initialized identity database missing one or more required tables could be treated as partially uninitialized and rebuilt.

### Security impact

Security-critical RBAC and authorization persistence could be silently reconstructed instead of failing closed.

Missing identity state therefore risked being interpreted as initialization state rather than corruption.

### Remediation

Identity initialization now distinguishes a genuinely new identity schema from an incomplete existing schema.

Partially missing required tables cause controlled startup failure.

### Finding P4-005

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Missing identity schema metadata could be silently recreated or accepted

### Initial behaviour

Missing identity schema-version metadata could cross startup without a strict non-mutating validation failure.

### Remediation

Existing identity databases now require valid schema metadata and fail closed when it is absent or malformed.

Failed validation does not recreate the missing metadata.

### Finding P4-006

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Malformed persisted identity state could escape controlled IdentityStore boundaries

### Initial behaviour

Malformed persisted roles and timestamps could surface raw parsing exceptions.

### Remediation

Identity persistence deserialization now validates security-sensitive fields and maps malformed persisted values to controlled `IdentityStoreError` outcomes.

### Result

Phase 4C:

**6/6 tests passed.**

P4-004, P4-005 and P4-006 are recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 4D — SQLite Lock and Crash Recovery

Failure-injection tests assessed:

- locked job submission;
- locked job claim;
- locked principal creation;
- locked token creation;
- locked token revocation;
- locked authorization assignment;
- locked authentication bookkeeping;
- locked audit-event persistence;
- recovery after lock release;
- uncommitted state after connection loss;
- queued-job persistence across restart;
- expired-lease recovery after restart.

### Finding P4-007

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** SQLite operational failures could escape IdentityStore mutation boundaries

### Initial behaviour

Generic SQLite operational failures, including locked-database conditions, could escape mutation paths as raw `sqlite3` exceptions.

### Security impact

Callers could observe implementation-level database exceptions instead of stable controlled identity-store outcomes.

### Remediation

IdentityStore mutation boundaries now translate SQLite operational failures into controlled store errors while preserving intentional integrity-conflict handling.

Transactions continue to roll back partial changes.

### Verified recovery invariants

The audit confirmed that:

- committed queued jobs survive restart;
- expired leases can be recovered after restart;
- uncommitted claim-like state disappears after connection loss;
- failed locked writes do not partially persist;
- stores recover normally after database locks are released.

### Result

Phase 4D:

**13/13 tests passed.**

P4-007 is recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 4E — Authorization Revocation Across Scheduler and Worker Boundaries

The audit tested organization authorization removal after earlier validation but before:

- recurring schedule materialisation;
- legacy worker claim;
- leased worker claim;
- scanner startup;
- subsequent runtime outbound requests.

### Finding P4-008

**Severity:** High

**Status:** Confirmed and remediated

**Title:** Organization authorization revocation was not enforced across scheduler materialisation and worker execution boundaries

### Initial behaviour

Organization authorization assignments could be valid during initial validation and later be removed while persisted work continued moving through orchestration boundaries.

The audit reproduced authorization removal after validation while work could still progress toward:

- scheduled job creation;
- worker claim;
- scanner execution.

### Security impact

P4-008 represented an authorization time-of-check/time-of-use gap.

Revoked tenant authorization could remain effective long enough for previously validated work to cross later execution boundaries.

The finding was classified as **High** because organization authorization is a primary security boundary controlling whether tenant-scoped work is permitted to execute.

### Remediation

Authorization assignment validity is now rechecked at multiple independent boundaries:

- schedule materialisation;
- legacy worker claim;
- leased worker claim;
- executor startup before scanner execution;
- runtime request boundaries before subsequent outbound requests.

Scheduler materialisation performs the assignment check transactionally when the identity subsystem is present.

Standalone store-only test and compatibility paths remain supported where identity tables are intentionally absent.

### Security invariant after remediation

Once an organization authorization assignment has been removed:

- no new scheduled work may materialise under that assignment;
- no queued job may newly cross the claim boundary under that assignment;
- claimed work cannot begin scanner execution under the removed assignment;
- already-running execution cannot send a subsequent request after revocation is observed.

### Regression verification

Dedicated tests confirmed:

- assignment removal after scheduler validation blocks materialisation;
- stale scheduler state cannot bypass expired permit enforcement;
- removed assignments block leased worker claims;
- removed assignments block legacy worker claims;
- removal after claim blocks execution before scanner startup;
- removal during execution blocks the next outbound request.

A compatibility regression discovered by the full test suite was also corrected.

The scheduler originally queried `organization_authorizations` unconditionally, which broke standalone `ScanJobStore` schedule tests where the identity schema is intentionally absent.

The final implementation enforces organization assignment when the identity table exists while preserving standalone store operation when identity persistence is not composed.

### Result

Dedicated P4-008 tests:

**6/6 tests passed.**

P4-008 is recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 4F — Persisted Scalar Validation

The audit directly modified SQLite scalar values to invalid types and values.

Test cases included:

- `principals.active = 2`;
- `cancellation_requested = 2`;
- malformed BLOB-backed `revision`;
- malformed BLOB-backed `attempt_count`.

### Finding P4-009

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Persisted scalar validation was incomplete

### Initial behaviour

The identity layer converted persisted principal activity using Python truthiness.

A persisted value of:

`active = 2`

was therefore accepted as:

`True`

instead of being rejected.

Job-store recovery also allowed malformed integer-backed values to reach raw conversion paths.

### Security impact

The principal activity flag is security-sensitive.

Failing open on an invalid persisted boolean could incorrectly treat corrupted principal state as active.

Malformed recovery integers could also escape controlled persistence validation.

### Remediation

Persisted booleans now accept only the canonical SQLite integer values:

- `0`;
- `1`.

All other values are rejected.

Persisted recovery integers now pass through explicit integer validation and malformed values are converted into the controlled:

`job_store_persisted_state_invalid`

error boundary.

### Result

Phase 4 scalar validation:

**4/4 tests passed.**

P4-009 is recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## P4-010 Investigation — SQLite ResourceWarning

### Initial observation

Python 3.14 emitted repeated:

`ResourceWarning: unclosed database`

messages while transaction-safety tests were running.

Because warnings appeared while production store initialization code was active, the issue was initially treated as a possible production database connection leak.

### Investigation

Targeted migration and initialization probes completed without warnings after forced garbage collection.

Tracemalloc then identified the actual allocations in:

`tests/unit/test_phase3_transaction_schedule_safety.py`

The test code used:

`with sqlite3.connect(...) as connection`

which handles transaction commit or rollback but does not close the SQLite connection.

Nine test-owned SQLite connection contexts used this pattern.

### Resolution

The test connections were changed to explicit closing contexts while retaining transaction semantics.

The exact reproducer then passed with:

`-W error::ResourceWarning`

and no warning.

The complete scheduler and transaction-safety regression suite also completed without a ResourceWarning.

### Classification

P4-010 is recorded as:

**DISMISSED AS PRODUCT SECURITY FINDING**

Cause:

**test-only SQLite connection lifecycle**

Security/product impact:

**none confirmed**

The test resource-hygiene defect was corrected.

---

## Phase 4G — Static Analysis of Persistence Code

The repository-native security gate identified one additional persistence-layer issue after the functional audit had passed.

### Finding P4-011

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Dynamic SQL construction in identity schema validation

### Initial behaviour

Identity schema initialization dynamically constructed an SQL `IN (...)` placeholder list while querying `sqlite_master`.

The values themselves were parameterized, but the string-built SQL triggered Ruff security rule:

`S608`

### Security impact

No user-controlled identifier interpolation was reproduced.

The finding was nevertheless retained because persistence initialization is a security-sensitive boundary and the same result could be achieved without dynamically constructing SQL.

### Remediation

Identity schema initialization now uses a fixed `sqlite_master` query and filters the returned table names against the required-table set in Python.

Detailed column validation remains enforced by the existing current-schema validation routine.

No static-analysis suppression was added.

### Regression verification

Focused identity regression:

**22/22 tests passed.**

Repository security gates then reported:

- secret scan passed;
- static Python security analysis passed;
- dependency audit passed;
- complete WebGuard security gates passed.

P4-011 is recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Final Verification

### Dedicated Phase 4 adversarial suites

The final Phase 4 suite included:

- migration and recovery: 6 tests;
- persisted-state corruption: 7 tests;
- identity persistence: 6 tests;
- lock and crash recovery: 13 tests;
- scheduler authority TOCTOU: 2 tests;
- worker claim authority: 2 tests;
- executor authority: 2 tests;
- persisted scalar validation: 4 tests.

Total:

**42/42 tests passed.**

The final dedicated suite was also run with:

`ResourceWarning`

promoted to an error.

No resource warning remained.

### Scheduler and transaction-safety regression

**31/31 tests passed.**

### Focused identity regression after P4-011

**22/22 tests passed.**

### Full repository unit verification

**1030/1030 tests passed.**

### Integration behaviour

Integration tests remained opt-in during the standard verification gate.

Authorized Juice Shop integration was then executed explicitly against:

`http://127.0.0.1:3000/`

with the lab container healthy and bound only to loopback.

Result:

**14/14 integration tests passed.**

Coverage included:

- authenticated activity pagination;
- crawl checkpoint resume;
- Juice Shop crawl and analysis;
- same-origin crawl enforcement;
- HTML analyzer persistence safety;
- commercial-policy local-target blocking;
- lab-policy local-target authorization;
- passive scanning;
- professional report rendering;
- validated-address HTTP fetch;
- authenticated tenant job submission;
- authenticated schedule execution;
- TLS-check behaviour on HTTP;
- TrustScan permit issue, binding and revocation.

### Security gates

Repository-native security tooling was installed using the reviewed hash-locked installer.

Final security-gate results:

- repository secret scan: passed;
- Ruff static Python security analysis: passed;
- locked dependency advisory audit: passed.

Final result:

**WebGuard security gates passed.**

### Repository hygiene

`git diff --check`

completed without errors.

---

## Phase 4 Closure

Phase 4 identified and remediated weaknesses across:

- schema integrity validation;
- migration failure handling;
- persisted-state deserialization;
- identity and RBAC persistence;
- SQLite operational-error boundaries;
- tenant authorization revocation;
- scheduler TOCTOU protection;
- worker claim authorization;
- runtime authority enforcement;
- persisted boolean and integer validation;
- static-analysis safety.

The highest-severity issue was P4-008, where organization authorization revocation could cross multiple orchestration boundaries after earlier validation.

The final implementation now revalidates authority at the persistence, scheduling, worker-claim, executor-start, and runtime request boundaries.

One suspected production database connection leak was disproved and traced to test-only resource handling.

All confirmed findings are remediated and covered by regression tests.

Phase 4 is therefore:

**COMPLETE**

Next audit area:

**Checkpoint 1 — Phase 5: Secrets, Keys & Artifact Security**
