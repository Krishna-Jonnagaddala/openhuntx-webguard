# ADR 0024: Recurring Scan Scheduling and Safe Catch-up

- Status: Accepted
- Date: 2026-08-07
- Milestone: 1.29

## Context

Milestone 1.28 made scanner execution durable through renewable worker leases, fencing tokens, and bounded crash recovery. Customers still had to submit every assessment manually. A commercial security-assurance service needs recurring scans, but schedule execution must preserve the same organisation boundary, owned-target authorisation, queue idempotency, and bounded-execution guarantees as direct submissions.

A naive timer that calls the HTTP API can create duplicate jobs when multiple scheduler processes observe the same due time. It can also flood the queue after downtime by creating one job for every missed interval. Persisting schedules without rechecking authorisation could continue scanning after an assignment is removed, an authorisation expires, or a target document changes.

## Decision

WebGuard adds organisation-scoped recurring scan schedules to the existing SQLite service database.

The job-store schema advances from version `2` to version `3`. The additive migration creates `scan_schedules` with:

- canonical schedule, organisation, and creator identifiers;
- a descriptive name;
- canonical target and owned-target authorisation identifier;
- the most recently validated authorisation fingerprint;
- scan mode;
- fixed interval in seconds;
- active or paused state;
- canonical creation, update, and next-run timestamps;
- optimistic revision number;
- last enqueue time and generated job identifier;
- controlled last-error code and timestamp.

Intervals are bounded from one hour to one year. Start times use canonical UTC microsecond notation and cannot be earlier than the service clock or more than one year in the future when created through the API.

### API and RBAC

The authenticated `/v1` API adds:

- `POST /v1/schedules`;
- `GET /v1/schedules`;
- `GET /v1/schedules/{schedule_id}`;
- `POST /v1/schedules/{schedule_id}/pause`;
- `POST /v1/schedules/{schedule_id}/resume`.

Permissions are:

- owner and administrator: full schedule access;
- analyst: create, read, pause, and resume schedules;
- viewer: read-only schedule access.

Every operation remains organisation-scoped. Cross-tenant schedule identifiers return `404` rather than disclosing existence. Create, list, read, pause, and resume operations emit the existing security audit events.

### Due-run materialisation

A scheduler pass reads a bounded, ordered batch of active schedules whose `next_run_at` is due. Before enqueue, it verifies:

- the authorisation remains assigned to the schedule organisation;
- the server-side authorisation document still exists;
- the canonical target still matches;
- the current time is within the authorisation validity window.

The schedule row is then advanced and the scan job is inserted in one immediate SQLite transaction. The update requires the schedule's expected revision and active state. This optimistic fence permits multiple local scheduler processes without duplicate due-run creation.

The generated job uses a deterministic internal idempotency key derived from the schedule identifier and scheduled occurrence. The job is organisation-scoped and attributes submission to the principal that created the schedule. The scanner worker still reloads and revalidates the authorisation immediately before network execution.

### Catch-up policy

Each scheduler pass can produce at most one job per due schedule.

When the service was offline across multiple intervals, WebGuard advances `next_run_at` to the first future interval after creating one job. It does not create a backlog job for every missed occurrence. This avoids a restart-time request burst against customer assets.

### Blocking policy

When assignment, document, target, or validity checks fail, WebGuard atomically pauses the schedule and stores a controlled error code and timestamp. It does not enqueue a job. An authorised operator must correct the issue and resume the schedule. Resume clears the prior error and sets the next run to one interval after the resume time.

### Runtime model

`webguard-api serve` runs:

- the authenticated loopback HTTP API;
- the lease-aware scanner worker;
- the recurring schedule coordinator.

A standalone `webguard-api scheduler` command supports one-pass and long-running scheduler operation. Poll interval and batch size are bounded configuration values.

## Security properties

- schedules are isolated by organisation;
- only permitted roles can create or change schedules;
- raw API tokens and authorisation documents are not stored in schedule rows;
- a schedule cannot enqueue after its authorisation is removed, missing, target-mismatched, not yet valid, or expired;
- due-run creation and schedule advancement are atomic;
- stale schedule revisions cannot create duplicate jobs;
- missed intervals cannot flood the queue;
- schedule-generated jobs retain worker leases, execution fencing, passive policy, and pre-execution authorisation revalidation;
- schedule responses omit the stored authorisation fingerprint;
- SQLite and artefact permissions remain owner-only.

## Consequences

### Positive

- customers can define repeatable passive assessments;
- multiple local scheduler processes coordinate safely through database revisions;
- service downtime produces bounded catch-up behaviour;
- authorisation changes fail closed before enqueue;
- schedule state and last-run metadata are available to a future dashboard;
- scheduled and direct jobs use the same queue, worker, report, and audit foundations.

### Trade-offs

- schedules use fixed UTC intervals rather than cron expressions or customer time zones;
- the scheduler remains single-host SQLite coordination and is not a distributed production scheduler;
- paused schedules require an operator to resume after an authorisation problem is corrected;
- schedule creator identity is retained as the submitting principal for generated jobs;
- calendar exceptions, maintenance windows, notification rules, and per-plan quotas remain out of scope.

## Alternatives considered

### In-process timers without database state

Rejected because timers are lost on restart and cannot coordinate duplicate prevention between processes.

### Create every missed occurrence after downtime

Rejected because a long outage could cause an unsafe burst of scans against a customer target.

### Enqueue without rechecking authorisation

Rejected because assignment, validity, target, or document state may have changed after schedule creation.

### Use cron expressions immediately

Deferred. Fixed intervals provide deterministic UTC semantics without introducing timezone, daylight-saving, parser, and calendar ambiguity before the customer dashboard exists.

### Introduce a distributed scheduler immediately

Deferred until PostgreSQL-backed shared persistence and multi-host coordination are implemented. The schedule revision and atomic enqueue semantics established here are intended to carry forward to that backend.

## Verification

Milestone tests cover:

- strict schedule submission contracts;
- interval and timestamp bounds;
- duplicate and unknown JSON field rejection;
- schema version `2` to `3` migration through the full migration chain;
- organisation-scoped schedule create, list, and read;
- pause and resume transitions;
- due ordering and batch limits;
- atomic job creation and schedule advancement;
- missed-interval catch-up without queue flooding;
- stale revision rejection;
- assignment, missing document, target mismatch, future validity, and expiry blocking;
- owner, analyst, and viewer RBAC;
- HTTP create, list, read, pause, and resume routes;
- standalone scheduler CLI behaviour;
- authenticated scheduler-to-worker integration;
- all existing scanner, reporting, RBAC, worker-lease, and authorised Juice Shop behaviour.
