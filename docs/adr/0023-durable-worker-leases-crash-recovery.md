# ADR 0023: Durable Worker Leases and Crash Recovery

- Status: Accepted
- Date: 2026-08-07
- Milestone: 1.28

## Context

Milestone 1.26 introduced a persistent SQLite scan-job queue and one background worker. Milestone 1.27 added organization isolation, API authentication, and RBAC. A claimed job previously changed from `queued` to `running`, but the database did not record which worker owned that execution or when ownership should expire.

If the process stopped after claiming a job, the job could remain `running` indefinitely. A restarted worker could not safely determine whether the previous process was dead, and a delayed previous worker could still attempt to write a terminal result after another process recovered the job.

This is unacceptable for a commercial security service because job recovery must not permit duplicate terminal writes, stale result projection, or unlimited retry loops.

## Decision

WebGuard adds durable, renewable worker leases to the existing SQLite job store.

The job-store schema advances from version `1` to version `2`. The additive migration introduces:

- `worker_id`;
- `lease_token`;
- `lease_expires_at`;
- `heartbeat_at`;
- `attempt_count`;
- an index for expired running leases.

Each leased claim is an immediate transaction that:

1. selects the oldest queued job;
2. changes it to `running`;
3. records a visible-ASCII worker identifier;
4. generates a new random lease token;
5. records the lease expiry and heartbeat time;
6. increments the execution attempt count and job revision.

The lease token is an internal fencing value. It is not an API credential, is not returned by customer-facing routes, and is cleared when the job leaves the running state.

### Heartbeats

A running worker renews its lease in a monitor thread while scanner execution is active. Renewal requires:

- the job to remain `running`;
- the same worker identifier;
- the same lease token;
- an unexpired current lease.

Renewal updates the heartbeat, expiry, update timestamp, and revision atomically.

### Terminal fencing

Service-run completion, failure, and cancellation transitions require the current worker identifier and lease token. The transition fails closed when:

- the lease expired;
- another worker recovered or reclaimed the job;
- the token or worker identifier does not match;
- the job already changed state.

This prevents a delayed worker from overwriting the state produced by a replacement worker.

Legacy unleased store methods remain available for deterministic internal compatibility tests, but they cannot transition a job that currently contains lease metadata.

### Recovery

Before claiming new work, each worker recovers expired leases in an immediate transaction.

For each expired running job:

- a pending customer cancellation becomes terminal `cancelled`;
- a job at or above the configured maximum attempt count becomes controlled `failed` with `worker_lease_attempts_exhausted`;
- any other job returns to `queued`, clears stale execution and lease metadata, and preserves the attempt counter.

A replacement worker receives a new lease token and increments the attempt count when it claims the recovered job.

### Schema migration

New databases are initialized through schema version `1` and immediately migrated to version `2`. Existing version `1` databases are upgraded transactionally.

Legacy running jobs have no lease ownership metadata. During migration:

- a running job with cancellation requested becomes terminal `cancelled`;
- another running job returns to `queued` with `started_at` cleared;
- revisions are incremented so observers can detect the recovery transition.

Future schema versions are rejected rather than interpreted optimistically.

### Configuration

The local service exposes bounded configuration for:

- worker identifier;
- lease duration;
- heartbeat interval;
- maximum execution attempts.

The heartbeat interval must be shorter than the lease duration. Defaults are:

- lease: 30 seconds;
- heartbeat: 10 seconds;
- maximum attempts: 3.

## Security properties

- only one current lease can own a queued job;
- each recovery and reclaim produces a new fencing token;
- stale workers cannot persist terminal state;
- expired leases cannot be renewed or completed;
- cancellation survives worker failure;
- retry attempts are bounded;
- unexpected worker exceptions remain redacted;
- lease metadata is internal and absent from public job representations;
- database and artifact permissions remain owner-only;
- scanner authorization is still reloaded and revalidated before execution.

## Consequences

### Positive

- worker-process interruption no longer leaves leased jobs permanently running;
- multiple local worker processes can coordinate claims through SQLite transactions;
- crash recovery is deterministic and bounded;
- stale completion writes are fenced;
- schema upgrades are explicit and testable;
- the queue is better prepared for a future shared database backend.

### Trade-offs

- SQLite coordination remains single-host and is not the final distributed production design;
- a lease that is too short may cause unnecessary recovery during host pauses;
- a lease that is too long delays crash recovery;
- recovering a job may repeat already-sent passive requests because response bodies and in-memory scanner state are intentionally not persisted by the service queue;
- the process-local rate limiter remains unsuitable for horizontal public deployment.

## Alternatives considered

### Leave running jobs for manual repair

Rejected because it creates an unbounded operational failure mode and does not fence delayed workers.

### Reset every running job on service startup

Rejected because another worker process may still be actively executing the job.

### Use only a worker identifier without a random token

Rejected because a restarted process could reuse the same identifier and accidentally act as the previous lease owner.

### Allow completion after lease expiry when no replacement claimed the job

Rejected because expiry is the ownership boundary. Allowing a stale completion would make recovery races non-deterministic.

### Introduce Redis, Celery, or PostgreSQL immediately

Deferred. Shared production infrastructure remains the next persistence phase, but the lease and fencing semantics must be defined and verified before changing the storage backend.

## Verification

Milestone tests cover:

- schema version `1` to `2` migration;
- preservation of queued jobs;
- safe migration of legacy running and cancelled jobs;
- future-version rejection;
- leased claim metadata and attempt counting;
- atomic exclusion between separate store instances;
- heartbeat renewal;
- wrong-worker and wrong-token rejection;
- expired-lease requeue;
- cancellation recovery;
- attempt exhaustion;
- stale-worker completion rejection;
- replacement-worker execution;
- existing service, RBAC, reporting, scanner, and authorized Juice Shop integration behavior.
