# ADR 0025: Signed Cursor Pagination and Organization Activity Feeds

- Status: Accepted
- Date: 2026-08-07
- Milestone: 1.30

## Context

Milestone 1.29 introduced recurring scan schedules, but the authenticated API still returned unpaginated schedule and audit collections and did not provide an organization job-list endpoint. A customer dashboard cannot safely depend on unbounded list responses or offset pagination as job and audit history grows.

Offset pagination becomes unstable when new rows are inserted between page requests. It can repeat or skip records, and large offsets become increasingly expensive. Plain client-supplied timestamps or UUIDs would expose implementation details and could be replayed across organizations, resources, or filter combinations unless every caller and query path validated them consistently.

The service remains loopback-only and SQLite-backed, but its list contracts should already enforce production-oriented tenant isolation, deterministic ordering, bounded work, and fail-closed cursor handling.

## Decision

WebGuard adds signed opaque cursor pagination for organization-scoped jobs, schedules, and security audit events.

### Page contract

List requests accept:

- `limit`, from 1 to 100, defaulting to 50;
- one optional opaque `cursor`;
- resource-specific exact-match filters.

The supported filters are:

- jobs: `state` and `mode`;
- schedules: `state`;
- audit events: `outcome`.

Unknown, duplicate, empty, malformed, or unsupported query parameters are rejected. Non-list routes continue to reject every query parameter.

Responses retain resource-specific arrays and add:

```json
{
  "page": {
    "limit": 50,
    "next_cursor": null
  }
}
```

A total count is intentionally omitted. Each store query reads at most `limit + 1` rows to determine whether another page exists.

### Stable keyset ordering

Resources are ordered newest first with a deterministic UUID tie-breaker:

- jobs: `submitted_at DESC, job_id DESC`;
- schedules: `created_at DESC, schedule_id DESC`;
- audit events: `occurred_at DESC, event_id DESC`.

The next request uses a strict keyset boundary below the final item in the previous page. This avoids offset drift when newer records are inserted.

### Signed opaque cursor

A cursor contains canonical JSON with:

- cursor version;
- organization ID;
- resource name;
- canonical filter map;
- ordering timestamp;
- ordering resource ID;
- expiry timestamp.

The canonical payload is authenticated using HMAC-SHA-256 and encoded with URL-safe base64. The cursor is opaque to API clients.

Validation rejects:

- malformed or oversized cursors;
- invalid signatures;
- unsupported versions;
- expired cursors;
- organization mismatch;
- resource mismatch;
- filter mismatch;
- non-canonical payloads.

Cursor validity is 24 hours. Cursors are not bearer credentials and do not bypass normal Bearer authentication or RBAC.

### Private signing key

Job-store schema version 4 adds `service_secrets`. Migration from version 3 creates one random 256-bit cursor HMAC key and stores its URL-safe base64 representation in the owner-only SQLite database.

The key:

- is generated with the operating system cryptographic random source;
- is never returned through the API;
- is never written to audit events or reports;
- remains stable across service restarts;
- is covered by the existing owner-only database permissions and backup requirements.

Loss or rotation of the key invalidates outstanding cursors, which is an acceptable fail-closed outcome.

### Authorization and disclosure

Existing permissions remain in force:

- `jobs.read` protects the job feed;
- `schedules.read` protects the schedule feed;
- `audit.read` protects audit events.

Every query remains organization-scoped in SQL. Cursor scope validation occurs before store execution. The API returns lifecycle metadata only and does not expose raw API tokens, authorization documents, report bodies, finding evidence, idempotency keys, or the cursor signing key.

## Consequences

### Positive

- Dashboard list operations are bounded and deterministic.
- New records do not cause offset-based duplicates or gaps.
- Cursors cannot be modified or replayed across tenants, resources, or filter sets.
- Page requests remain efficient as history grows.
- The API now exposes organization scan-job history without exposing private report contents.
- The same cursor framework can support future findings, targets, notifications, and remediation feeds.

### Trade-offs

- Cursors expire and clients must restart pagination after 24 hours.
- Restoring a database without `service_secrets` invalidates prior cursors.
- Exact snapshot isolation across a long multi-page traversal is not provided; newer rows may appear only when pagination restarts.
- SQLite remains a single-host persistence layer.
- A future shared database implementation must preserve equivalent keyset ordering and cursor-key management.

## Alternatives considered

### Offset and limit

Rejected because concurrent inserts can repeat or skip records and large offsets degrade query performance.

### Unsigned timestamp and UUID parameters

Rejected because clients could alter or replay positions across resources and tenant scopes.

### Encrypt cursor payloads

Not required for this milestone. The cursor contains ordering and scope metadata rather than credentials or report content. HMAC authentication prevents modification, while opaque base64 representation avoids making the fields part of the public API contract.

### Return every record

Rejected because activity history is unbounded and would eventually create excessive memory, response-size, and latency costs.

### Return total counts

Deferred. Exact counts add database work and are not required to navigate activity feeds. Product analytics may use separately maintained aggregates later.

## Verification

Milestone tests cover:

- page-limit and query validation;
- canonical filter ordering;
- deterministic cursor round trips;
- signature modification rejection;
- organization, resource, and filter replay rejection;
- expiry handling;
- stable, descending, non-overlapping job pages;
- job state and mode filtering;
- organization isolation;
- stable schedule pages and state filtering;
- audit-event pagination and outcome filtering;
- schema version 3 to 4 migration;
- cursor-key creation and restart stability;
- HTTP job-feed pagination;
- duplicate and unknown query rejection;
- exact feature-branch integration through the authenticated HTTP service.
