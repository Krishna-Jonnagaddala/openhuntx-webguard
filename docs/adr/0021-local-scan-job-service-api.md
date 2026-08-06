# ADR 0021: Local scan-job service API and persistent queue

- Status: Accepted
- Date: 2026-08-06

## Context

WebGuard's scanner, owned-target readiness gate, report contracts, and professional reporting were available through the local CLI. A corporate SaaS control plane needs an API-facing execution boundary, durable job metadata, idempotent submission, cancellation, and a background worker without weakening the scanner's scope and authorization controls.

Publishing a remotely reachable service at this stage would be premature. Customer identity, asset ownership verification, authentication, tenant isolation, distributed secrets management, production observability, and deployment hardening are not yet complete.

## Decision

Milestone 1.26 introduces a standard-library-only local control-plane foundation under `apps/api`.

### Binding and transport

- The API accepts loopback IP literals only (`127.0.0.1` or `::1`).
- `0.0.0.0`, public addresses, interface hostnames, and remote binding are rejected.
- Requests and responses use bounded JSON over HTTP/1.1.
- Job submission requires exactly one `Idempotency-Key` header and an exact owned-target authorization confirmation.
- Transfer-Encoding is rejected and request bodies require a bounded Content-Length.
- Responses use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

### API surface

The initial API exposes:

- `GET /healthz`
- `POST /v1/jobs`
- `GET /v1/jobs/{job_id}`
- `POST /v1/jobs/{job_id}/cancel`
- `GET /v1/jobs/{job_id}/result`

The API returns lifecycle metadata and safe relative artifact references. It does not return authorization documents, authorization fingerprints, idempotency keys, scan report bodies, or audit document bodies.

### Job contracts and lifecycle

A versioned `1.0` scan-job contract defines:

- execution modes: `single_page` and `crawl`
- states: `queued`, `running`, `completed`, `completed_with_errors`, `failed`, and `cancelled`
- canonical timestamps, UUIDs, state transitions, error projections, and safe relative artifact references
- strict JSON loading with unknown-field, duplicate-key, encoding, and size rejection

Result-backed failed and cancelled jobs may retain their machine-readable report and authorization audit. Service failures expose a controlled error and no result artifacts.

### Persistence and idempotency

- Job metadata is stored in an owner-only SQLite database.
- Queue claiming and lifecycle transitions use immediate transactions and revision checks.
- Idempotency keys are unique.
- Replaying the same key and canonical request returns the original job.
- Reusing a key for a different canonical request returns a conflict.

### Authorization enforcement

- The service loads authorization documents only from one configured private directory.
- Authorization files must be regular, non-symlink files with owner-only permissions.
- Duplicate authorization UUIDs are rejected.
- The API verifies the requested target against the server-side authorization before queueing.
- The worker reloads the authorization and verifies its SHA-256 fingerprint immediately before execution.
- Authorization expiry, DNS/public address validation, HTTPS requirements, scope, conservative limits, and the owned-target readiness gate are re-evaluated at execution time.

### Worker and artifacts

- One background worker claims queued jobs from SQLite.
- Crawl cancellation is cooperative and checked between requests through the existing cancellation token.
- Queued jobs cancel immediately; running single-page cancellation remains best effort because an in-flight request is not interrupted.
- The authorization audit is written before scanner execution.
- Reports and audits are stored beneath an owner-only artifact root using generated job UUID directories.
- Only safe relative artifact references are persisted and returned.
- Existing artifacts are never overwritten.
- Unexpected worker exceptions are redacted to a generic internal error.

### Compatibility

- The `webguard` CLI remains unchanged and supported.
- The service uses the same scanner, contracts, readiness gate, and report formats.
- The implementation uses only the Python standard library and existing WebGuard packages.

## Consequences

### Positive

- WebGuard now has a durable control-plane execution boundary suitable for a future dashboard.
- API submissions are idempotent and survive process restarts.
- Scanner execution remains owned-target-authorized, passive, bounded, and audited.
- Job status, cancellation, and result references are available without exposing report bodies.
- SQLite keeps local development simple while preserving transactional queue semantics.

### Limitations

- The service is local-only and must not be exposed through a reverse proxy or public network.
- There is no customer authentication, organization tenancy, RBAC, SSO, billing, or remote asset verification yet.
- SQLite and a single worker are not the final distributed production queue architecture.
- Artifact download endpoints are intentionally absent.
- Running single-page requests cannot be interrupted mid-request.
- Authorization files remain locally managed and do not independently prove legal ownership.

## Rejected alternatives

### Publish the API on all interfaces

Rejected because authentication, tenant isolation, rate limiting, and production deployment controls are not complete.

### Introduce FastAPI, Flask, Celery, Redis, or PostgreSQL immediately

Rejected for this foundation milestone to avoid dependency and deployment complexity before the contracts, lifecycle, and security boundary are stable.

### Store authorization documents inside each job

Rejected because it duplicates security-sensitive data and could allow stale authorization to bypass execution-time revalidation.

### Return complete report bodies through the initial API

Rejected to minimize sensitive-data exposure and keep artifact authorization as a separate future concern.

### Use an in-memory queue

Rejected because process restarts would lose jobs, idempotency records, cancellation requests, and lifecycle evidence.
