# ADR 0022: Organizations, API Authentication, and RBAC

- Status: Accepted
- Date: 2026-08-06
- Milestone: 1.27

## Context

Milestone 1.26 introduced a loopback-only HTTP API, persistent scan-job queue, and background worker. That control plane did not yet authenticate callers or isolate jobs by customer organization. A corporate security product cannot expose scan submission, cancellation, result references, authorization records, or audit history without a clear tenant boundary and an accountable principal.

## Decision

WebGuard adds a versioned tenancy contract and a SQLite-backed identity layer in the existing private service database.

The identity model contains:

- organizations with active or disabled status;
- user and service-account principals;
- roles: owner, administrator, analyst, and viewer;
- API-token metadata, expiry, revocation, and last-use timestamps;
- explicit organization-to-target-authorization assignments;
- immutable security audit events.

API tokens use the format `wgt_<token-id>_<secret>`. Only an scrypt-derived secret hash is persisted. The raw token is returned once when created and is never included in job records, API responses, audit events, or report artifacts.

All `/v1/*` routes require exactly one Bearer token. `/healthz` remains unauthenticated. Authenticated requests receive a generated canonical request UUID through `X-Request-ID`, and controlled errors include the same identifier.

RBAC is enforced as follows:

- owner and administrator: all current job and audit actions;
- analyst: submit, read, and cancel jobs;
- viewer: read job status and results only.

Jobs are associated with an organization in a dedicated scope table. Reads and cancellation use organization-scoped lookup and return `404` for cross-tenant identifiers to avoid disclosing job existence. Client idempotency keys are transformed into organization-scoped digests before persistence, preventing collisions between tenants without exposing the original key.

Owned-target authorization documents must be explicitly assigned to the caller's organization before a job can be submitted. The scanner worker continues to revalidate the server-side authorization at execution time. Service-generated artifacts are placed under organization-specific directories when the job has tenant scope.

A process-local fixed-window rate limiter is added per API token. It is a local safety foundation, not a distributed production quota system.

The HTTP server remains loopback-only. Public deployment, browser sessions, SSO, password login, distributed rate limiting, and multi-node database coordination remain out of scope.

## Security properties

- raw API tokens are not persisted;
- token comparison uses a memory-hard scrypt hash and constant-time comparison;
- expired and revoked tokens fail authentication;
- disabled principals or organizations cannot authenticate;
- authorization assignment and job access are organization-scoped;
- viewer and analyst permissions are explicitly bounded;
- audit events record organization, principal, token, request ID, action, resource, outcome, time, and controlled detail code;
- report bodies and authorization contents are not returned by job-status endpoints;
- database and artifact permissions remain owner-only;
- API binding remains restricted to loopback addresses.

## Consequences

Operators must bootstrap an organization, owner principal, and API token before using protected API routes. Existing local job databases are upgraded additively with identity and job-scope tables. Legacy unscoped jobs remain readable only through internal store methods and are not exposed through authenticated tenant-scoped API operations.

A future production milestone must replace the process-local rate limiter and local SQLite identity store with deployment-appropriate shared infrastructure before horizontal scaling or public exposure.
