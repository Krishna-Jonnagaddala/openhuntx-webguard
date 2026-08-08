# WebGuard Stability & Security Audit — Checkpoint 1

## Phase 2 — Authentication, Authorization & Tenant Isolation

Date: 2026-08-08

Baseline:

`76f5345`

Audit branch:

`audit/checkpoint1-phase2-auth-tenant-isolation`

## Scope

Phase 2 reviewed the WebGuard control-plane boundaries responsible for:

- API token authentication
- organization and principal isolation
- RBAC enforcement
- job tenant isolation
- schedule tenant isolation
- TrustScan permit tenant isolation
- authorization assignment boundaries
- idempotency-key isolation
- activity-feed and pagination cursor isolation
- revoked and expired credentials
- disabled principals and organizations
- request-rate enforcement at the authentication boundary
- signed TrustScan permit integrity
- real HTTP transport tenant isolation

The review used adversarial tests rather than relying only on expected-path
service tests.

## Findings

### P2-001 — Cross-tenant idempotency collision

Status: CLOSED — NOT A VULNERABILITY

An initial direct-store test suggested that identical client-provided
idempotency keys could collide globally.

Further review showed that this bypassed the service boundary.

WebGuard derives the persisted idempotency key from both:

- organization identity
- client-provided idempotency key

Identical client keys submitted by separate tenants therefore create
independent jobs, while replay inside the same tenant returns the original
job.

No production change was required.

## P2-002 — Authentication attempts bypass rate limiting

Severity: Medium

Status: CONFIRMED — REMEDIATED

### Initial condition

The authenticated API rate limiter executed only after successful API-token
authentication.

Invalid credentials therefore entered token verification before any
rate-limit decision was applied.

Repeated failed authentication attempts against a known token identifier
could consequently cause repeated expensive secret verification without
consuming the authenticated request quota.

The current WebGuard HTTP service is restricted to loopback addresses, which
reduces present exposure, but the behavior was not suitable for a future
remote control plane.

### Initial remediation

A pre-authentication failure bucket was introduced.

The bucket used:

- the canonical token identifier when a structurally valid WebGuard token
  identifier was available
- otherwise the peer IP address

The secret portion of a token is never used as a rate-limit key.

Sequential adversarial testing confirmed that repeated invalid secrets were
rate limited before repeated authentication work.

### Concurrency finding during remediation validation

WebGuard uses a threaded HTTP server.

An adversarial concurrency test demonstrated a check-then-authenticate race
in the first remediation:

1. request A checked available capacity
2. request B checked the same available capacity
3. both entered authentication
4. failure capacity was consumed only afterward

Both requests therefore crossed the expensive authentication boundary even
though one eventually received HTTP 429.

The remediation was considered incomplete until this race was removed.

### Final remediation

The final implementation atomically consumes a pre-authentication
reservation before token verification.

Behavior is now:

1. derive a secret-free authentication-failure key
2. atomically consume pre-authentication capacity
3. reject with HTTP 429 before authentication when capacity is exhausted
4. authenticate the credential
5. retain the reservation when authentication fails
6. release exactly one reservation when authentication succeeds
7. apply the existing authenticated per-token request quota

A successful request releases only its own reservation. It does not reset
the entire failure bucket, so concurrent failed authentication attempts
cannot be erased by a successful request.

### Security properties verified

- repeated invalid secrets are rate limited
- distinct invalid secrets for the same token identifier share the failure
  boundary
- concurrent requests cannot both bypass the pre-authentication reservation
- a rejected concurrent request does not enter authentication
- successful authentication refunds only one reservation
- existing authenticated per-token quotas remain isolated
- raw token secrets are not included in limiter keys

### Deployment note

The current mitigation is appropriate for the existing loopback-only
WebGuard API.

A future remotely exposed SaaS control plane should use distributed,
edge-enforced authentication-abuse controls combining appropriate network
and identity signals rather than relying only on an in-process limiter.

This is a production-hardening requirement, not a new Phase 2 vulnerability.

## Tenant-isolation results

### Jobs

Verified that a foreign tenant cannot:

- read a job
- read a job result
- cancel a job
- distinguish a foreign job from an unknown job

### TrustScan permits

Verified that a foreign tenant cannot:

- read a permit
- revoke a permit
- use a permit to authorize a job
- use a permit to create a schedule

### Schedules

Verified that a foreign tenant cannot:

- read a schedule
- pause a schedule
- resume a schedule
- enumerate another organization's schedules

### Pagination and activity feeds

Verified that signed cursors are bound to:

- organization
- resource type
- filters

Cross-tenant cursor replay is rejected.

Job, schedule, and audit feeds return data only for the authenticated
organization.

### RBAC and credential state

Verified:

- malformed Authorization headers fail closed
- ambiguous Authorization headers fail closed
- Bearer scheme matching is case-insensitive
- revoked tokens are rejected
- expired tokens are rejected
- disabled principals are rejected
- disabled organizations are rejected
- persisted principal role determines authorization
- Viewer permissions remain read-only
- Analyst permissions remain limited to the intended operational actions
- Owner and Administrator retain their intended complete permissions

No HTTP endpoint currently exposes principal-role mutation or authorization
assignment to lower-privileged principals.

### TrustScan permit integrity

Persisted signed permit material was deliberately modified in temporary test
databases.

Verified fail-closed behavior for changes to:

- Ed25519 signature
- organization claim
- authorization identifier
- authorization fingerprint
- target
- permitted mode
- request-attempt budget

Tampered permits could not create jobs or schedules.

An untampered persisted permit remained usable as the positive control.

Organization-claim corruption that made the persisted permit document
internally inconsistent was rejected as:

`trustscan_permit_document_invalid`

No job was persisted.

## Validation evidence

Phase 2 adversarial suite:

- 55 tests
- PASS

Complete unit suite:

- 963 tests
- PASS

Repository verification gate:

- supply-chain pin verification — PASS
- security-governance verification — PASS
- Python compilation — PASS
- unit tests — PASS
- integration opt-in enforcement — PASS

Security gates:

- repository secret scan — PASS
- 203 repository files checked before this audit record was added
- Ruff security/static analysis — PASS
- dependency advisory audit — PASS
- 6 exact locked packages checked

Authorised OWASP Juice Shop integration suite:

- 14 tests
- PASS

The Juice Shop integration target was the local explicitly authorised lab:

`http://127.0.0.1:3000/`

## Phase 2 conclusion

Confirmed findings:

- P2-002 — Medium — Remediated

Closed false alarms:

- P2-001 — Not a vulnerability

Unresolved Critical findings:

- None

Unresolved High findings:

- None

Authentication, authorization, tenant isolation, pagination scope,
TrustScan permit binding, and the authentication rate-limit boundary passed
the Phase 2 adversarial validation performed in this checkpoint.
