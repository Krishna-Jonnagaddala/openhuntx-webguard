# OpenHuntX WebGuard Architecture

## 1. Purpose

This document describes the implemented architecture of OpenHuntX WebGuard at the Milestone 1.32 / Checkpoint 1 baseline. It distinguishes current behaviour from planned production architecture so that future changes do not silently expand trust assumptions.

WebGuard is an authorisation-native web security-assurance platform. Its current design prioritises permission, bounded execution, deterministic evidence, and fail-closed behaviour over maximum scan coverage.

## 2. Current deployment status

The current system is a local, single-host engineering foundation:

- the HTTP API binds only to a loopback IP literal;
- the API, identity state, jobs, schedules, permits, and service secrets use a private SQLite database;
- background scanner execution runs from the same host as the control-plane foundation;
- scanner artefacts are written to owner-only local paths; and
- OWASP Juice Shop is used only as an explicitly enabled local integration target.

The current architecture is not approved as a directly internet-exposed SaaS control plane.

## 3. Repository components

### `packages/contracts/python`

Shared, versioned contracts for:

- findings and scan results;
- crawl results, coverage, and termination;
- checkpoints;
- owned-target authorisations and audit records;
- tenancy and audit events;
- jobs and schedules;
- signed pagination cursors;
- TrustScan Scan Permits; and
- TrustScan Safety Receipts.

The contracts package intentionally has no external runtime dependency.

### `workers/scanner`

Scanner-side security logic including:

- target and network-scope validation;
- safe HTTP execution;
- retry/error handling and request-attempt audit trails;
- passive analyzers;
- same-origin crawling;
- execution budgets and cancellation;
- checkpoint/resume logic;
- owned-target preflight enforcement;
- runtime hooks used by the TrustScan safety engine; and
- permit-gated active detectors (`xss_reflected_detector.py`, `sqli_error_detector.py`) and the generalized attack-surface/candidate discovery model they consume (`attack_surface.py`) — see `docs/audit/active-detection-phase1-xss.md` through `phase5-attack-surface-discovery.md`.

### `apps/api`

The local control-plane foundation including:

- loopback HTTP transport;
- organisation/principal/token identity;
- RBAC;
- organisation-scoped authorisation assignments;
- job and schedule services;
- worker leases and recovery;
- signed pagination cursors;
- TrustScan permit signing, validation, and revocation;
- TrustScan runtime safety orchestration;
- TrustScan Safety Receipt persistence; and
- active-detector orchestration (`executor.py`'s `_apply_active_detection`), which runs the same authorized-detector loop against every candidate the scanner's attack-surface discovery finds, regardless of which interface (CLI or API) requested the scan.

### `infra/compose`

Contains the isolated, explicitly authorised OWASP Juice Shop integration environment. The lab service is bound to `127.0.0.1`, runs with all Linux capabilities dropped, uses `no-new-privileges`, and is constrained by process, memory, and CPU limits.

### `tests`

- `tests/unit` contains deterministic tests that should not require external network access.
- `tests/integration` is opt-in and requires `WEBGUARD_RUN_INTEGRATION=1`.

## 4. High-level architecture

```text
Operator / local API client
        |
        | Bearer token
        | TrustScan-Permit ID on job/schedule creation
        v
+-------------------------------------------------------+
| Loopback WebGuard control plane                       |
|                                                       |
|  Authentication -> RBAC -> tenant-scoped service      |
|       |                 |                             |
|       |                 +--> audit events             |
|       |                                               |
|       +--> authorisation assignment checks            |
|                                                       |
|  TrustScan permit authority                           |
|       +--> Ed25519 signing / verification             |
|       +--> immutable claims + mutable revocation       |
|                                                       |
|  SQLite state                                         |
|       +--> organisations / principals / token hashes  |
|       +--> jobs / schedules / leases                  |
|       +--> permits / receipt references               |
|       +--> cursor HMAC + TrustScan signing seed       |
+---------------------------+---------------------------+
                            |
                            v
                 Lease-aware background worker
                            |
                 server-side auth reload
                 permit signature/state check
                            |
                            v
                 TrustScan runtime safety engine
                            |
                 before each outbound request
                            |
                            v
                 scanner target validation
                            |
                            v
                     safe HTTP client
                            |
                            v
                  explicitly authorised target
                            |
                            v
             bounded passive analysis / crawling
                            |
                            v
             report + audit + signed Safety Receipt
```

## 5. Principal execution flow

### 5.1 Identity and API request

1. The local API receives an HTTP request on a loopback address.
2. Public endpoints are limited to health and the TrustScan public verification key.
3. Protected endpoints require exactly one Bearer `Authorization` header.
4. The token ID selects stored token metadata; the token secret is verified against an scrypt hash.
5. The organisation and principal must still be active.
6. The request is evaluated against the role-to-permission map.
7. Service methods scope state access by the authenticated organisation.
8. Security-relevant actions are recorded as organisation-scoped audit events.

### 5.2 Authorisation and permit issuance

1. An owned-target authorisation document is loaded and strictly validated.
2. The authorisation must be assigned to the authenticated organisation.
3. The requested target must exactly match the canonical target in the authorisation.
4. A permitted role requests a TrustScan permit.
5. Permit claims bind the organisation, authorisation ID and fingerprint, target, validity window, scan modes, HTTP methods, request-attempt budget, request rate, concurrency, and prohibited operations.
6. Claims are signed with Ed25519 and stored with mutable revocation metadata.

### 5.3 Job or schedule creation

1. Job submission requires an idempotency key and a TrustScan permit ID.
2. The server reloads the current authorisation and permit rather than trusting client-provided authority.
3. The permit signature and bindings are validated.
4. The job stores the authorisation and permit fingerprints used for submission.
5. Recurring schedules carry the same binding and are revalidated when materialised.

### 5.4 Worker execution

1. A worker claims a job using a renewable lease and fencing token.
2. The executor reloads the current authorisation and TrustScan permit.
3. Changed, expired, revoked, unbound, or otherwise invalid permission fails closed before network execution.
4. The owned-target preflight validates HTTPS, canonical target equality, public DNS results, host allowlisting, and authorised execution limits.
5. The TrustScan runtime safety engine is attached to scanner request hooks.

### 5.5 Request-boundary enforcement

Immediately before every outbound request, the runtime safety engine:

- increments the attempted-request counter;
- rejects an open safety circuit;
- verifies same-origin scope;
- verifies the HTTP method;
- verifies the remaining permit request budget;
- verifies the concurrency limit;
- revalidates the current authorisation and permit state;
- applies permit rate throttling; and
- revalidates permission again after any enforced wait.

Only after those checks may the safe HTTP client perform network activity.

The engine observes request errors, HTTP `429`, and HTTP `5xx` responses. Three consecutive protective events open the conservative runtime circuit breaker and prevent further requests.

### 5.6 Terminal evidence

Terminal execution produces or associates private artefacts such as:

- scan JSON;
- owned-target audit evidence;
- HTML reports;
- comparison/remediation evidence; and
- a signed TrustScan Safety Receipt.

The Safety Receipt records what the runtime safety engine enforced and observed. It does not claim zero impact and does not certify that the target is secure.

## 6. Trust boundaries

### Boundary A — operator to local API

Untrusted input crosses into authenticated API handling. Controls include strict header/body parsing, bounded request size, Bearer authentication, RBAC, request IDs, and per-token process-local rate limiting.

### Boundary B — tenant context to persistent state

Every tenant-owned resource must be read or mutated through organisation-scoped queries or explicit ownership validation. Identifiers alone do not grant access.

### Boundary C — authorisation record to TrustScan permit

The permit does not replace the underlying authorisation. It cryptographically narrows an existing authorisation and binds to its SHA-256 fingerprint.

### Boundary D — scheduler/job queue to worker

A queued job is not itself permission to send traffic. The worker revalidates the authorisation and permit at execution time. Worker leases and fencing prevent stale workers from finalising state after lease recovery.

### Boundary E — scanner to network

This is the most important network safety boundary. Target validation, owned-target preflight, the runtime safety engine, and the safe HTTP client all apply before or during network execution.

### Boundary F — execution to customer evidence

Reports, audits, checkpoints, permits, and Safety Receipts may reveal customer security posture. They are confidential artefacts and must not be exposed as public content by default.

## 7. Persistence

The current SQLite database contains:

- job queue and lease state;
- recurring schedules;
- organisation and principal records;
- API token metadata and scrypt hashes;
- organisation-to-authorisation assignments;
- security audit events;
- signed TrustScan permit records and revocation state;
- pagination signing material;
- TrustScan Ed25519 private signing material; and
- Safety Receipt references and fingerprints.

The database is owner-only (`0600`). There is currently no application-layer database encryption or external KMS/HSM boundary. That limitation is explicitly tracked for production architecture.

## 8. Cryptographic uses

### API tokens

Raw API token secrets are not persisted. The identity store persists scrypt-derived hashes and metadata. Token verification uses constant-time digest comparison.

### Signed crawl checkpoints

Checkpoint integrity uses an operator-controlled signing key. Resume rejects changed policy, changed addresses, invalid integrity, and mismatched scan state.

### Pagination cursors

Opaque cursors are HMAC-SHA256 signed, expiring, and bound to organisation, resource type, and filters.

### TrustScan permits and Safety Receipts

Both use Ed25519. A public verification-key document can be retrieved without authentication. The private seed currently resides in the owner-only SQLite service-secret store.

## 9. Network safety model

External owned-target execution currently requires:

- HTTPS;
- canonical target equality;
- public-address DNS resolution;
- no loopback/private/link-local/multicast/reserved/unspecified destinations;
- strict authorisation limits;
- redirect blocking;
- approved HTTP methods;
- bounded response headers and bodies;
- bounded retries; and
- passive execution only.

The current external path does not submit forms, execute JavaScript, inject active payloads, brute-force credentials, enumerate directories, exploit vulnerabilities, or follow redirects.

## 10. Failure posture

Security-sensitive ambiguity should fail closed. Examples include:

- unsupported or changed authorisation;
- invalid or revoked TrustScan permit;
- signature verification failure;
- permit/organisation/target/mode mismatch;
- exhausted request budget;
- same-origin escape;
- unsupported HTTP method;
- unsafe DNS result;
- redirect response;
- stale worker lease; and
- invalid signed checkpoint or cursor.

Controlled failures use stable error codes where possible so that callers can distinguish policy denial from transient execution failure.

## 11. Supply-chain and CI boundary

Checkpoint 1 C1-001 established reproducible CI inputs:

- reviewed SHA-256 locks for external Python dependencies;
- exact Python patch versions in CI;
- immutable GitHub Action commit SHAs;
- a fixed Ubuntu runner family; and
- a digest-pinned OWASP Juice Shop integration image.

The repository verification gate checks these pins before compiling and running tests.

## 12. Current limitations

The current architecture intentionally does not yet provide:

- a public multi-node control plane;
- a production web dashboard;
- customer-hosted scanner runners;
- distributed rate limiting;
- hosted secrets management or KMS/HSM key custody;
- production domain-control verification;
- SSO/enterprise identity federation;
- regional data-sovereignty controls; or
- formal high-availability/disaster-recovery architecture.

Those are roadmap items, not current product claims.

## 13. Architecture-change rule

Changes that alter a trust boundary, persistent schema, authorisation semantics, cryptographic format, network safety invariant, tenant boundary, or runner isolation requirement must be accompanied by tests and an ADR before release.
