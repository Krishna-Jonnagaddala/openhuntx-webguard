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
- permit-gated active detectors (`xss_reflected_detector.py`, `sqli_error_detector.py`), the generalized attack-surface/candidate discovery model they consume (`attack_surface.py`), the request-template/mutation layer between them (`request_template.py`), the authentication-context/session-application layer that lets any of these run against an authenticated surface (`authentication.py`, `login_workflow.py`), and the multi-identity authorization-comparison engine (`authorization_resource.py`, `idor_authorization_detector.py`) that IDOR/BOLA detection is built on — see `docs/audit/active-detection-phase1-xss.md` through `phase8-idor-bola.md`.

Active-detection data flow, current as of Slice 7 (single-identity detectors — XSS, SQLi):

```
Discovery (attack_surface.py)
   -> AttackSurfaceCandidate (endpoint, method, input location, safety classification)
   -> RequestTemplate (request_template.py: query/form/JSON shape, no secrets)
   -> mutate() (one parameter changed, everything else preserved)
                                AuthenticationContext (authentication_contexts.py, apps/api)
                                     |  metadata: org/target/authorization/identity label/status
                                     |  secret: AuthenticationMaterial, resolved separately, in-memory only
                                     v
   -> apply_authentication() (authentication.py: adds Authorization/Cookie, or nothing if unauthenticated)
   -> issue_templated_request() / issue_probe() / fetch_same_origin_page() (safe_http, same-origin + runtime-safety hooks)
   -> xss_reflected_detector.py / sqli_error_detector.py (classification)
   -> NormalizedFinding
```

`AuthenticationContext` metadata (organization/target/authorization
binding, identity label, method, status) is safe to log and audit.
Secret material (`AuthenticationMaterial` -- a bearer token, session
cookies, basic-auth credentials) is looked up separately, held only in
memory for the duration of one request-issuance call, and is never
attached to a `RequestTemplate`, a `NormalizedFinding`, a report, an
audit event, or a checkpoint -- `apply_authentication` is the *only*
place headers carrying it are constructed, and it is applied
immediately before a request is sent, never stored alongside it
afterward. A TrustScan permit's signed `authentication_context_id` claim
binds *which* context a scan may use; it never contains the secret
itself. See `docs/audit/active-detection-phase7-authenticated-scanning.md`
for the full secret/session lifecycle, expiration/revocation, and login
verification model.

Representability (can a request of this shape be built and mutated) is
independent of authorization (is this detector, this HTTP method, this
target, this budget, this authentication context allowed to be used to
send it). `RequestTemplate`/`mutate` only answer the first question; the
TrustScan permit's `active_checks`, `allowed_http_methods`, and
`authentication_context_id` claims, enforced by the executor and the
runtime safety engine, answer the second — unchanged by this layer's
existence.

#### Authorization-comparison (IDOR/BOLA) data flow, added Slice 8

IDOR/BOLA detection is architecturally separate from the single-
identity detectors above, not a variant of them: it compares behavior
across *two* controlled identities rather than classifying one
response in isolation, so it runs through a dedicated orchestration
path instead of the generic `ACTIVE_DETECTOR_REGISTRY` used by
`active.xss.reflected`/`active.sqli.error`
(`COMPARISON_ACTIVE_CHECK_IDS` tracks check IDs that opt out of that
per-page dispatch table for this reason).

```
AuthorizationComparisonPlan (authorization_comparison.py, apps/api)
   |  references: primary_context_id, secondary_context_id (two
   |  AuthenticationContexts -- never a reinterpretation of the
   |  single-identity authentication_context_id claim), an explicit
   |  operator-supplied resource_scope (ResourcePairSpec list) --
   |  never a generated or enumerated identifier
   v
_resource_pair_from_spec() (executor.py)
   -> AuthorizationResource x2 (authorization_resource.py: structural
      resource_id = SHA-256 of endpoint+method+identifier location/
      name/value only -- never response content)
   v
run_idor_authorization_detector() (idor_authorization_detector.py)
   -> apply_authentication() (the same Slice-7 mechanism, once per
      identity -- baseline A->A, baseline B->B, cross A->B, cross B->A)
   -> content-fingerprint differential classification
   -> CONFIRMED / PROBABLE / INCONCLUSIVE / NOT_VULNERABLE / ERROR
   -> NormalizedFinding (CWE-639 + OWASP-API, only for CONFIRMED/PROBABLE)
```

A permit's `authorization_comparison_plan_id` claim (schema 1.3) is a
second, independent signed reference alongside `authentication_context_id`
— the plan references two contexts, the permit references the plan.
Both the plan and both contexts are validated (organization/target/
authorization/active-status) at permit-issuance time and again at
execution time. A permit can carry this claim only if `active_checks`
also includes `active.authorization.idor`; the reverse is equally
enforced — referencing the plan without requesting the check, or
requesting the check without a plan, are both rejected. See
`docs/audit/active-detection-phase8-idor-bola.md` for the full
classification logic, false-positive controls, and safety budgets.

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
- TrustScan Safety Receipt persistence;
- active-detector orchestration (`executor.py`'s `_apply_active_detection`), which runs the same authorized-detector loop against every candidate the scanner's attack-surface discovery finds, regardless of which interface (CLI or API) requested the scan; and
- authentication-context metadata/secret storage (`authentication_contexts.py`) for authenticated scanning — deliberately in-memory only this slice, not SQLite (see its module docstring and `docs/audit/active-detection-phase7-authenticated-scanning.md` for why), so it does not yet persist across separate CLI/worker process invocations; and
- authorization-comparison plan storage (`authorization_comparison.py`) for IDOR/BOLA scanning — a reference-only record (two authentication-context IDs plus an explicit resource scope, never a secret itself), in-memory only for the same reason as authentication-context storage, so it shares the same cross-process persistence limitation.

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
