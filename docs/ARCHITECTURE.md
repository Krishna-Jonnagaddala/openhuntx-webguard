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

**Slice 12 addition**: a parallel, opt-in production persistence and signing path now exists alongside the local baseline above, not in place of it. `ProductionServiceConfig` (`apps/api/src/webguard_api/production_config.py`) is a separate, fail-closed configuration type that requires PostgreSQL and KMS-backed signing to be explicitly configured — it never silently activates from a missing setting, and the local SQLite/in-memory/local-development-signing baseline described in this section remains the default and the only thing `ServiceConfig` (the pre-existing local config type) can produce. See §7 and §8 below, and `docs/audit/production-platform-phase1-postgres-kms-tenancy.md` for the full slice.

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
- permit-gated active detectors (`xss_reflected_detector.py`, `sqli_error_detector.py`, `ssrf_callback_detector.py`), the generalized attack-surface/candidate discovery model they consume (`attack_surface.py`), the request-template/mutation layer between them (`request_template.py`), the authentication-context/session-application layer that lets any of these run against an authenticated surface (`authentication.py`, `login_workflow.py`), the multi-identity authorization-comparison engine (`authorization_resource.py`, `idor_authorization_detector.py`) that IDOR/BOLA detection is built on, the authenticated crawl/resource-discovery layer (`authorization_crawl.py`, `authorization_resource_discovery.py`, `resource_graph.py`) that turns legitimate authenticated observation into resource pairs for that engine, and the controlled-callback protocol (`callback_broker.py`) SSRF detection is built on — see `docs/audit/active-detection-phase1-xss.md` through `phase10-ssrf-callback.md`.

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

#### Authenticated crawl & authorization resource discovery, added Slice 9

Resource pairs for the engine above no longer need to be entirely
operator-supplied. When a comparison plan sets `enable_discovery`, the
executor runs one small, bounded authenticated crawl per identity and
turns what it legitimately observes into the same `AuthorizationResource`
type Slice 8 already consumes — discovery is a second *source* of
resource pairs, not a second detector, and the classification engine
above is completely unmodified by its existence.

```
AuthorizationComparisonPlan.enable_discovery (authorization_comparison.py)
   v
run_authenticated_resource_discovery_crawl() (authorization_crawl.py), once per identity
   -> crawl_same_origin() (crawler.py: authentication_material now
      threaded through the one shared apply_authentication() mechanism
      -- same-origin/DNS/budget/rate/checkpoint/cancellation controls
      all unchanged from Slice 5)
   -> ResourceDiscoverySink.visit_page() per crawled page
        -> AuthenticationHealthCriterion (login-page/expired-session
           detection -- an unhealthy page halts discovery for that
           identity via the crawl's own CrawlCancellationToken,
           contributes zero resources, never mistaken for content)
        -> HTML-link / JSON-field extraction (authorization_resource_discovery.py),
           bounded, provenance-tagged (IdentifierProvenance), never
           generated or enumerated
   v
AuthorizationResourceGraph (resource_graph.py) -- identity-keyed, deduplicated
   v
build_comparison_pairs() -- deterministic eligibility: distinct
   identities, matching resource_type/method/identifier_location,
   PRIVATE_TO_OWNER on both sides, approved provenance, distinct
   identifier values, matching endpoint template
   v
merged into the SAME resource_pairs list Slice 8's explicit
   resource_scope already populates
   v
run_idor_authorization_detector() -- unchanged
```

A resource shared identically between both identities (same endpoint,
same identifier value, because it is literally the same object) is
excluded from comparison automatically by the "distinct identifier
values" eligibility rule alone — no separate shared/public
classification signal is needed for *discovered* resources to get this
right. Discovery requests flow through the executor's own
`before_request`/`after_request` runtime-safety hooks exactly like
every other request this executor issues, so they count toward the
same TrustScan budget and rate limits. See
`docs/audit/active-detection-phase9-authenticated-resource-discovery.md`
for the full eligibility rules, false-positive controls, and the Juice
Shop discovery validation.

#### Controlled SSRF detection & callback infrastructure, added Slice 10

SSRF (`active.ssrf.callback`, CWE-918) is architecturally distinct from
every prior detector in this project: confirmation depends on
something *receiving* a connection the target's own server makes, not
on anything WebGuard's own client observes in a response. This adds a
new component role — a receiver, not a client — that intentionally sits
outside the request/response cycle every other detector operates
within.

```
CallbackToken/CallbackObservation/CallbackPolicy/CallbackBroker (callback_broker.py, scanner)
   |  protocol only -- register()/wait_for_observation(), zero apps/api dependency
   v
InMemoryCallbackBroker (scanner)         CallbackRepository (callback_service.py, apps/api)
   |  self-contained default                |  multi-tenant wrapper: org/target/authorization
   |  (webguard scan CLI, tests)             |  metadata per registration, one shared broker
   v                                          v
run_ssrf_callback_detector()             _ScanScopedCallbackBroker (executor.py)
   |  RequestTemplate + mutate() (Slice 6,     |  binds one scan's tenancy via closure,
   |  unmodified) -> issue_templated_request    |  satisfies the scanner's protocol exactly
   |  with the callback URL as the probe value
   v
CallbackHttpReceiver (callback_server.py, apps/api)
   |  a real, separately-startable ThreadingHTTPServer -- not embedded
   |  in the detector -- accepting /<scan_id>/<token> and recording an
   |  observation keyed ONLY on the token (never Host header, never
   |  source address)
   v
CONFIRMED (observed in the primary wait window) / PROBABLE (grace
window only) / NOT_VULNERABLE / INCONCLUSIVE / ERROR
   -> NormalizedFinding (CWE-918 + OWASP A10:2021, only for CONFIRMED/PROBABLE)
```

The only destination this detector ever hands to a probe is a callback
URL a `CallbackBroker.register()` call itself produced -- there is no
code path that falls back to, or accepts, an internal address
(127.0.0.1, RFC1918, cloud metadata) to "prove" SSRF, and this
detector's own safety boundary is completely independent of
`scope_validator.py`/`safe_http.py`, which continue to govern
WebGuard's own outbound *client* requests to the target unchanged.
Tokens are `secrets.token_urlsafe`-generated, scan-bound,
candidate-bound, time-limited, and bounded-use; correlation is
token-only, never DNS/Host-dependent, which is what makes it robust to
DNS rebinding or callback-host spoofing by construction rather than by
policy. See
`docs/audit/active-detection-phase10-ssrf-callback.md` for the full
confirmation model, false-positive controls, and documented (not yet
built) production callback-service requirements.

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
- authorization-comparison plan storage (`authorization_comparison.py`) for IDOR/BOLA scanning — a reference-only record (two authentication-context IDs plus an explicit resource scope, never a secret itself), in-memory only for the same reason as authentication-context storage, so it shares the same cross-process persistence limitation; and
- callback registration/receiver infrastructure (`callback_service.py`, `callback_server.py`) for SSRF scanning — a multi-tenant, in-memory correlation store (tokens, not secrets) plus a real, independently-startable local HTTP receiver; not wired into `webguard-api serve`'s default startup this slice, and not yet backed by a public hostname or persistent storage (see `docs/audit/active-detection-phase10-ssrf-callback.md`'s documented production requirements).

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

### Production persistence (PostgreSQL, Slice 12)

A production PostgreSQL schema and a defensible subset of repository implementations now exist alongside the SQLite baseline above — SQLite is not being removed or deprecated by this addition (`docs/audit/production-platform-phase1-postgres-kms-tenancy.md` explains the scoping). Concretely:

- **Full schema, all entities** (`infra/postgres/migrations/`): organizations, principals, memberships (a new append-only role-assignment history not present in SQLite), API tokens, organization-authorization assignments, security audit events, targets/assets, target-verification metadata, callback registrations/observations, and — schema-only, no repository yet — jobs, schedules, scan records, findings, reports, authentication contexts, authorization-comparison plans, and crawl checkpoints.
- **Repository implementations with contract tests proven against both backends** (`postgres_identity.py`, `postgres_targets.py`, `postgres_callback_service.py`, `targets.py`): organizations/principals/tokens/authorizations/audit-events, targets, and callback registrations. Every one of these satisfies the same `Protocol` (`repository_contracts.py`) as its SQLite/in-memory counterpart.
- **Connection pooling** (`postgres_pool.py`): `psycopg_pool`-backed, with a normalized failure taxonomy (`db_errors.py`) translating raw driver exceptions — never a connection string or SQL text reaches a caller.
- **Migrations** (`scripts/run-postgres-migrations.py`): a hand-rolled, checksum-verified runner over numbered `.sql` files, matching this project's existing no-ORM convention (raw `sqlite3` elsewhere; raw `psycopg` here, not SQLAlchemy/Alembic).
- **Deferred repositories** (jobs, schedules, scan records, findings, reports, authentication contexts, comparison plans): schema exists; Python repository classes are explicitly next-platform-slice work, not attempted this slice.

None of this is wired into `webguard-api serve`'s default startup — the local SQLite/in-memory baseline remains what actually runs today. Wiring `ProductionServiceConfig` into the service's real startup path is future work.

## 8. Cryptographic uses

### API tokens

Raw API token secrets are not persisted. The identity store persists scrypt-derived hashes and metadata. Token verification uses constant-time digest comparison.

### Signed crawl checkpoints

Checkpoint integrity uses an operator-controlled signing key. Resume rejects changed policy, changed addresses, invalid integrity, and mismatched scan state.

### Pagination cursors

Opaque cursors are HMAC-SHA256 signed, expiring, and bound to organisation, resource type, and filters.

### TrustScan permits and Safety Receipts

Both use Ed25519. A public verification-key document can be retrieved without authentication. The private seed currently resides in the owner-only SQLite service-secret store.

**Signing abstraction (Slice 12)**: `TrustScanSigner` (`permits.py`) now delegates raw sign/verify operations to a provider-neutral `SigningKeyRegistry` (`signing.py`) rather than holding an Ed25519 key directly — `LocalDevelopmentSigner` (unchanged Ed25519 behavior, the only provider actually wired in today) and `KmsSigningProvider` (AWS KMS-backed, `ECDSA_SHA_256`, built and unit-tested against a duck-typed KMS client but not wired as the active signer) both satisfy the same narrow `SigningProvider` protocol (`sign`, public-key material, key ID, algorithm). Verification now resolves by key ID against a registry of active/retired/disabled keys, enabling rotation that the pre-Slice-12 single-key design could not support. **AWS KMS has no Ed25519 KeySpec** — `KmsSigningProvider` targets `ECDSA_SHA_256` as its own honestly-labeled algorithm and never claims Ed25519 compatibility; an actual algorithm migration remains a separate, explicit, not-yet-made decision (see `signing.py`'s module docstring and `docs/audit/production-platform-phase1-postgres-kms-tenancy.md`).

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
