# Production Infrastructure Requirements

## Status

This document extracts real infrastructure requirements from the scanner architecture actually built across Slices 1-11 — not from an aspirational platform roadmap written before the scanner existed. **No infrastructure is provisioned by this document.** It exists so that when infrastructure decisions are made, they are made deliberately, against the real shape of the system, not against assumptions.

## What the current architecture actually is

- **API/control plane**: `webguard-api serve` — a single-process, loopback-only (`127.0.0.1`) HTTP server. Not designed to be exposed to the public internet as-is.
- **Job store**: SQLite, single file, lease-based worker dispatch with heartbeat renewal and crash recovery. No message queue.
- **Identity/RBAC/audit**: SQLite (organizations, principals, scrypt-hashed API tokens, audit events).
- **Artifacts**: local filesystem (reports, safety receipts, owned-target audit files), with ownership/atomic-write/no-symlink hardening.
- **Secrets**: TrustScan permit signing key is a locally-generated Ed25519 key stored via the service's own secret file (`service_secret_path`), not a KMS/HSM.
- **Authentication contexts, authorization-comparison plans, callback registrations**: in-memory only, per-process, never persisted. Explicitly, repeatedly re-affirmed as deliberate across Slices 7, 8, 10 — never store raw secrets in SQLite as a stand-in for real KMS-backed storage.
- **SSRF callback receiver**: a real, separately-startable local `ThreadingHTTPServer`, not currently bound to any public hostname.
- **Worker/scheduler**: separate long-running processes (`webguard-api worker`, `webguard-api scheduler`), currently expected to run on the same host/filesystem as the API (they share the SQLite file directly).
- **Owned-target authorization**: self-attested JSON documents on the local filesystem; no DNS/domain-ownership verification exists.

## Requirement extraction, by category

### PostgreSQL

**Required for**: multi-instance API/worker deployment (SQLite does not support concurrent writers across hosts), and for building the finding-lifecycle store (`first_seen`/`last_seen`, dedup by fingerprint) that `docs/scanner/SCANNER_V1_LIMITATIONS.md` identifies as absent today. **Not required for**: a single-host, single-operator deployment — the current SQLite design is functionally complete (tested lease/crash-recovery/cancellation) for that case. **Data actually needing a schema**: organizations, principals, API tokens (hashed), authorizations, TrustScan permits, jobs/schedules, audit events, and — new — a `findings`/`finding_occurrences` table if finding-lifecycle tracking is built.

**Slice 12 update**: this requirement is now substantially delivered as design/foundation, not yet as a live deployment. Full schema exists for every entity listed above (`infra/postgres/migrations/`), with a checksum-verified migration runner (`scripts/run-postgres-migrations.py`) proven against a real PostgreSQL 16 instance. Repository implementations with cross-backend contract tests exist for organizations/principals/tokens/authorizations/audit-events, targets, and callback registrations; jobs/schedules/scan-records/findings/reports/authentication-contexts/comparison-plans have schema but no repository classes yet (explicitly deferred to the next platform slice — see `docs/audit/production-platform-phase1-postgres-kms-tenancy.md`). **Callback-registration durability has moved from "explicitly not to migrate" to "migrated, with a caveat"**: `PostgresCallbackRegistrationRepository` now provides durable, tenant-isolated storage for callback registration/observation *metadata*, superseding this document's prior blanket "do not persist callback-registration references to Postgres" guidance for that one entity specifically — but the live, real-time wait/correlate mechanism a running scan actually uses remains the in-memory `InMemoryCallbackBroker`, unchanged. Authentication-context and comparison-plan *secrets* remain explicitly out of scope for any relational store, unchanged from this document's original guidance — only their non-secret metadata has a deferred schema (`authentication_contexts`, `authorization_comparison_plans` tables), and no secret column exists on either.

### Queue / Redis

**Required for**: true horizontal worker scaling across hosts, and for callback-wait coordination if the SSRF detector's polling loop needs to span multiple API-server instances rather than one process's memory. **Not required for**: the current single-host deployment shape — SQLite leases already provide correct-under-crash dispatch semantics, just not cross-host ones.

### Workers

**Required**: containerized worker processes that can scale horizontally once job/permit/callback state lives somewhere shared (Postgres + Redis, not SQLite + in-memory). The worker's *logic* (lease renewal, cancellation, active-detector orchestration) needs no change — only its state backend does.

### Object storage

**Required for**: reports/artifacts/safety-receipts once more than one worker host needs to read/write them, or once retention/lifecycle policies (per `docs/ROADMAP.md`'s "Data and regional controls") need enforcing centrally rather than per-filesystem. **Not required for**: the current single-host deployment.

### Secret/KMS

**Required for**: TrustScan permit signing-key custody (currently a local file), and for any future persisted authentication-context/callback-registration secret material. `docs/THREAT_MODEL.md` already states this requirement independently ("KMS/HSM-backed key custody, key versions, rotation, audit, incident revocation/distrust procedures"). This is one of the highest-priority production gaps: a compromised local signing key today can forge permits with no rotation/revocation path.

**Slice 12 update**: the rotation/revocation gap is closed at the abstraction layer — `SigningKeyRegistry` (`apps/api/src/webguard_api/signing.py`) supports active/retired/disabled key states and key-ID-based verification today, for whichever provider is active. The KMS *custody* gap is not yet closed in production: `KmsSigningProvider` is built and unit-tested against a duck-typed KMS client, and `infra/terraform/signing.tf` provisions (unapplied) the AWS KMS key it would use, but `LocalDevelopmentSigner` remains the only provider actually wired into any running WebGuard process. **AWS KMS cannot satisfy the existing Ed25519 requirement** — its asymmetric `KeySpec` options have no Ed25519/EdDSA entry — so `KmsSigningProvider` targets `ECDSA_SHA_256` as a distinct, honestly-labeled algorithm rather than silently downgrading or misrepresenting Ed25519 compatibility. AWS CloudHSM (general-purpose, PKCS#11-reachable, genuine Ed25519 support) is the recommended path if HSM-backed Ed25519 custody specifically is required; migrating TrustScan's active algorithm to ECDSA_SHA_256 via KMS instead remains a separate, explicit, not-yet-made permit-schema/security decision.

### Callback service

**Required for**: SSRF detection against any real-world (non-loopback) target. The scanner-side interface (`CallbackBroker` protocol) is already designed to make this a drop-in swap — no detector code needs to change. Concretely needed: a stable, WebGuard-controlled public hostname (e.g. `callback.openhuntx.com`), TLS termination, wildcard or token-based path routing, rate limiting/abuse controls (a public receiver is itself an abuse target), short-lived correlation storage (Redis or Postgres with TTL, not in-process memory), and DNS that does not rebind between token issuance and observation — the correlation model is already token-only (never Host/source-address-trusting), which is exactly what makes it safe to move behind a real DNS name without weakening the security property.

### Web/API (public-facing)

**Required for**: any hosted, multi-tenant product. The current API is intentionally loopback-only; a public-facing version needs, at minimum, TLS termination, a real reverse proxy/WAF layer, and rate limiting beyond the current `FixedWindowRateLimiter` (which is in-process and per-instance, not shared across a horizontally-scaled deployment).

### Monitoring

**Required for**: any production operation. Today: in-process counters only (attempted/permitted/blocked request counts), nothing exported externally. Needed: metrics/tracing export (the runtime-safety engine's own before/after-request hooks are already a natural instrumentation point), alerting on worker-lease staleness and callback-receiver health, and audit-event export for compliance/SIEM ingestion.

### Email

**Not built at all.** Needed eventually for account verification, job-completion notifications, and incident communication — no code exists for this today, and it is not a scanner-engine concern (correctly out of scope for this audit's focus).

## What NOT to build first

The scanner engine's own architecture already answers several questions an infrastructure plan might otherwise guess at:
- Do not build a version-aware TrustScan permit loader speculatively — see `docs/audit/trustscan-permit-schema-policy.md`'s decision (below) that permits should remain short-lived, reissuable capability tokens.
- Do not persist authentication/comparison-plan/callback secrets to Postgres merely because Postgres exists — the KMS/secret-manager boundary should arrive first.
- Do not build a public callback service before deciding the DNS/TLS/abuse-control model; the interface is ready, the endpoint is not.

## Permit schema production policy (resolves a previously-deferred decision)

`docs/audit/trustscan-permit-schema-policy.md` correctly left "support old permit versions vs. reject with migration" undecided until a real production deployment made the question concrete. This document now decides it, given the architecture actually built: **reject old versions, no migration path needed.** TrustScan permits are short-lived (`expires_at` bounded to days in every real usage pattern observed across this project's own E2E tests), narrowly-scoped, single-campaign capability grants — not long-lived stored entities with independent lifecycles. A schema bump simply means: any permit issued under the old schema that hasn't already been consumed expires normally and the operator re-issues a new one under the current schema. There is no persisted permit *data* that needs migrating, because a permit carries references, not state. Revisit this decision only if permits are ever redesigned to be long-lived (e.g., a standing "always-on monitoring" grant) — that would be a different object with different lifecycle requirements, not an incremental change to the current model.
