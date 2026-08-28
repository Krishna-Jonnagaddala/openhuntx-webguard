# Production Platform Phase 1: PostgreSQL, KMS Signing & Tenant Isolation

## Status

Scanner v1 is feature-frozen (Slice 11). This slice closes the two
production security remediations Slice 11's stabilization audit
flagged, and establishes a PostgreSQL foundation for the future
WebGuard API and web application. **The scanner behaves identically
from an external security perspective** — nothing in this slice
touches a detector, `scope_validator.py`, `safe_http.py`, or any file
under `workers/scanner/src` other than through the unchanged
`CallbackBroker` protocol boundary.

## 1. Callback tenant-isolation remediation (closes Slice 11 item 3)

**Before**: `CallbackRepository.registration_for(token_value)` took
only a token value — isolation rested entirely on the token's entropy,
not an explicit ownership check, unlike every other tenant-owned
resource in this codebase.

**After** (`apps/api/src/webguard_api/callback_service.py`):

- `register()` now records `job_id`/`permit_id` alongside the existing
  `scan_id`/`organization_id`/`target`/`authorization_id`.
- The unscoped `registration_for()` is replaced by
  `get_registration(token_value, *, organization_id)` — fails closed
  with the identical `callback_registration_not_found` signal for both
  an unknown token and a token that belongs to a different
  organization. Token possession alone never bypasses the ownership
  check.
- `wait_for_observation()` now requires `organization_id` and verifies
  ownership before polling — a cross-tenant caller gets
  `callback_registration_not_found` before the wait mechanism (Slice
  10's unchanged `InMemoryCallbackBroker`) is ever touched.
- `revoke_registration(token_value, *, organization_id, now)` is new —
  organization-checked, idempotent, sets `revoked_at`; a revoked
  registration then fails `get_registration` with
  `callback_registration_revoked`, distinct from "not found" (a caller
  who genuinely owns the registration is told it exists and is
  revoked, not lied to that it never existed).
- `record_observation()` (the inbound-request-recording path, called
  by the real HTTP receiver) deliberately takes no `organization_id` —
  the receiver has no caller authentication context at all (it is the
  *target application* connecting back, not an authenticated WebGuard
  API caller); it now also checks `revoked_at` so a revoked
  registration cannot be observed into.
- `apps/api/src/webguard_api/executor.py`'s `_ScanScopedCallbackBroker`
  threads `organization_id`/`job_id`/`permit_id` through to the new
  signatures; `_apply_ssrf_callback_detection` passes `record.job_id`.

Callback token authenticity and bounded-use semantics (`secrets.
token_urlsafe` generation, scan/candidate binding, expiry, bounded
observation count) are entirely unchanged from Slice 10 — this
remediation adds an ownership check in front of that existing
mechanism, it does not touch it.

**New tests**: `tests/unit/test_callback_service.py`'s
`CallbackTenantIsolationTests` (6 tests) — cross-tenant
get/wait/revoke all fail closed identically to an unknown token; the
genuine owner can still read/revoke; revoke is idempotent;
`job_id`/`permit_id` round-trip.

## 2. Signing architecture (closes Slice 11 item 4, requirements 2-3)

**Design**: `apps/api/src/webguard_api/signing.py` introduces a
provider-neutral `SigningProvider` protocol — deliberately narrow
(`sign(message)`, `public_key_material()`, `key_id`, `algorithm`; no
encrypt/decrypt/key-wrap) — with two implementations:

- `LocalDevelopmentSigner` — identical Ed25519 cryptography to every
  prior slice, the fully-supported local/unit/lab backend.
- `KmsSigningProvider` — signs through an injected, duck-typed
  `KmsClientProtocol` matching `boto3`'s KMS client shape
  (`sign(...)`/`get_public_key(...)`), so this codebase never imports
  `boto3` (kept out of `requirements-ci.lock` entirely; a real
  `boto3.client("kms")` satisfies the protocol structurally in
  production, a fake satisfies it in tests).

**The AWS KMS Ed25519 gap**: AWS KMS's asymmetric `KeySpec` values are
RSA_2048/3072/4096 and ECC_NIST_P256/P384/P521/SECG_P256K1 — there is
no Ed25519/EdDSA option. `KmsSigningProvider.algorithm` is
`"ECDSA_SHA_256"`, a distinct, honestly-labeled algorithm; it never
claims Ed25519 compatibility, and it is **not wired as TrustScan's
active signer anywhere in this slice**. `infra/terraform/signing.tf`
provisions (unapplied) the corresponding `ECC_NIST_P256`/`SIGN_VERIFY`
AWS KMS key. **AWS CloudHSM** (a general-purpose HSM reachable via
PKCS#11, which does support Ed25519) is the recommended path if
genuine HSM-backed Ed25519 custody is required — see
`docs/production/PROVIDER_EVALUATION.md`'s Slice 12 correction. Any
actual migration of TrustScan's active algorithm remains a separate,
explicit, not-yet-made permit-schema/security decision.

**Key lifecycle** (requirement 3): `SigningKeyRegistry` holds one
active provider (used for new signatures) plus a set of
`VerificationKey` records (`active`/`retired`/`disabled`), resolved by
key ID at verification time. A permit signed under a now-retired key
still verifies (until it naturally expires); a `disabled` key is
rejected unconditionally — the emergency-revocation case, e.g. a
suspected key compromise, even for an otherwise-genuine signature.

**Backward compatibility**: `permits.py`'s `TrustScanSigner` keeps its
exact pre-Slice-12 constructor (`TrustScanSigner(private_key_bytes)`)
— every existing call site (`cli.py`, `service.py`, 15+ test files)
required zero changes. It now delegates to a `SigningKeyRegistry`
internally; `TrustScanSigner.from_registry(registry)` is the new entry
point for a KMS-backed or multi-key registry. No raw private key is
newly persisted anywhere — `LocalDevelopmentSigner` holds its key
in-process exactly as before, and KMS private key material never
leaves AWS by design.

**New tests**: `tests/unit/test_signing_provider.py` (15 tests) —
`LocalDevelopmentSigner` round-trip, `KmsSigningProvider` against a
fake duck-typed client (algorithm targeting, request shape, failure
normalization, zero `boto3` import), and `SigningKeyRegistry` lifecycle
(unknown key, rotation/retired-key verification, disabled-key
rejection, tampered-message rejection, no private material in
verification-key documents).

## 3. PostgreSQL architecture (requirements 4-9)

**Scope decision** (confirmed with the user before implementation):
full schema for every entity the brief lists "at minimum," but
repository implementations only for the entities directly tied to this
slice's own remediation and identity/ownership chain:

| Entity | Schema | Repository + contract tests |
|---|---|---|
| organizations, principals, memberships, API tokens, organization-authorizations, security audit events | ✅ | ✅ `PostgresIdentityRepository` |
| targets/assets, target-verification metadata | ✅ | ✅ `PostgresTargetRepository` (verification metadata: schema only, no verification mechanism exists yet in any backend) |
| callback registrations/observations | ✅ | ✅ `PostgresCallbackRegistrationRepository` — metadata durability only, see §3.4 |
| jobs, schedules, scan records, findings, reports, authentication contexts, authorization-comparison plans, crawl checkpoints | ✅ | ❌ deferred — see §9 |

### 3.1 No mechanical SQLite→Postgres translation (requirement 5)

UUID columns (not TEXT), `TIMESTAMPTZ` (not ISO strings), explicit
`CHECK` constraints matching each contract enum's real values, foreign
keys everywhere a reference exists, and one genuine schema improvement
over SQLite: `memberships` is a new append-only role-assignment history
table (`organization_id`, `principal_id`, `role`, `assigned_by`,
`assigned_at`) that SQLite's `principals.role` column (a single mutable
current value, no history) has never tracked — created alongside every
`create_principal` call, in addition to (not instead of) the same
fast-read `role` column SQLite uses. Every tenant-owned table carries
`organization_id` directly — no query needs more than one join to
establish tenant ownership.

### 3.2 Migrations (requirement 7)

`scripts/run-postgres-migrations.py` — a hand-rolled runner over
numbered `.sql` files in `infra/postgres/migrations/`, matching this
project's existing no-ORM convention (not Alembic/SQLAlchemy). A
`schema_migrations` table (created by the runner itself) tracks
applied version + SHA-256 checksum; re-running is a safe no-op, and a
migration whose on-disk content changed after being applied is refused
rather than silently re-applied — proven with a real check-then-tamper-
then-verify-rejection test this slice. Applying all 4 migrations from
zero against a fresh PostgreSQL 16 container **is** this project's
"upgrade path" test, since it is the only migration history that
exists yet.

### 3.3 PostgreSQL integration environment (requirement 8)

`infra/compose/compose.postgres.yml` — PostgreSQL 16.10-alpine, pinned
by digest, loopback-bound (`127.0.0.1:5433`), `no-new-privileges`,
dropped capabilities (only `CHOWN`/`DAC_OVERRIDE`/`FOWNER`/`SETGID`/
`SETUID` retained, matching what the official Postgres entrypoint
needs to `chown` its own data directory), `tmpfs`-backed (disposable by
construction), resource-bounded (512MB/1 CPU/256 PIDs), a dev-only
default credential overridable via `WEBGUARD_POSTGRES_PASSWORD` — no
production credential anywhere in the file. Kept in a separate compose
file, separate Docker network, and separate lifecycle from
`compose.lab.yml`'s Juice Shop scan target, per the brief's explicit
instruction.

### 3.4 Callback registration durability — scope, stated plainly

`PostgresCallbackRegistrationRepository` proves durable, tenant-
isolated storage for callback registration/observation *metadata*
(register/get/revoke/record-observation) — it does **not** replace
`InMemoryCallbackBroker`'s real-time wait/correlate mechanism a live
scan actually uses (`wait_for_observation`), which is inherently a
low-latency, in-process operation. Wiring this repository in as the
executor's live callback broker (rather than a durable audit/
introspection store alongside it) is future work — see §9.

### 3.5 Connection management (requirement 12)

`WebGuardPostgresPool` wraps `psycopg_pool.ConnectionPool`. A real bug
was found and fixed during this slice's own testing: the connection
context manager's original broad `except Exception` clause normalized
*every* exception raised inside a borrowed connection — including
application-level exceptions like `IdentityStoreError` — into a
generic `DatabaseUnavailableError`, masking the real error. Fixed to
catch only `psycopg.Error` (which `psycopg_pool.PoolTimeout` already
subclasses, so pool exhaustion is still normalized); a regression test
(`test_application_exception_propagates_unmodified`) now guards this.
`tests/integration/test_postgres_connection_pool.py` (6 tests, against
a real database) proves: connectivity check, rollback after an
exception (the insert is genuinely not visible afterward), connection
release after both success and exception (pool occupancy returns to
baseline after 20/10 iterations), and 20 concurrent writer threads
completing without deadlock or connection leak.

### 3.6 Failure model (requirement 13)

`db_errors.py` normalizes raw `psycopg` exceptions into a closed set:
`DatabaseUnavailableError`, `DatabaseTimeoutError`,
`DatabaseConflictError` (serialization failure/deadlock, retryable),
`DatabaseIntegrityError` (unique/FK/check violation),
`DatabaseNotFoundError`, `DatabaseAuthorizationDeniedError`,
`DatabaseMigrationError` (undefined table/column — schema mismatch,
distinct from generic unavailability). No normalized error message
ever includes the original exception's text (which can contain SQL or
connection parameters) — only a fixed, reviewed message per category.

## 4. Tenant isolation (requirement 6)

Proven with cross-tenant contract tests against a **real** PostgreSQL
instance (not mocked) for every implemented repository:

- Identity: cross-tenant authorization assignment rejected
  (`cross_tenant_assignment_rejected`); audit events are tenant-
  filtered and paginated correctly, Org B sees zero of Org A's events.
- Targets: cross-tenant `get`/`archive` fail with the identical
  `target_not_found` an unknown target ID produces; same URL is
  allowed across different organizations (uniqueness is per-tenant,
  not global) but rejected as a conflict within one organization.
- Callback registrations: cross-tenant `get`/`revoke` fail with the
  identical `callback_registration_not_found` an unknown token
  produces.

Deferred entities (jobs/schedules/scan-records/findings/reports/
authentication-contexts/comparison-plans) have no repository to test
tenant isolation against yet — their schema carries `organization_id`
directly so the same pattern applies the moment a repository is built.

**PostgreSQL RLS decision**: not implemented this slice. Application-
layer authorization (every repository method requires and checks
`organization_id` explicitly) remains the mandatory enforcement
mechanism, consistent with every other tenant-scoped resource in this
codebase (`<resource>_scoped(id, organization_id)`). RLS would be
defense-in-depth on top of that, not a replacement — deferred as its
own explicit decision for a future slice rather than added
speculatively alongside this one, since it interacts with connection-
role design (RLS policies are typically enforced per-database-role,
which this slice's single-application-role connection pool does not
yet model).

## 5. Finding persistence (requirement 10)

`findings` table schema only (no repository). Preserves fingerprint,
check ID, severity, confidence, CWE, OWASP category, asset, endpoint,
method, parameter, scanner/check version, bounded evidence, first/
last-seen timestamps, scan association. **No CVSS column** — nothing
in this codebase computes a CVSS value, and adding a column nothing
populates would misrepresent the schema's own honesty about what data
backs it (`docs/scanner/SCANNER_V1_CAPABILITIES.md`'s existing
position, carried forward unchanged). A `status` column exists with
the full future enum (`open`/`confirmed`/`false_positive`/
`accepted_risk`/`resolved`/`reopened`, defaulting to `open`) so future
lifecycle work fits without a column-shape migration — no lifecycle
UI or transition logic is built this slice.

## 6. Audit persistence (requirement 11)

`security_audit_events` — durable, tenant-scoped (via
`PostgresIdentityRepository`, contract-tested against SQLite),
immutable by construction (no UPDATE/DELETE path exists anywhere in
the repository layer). No secret column exists anywhere in this table
or any deferred audit-adjacent table.

## 7. Configuration (requirement 15)

`apps/api/src/webguard_api/production_config.py` — `ProductionServiceConfig`,
a separate type from the existing `ServiceConfig` (which remains the
untouched local/dev/lab config). Every field required for production
must be present and exactly valid or construction raises immediately:
`environment` must be exactly `"production"`, `database_backend` must
be exactly `"postgresql"`, `signing_provider` must be exactly `"kms"`
— there is no default that could silently activate SQLite, an
in-memory repository, or local development signing. `from_environment()`
reads every required field from a `WEBGUARD_*` environment variable
with no dev-safe fallback for any of them (only the connection-pool
size bounds have defaults, since they have safe production-sized
values rather than a dev-oriented one). 11 unit tests prove every
rejection path plus the happy path from both direct construction and
environment loading.

## 8. Health/readiness (requirement 14)

`/healthz` (pre-existing) and the new `/health` (identical, requirement
14's own naming) remain pure liveness — always 200, no dependency
check, so a transient database outage never fails liveness. New
`/ready` calls `WebGuardJobService.readiness()`, which invokes an
injectable `readiness_check` callable (defaults to a no-op for the
current SQLite deployment, wireable to `WebGuardPostgresPool.
check_connectivity` in production) and reports only `{"status": ...,
"reason": ...}` — a fixed reason code, never the underlying exception
message (which could name a host or connection parameter). 4 new HTTP
tests prove both the ready and not-ready paths, including that a
simulated dependency failure's real exception text never reaches the
response body.

## 9. Infrastructure/IaC (requirements 16-17-18)

`infra/terraform/` — unapplied, hand-reviewed (no Terraform binary or
AWS credentials available in this environment, so `terraform validate`
has not been run against it). Provisions only: a minimal VPC + two
private subnets + DB subnet group + security group (networking
foundation, the minimum RDS itself requires), one `aws_db_instance`
(encrypted, private, RDS-managed master credential via Secrets Manager
— no password anywhere in this configuration or Git), one `aws_kms_key`
(`ECC_NIST_P256`/`SIGN_VERIFY`, the AWS-side counterpart of
`KmsSigningProvider`). Redis/S3/ECS/Cloudflare/Grafana/Postmark are
explicitly not provisioned — see `infra/terraform/README.md`.

`docs/production/BACKUP_RESTORE.md` — new. Specifies RDS automated
backups (7-day default retention, RDS max 35), implicit point-in-time
recovery (inherent to automated backups being enabled, no separate
toggle), encryption inheritance from the source volume, and manual-
snapshot guidance for pre-migration checkpoints. Explicitly states a
backup strategy is not "proven" until restore is tested in a real
deployed environment — which has not happened, because no production
database has been deployed yet.

## 10. Regression (requirement 20)

See the end-of-slice report for exact counts. Summary: full unit suite
green, full contract-test suite green against both backends (SQLite/
in-memory and a real PostgreSQL 16 container), all opt-in integration/
lab/E2E tests green (including the pre-existing SSRF callback E2E lab
test, re-run end-to-end through the modified `executor.py` code path
to prove the tenant-isolation remediation didn't regress it), new
PostgreSQL connection-pool tests green, `ruff --select S` clean, PyPI
dependency advisory audit clean (10 exact locked packages including
the four new PostgreSQL-driver dependencies), `git diff --check` clean.

**Secret scan**: the repository's actual secret-scan gate
(`scripts/scan-secrets.py`) could not be run end-to-end in this
environment — it enumerates files via `git ls-files --others`, which
fails on a pre-existing, untracked, unrelated nested git repository at
`Breach/Checker/breach-checker/` (predates this slice; the user's own
instructions say not to stage or touch `Breach/`). Every file this
slice added or changed was instead scanned directly with the gate's
own `scan_file()` detection function (48 files, zero findings) — the
same detection logic, applied without the enumeration step that a
pre-existing, out-of-scope directory breaks.

## 11. Known limitations

1. **Nothing in this slice is wired into a running production
   deployment.** `ProductionServiceConfig`, `WebGuardPostgresPool`,
   and every Postgres repository exist, are tested against a real
   database, and are ready to be wired in — but `webguard-api serve`'s
   actual startup path still constructs the SQLite/in-memory backend
   exactly as before. Wiring production config into real startup is
   explicitly the next platform slice's work.
2. **Repository implementations for jobs, schedules, scan records,
   findings, reports, authentication contexts, authorization-
   comparison plans, and crawl checkpoints do not exist yet.** Full
   schema does. This was a scope decision confirmed with the user
   before implementation, not an oversight.
3. **`KmsSigningProvider` is not wired as any active signer anywhere.**
   It is built, unit-tested against a fake client, and documented — a
   real `boto3.client("kms")` has never been exercised against it (no
   AWS credentials in this environment).
4. **PostgreSQL RLS is not implemented** — a deliberate, documented
   decision (§4), not an oversight.
5. **`infra/terraform/` has not been validated with the Terraform
   binary** (unavailable in this environment) or applied to any AWS
   account.
6. **Backup/restore has not been tested** — there is no deployed
   database to test it against yet (`BACKUP_RESTORE.md` is design-only
   by necessity).
7. **`target_verifications` has no verification mechanism** in any
   backend — schema only, forward-looking, matching the existing
   "no DNS/domain-ownership verification exists" limitation.
8. **Callback-registration Postgres durability is metadata-only** — it
   does not participate in a live scan's real-time wait/correlate path
   (§3.4).

## 12. Next platform slice

In priority order: wire `ProductionServiceConfig` and
`WebGuardPostgresPool` into `webguard-api serve`'s actual startup path
(behind an explicit environment switch, never a silent default);
repository implementations + contract tests for jobs/schedules/scan-
records (the highest-value remaining gap, since these are what a
horizontally-scaled worker fleet actually needs shared state for);
finding-lifecycle status transitions; a real (non-fake) `boto3`-backed
integration test for `KmsSigningProvider` once AWS credentials are
available in a reviewed environment; PostgreSQL RLS as defense-in-
depth, revisited against whatever connection-role model the production
deployment actually adopts.
