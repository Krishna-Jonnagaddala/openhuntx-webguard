# OpenHuntX

Authorized security assurance across web assets, security operations, and continuous compliance.

> **Development status:** Under active development. Not yet a publicly hosted, generally available service: no public signup, no billing, no SLA.

## Overview

OpenHuntX is one platform with three separately usable modules, sharing one entity, evidence, and authority substrate rather than three disconnected apps:

| Module | Responsibility | Maturity |
|---|---|---|
| **WebGuard** | Authorized web/API security assessment: TrustScan permits, passive scanning, findings, coverage, comparable retesting | Live, usable end to end: real accounts, a customer web app, PostgreSQL-backed multi-tenant API |
| **SOC** | Federated security operations: detection assurance, investigation, governed response | Connector manifests designed and unit-tested for Microsoft Entra, Defender XDR, and Sentinel; no live HTTP client yet, blocked on real tenant credentials |
| **Compliance** | Continuous control assurance, governance, audit preparation | Framework/master-control catalog, scoped control applicability, and a technical-assertion catalog are built and Postgres-tested; one assertion (`entra_conditional_access_policy_mode`) now executes end to end against fixture or manually-supplied evidence, with no service/HTTP/CLI surface yet |

This expansion from a WebGuard-only project is deliberate and recorded in `docs/PLATFORM_SCOPE.md`, which is the current, actively-maintained scope contract. Module entitlement is tracked per organization; an unsubscribed module never leaks another module's data.

WebGuard itself combines:

- account creation, email verification, password reset, and team invitations against a real customer web application
- organization isolation, role-based access control, and audit events, backed by PostgreSQL with row-level-security policies defined for every tenant-owned table
- two independent ownership-verification methods (a well-known HTTP file, or a DNS TXT record) before an asset can be scanned
- strict target and network-scope validation
- bounded passive single-page and same-origin crawl assessments
- passive HTTP, HTML, cookie, CORS, disclosure, TLS, and certificate analysis
- deterministic finding contracts and fingerprints, with a Coverage Truth Map read API and frontend view showing what was actually assessed
- signed crawl checkpoints and safe resume
- professional HTML reporting and remediation comparison
- a persistent, lease-aware job queue with recurring scan scheduling
- cryptographic TrustScan execution permits and Ed25519-signed Safety Receipts, with KMS and CloudHSM signing-provider code written and tested (neither is the active default signer yet)

WebGuard does not claim to identify every vulnerability. Its current scan mode is intentionally conservative and passive.

## Current state

The most recent work is the OpenHuntX Scope & Progress Audit (2026-09-14) and its follow-through, now merged to `main`:

- reconciled tenant-isolation RLS policies for every tenant-owned table added since the original audit (`coverage_records`, `module_entitlements`, `scoped_control_implementations`, `technical_assertion_collections`): 106 policies across 33 tracked tables, proven against a real disposable PostgreSQL instance; RLS itself remains defined but not force-enabled anywhere (tracked as open finding P1-2)
- a tenant-scoped, paginated Coverage Truth Map read API (`GET /v1/assets/{id}/coverage`) and a minimal frontend panel, closing the gap where coverage data was recorded but never readable
- the first genuinely *executed* Compliance signal: a technical-assertion collection-and-evaluation record, backed by fixture or manually-supplied evidence and clearly labeled as such, never presented as a live vendor read
- DNS TXT as a second ownership-verification method alongside the existing well-known-HTTP check

See `docs/PROJECT_EXECUTION_LEDGER.md` for the full, requirement-level history (including corrections recorded in place when an earlier claim in that file turned out to be wrong), `docs/IMPLEMENTATION_STATUS.md` for the current layer-by-layer rollup, and `docs/RELEASE_EVIDENCE.md` for per-capability deployment-stage evidence.

## Safety and authorisation

OpenHuntX must only assess systems that the customer owns or is explicitly authorised to test.

Every asset must pass one of two ownership-verification methods before it can be scanned:

- publishing a WebGuard-issued token at `/.well-known/webguard-verification.txt`, or
- publishing the same token as a DNS TXT record under `_webguard-verification.<domain>`

Laboratory scans additionally require:

- `--lab`
- an explicit host allowlist
- an isolated authorised target such as OWASP Juice Shop

External scans require:

- a validated owned-target authorisation document
- an exact operator confirmation
- an HTTPS target
- public-address resolution
- bounded passive execution
- an authorisation audit record

Ownership verification and a locally generated authorisation document together record what the customer asserted and what WebGuard independently checked; neither one is a legal proof of ownership on its own. TrustScan v1 cryptographically narrows and proves the service-issued execution policy for an existing authorisation. Automated, centrally controlled delegated-authority verification (proving a customer's *legal* right to authorize testing, not just DNS/HTTP control of the asset) remains future work.

External execution currently performs no:

- form submission
- JavaScript execution
- active payload injection
- exploitation
- brute force
- directory enumeration
- redirect following

## Capabilities

### Customer web application

A 19-page React frontend (`apps/web/`) against the real, PostgreSQL-backed API:

- registration, email verification, login/logout, password reset
- team invitations and role management, scoped API keys, an audit log, organization settings
- asset registration, ownership verification (well-known file or DNS TXT, with in-app instructions and copy-to-clipboard helpers), and a coverage panel showing actually-recorded assessment states
- scan submission and detail views, findings list and detail with lifecycle status changes, recurring schedules
- report generation and download, with baseline comparison

### Target and transport safety

- canonical URL validation
- public/private/loopback address policy enforcement
- DNS-result validation
- cloud metadata and ambiguous-address protection
- redirect blocking
- validated destination connection
- safe `Host` header construction
- response-size limits
- conflicting `Content-Length` protection
- approved-method enforcement
- retry and request-attempt audit trails

### Passive assessment

- security-header analysis
- cookie security analysis
- CORS analysis
- information-disclosure analysis
- passive HTML security analysis
- TLS and certificate analysis
- single-page assessment
- bounded same-origin crawling
- crawl cancellation and execution budgets
- validated checkpoints and safe resume

### Findings, coverage, and reporting

- strict versioned scan and finding contracts
- deterministic JSON serialisation
- stable SHA-256 finding fingerprints
- severity, confidence, evidence, references, and remediation
- Coverage Truth Map: a durable, tenant-scoped record of what was discovered, authorized, attempted, completed, blocked, or unreachable, readable through a paginated API and frontend view (v1 populates the completed/blocked/unreachable states; discovered/authorized need signal that doesn't exist yet)
- self-contained JavaScript-free HTML reports
- baseline comparison
- new, remaining, and fixed finding classification
- remediation-verification reporting
- owner-only report-file permissions

### Multi-tenant platform foundation

- PostgreSQL persistence with organizations, principals, RBAC, and audit events
- row-level-security policies defined for every tenant-owned table with a current ACL grantee (106 policies across 33 tables); RLS itself is not yet force-enabled in any real environment (P1-2, open)
- report artifacts and authenticated-scanning secret material are isolated by construction (a caller-derived reference from an already tenant-scoped read), not yet independently re-enforced by the storage/secrets layer itself (P1-13, open)
- persistent job queue with versioned schema migrations (17 migrations to date)
- renewable worker leases, heartbeat updates, stale-worker fencing, and crash recovery
- organisation-scoped recurring scan schedules with atomic due-run materialisation and safe catch-up
- signed, expiring, organisation-bound cursor pagination
- Ed25519-signed TrustScan execution permits and Safety Receipts, with KMS and CloudHSM signing-provider implementations written and tested but not the active default signer

### SOC (early stage)

- Connector manifests for Microsoft Entra, Defender XDR, and Sentinel (`apps/api/src/webguard_api/soc_connectors.py`), with every permission/RBAC role verified against Microsoft's current documentation
- No live HTTP client for any connector: no design or code exists for telemetry normalization, detection engineering, investigations, or response beyond the manifest layer

### Compliance (early stage)

- Framework/master-control catalog (5 seeded frameworks: SOC 2, ISO/IEC 27001:2022, HIPAA, GDPR, UK GDPR), placeholder content with no real control text yet and no legal review performed
- Scoped control implementation and applicability tracking, tenant-scoped
- A technical-assertion catalog (5 assertions) with real, tested evaluation logic for one of them (`entra_conditional_access_policy_mode`); the other four raise a fail-closed "not evaluatable" error rather than fabricate a result
- Technical-assertion collection and evaluation now executes end to end against fixture-backed or manually-supplied evidence, always labeled as such; no live vendor connector exists to feed it
- No service, HTTP, or CLI surface yet for any Compliance capability (this stage's own established pattern, not an oversight)

## Architecture

```text
Customer web application (apps/web/, React)
        |
        | session cookie or Bearer token + TrustScan permit ID
        v
PostgreSQL-backed control-plane API (apps/api/)
        |
        +--> identity, organisation, RBAC, and audit controls
        |      +--> row-level security policies defined per tenant table (not yet force-enabled)
        |
        +--> TrustScan permit authority
        |      +--> Ed25519 signing (local key active; KMS/CloudHSM providers written, not yet wired as default)
        |      +--> immutable signed claims + revocation state
        |
        +--> asset ownership verification (well-known HTTP file or DNS TXT)
        |
        +--> Coverage Truth Map read API
        |
        +--> Compliance module (framework catalog, scoped controls, technical assertions; no HTTP surface)
        |
        +--> SOC module (connector manifests only; no live client)
        |
        +--> database-backed scheduler
        |      +--> revalidates authorisation and TrustScan permit
        |      +--> atomically creates permit-bound due jobs
        |
        v
Lease-aware background scanner worker
        |
        +--> revalidates permit signature, scope, state, and limits
        +--> TrustScan runtime safety engine
        |      +--> checks every outbound request boundary
        |      +--> throttles or blocks outside the approved safety envelope
        |      +--> records observed target-health and policy events
        +--> target-scope and authorisation validation
        +--> safe HTTP client
        +--> bounded passive analyzers and crawler
        |      +--> writes findings and Coverage Truth Map rows
        |
        v
Private JSON, audit, Safety Receipt, comparison, and HTML artefacts
```

The local, single-host CLI/loopback API described later in this document (`webguard-api serve`, SQLite job store) is a separate, lower-level developer/lab path used for local scanner development; it does not run the customer web application or PostgreSQL tenant-isolation model above.

## Repository structure

- `apps/api`: PostgreSQL-backed control-plane API (also runnable in a local, SQLite-backed lab mode)
- `apps/web`: customer web application (React, 19 pages)
- `workers/scanner`: isolated scanner components
- `packages/contracts`: shared API, scan, finding, and tenancy contracts
- `infra/postgres`: schema migrations and tenant-isolation bootstrap SQL
- `infra/compose`: local infrastructure and authorised lab target
- `docs`: product, architecture, security, roadmap, ADR, and audit documentation
- `scripts`: local verification and development utilities
- `tests/unit`: deterministic unit tests
- `tests/contract`: repository contract tests (SQLite/in-memory always; PostgreSQL when a test DSN is set)
- `tests/integration`: opt-in authorised integration tests, including a real-Postgres tenant-isolation suite and Playwright browser E2E specs

Planned components that do not yet exist in the repository are tracked in `docs/ROADMAP.md` (itself marked historical as of 2026-09-15; `docs/PLATFORM_SCOPE.md` is the current scope contract) rather than listed as current repository structure.

## Security and governance

- `SECURITY.md`: vulnerability reporting, supported development baseline, and secret-handling expectations
- `docs/PLATFORM_SCOPE.md`: the current three-module scope contract, claim boundaries, and open blockers
- `docs/PROJECT_EXECUTION_LEDGER.md`: requirement-level status, including corrections recorded in place
- `docs/IMPLEMENTATION_STATUS.md` / `docs/RELEASE_EVIDENCE.md`: layer-level and per-capability current state
- `docs/PRODUCT_VISION_TRACEABILITY.md`: WebGuard's ten-pillar vision status
- `docs/ARCHITECTURE.md`: implemented architecture, persistence, cryptographic uses, and trust boundaries
- `docs/AUTHORIZATION_MODEL.md`: layered owned-target and TrustScan permission model
- `docs/DATA_CLASSIFICATION.md`: data sensitivity and handling requirements
- `docs/THREAT_MODEL.md`: threats, controls, assumptions, and residual risks
- `docs/CONNECTOR_CAPABILITIES.md`: SOC connector manifest scope and permission model
- `docs/CWE_COVERAGE.md`: per-CWE implemented/partial/planned status for passive analyzers
- `THIRD_PARTY_NOTICES.md`: directly referenced third-party component inventory

## Requirements

- Python 3.11 through 3.14 (`>=3.11,<3.15`)
- Node.js 24, for the web frontend
- Git
- Docker with Docker Compose, for the PostgreSQL-backed test paths and the authorised lab target

GitHub CI verifies unit tests on Python 3.11.15, 3.12.13, 3.13.14, and 3.14.6; the authorised OWASP Juice Shop integration suite; a real-PostgreSQL repository-and-tenant-isolation integration job; Terraform/IaC validation; and the frontend's build, lint, unit tests, and Playwright browser E2E suite.

## Development setup

```bash
git clone https://github.com/Krishna-Jonnagaddala/openhuntx-webguard.git
cd openhuntx-webguard

./scripts/bootstrap-dev.sh
source .venv/bin/activate
```

Run the local verification gate:

```bash
./scripts/verify.sh
```

External Python dependencies are installed from repository-reviewed SHA-256 locks, cross-checked by `scripts/verify-supply-chain-pins.py`. CI also pins GitHub Actions by immutable commit SHA, Python to reviewed patch releases on the Ubuntu 24.04 runner family, and the authorised Juice Shop image by its multi-platform OCI index digest. Dependency updates are therefore deliberate review events rather than implicit upgrades.

Current test totals are emitted by `./scripts/verify.sh` and CI. The README intentionally does not hardcode volatile test counts.

### Web frontend

```bash
cd apps/web
npm ci
npm run dev
```

The frontend expects the API at `VITE_API_BASE_URL` (defaults to `http://127.0.0.1:8765`). See `apps/web/e2e/` for the Playwright specs that drive the real product end to end against a real PostgreSQL-backed API and worker.

### PostgreSQL-backed local API

```bash
docker compose -f infra/compose/compose.postgres.yml up -d
python scripts/run-postgres-migrations.py
```

Tenant-isolation roles, ACLs, and control functions must also be bootstrapped before the API can authenticate any request against a fresh database; see `infra/postgres/bootstrap/` and `tests/contract/test_identity_repository_contract.py`'s own `setUpClass` for the exact order.

## Authorised lab integration

Start the isolated OWASP Juice Shop target:

```bash
docker compose \
  -f infra/compose/compose.lab.yml \
  up -d
```

Run the authorised integration suite:

```bash
WEBGUARD_RUN_INTEGRATION=1 \
WEBGUARD_LAB_TARGET=http://127.0.0.1:3000/ \
python -m unittest discover \
  -s tests/integration \
  -p "test_*.py" \
  -v
```

Stop the laboratory environment:

```bash
docker compose \
  -f infra/compose/compose.lab.yml \
  down
```

## Professional reporting

Render a self-contained customer-facing HTML report:

```bash
webguard report render scan-results/current.json \
  --organization "Example Ltd" \
  --prepared-by "OpenHuntX" \
  --classification "Confidential" \
  --output scan-results/current.html
```

Compare a current scan with an earlier baseline:

```bash
webguard report compare \
  scan-results/baseline.json \
  scan-results/current.json \
  --output scan-results/comparison.json

webguard report validate-comparison \
  scan-results/comparison.json
```

Render a remediation-verification report:

```bash
webguard report render scan-results/current.json \
  --baseline scan-results/baseline.json \
  --organization "Example Ltd" \
  --output scan-results/remediation-verification.html
```

The generated HTML is self-contained, JavaScript-free, escaped, and written with owner-only permissions. Comparison requires both reports to use the same canonical target and uses stable finding fingerprints to classify new, remaining, and fixed findings.

## Local, single-host API (developer/lab mode)

This is the low-level CLI/loopback path used for local scanner development, distinct from the customer web application and PostgreSQL tenant-isolation model described above. It uses a SQLite job store on one host and a raw bearer token instead of the web app's session-based login.

### 1. Initialise the private service database

```bash
webguard-api init \
  --database var/webguard-api/jobs.sqlite3 \
  --authorizations authorizations \
  --artifacts scan-results/service
```

### 2. Bootstrap the first organisation owner

```bash
webguard-api bootstrap \
  --organization "Example Organisation" \
  --principal "Initial Owner" \
  --database var/webguard-api/jobs.sqlite3 \
  --authorizations authorizations \
  --artifacts scan-results/service
```

The bootstrap command prints a raw API token once.

Do not:

- commit the token
- paste it into documentation
- include it in screenshots
- store it in shell history
- place it in source-controlled environment files

For local development, load it without echoing the value:

```bash
unset WEBGUARD_API_TOKEN

printf "Paste WebGuard API token: "
IFS= read -r -s WEBGUARD_API_TOKEN
printf "\n"

export WEBGUARD_API_TOKEN
```

Production deployments must use a dedicated secrets manager.

### 3. Assign an owned-target authorisation

```bash
webguard-api authorization assign \
  --organization-id ORGANIZATION_UUID \
  --principal-id OWNER_PRINCIPAL_UUID \
  --authorization-id AUTHORIZATION_UUID \
  --database var/webguard-api/jobs.sqlite3 \
  --authorizations authorizations \
  --artifacts scan-results/service
```

### 4. Start the loopback-only API

```bash
webguard-api serve \
  --host 127.0.0.1 \
  --port 8765 \
  --database var/webguard-api/jobs.sqlite3 \
  --authorizations authorizations \
  --artifacts scan-results/service \
  --worker-lease-seconds 30 \
  --worker-heartbeat-seconds 10 \
  --worker-maximum-attempts 3
```

The service generates a unique worker ID unless `--worker-id` is supplied. While a scan is running, the worker renews its lease. A replacement worker may recover an expired lease, but the previous worker cannot write a stale terminal result after losing ownership.

### 5. Verify the authenticated principal

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  http://127.0.0.1:8765/v1/me
```

Responses include correlation and rate-limit headers such as `X-Request-ID` and `RateLimit-*`.

### 6. Read the TrustScan verification key

The public verification key may be retrieved without authentication. The active private signing key never leaves the owner-only service database (or the configured KMS/HSM, when one of those providers is active).

```bash
curl --fail-with-body \
  http://127.0.0.1:8765/v1/trustscan/verification-key
```

### 7. Register and verify ownership of an asset

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"url": "https://security.example/"}' \
  http://127.0.0.1:8765/v1/assets

curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"method": "well_known_http"}' \
  http://127.0.0.1:8765/v1/assets/TARGET_UUID/verification
```

Publish the returned token at the given path (or as a DNS TXT record, if `"method": "dns_txt"` was requested instead), then request a check:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  -H "Content-Length: 0" \
  http://127.0.0.1:8765/v1/assets/TARGET_UUID/verification/check
```

A non-matching check leaves the original token intact for retry; it never issues a new token unless one is explicitly requested again.

### 8. Issue a TrustScan scan permit

Only an organisation owner or administrator may issue or revoke a permit. The underlying owned-target authorisation must already be assigned to that organisation and must be current.

```bash
NOT_BEFORE="$(python - <<'PYTHON'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"))
PYTHON
)"

EXPIRES_AT="$(python - <<'PYTHON'
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc) + timedelta(days=7)).isoformat(timespec="microseconds").replace("+00:00", "Z"))
PYTHON
)"

curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "{
    \"target\": \"https://security.example/\",
    \"authorization_id\": \"AUTHORIZATION_UUID\",
    \"confirm_authorization\": \"AUTHORIZATION_UUID\",
    \"permitted_modes\": [\"crawl\", \"single_page\"],
    \"allowed_http_methods\": [\"GET\", \"HEAD\"],
    \"not_before\": \"${NOT_BEFORE}\",
    \"expires_at\": \"${EXPIRES_AT}\",
    \"maximum_request_attempts\": 15,
    \"maximum_requests_per_second\": 1.0,
    \"maximum_concurrency\": 1
  }" \
  http://127.0.0.1:8765/v1/permits
```

Store the returned permit UUID in a shell variable without treating it as a bearer credential. The permit does not replace API authentication.

```bash
export TRUSTSCAN_PERMIT_ID="PERMIT_UUID"
```

Permit v1 is deliberately conservative: `GET` is required, `HEAD` is optional, concurrency is fixed at one, the permit may be valid for at most 90 days, and it cannot exceed the request budget, request rate, expiry, or target authorised by the underlying owned-target document.

Read or revoke a permit:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  http://127.0.0.1:8765/v1/permits/${TRUSTSCAN_PERMIT_ID}

curl --fail-with-body -X POST \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  -H "Content-Length: 0" \
  http://127.0.0.1:8765/v1/permits/${TRUSTSCAN_PERMIT_ID}/revoke
```

### 9. Submit a permit-bound authorised scan job

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  -H "TrustScan-Permit: ${TRUSTSCAN_PERMIT_ID}" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: owned-target-001" \
  --data '{
    "target": "https://security.example/",
    "authorization_id": "AUTHORIZATION_UUID",
    "confirm_authorization": "AUTHORIZATION_UUID",
    "mode": "crawl"
  }' \
  http://127.0.0.1:8765/v1/jobs
```

The job is transactionally bound to the exact permit ID and permit fingerprint (the SHA-256 digest of the canonical signed claims). The worker reloads the server-side authorisation and signed permit immediately before network execution. Missing, revoked, expired, altered, cross-organisation, target-mismatched, authorisation-mismatched, or mode-mismatched permits fail closed.

### 10. Create a permit-bound recurring schedule

Schedule start times use canonical UTC microsecond notation. The minimum interval is one hour, and the first run must fall inside the TrustScan permit validity window.

```bash
STARTS_AT="$(python - <<'PYTHON'
from datetime import datetime, timedelta, timezone
value = datetime.now(timezone.utc) + timedelta(hours=1)
print(value.isoformat(timespec="microseconds").replace("+00:00", "Z"))
PYTHON
)"

curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  -H "TrustScan-Permit: ${TRUSTSCAN_PERMIT_ID}" \
  -H "Content-Type: application/json" \
  --data "{
    \"name\": \"Daily passive crawl\",
    \"target\": \"https://security.example/\",
    \"authorization_id\": \"AUTHORIZATION_UUID\",
    \"confirm_authorization\": \"AUTHORIZATION_UUID\",
    \"mode\": \"crawl\",
    \"interval_seconds\": 86400,
    \"starts_at\": \"${STARTS_AT}\"
  }" \
  http://127.0.0.1:8765/v1/schedules
```

The scheduler revalidates both the underlying authorisation and the permit before every due run. A revoked or expired permit pauses the schedule rather than creating an unauthorised job. Missed intervals still use the existing safe catch-up policy rather than producing a backlog burst.

### 11. Read coverage and list organisation activity with signed pagination

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  "http://127.0.0.1:8765/v1/assets/TARGET_UUID/coverage?limit=25"

curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  "http://127.0.0.1:8765/v1/jobs?limit=25&state=queued&mode=crawl"
```

Each response contains a `page.next_cursor` value when another page exists. Treat it as opaque and send it back unchanged with the same filters. The same bounded signed-pagination model applies to `/v1/schedules` and `/v1/audit-events`.

The API deliberately omits total counts and never exposes raw API tokens, the active TrustScan signing key material, owned-target authorisation documents, or report bodies through list responses.

## Token lifecycle

API tokens are stored as scrypt hashes rather than raw values and support expiry and revocation.

Create separate tokens for separate operators or service accounts. Revoke a token immediately when it is exposed, replaced, or no longer required.

Never use a shared production token for multiple customers or organisations.

## Data handling

The following paths contain private runtime material and must remain outside source control:

- `authorizations/`
- `scan-results/`
- `var/`
- SQLite and PostgreSQL databases
- generated audit and TrustScan Safety Receipt records
- raw API tokens and session secrets
- the database-held pagination cursor HMAC key
- the active TrustScan Ed25519 signing key material

Scan reports may contain sensitive target metadata and security findings. Treat them as confidential customer records.

## Current limitations

Known limitations include:

- row-level security policies are defined for every tenant-owned table but not yet force-enabled in any real, non-disposable environment (P1-2); dormant-state and adversarial-reproduction proofs exist only against a disposable test database
- object storage and authenticated-scanning secret material are isolated by construction only (a caller-derived reference from an already tenant-scoped read), not independently re-enforced by the storage/secrets layer itself (P1-13)
- KMS and CloudHSM TrustScan signing-provider code exists and is tested, but neither is the active default signer; CloudHSM specifically is unverified against real hardware
- no cross-host distributed worker or scheduler coordination; both remain single-host coordination even in the PostgreSQL-backed mode
- SOC connector manifests exist for three Microsoft products with no live HTTP client for any of them; no real tenant credentials are available to this project
- Compliance's framework/master-control catalog uses placeholder content with no authoritative legal-text verification performed; only 1 of 5 technical-assertion catalog entries has real evaluation logic
- no code path yet connects a WebGuard finding, a SOC detection, and a Compliance control record to each other: the flagship cross-module workflow is not built
- Coverage Truth Map v1 populates 3 of its own 6 planned states (completed/blocked/unreachable); discovered/authorized need signal that doesn't exist yet, and identity attribution is always `"unauthenticated"`
- no automated, centrally controlled delegated-authority (legal right to authorize) verification; ownership verification proves DNS/HTTP control of an asset, not legal authority over it
- no production identity federation or enterprise SSO
- fixed-interval schedules only; cron expressions and customer time zones are not yet supported
- pagination cursors are local-service cursors and become invalid if the private database secret is rotated or lost
- no email/webhook notifications beyond the transactional account-lifecycle emails (verification, password reset, invitations)
- no billing, subscriptions, or usage metering
- local rather than distributed rate limiting
- no high-availability or disaster-recovery design
- passive assessment only

## Roadmap

Per `docs/PLATFORM_SCOPE.md`'s dependency-ordered delivery sequence, the concrete, currently-open blockers are:

- **RLS+FORCE activation**: needs a real, non-disposable PostgreSQL environment this project does not yet have standing authorization to provision.
- **SOC connectors** (Sentinel, Defender XDR, Entra): need real Microsoft tenant credentials before any live client work can start.
- **Compliance framework packs**: need authoritative legal-text verification (SOC 2, ISO/IEC 27001:2022, HIPAA, GDPR, UK GDPR) before any legal claim can ship.
- **Object storage and secret-provider tenant isolation**: a real per-tenant enforcement layer, or an explicitly accepted residual risk decision, is unmade.

Beyond those, the next priorities are the full three-module lab workflow (an authorized WebGuard assessment flowing through SOC validation to scoped Compliance evidence), reviewer workflows (investigations, audit requests, exceptions, historical views), governed response actions (shadow evaluation first, then explicit approval with independent postcondition checking), and production hardening (live connector proof, restore tests, deployment evidence, independent penetration testing).

Additional framework packs beyond the initial five, a native SIEM, a universal query language, AI-generated connectors, autonomous response, and several other explicitly deferred areas are tracked with their entry conditions in `docs/PLATFORM_SCOPE.md` rather than promised here.

## Security principles

OpenHuntX development follows these principles:

- authorised targets only
- deny by default
- validate before connecting
- revalidate authorisation and cryptographic permit before execution and at every outbound request boundary
- no valid TrustScan permit means no scanner network execution
- cryptographically bind jobs and recurring schedules to their approved execution permit
- fail closed when runtime permission or safety policy cannot be verified
- record signed evidence of the safety controls WebGuard enforced and observed
- minimise network capability
- keep scans passive and bounded
- isolate customer data by organisation
- never store raw API tokens or session secrets
- produce deterministic evidence
- preserve auditable execution records
- sign and scope opaque pagination cursors before returning them
- atomically advance schedules when due jobs are created
- skip missed intervals instead of flooding the scanner queue
- fence stale workers before terminal state changes
- no fabricated or uncalibrated precision in any module's claims (see `docs/PLATFORM_SCOPE.md`'s claim boundaries)
- do not overstate security assurance

## Responsible use

OpenHuntX is intended for defensive security assurance on authorised systems.

Do not use this software against systems you do not own or lack explicit permission to assess.
