# OpenHuntX WebGuard

Continuous web vulnerability discovery and security assurance for authorised targets.

> **Development status:** Private commercial product under active development.  
> WebGuard is not yet a publicly hosted production service.

## Overview

OpenHuntX WebGuard is a security-assurance platform for organisations that need controlled, repeatable visibility into web security posture across assets they own or are explicitly authorised to assess.

The current platform combines:

- strict target and network-scope validation
- bounded passive single-page and same-origin crawl assessments
- passive HTTP, HTML, cookie, CORS, disclosure, TLS, and certificate analysis
- deterministic finding contracts and fingerprints
- signed crawl checkpoints and safe resume
- professional HTML reporting and remediation comparison
- a local scanner-service API with a persistent, lease-aware job queue
- organisation isolation, API authentication, and role-based access control
- request correlation, audit events, rate-limit foundations, crash recovery, recurring scan scheduling, signed cursor pagination, and cryptographic TrustScan permits

WebGuard does not claim to identify every vulnerability. Its current external scan mode is intentionally conservative and passive.

## Current milestone

**Milestone 1.32: TrustScan runtime safety engine and Safety Receipt v1**

The current implementation moves TrustScan enforcement from a pre-execution permit check to the outbound request boundary. Every scanner request is evaluated against the permit-authorised origin, HTTP method, request-attempt budget, request rate, maximum concurrency, current authorisation state, and current permit state immediately before network activity.

Milestone 1.32 adds:

- versioned SQLite job-store migration from schema `5` to schema `6`
- strict TrustScan Safety Receipt schema `1.0`
- Ed25519-signed safety receipts using the existing TrustScan signing authority
- strict canonical JSON loading and signature verification for exported receipts
- request-boundary TrustScan permit and authorisation revalidation
- fail-closed blocking for revoked, expired, changed, or otherwise invalid permission
- permit-bound HTTP-method, same-origin, request-budget, request-rate, and concurrency enforcement
- runtime request-rate throttling with permission revalidation after every enforced wait
- conservative circuit breaking after repeated request failures, HTTP `429`, or HTTP `5xx` responses
- observed counters for attempted, permitted, and blocked requests, target-health signals, throttles, circuit-breaker activations, scope violations, and permit revalidations
- owner-only `trustscan-safety-receipt.json` artefacts associated transactionally with terminal jobs
- safety-receipt references and SHA-256 fingerprints in job result metadata
- runtime hooks wired through both single-page and same-origin crawl execution paths
- API version `0.7.0`

Milestone 1.31 cryptographic Scan Permit v1 remains the permission authority. A Safety Receipt proves what WebGuard enforced and observed during one execution; it does **not** claim that testing could not affect a target or that the target is secure. The API remains a local, single-host engineering foundation and must not be exposed directly to the public internet.

## Safety and authorisation

OpenHuntX WebGuard must only assess systems that the customer owns or is explicitly authorised to test.

Laboratory scans require:

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

A locally generated authorisation document records operator approval and scan limits. It does not independently prove legal ownership. TrustScan v1 cryptographically narrows and proves the service-issued execution policy for an existing authorisation; it does not itself prove that the customer legally owns the target. A future production release must add centrally controlled customer identity, asset-ownership or delegated-authority verification, and production-grade authorisation workflows.

External execution currently performs no:

- form submission
- JavaScript execution
- active payload injection
- exploitation
- brute force
- directory enumeration
- redirect following

## Capabilities

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

### Findings and reporting

- strict versioned scan and finding contracts
- deterministic JSON serialisation
- stable SHA-256 finding fingerprints
- severity, confidence, evidence, references, and remediation
- coverage and skipped-check accounting
- self-contained JavaScript-free HTML reports
- baseline comparison
- new, remaining, and fixed finding classification
- remediation-verification reporting
- owner-only report-file permissions

### Service foundation

- loopback-only HTTP API
- persistent SQLite job queue with versioned schema migrations
- renewable worker leases and heartbeat updates
- stale-worker fencing and expired-lease recovery
- bounded retry attempts after worker-process interruption
- background scanner execution
- idempotent job submission
- safe relative artefact references
- server-side authorisation reload and revalidation
- organisation isolation
- authenticated `/v1` API
- role-based permissions
- audit events
- request IDs
- token rate-limit foundations
- organisation-scoped recurring scan schedules
- atomic due-run materialisation and safe catch-up
- automatic schedule blocking when authorisation becomes invalid
- signed, expiring, organisation-bound cursor pagination
- paginated jobs, schedules, and audit activity feeds
- Ed25519-signed TrustScan execution permits
- permit issuance, read, revocation, and public verification-key APIs
- job and schedule permit binding with pre-execution revalidation
- permit-level request budget, rate, method, validity-window, and concurrency constraints
- request-boundary TrustScan runtime safety enforcement
- conservative target-health circuit breaking and runtime throttling
- Ed25519-signed TrustScan Safety Receipt v1 artefacts

## Architecture

```text
Operator / local client
        |
        | Bearer token + TrustScan permit ID for scan creation
        v
Loopback control-plane API
        |
        +--> identity, organisation, RBAC, and audit controls
        |
        +--> TrustScan permit authority
        |      +--> Ed25519 signing and public verification key
        |      +--> immutable signed claims + revocation state
        |
        +--> SQLite job, identity, schedule, permit, and service-secret store
        |      +--> versioned migrations and private signing keys
        |      +--> recurring schedules and due-run fencing
        |      +--> job leases, heartbeats, and attempt counters
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
        |
        v
Private JSON, audit, Safety Receipt, comparison, and HTML artefacts
```

## Repository structure

- `apps/api`: local control-plane API
- `workers/scanner`: isolated scanner components
- `packages/contracts`: shared API, scan, finding, and tenancy contracts
- `infra/compose`: local infrastructure and authorised lab target
- `docs`: product, architecture, security, roadmap, and ADR documentation
- `scripts`: local verification and development utilities
- `tests/unit`: deterministic unit tests
- `tests/integration`: opt-in authorised integration tests

Planned components that do not yet exist in the repository are tracked in `docs/ROADMAP.md` rather than listed as current repository structure.

## Security and governance

- `SECURITY.md`: vulnerability reporting, supported development baseline, and secret-handling expectations
- `docs/ARCHITECTURE.md`: implemented architecture, persistence, cryptographic uses, and trust boundaries
- `docs/AUTHORIZATION_MODEL.md`: layered owned-target and TrustScan permission model
- `docs/DATA_CLASSIFICATION.md`: data sensitivity and handling requirements
- `docs/THREAT_MODEL.md`: threats, controls, assumptions, and residual risks
- `docs/ROADMAP.md`: implemented foundation versus planned production capabilities
- `THIRD_PARTY_NOTICES.md`: directly referenced third-party component inventory

## Requirements

- Python 3.11 through 3.14 (`>=3.11,<3.15`)
- Git
- Docker with Docker Compose for authorised integration tests

GitHub CI currently verifies unit tests on Python 3.11.15, 3.12.13, 3.13.14, and 3.14.6, plus the authorised OWASP Juice Shop integration suite.

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

External Python dependencies are installed from repository-reviewed SHA-256 locks. CI also pins GitHub Actions by immutable commit SHA, Python to reviewed patch releases on the Ubuntu 24.04 runner family, and the authorised Juice Shop image by its multi-platform OCI index digest. Dependency updates are therefore deliberate review events rather than implicit upgrades.

At Milestone 1.32, repository verification includes:

- the deterministic unit suite on Python 3.11.15, 3.12.13, 3.13.14, and 3.14.6
- the opt-in authorised integration suite
- an authorised, digest-pinned Juice Shop integration job

Current test totals are emitted by `./scripts/verify.sh` and CI. The README intentionally does not hardcode volatile test counts.

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

## Local authenticated API

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

The public verification key may be retrieved without authentication. The private Ed25519 seed never leaves the owner-only service database.

```bash
curl --fail-with-body \
  http://127.0.0.1:8765/v1/trustscan/verification-key
```

### 7. Issue a TrustScan scan permit

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

### 8. Submit a permit-bound authorised scan job

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

### 9. Create a permit-bound recurring schedule

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

### 10. List organisation activity with signed pagination

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
  "http://127.0.0.1:8765/v1/jobs?limit=25&state=queued&mode=crawl"
```

The response contains a `page.next_cursor` value when another page exists. Treat it as opaque and send it back unchanged with the same filters. The same bounded signed-pagination model applies to `/v1/schedules` and `/v1/audit-events`.

The API deliberately omits total counts and never exposes raw API tokens, the private TrustScan signing seed, owned-target authorisation documents, or report bodies through list responses.

## Token lifecycle

API tokens are stored as scrypt hashes rather than raw values and support expiry and revocation.

Create separate tokens for separate operators or service accounts. Revoke a token immediately when it is exposed, replaced, or no longer required.

Never use a shared production token for multiple customers or organisations.

## Data handling

The following paths contain private runtime material and must remain outside source control:

- `authorizations/`
- `scan-results/`
- `var/`
- SQLite databases
- generated audit and TrustScan Safety Receipt records
- raw API tokens
- the database-held pagination cursor HMAC key
- the database-held TrustScan Ed25519 private signing seed

Scan reports may contain sensitive target metadata and security findings. Treat them as confidential customer records.

## Current limitations

The current release is a local engineering foundation, not a complete hosted SaaS platform.

Known limitations include:

- loopback-only API deployment
- SQLite persistence on one host
- no PostgreSQL or shared production database backend
- no cross-host distributed worker coordination
- no customer dashboard
- no production identity provider
- no automated asset-ownership or delegated-authority verification
- TrustScan v1 uses one local Ed25519 signing key and does not yet provide key rotation, external KMS/HSM custody, or multi-region trust distribution
- TrustScan v1 permits only the existing passive scan modes and `GET`/`HEAD` transport methods
- permit maximum concurrency is fixed at one and enforced through the current single-host SQLite job queue
- the runtime circuit breaker currently uses conservative local response/error signals and is not an external application-health monitor
- Safety Receipt v1 records WebGuard-observed enforcement facts; it does not prove that testing caused no target impact
- fixed-interval schedules only; cron expressions and customer time zones are not yet supported
- scheduler coordination remains single-host SQLite coordination
- pagination cursors are local-service cursors and become invalid if the private database secret is rotated or lost
- no email or webhook notifications
- no billing, subscriptions, or usage metering
- local rather than distributed rate limiting
- no high-availability or disaster-recovery design
- passive assessment only

## Roadmap

Upcoming engineering priorities include:

- PostgreSQL-backed shared persistence and production migrations
- distributed worker and scheduler coordination
- richer calendar schedules, customer time zones, and maintenance windows
- customer dashboard and organisation administration
- target ownership/delegated-authority verification and production authorisation workflows
- TrustScan key rotation, KMS/HSM-backed signing, and runner attestation
- coverage-truth maps, signed remediation evidence, and independently verifiable assessment capsules
- findings search, filtering, comparison, and export
- notifications and customer remediation workflows
- production secrets, observability, backups, and deployment controls
- usage quotas, metering, and commercial billing
- production security review and independent penetration testing

## Security principles

WebGuard development follows these principles:

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
- never store raw API tokens
- produce deterministic evidence
- preserve auditable execution records
- sign and scope opaque pagination cursors before returning them
- atomically advance schedules when due jobs are created
- skip missed intervals instead of flooding the scanner queue
- fence stale workers before terminal state changes
- do not overstate security assurance

## Responsible use

OpenHuntX WebGuard is intended for defensive security assurance on authorised systems.

Do not use this software against systems you do not own or lack explicit permission to assess.
