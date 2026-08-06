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
- request correlation, audit events, rate-limit foundations, and crash recovery

WebGuard does not claim to identify every vulnerability. Its current external scan mode is intentionally conservative and passive.

## Current milestone

**Milestone 1.28 — Durable worker leases and crash recovery**

The current implementation adds a fenced execution lease to every service-run scan job:

- versioned SQLite job-store migration from schema `1` to schema `2`
- atomic worker identity, lease token, expiry, heartbeat, and attempt metadata
- renewable leases while scanner execution is active
- stale-worker fencing on completion, failure, and cancellation transitions
- automatic recovery of expired running jobs
- requeue of recoverable jobs without preserving stale execution state
- terminal cancellation recovery when a customer already requested cancellation
- controlled failure after the configured maximum number of attempts
- safe migration of legacy running jobs during database upgrade
- configurable worker IDs, lease durations, heartbeat intervals, and attempt limits
- API version `0.3.0`

Milestone 1.27 organisation isolation, authentication, RBAC, audit events, and rate-limit foundations remain in force. The API remains loopback-only and must not be exposed directly to the public internet.

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

A locally generated authorisation document records operator approval and scan limits. It does not independently prove legal ownership. A future production release must add centrally controlled customer identity, asset ownership verification, and production-grade authorisation workflows.

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

## Architecture

```text
Operator / local client
        |
        | Bearer token
        v
Loopback control-plane API
        |
        +--> identity, organisation, RBAC, and audit controls
        |
        +--> SQLite job and identity store
        |      +--> versioned migrations
        |      +--> job leases, heartbeats, and attempt counters
        |
        v
Lease-aware background scanner worker
        |
        +--> target-scope and authorisation validation
        +--> safe HTTP client
        +--> bounded passive analyzers and crawler
        |
        v
Private JSON, audit, comparison, and HTML artefacts
```

## Repository structure

- `apps/api` — local control-plane API
- `apps/web` — future customer dashboard
- `workers/scanner` — isolated scanner components
- `packages/contracts` — shared API, scan, finding, and tenancy contracts
- `infra/compose` — local infrastructure and authorised lab target
- `infra/zap` — future controlled ZAP automation plans
- `docs` — product, architecture, security, and ADR documentation
- `scripts` — local verification and development utilities
- `tests/unit` — deterministic unit tests
- `tests/integration` — opt-in authorised integration tests

## Requirements

- Python 3.11 or later
- Git
- Docker with Docker Compose for authorised integration tests

GitHub CI currently verifies unit tests on Python 3.11, 3.13, and 3.14, plus the authorised OWASP Juice Shop integration suite.

## Development setup

```bash
git clone https://github.com/Krishna-Jonnagaddala/openhuntx-webguard.git
cd openhuntx-webguard

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
python -m pip install --requirement requirements-dev.txt
```

Run the local verification gate:

```bash
./scripts/verify.sh
```

At Milestone 1.28, the repository contains:

- 768 unit tests
- 11 opt-in authorised integration tests
- CI validation across three Python versions
- an authorised Juice Shop integration job

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

### 6. Submit an authorised scan job

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${WEBGUARD_API_TOKEN}" \
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

The service returns job metadata and safe relative artefact references. It does not return authorisation documents or report bodies through the API.

Before execution, the worker:

1. reloads the server-side authorisation
2. validates organisation and principal scope
3. revalidates the target and authorisation limits
4. writes the authorisation audit record
5. executes the conservative owned-target policy

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
- generated audit records
- raw API tokens

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
- no automated asset-ownership verification
- no recurring scan scheduler
- no email or webhook notifications
- no billing, subscriptions, or usage metering
- local rather than distributed rate limiting
- no high-availability or disaster-recovery design
- passive assessment only

## Roadmap

Upcoming engineering priorities include:

- PostgreSQL-backed shared persistence and production migrations
- distributed worker coordination and database-backed scheduling
- scan scheduling and recurring assessments
- customer dashboard and organisation administration
- target and authorisation management workflows
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
- revalidate before execution
- minimise network capability
- keep scans passive and bounded
- isolate customer data by organisation
- never store raw API tokens
- produce deterministic evidence
- preserve auditable execution records
- fence stale workers before terminal state changes
- do not overstate security assurance

## Responsible use

OpenHuntX WebGuard is intended for defensive security assurance on authorised systems.

Do not use this software against systems you do not own or lack explicit permission to assess.
