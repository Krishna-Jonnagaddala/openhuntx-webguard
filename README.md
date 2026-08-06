# OpenHuntX WebGuard

Continuous web vulnerability discovery and security assurance for authorised targets.

## Status

Private commercial product under active development. The native scanner currently supports bounded passive single-page and same-origin crawl assessments, strict report contracts, signed crawl checkpoints, an external owned-target readiness gate, and professional HTML reporting with remediation comparison.

## Safety

OpenHuntX WebGuard must only assess systems that the customer owns or is explicitly authorised to test.

Laboratory scans require `--lab` and an explicit host allowlist. External scans require a validated owned-target authorization document plus an exact operator confirmation before WebGuard sends an HTTP request. External scans are HTTPS-only, public-address-only, passive, bounded, and audited.

A locally generated authorization document records operator approval and limits. It does not independently prove legal ownership. Production service releases must add server-side customer identity, asset ownership verification, and centrally controlled authorization.

## Repository structure

- `apps/api` — control-plane API
- `apps/web` — customer dashboard
- `workers/scanner` — isolated scanner workers
- `packages/contracts` — shared API and finding contracts
- `infra/compose` — local infrastructure
- `infra/zap` — ZAP automation plans
- `docs` — product, architecture, and security documentation
- `tests` — automated tests and safe fixtures

## Current scanner milestone

Milestone 1.26 adds a local-only control-plane API, persistent SQLite scan-job queue, and background worker while preserving the CLI scanner and strict report contracts.

Render a self-contained customer-facing HTML report:

```bash
webguard report render scan-results/current.json \
  --organization "Example Ltd" \
  --prepared-by "OpenHuntX" \
  --classification "Confidential" \
  --output scan-results/current.html
```

Compare a current scan with an earlier baseline and include new, remaining, and fixed findings:

```bash
webguard report compare \
  scan-results/baseline.json \
  scan-results/current.json \
  --output scan-results/comparison.json

webguard report validate-comparison \
  scan-results/comparison.json

webguard report render scan-results/current.json \
  --baseline scan-results/baseline.json \
  --organization "Example Ltd" \
  --output scan-results/remediation-verification.html
```

The HTML is self-contained, JavaScript-free, escaped, and written with owner-only permissions. Comparison uses stable finding fingerprints and requires both reports to use the same canonical target.

The Milestone 1.23 owned-target readiness gate remains mandatory for external scans. External execution remains passive: no form submission, JavaScript execution, active payload injection, redirect following, brute force, or directory enumeration.


## Local scanner service foundation

Initialize the private SQLite job store:

```bash
webguard-api init
```

Run the loopback-only API and one background scanner worker:

```bash
webguard-api serve \
  --host 127.0.0.1 \
  --port 8765 \
  --database var/webguard-api/jobs.sqlite3 \
  --authorizations authorizations \
  --artifacts scan-results/service
```

Submit an owned-target job with an idempotency key:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: internstack-20260806-001' \
  --data '{"target":"https://internstack.in/","authorization_id":"<AUTHORIZATION-UUID>","confirm_authorization":"<AUTHORIZATION-UUID>","mode":"crawl"}' \
  http://127.0.0.1:8765/v1/jobs
```

The initial service binds only to a loopback IP literal. It returns job metadata and safe relative artifact references, not authorization documents or report bodies. The worker reloads and revalidates the server-side authorization immediately before execution, writes the authorization audit first, and uses the conservative owned-target scan policy.
