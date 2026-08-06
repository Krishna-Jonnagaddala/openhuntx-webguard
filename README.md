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

Milestone 1.25 adds professional security reporting and remediation verification while preserving the strict machine-readable scan reports.

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
