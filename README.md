# OpenHuntX WebGuard

Continuous web vulnerability discovery and security assurance for authorised targets.

## Status

Private commercial product under active development. The native scanner currently supports bounded passive single-page and same-origin crawl assessments, strict report contracts, signed crawl checkpoints, and an external owned-target readiness gate.

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

Milestone 1.23 adds the external owned-target readiness gate. Before any external scan, operators can create, validate, inspect, and explicitly confirm a bounded passive authorization.

```bash
webguard authorization create https://example.com/ \
  --organization "Example Ltd" \
  --authorized-by "Security Owner" \
  --purpose "Controlled passive security assessment" \
  --output authorizations/example.com.json
```

A readiness-only run performs strict authorization and scope validation, including DNS resolution, but sends no HTTP request and writes no report, audit, or checkpoint files:

```bash
webguard scan https://example.com/ \
  --authorization-file authorizations/example.com.json \
  --confirm-authorization <AUTHORIZATION_UUID> \
  --crawl \
  --preflight-only
```

External execution remains passive: no form submission, JavaScript execution, active payload injection, redirect following, brute force, or directory enumeration.
