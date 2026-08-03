# OpenHuntX WebGuard

Continuous web vulnerability discovery and security assurance for authorised targets.

## Status

Private commercial product under active development.

## Safety

OpenHuntX WebGuard must only assess systems that the customer owns or is explicitly authorised to test.

The initial implementation supports local and deliberately vulnerable test systems only.

## Repository structure

- `apps/api` — control-plane API
- `apps/web` — customer dashboard
- `workers/scanner` — isolated scanner workers
- `packages/contracts` — shared API and finding contracts
- `infra/compose` — local infrastructure
- `infra/zap` — ZAP automation plans
- `docs` — product, architecture and security documentation
- `tests` — automated tests and safe fixtures

## Current milestone

Build a local passive-scanning proof of concept against an isolated OWASP Juice Shop instance.