# ADR 0029: Security Governance Baseline

- **Status:** Accepted
- **Date:** 2026-08-07
- **Checkpoint:** Stability & Security Audit, Checkpoint 1
- **Findings:** C1-002, C1-005, C1-009

## Context

Checkpoint 1 found that several repository-level security and governance documents existed as empty placeholders, while the implementation had already accumulated substantial authorisation, tenancy, cryptographic, persistence, and runtime-safety behaviour across milestone ADRs and code.

The README also contained stale Milestone 1.31 test counts and listed future directories as if they were part of the current repository structure.

A commercial security product needs a current, reviewable security baseline that distinguishes implemented controls from planned production architecture and that does not silently drift back to empty/stale placeholders.

## Decision

Adopt a repository security-governance baseline containing:

- `SECURITY.md` for vulnerability reporting, supported development baseline, secret handling, and security limitations;
- `docs/ARCHITECTURE.md` for current components, execution flow, persistence, cryptographic uses, and trust boundaries;
- `docs/AUTHORIZATION_MODEL.md` for the layered permission chain from owned-target authority through runtime enforcement;
- `docs/DATA_CLASSIFICATION.md` for Public/Internal/Confidential/Restricted handling;
- `docs/THREAT_MODEL.md` for assets, actors, threats, controls, assumptions, and residual risk;
- `docs/ROADMAP.md` to separate implemented capability from planned hosted/enterprise work;
- `THIRD_PARTY_NOTICES.md` for directly referenced third-party components and release-review obligations; and
- a non-secret `.env.example` limited to opt-in integration-test controls.

The README will describe only repository paths that currently exist and will avoid hardcoding volatile test totals; current counts remain visible in `./scripts/verify.sh` and CI output.

The loopback-binding error text will no longer refer to an obsolete milestone number.

A fail-closed governance verifier will run from `scripts/verify.sh` to reject empty required documents, known stale README markers, reintroduction of nonexistent repository-path claims, or secret-like example configuration.

## Consequences

### Positive

- Security architecture is reviewable without reconstructing it from dozens of implementation files.
- Current controls and future plans are explicitly separated.
- The permission model and threat model become auditable baselines for future changes.
- README milestone/test drift is less likely to recur.
- Empty governance placeholders fail the normal verification gate.

### Trade-offs

- Documentation becomes part of the maintained security surface and must change when architecture changes.
- The threat model does not replace adversarial testing or an independent security assessment.
- Third-party notices remain a direct-component inventory until release tooling produces a complete SBOM/licence bundle.

## Security invariant

Documentation must never weaken implementation controls. If documentation and code disagree, execution must continue to fail according to code, and the mismatch must be treated as a defect to resolve before release.
