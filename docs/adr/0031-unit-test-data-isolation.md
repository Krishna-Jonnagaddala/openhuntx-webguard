# ADR 0031: Unit Test Data Isolation

- Status: Accepted
- Date: 2026-08-07
- Audit finding: C1-006

## Context

Ordinary WebGuard unit tests contained references to a real owned production domain.

Although the references were test fixtures and did not contain authorization documents, secrets, or credentials, coupling unit tests to a real operational asset creates unnecessary association between automated test data and production infrastructure.

Unit tests should be deterministic, neutral, and independent of real customer or company assets.

## Decision

WebGuard unit tests must use reserved or clearly synthetic test identifiers for ordinary fixtures.

For DNS and HTTP examples, `example.com` and related reserved example-domain variants are preferred where appropriate.

Real owned-target domains must not be embedded in ordinary unit-test fixtures.

Real-target validation remains a separate, explicitly authorized operational activity using uncommitted authorization material and controlled external-validation procedures.

Case-normalization and hostname-validation tests may continue using mixed-case variants of neutral example domains where required to preserve test intent.

## Consequences

- Unit tests no longer encode a real owned production domain.
- Test behavior remains independent of operational assets.
- Public repository contents disclose less operational information.
- Real owned-target testing remains clearly separated from deterministic automated tests.
- Future unit-test fixtures should use reserved or synthetic domains.

## Verification

Checkpoint 1 remediation replaced the real owned-target domain in the affected unit-test fixtures with neutral `example.com` fixtures while preserving test semantics.

The repository verification gate must continue to pass after the replacement.
