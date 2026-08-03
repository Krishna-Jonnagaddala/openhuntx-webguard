# ADR 0002: Normalized Finding Contract

## Status

Accepted

## Context

OpenHuntX WebGuard will receive findings from multiple sources, including:

- Native passive security checks;
- OWASP ZAP;
- TLS analysis;
- Dependency scanning;
- NVD and OSV correlation;
- Source-code scanning; and
- Manual security review.

Each source uses different names, severity systems, evidence formats and
identifiers.

## Decision

All scanner and vulnerability-intelligence results will be converted into a
versioned, scanner-independent `NormalizedFinding` contract before storage,
reporting or message-queue delivery.

A finding identity consists of:

- Internal canonical rule ID;
- Canonical asset origin;
- HTTP path;
- HTTP method; and
- Optional parameter.

These identity fields produce a deterministic SHA-256 fingerprint.

The fingerprint intentionally excludes:

- Title;
- Description;
- Severity;
- Confidence;
- Evidence;
- Remediation; and
- Detection time.

This allows the same vulnerability to retain its identity when its evidence,
severity or risk assessment changes between scans.

Raw HTTP responses, credentials and sensitive evidence will not be stored
directly inside finding records. They will be stored separately in protected
artifact storage and referenced through an opaque artifact identifier.

## Consequences

Every scanner adapter must convert its native results into the shared contract.

Changing the fingerprint identity rules will require:

- A new fingerprint version;
- A documented migration strategy; and
- Compatibility handling for existing findings.

The normalized finding contract represents a security observation only.

Customer workflow state, including false positive, accepted risk, remediated,
reopened or suppressed, will be stored separately from the finding itself.
