# OpenHuntX WebGuard Security Policy

## Product status

OpenHuntX WebGuard is a private commercial security product under active development. The repository currently represents a local, single-host engineering foundation rather than a publicly hosted production service.

The local WebGuard API is intentionally restricted to loopback IP addresses. It is not approved for direct exposure to untrusted networks or the public internet.

## Supported versions

| Version or branch | Security support |
| --- | --- |
| Current `main` branch | Supported for active development and security fixes |
| Historical milestone commits | Not independently supported |
| Public hosted service | Not yet released |

Until a formal release policy exists, security fixes are made against the current development baseline rather than backported to historical milestones.

## Reporting a vulnerability

Do not open a public GitHub issue containing exploit details, credentials, private target information, scan artefacts, or other sensitive security information.

Preferred reporting paths are:

1. the repository's private GitHub security-reporting or security-advisory channel, when enabled; or
2. the official private OpenHuntX security contact published through OpenHuntX-operated channels.

A report should contain only the information needed to reproduce and assess the issue:

- affected WebGuard version or commit;
- affected component;
- technical impact;
- reproducible steps or a minimal proof of concept;
- whether authentication or a specific role is required;
- whether tenant isolation, scan authorisation, TrustScan permits, runtime safety, signing keys, or artefacts are affected; and
- suggested remediation, if known.

Do not include live customer credentials, API tokens, private keys, or unrelated customer data. Redact them before submission.

## Security response principles

OpenHuntX will triage reported issues according to technical impact and exploitability. Remediation and disclosure timing depend on severity, affected deployments, and the need to protect customers while a fix is prepared.

Security-sensitive fixes should include regression coverage whenever practical. Changes to trust boundaries, authorisation, cryptographic formats, tenancy, persistent schemas, runner isolation, or safety enforcement should be documented in an Architecture Decision Record (ADR).

## Scope of authorised testing

WebGuard must only be used against targets that the operator owns or is explicitly authorised to assess.

A public hostname, reachable IP address, DNS record, or working HTTP endpoint does not by itself establish permission to test it. TrustScan permits are technical execution-authorisation records and do not independently prove legal ownership or legal permission.

Testing WebGuard itself must not be used as a reason to send traffic to an unrelated third-party target. Use isolated laboratory targets or systems for which explicit permission exists.

## Current security boundaries

The current implementation relies on several deliberate boundaries:

- loopback-only API binding;
- Bearer-token authentication and organisation-scoped RBAC;
- server-side owned-target authorisation assignments;
- cryptographically signed TrustScan permits;
- request-boundary permit and authorisation revalidation;
- same-origin, method, request-budget, rate, and concurrency enforcement;
- safe HTTP target validation and redirect blocking;
- private SQLite and artefact permissions;
- bounded worker leases and stale-worker fencing;
- signed crawl checkpoints and signed TrustScan Safety Receipts; and
- hash-locked external Python dependencies and pinned CI/lab inputs.

These controls reduce risk but do not prove that a target cannot be affected by testing and do not prove that a target is secure.

## Secrets and credentials

The following must be treated as restricted secrets:

- raw `wgt_...` API tokens;
- TrustScan Ed25519 private signing material;
- cursor-signing HMAC material;
- checkpoint signing keys;
- any future customer credentials or authenticated-scan secrets; and
- deployment or CI credentials.

Raw API tokens are intended to be displayed once and stored outside the repository. If a token or private key is exposed, revoke or rotate it and treat the previous value as compromised.

Never commit secrets, production databases, authorisation documents, customer scan results, private reports, or backups to Git.

## Sensitive artefacts

Treat the following as confidential unless an explicit release process states otherwise:

- owned-target authorisation documents;
- job and schedule metadata;
- security audit events;
- signed TrustScan permits;
- scan reports and findings;
- comparison and remediation-verification reports;
- checkpoints;
- TrustScan Safety Receipts; and
- service databases and backups.

See `docs/DATA_CLASSIFICATION.md` for the repository's detailed handling model.

## Security design documentation

The security model is documented in:

- `docs/ARCHITECTURE.md`: current system architecture and trust boundaries;
- `docs/AUTHORIZATION_MODEL.md`: authorisation layers and fail-closed execution flow;
- `docs/DATA_CLASSIFICATION.md`: data sensitivity and handling rules;
- `docs/THREAT_MODEL.md`: threat actors, attack paths, mitigations, and residual risks;
- `docs/PRODUCT_CHARTER.md`: product principles and scope; and
- `docs/adr/`: milestone and security architecture decisions.

## Production-readiness limitation

The current single-host implementation is not the final hosted architecture. In particular, the current SQLite database stores service cryptographic secret material protected by owner-only filesystem permissions. A production hosted control plane must move signing secrets to an appropriate managed key boundary such as KMS/HSM-backed storage and separate the control plane from scanner execution infrastructure.
