# OpenHuntX WebGuard Data Classification and Handling

## 1. Purpose

WebGuard processes security-assessment information that can materially increase risk if disclosed. This document defines a minimum classification model for repository, development, and future service data.

The classifications describe required handling. They do not replace contractual, privacy, regulatory, or customer-specific requirements.

## 2. Classification levels

### Public

Information intentionally safe for unrestricted release.

Examples:

- public product documentation;
- the TrustScan public verification key;
- published security contact information;
- approved redacted assurance summaries; and
- public source-code material in repositories intentionally released by OpenHuntX.

### Internal

Operational or engineering information not intended for public release but unlikely to create direct customer security harm by itself.

Examples:

- non-sensitive development notes;
- generic architecture discussions without secrets/customer data;
- test plans using neutral fixtures; and
- CI metadata that contains no credentials.

### Confidential

Customer, security, or operational information that could create meaningful risk if disclosed.

Examples:

- target inventories;
- owned-target authorisations;
- scan findings and reports;
- job and schedule metadata;
- security audit events;
- signed TrustScan permits;
- Safety Receipts before an explicit release decision;
- organisation/principal metadata; and
- system logs containing customer identifiers or security posture.

### Restricted

Secrets or highly sensitive data whose disclosure can enable authentication bypass, cryptographic impersonation, customer compromise, or material security harm.

Examples:

- raw `wgt_...` API tokens;
- TrustScan Ed25519 private signing material;
- pagination HMAC keys;
- checkpoint signing keys;
- future authenticated-scan credentials;
- CI/CD credentials;
- production database credentials; and
- unredacted secrets accidentally observed in target content.

## 3. Data inventory

| Data | Default class | Current behaviour / handling |
| --- | --- | --- |
| Source code | Internal or Public by repository policy | Git-controlled; secrets prohibited |
| Public verification key | Public | Exposed through unauthenticated verification-key API |
| Raw API token | Restricted | Returned once; raw secret is not persisted by identity store |
| API token hash/metadata | Confidential | Stored in owner-only SQLite database; secret uses scrypt hash |
| TrustScan private key | Restricted | Stored in owner-only SQLite service-secret table at current local stage |
| Cursor HMAC key | Restricted | Stored in owner-only SQLite service-secret table at current local stage |
| Organisation/principal records | Confidential | Stored in SQLite |
| Owned-target authorisation | Confidential | Owner-only authorisation file; server assignment required |
| Authorisation audit record | Confidential | Private scan artefact |
| TrustScan permit | Confidential | Signed claims plus revocation metadata; contains identifiers and target |
| Job/schedule metadata | Confidential | Organisation-scoped SQLite state |
| Security audit events | Confidential | Organisation-scoped SQLite state |
| Scan finding/report | Confidential | Owner-only artefact by default |
| Comparison/remediation report | Confidential | Owner-only artefact by default |
| Crawl checkpoint | Confidential | Signed owner-only artefact; must not contain response bodies |
| Checkpoint signing key | Restricted | Separate owner-only key material |
| Safety Receipt | Confidential | Owner-only signed artefact; may be selectively redacted/released later |
| Response body in scanner memory | Confidential | Bounded transient processing; not intended as checkpoint/report raw-body persistence |
| Integration-test lab data | Internal | Local authorised Juice Shop only; no production customer content |

## 4. Repository rules

The Git repository must not contain:

- raw API tokens;
- private keys;
- production databases;
- authorisation documents for real customers;
- customer scan results;
- private reports;
- secret-bearing `.env` files;
- backups containing customer or secret state; or
- generated service artefacts.

Known private/generated paths such as `var/`, `authorizations/`, and `scan-results/` are operational data, not source-controlled product content.

## 5. API token handling

API tokens use the `wgt_...` format and must be treated as Restricted.

Current controls:

- the raw token is returned only at issue time;
- the identity store persists an scrypt hash rather than the raw secret;
- tokens have bounded validity;
- revoked or expired tokens are rejected; and
- last-used metadata may be updated on successful authentication.

Operational rule: do not paste raw tokens into screenshots, tickets, chat transcripts, commits, shell history, or documentation. Prefer interactive input or a secrets manager appropriate to the deployment stage.

## 6. Cryptographic key handling

TrustScan private signing material, cursor HMAC keys, and checkpoint signing keys are Restricted.

At the current local milestone:

- the TrustScan private seed and cursor HMAC secret are protected by owner-only SQLite file permissions;
- checkpoint keys are expected to use owner-only permissions; and
- the TrustScan public key is intentionally distributable.

Production requirement: move hosted signing keys out of a general application database and into a managed key boundary with access control, rotation, auditability, and recovery procedures.

## 7. Authorisation data

Owned-target authorisations contain organisation, approver, target, scope, validity, purpose, and execution limits. Treat them as Confidential even when the hostname is publicly known because the complete document reveals customer testing authority and policy.

Do not publish authorisation IDs or documents as evidence of legal permission without an explicit disclosure decision.

## 8. Findings and reports

Scan results can reveal exploitable weaknesses. Default classification is Confidential.

Reports should follow data minimisation:

- retain enough evidence to reproduce and remediate a finding;
- avoid retaining secrets or full sensitive response bodies when a smaller evidence representation is sufficient;
- escape customer-controlled text in rendered reports;
- keep generated artefacts owner-only; and
- release externally only after customer and OpenHuntX review.

A report showing no identified issue does not justify downgrading the underlying scan evidence to Public.

## 9. Safety Receipts and permits

TrustScan permits and Safety Receipts are cryptographically verifiable but are not automatically public.

They can disclose:

- organisation IDs;
- target URLs;
- job/scan identifiers;
- permission windows;
- scan budgets; and
- runtime safety counters.

A future public assurance badge or transparency record should use a deliberately redacted/public representation rather than expose private operational artefacts wholesale.

## 10. Logs and errors

Logs and API error responses must not intentionally echo raw tokens, signing keys, private response bodies, or unnecessary customer secrets.

Stable error codes are preferred over dumping internal exceptions. Operational logs should be treated as Confidential unless proven otherwise because request IDs, target information, and security state can become sensitive in combination.

## 11. Development and test data

Unit tests should use neutral synthetic identifiers and domains wherever possible. Real owned targets belong only in explicit operator-controlled validation or authorised integration workflows.

This rule supports audit finding C1-006 and reduces accidental coupling between test fixtures and a real business asset.

## 12. Retention and deletion

The current local engineering foundation does not implement a complete hosted retention service. Operators are responsible for deleting no-longer-needed local databases and artefacts securely enough for the underlying environment.

Before production release, each persistent data class must have an explicit retention, deletion, backup, restore, and legal-hold policy.

## 13. Backups

A backup inherits the highest classification of the data it contains. Backing up an owner-only SQLite database creates another Restricted object because the database contains signing material.

Backups must not be placed in source control or general file-sharing locations.

## 14. Incident handling

If Restricted material is exposed:

1. stop further disclosure;
2. revoke or rotate the affected secret when possible;
3. preserve necessary audit evidence without spreading the secret;
4. identify affected organisations, jobs, permits, and artefacts;
5. assess whether signed evidence must be distrusted or reissued; and
6. document remediation and lessons learned.

Do not rely on deletion of a chat message, Git commit, log entry, or screenshot as proof that an exposed secret was never copied.
