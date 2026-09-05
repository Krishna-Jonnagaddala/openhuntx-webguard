# OpenHuntX WebGuard Roadmap

## Status language

This roadmap separates implemented capability from planned work. Planned items are not current product claims and may change as security, legal, customer, and engineering requirements evolve.

## Platform scope

OpenHuntX WebGuard's end goal is a product with one shared scanner/security engine consumed by three interfaces: a web application (primary customer interface), an API (control plane), a CLI (developer/DevSecOps interface), and eventually a private-network scanning agent. **The scanner is the engine; WebGuard is the platform.** No interface may implement its own scanning or authorization logic: all of them call the same `ScanJobExecutor`, the same TrustScan permit model, the same active-detector registry.

Today, only two of those interfaces exist: the `webguard-api` CLI and its local, loopback-only HTTP API (`apps/api/`). There is no web application, no hosted/multi-instance deployment, no PostgreSQL/Redis, and no enterprise agent. This is a real gap against the platform vision, not a hidden one. See `docs/audit/production-gap-matrix.md` for the full inventory and "Control-plane and runner separation" below for what a hosted control plane requires. Per the project's own stated priority, closing this gap comes *after* the current detection-engine work (candidate discovery, additional detector classes, finding/evidence stabilization), not before it: building a web frontend or a PostgreSQL migration on top of an unstable scanner contract would mean redoing that work later.

## Implemented foundation, through Milestone 1.32

The current local engineering foundation includes:

- strict target-scope validation and safe HTTP handling;
- versioned finding, scan, crawl, checkpoint, job, schedule, permit, and Safety Receipt contracts;
- passive HTTP/HTML/cookie/CORS/disclosure/TLS analysis;
- bounded same-origin crawling;
- cancellation, execution budgets, retry controls, and signed resume checkpoints;
- owned-target external preflight and audit evidence;
- professional reporting and remediation comparison;
- local loopback API and persistent job queue;
- organisations, principals, Bearer authentication, RBAC, and audit events;
- worker leases, heartbeat renewal, crash recovery, and stale-worker fencing;
- recurring scheduling and safe catch-up;
- signed cursor pagination and organisation activity feeds;
- Ed25519-signed TrustScan Scan Permit v1;
- request-boundary runtime safety enforcement; and
- Ed25519-signed TrustScan Safety Receipt v1.

Checkpoint 1 also establishes a reproducible CI/supply-chain baseline with reviewed dependency hashes and immutable workflow/lab pins.

## Checkpoint 1 remediation

Before expanding the feature surface, the security audit is addressing:

- security and governance documentation;
- CI security gates;
- package/version consistency;
- neutral test-data isolation; and
- explicit acceptance/deferment of local signing-secret storage until the production key architecture is implemented.

## Next product-engineering priorities

### Permission and identity maturity

Planned:

- production asset registration;
- verifiable domain/asset control or delegated-authority workflows;
- customer acceptance/recording of testing terms;
- stronger hosted identity and session controls;
- enterprise SSO/federation; and
- permission lifecycle evidence suitable for customer review.

### Control-plane and runner separation

Planned:

- hosted web/API control plane;
- isolated managed scanner runners;
- explicit runner identity;
- restricted runner egress;
- workload-scoped credentials;
- control-plane-to-runner job attestation; and
- later customer-hosted Docker/Kubernetes runners for enterprise environments.

### Key management

Planned before hosted production:

- KMS/HSM-backed TrustScan signing keys;
- key versioning and public verification-key history;
- rotation procedures;
- compromise/distrust procedures;
- separation of signing authority from scanner runtime; and
- backup/recovery that does not export unrestricted private keys.

### Proof-carrying assessments

Planned evolution of TrustScan:

- scanner execution attestation;
- signed runtime-safety receipts with richer policy provenance;
- coverage truth maps;
- tamper-evident assessment ledger;
- signed/verifiable remediation receipts; and
- customer-verifiable evidence chains from permission through retest.

### Coverage growth

Any increased scan capability must preserve explicit authorisation levels and safety limits.

Planned areas may include:

- broader passive web/API discovery;
- technology and software-component inventory;
- known-vulnerability intelligence correlation;
- API schema-aware assessment;
- controlled authenticated scanning; and
- carefully permissioned active checks.

Active exploitation, denial-of-service testing, password attacks, persistence, destructive testing, or unverified third-party testing are not part of the current initial release scope.

### Detection architecture and CWE coverage

Today's passive analyzers (`cors_analyzer`, `header_analyzer`, `cookie_analyzer`, `html_analyzer`, `disclosure_analyzer`, `tls_analyzer`) already attach CWE identifiers to findings; see `docs/CWE_COVERAGE.md` for the current implemented/planned registry. Growing this into a standardised detection framework is planned, not yet built:

- a common `SecurityCheck` interface (check ID, CWE/OWASP mapping, severity, confidence, detection mode, prerequisites) so new checks are additive rather than bespoke;
- a finding model that separates severity from confidence, and separates "indicator detected" from "exploitability confirmed";
- an evidence model (request, response, reproduction data, evidence hash) sufficient to reproduce a finding independently of the original scan run;
- check and scanner-engine versioning, so historical findings remain reproducible against the check version that produced them;
- finding lifecycle and deduplication (open/confirmed/false-positive/accepted-risk/resolved), so one underlying weakness does not produce duplicate findings across pages;
- OWASP and CVSS classification layered on top of CWE, with CVSS only assigned when evidence supports it; and
- SARIF, JSON, and CSV export alongside the existing report formats.

Every new active check must still cross the TrustScan permit boundary described above; this section extends detection breadth, not the authorization model.

CWE coverage claims must always be honest and specific: WebGuard tracks web-relevant, externally observable CWE classes with transparent per-CWE status (implemented / partial / planned / not applicable), not a claim of covering the full CWE catalog. See `docs/CWE_COVERAGE.md`.

### Reporting and interoperability

Planned:

- customer dashboard and assessment history;
- downloadable evidence bundles;
- standards-oriented exports where semantically appropriate, including SARIF, OSCAL, and CycloneDX/VEX-style evidence;
- remediation workflow integrations; and
- redacted public assurance summaries that never imply permanent security.

### Data and regional controls

Planned for hosted/enterprise use:

- explicit retention and deletion policies;
- backup/restore controls;
- regional data placement;
- tenant-configurable retention where appropriate;
- customer data export/deletion workflows; and
- auditable access to sensitive assessment data.

## Commercial-readiness gates

A hosted private beta should not begin until, at minimum:

- target authority is centrally verified;
- control-plane and scanner execution boundaries are defined and hardened;
- production signing secrets are outside general application state;
- CI includes automated secret/dependency/static-security gates;
- core tenant-isolation and authorisation paths complete adversarial review;
- retention/backups are defined;
- abuse prevention and incident response are documented;
- customer-facing limitations are clear; and
- an independent security assessment is planned or completed at the appropriate release stage.

## Non-goals and claims

The roadmap does not create claims that WebGuard:

- finds every vulnerability;
- makes testing risk-free;
- proves legal authority by cryptography alone;
- proves a target is secure; or
- is the first or only product to implement any individual security technique.

WebGuard's intended differentiation is the end-to-end combination of explicit permission, runtime safety enforcement, coverage truth, verifiable evidence, and remediation verification.
