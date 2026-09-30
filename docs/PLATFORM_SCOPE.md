# Platform Scope

OpenHuntX is one platform with three separately usable modules: WebGuard, SOC, and Compliance. This is a deliberate, approved expansion of the original WebGuard-only project, recorded 2026-09-12 per `docs/audit/OPENHUNTX_THREE_MODULE_PLATFORM_HANDOFF_2026-09.md` (the supplied decision document, committed verbatim for durability). This file is the reconciled, currently-tracked scope contract; the handoff document is the historical source, not the other way around, since this file gets updated as work actually lands and that one does not.

## The three modules

| Module | Responsibility | Outcome |
|---|---|---|
| WebGuard | Authorized web and API security assessment: TrustScan, coverage, findings, comparable retesting | What was permitted, tested, found, and verified after remediation |
| SOC | Federated security operations: detection assurance, investigation, governed response | Which selected defensive paths work, where they fail, what evidence supports action |
| Compliance | Continuous control assurance, governance, privacy workflows, audit preparation | Control scope, operating evidence, deficiencies, exceptions, audit-period history |

Individual users can use WebGuard without SOC or Compliance. An organization can start with one module. Module entitlement is separate from data permission: an unsubscribed module must not leak sensitive summary data, and disabling a module must not break evidence another module already used.

## What this is not

Not three disconnected applications, and not three labels over one dashboard. One shared entity identity and evidence system (`docs/adr/0033-platform-expansion-module-boundaries.md`) underlies all three, with separate domain views and permissions per module. A scanner finding is not automatically an incident; an incident is not automatically a failed legal requirement; a satisfied control assertion is not automatically a passed audit. These stay distinct, linked objects, never flattened into one status enum.

## Product promise

Authorize. Observe. Validate. Remediate. Prove. TrustScan is WebGuard's authority and safety layer; ProofLoop is SOC's defensive-path validation layer; continuous assurance is Compliance's scoped control-evidence layer. These are product concepts this project is building, not claims of trademark clearance or unique invention over prior art (Invicti, Anvilogic, Picus, Drata, Vanta, and MITRE CTID's own published research all cover pieces of this ground; see the handoff's §4 for the honest competitive comparison).

## Claim boundaries (binding on every module's UI, docs, and exports)

- No fabricated or uncalibrated precision. Show components, denominators, and method versions, not a single invented score (e.g. never "87/100 defense" or "99.7% confidence" without a real, reproducible calculation behind it).
- A green detection-coverage indicator means a selected, versioned implementation was tested, not that all possible attacker behavior is enumerated.
- An incident affecting a mapped control shows a potential control implication and the mapping rationale. Incident response and legal determination stay separate; this platform never asserts a legal violation.
- "All applicable controls continuously verified" is prohibited phrasing. Show supported/applicable/enabled/executed/unknown populations and observation windows instead.
- Zero applicable population yields "not applicable" or "unresolved," never a manufactured 100% pass.
- "Certified by ISO," "HIPAA Certified," and automatic legal-compliance labels are prohibited. A SOC 2 report is an examination, not a certificate with a fixed expiry; store examination period, report date, opinion, and scope instead of an expiry date.
- Revoked sessions cannot be restored; reauthentication is recovery, not rollback. A provider 2xx response does not by itself prove a containment action succeeded; verify the postcondition.
- Read-only assessment output does not imply proven response capability. Report inferred readiness separately from observed execution and from expressly authorized active validation.
- No production infrastructure changes, no public service exposure, no real customer telemetry connection, and no regulatory submission are authorized by this scope document. Those each need their own explicit, separate authorization when the time comes.

## Delivery sequence (dependency-ordered, not separate permission checkpoints)

1. Reconcile current work and preserve existing WebGuard contracts. (Done, 2026-09-12; see `docs/PROJECT_EXECUTION_LEDGER.md`.)
2. Finish critical shared security foundations. (Done: Phase H runtime tenant-context conversion, PRs #30-47. RLS+FORCE activation in a real environment remains open and is infrastructure-gated, tracked as P1-2.)
3. Unify entity/evidence/authority contracts across modules. (Module entitlement shipped and wired into organization creation; see `docs/adr/0033-platform-expansion-module-boundaries.md`.)
4. Deliver federated observation (the Microsoft connector subset: Sentinel, Defender XDR, Entra). All three named connectors now have contract-designed manifests with verified permissions/RBAC roles (PRs #53, #55, #57); live HTTP clients remain blocked on real tenant credentials.
5. Deliver the full three-module lab workflow: an authorized WebGuard assessment flows through SOC validation to scoped Compliance evidence and independent export verification. Not started: no code path yet connects a WebGuard finding to a SOC or Compliance record in either direction. Compliance's own foundation for this (framework/master-control catalog, PR #54; scoped control implementation/applicability, PR #56; technical assertion catalog, PR #58) is in place, but nothing has executed against it yet.
6. Complete reviewer workflows: investigations, audit requests, exceptions, historical views, privacy/vendor registers, comparable retest closure.
7. Introduce governed actions: shadow evaluation first, then explicit approval execution with independent postcondition checking.
8. Harden for scoped enterprise use: live connector proof, operational limits, restore tests, deployment evidence, design-partner assessment.
9. Expand validated content: more ecosystems, assertion families, customer-hosted options, through the same gates.

Steps 1-3 are substantially complete. Step 4's contract/fixture work is complete for all three named connectors; step 5's Compliance-side foundation exists but nothing has run end to end yet. Do not read step numbers as a claim that later steps have zero work started; contracts and fixtures for blocked items (step 4's connectors, step 6's framework packs) can and do proceed in parallel where the work itself needs no missing credential or missing legal text. This section was last reconciled against actual repository state on 2026-09-15 (see the OpenHuntX Scope & Progress Audit, 2026-09-14, and `docs/PROJECT_EXECUTION_LEDGER.md`'s per-PR narrative entries); the previous version of this section was written 2026-09-12 and had not been updated across the seven PRs that shipped since.

## Explicitly deferred (not silently dropped)

| Area | Entry condition |
|---|---|
| Native SIEM / OpenHuntX lake | Measured scale, storage economics, retention/replay, migration and operational ownership |
| Security cost engine and tiering simulation | Start with measured cost/dependency reports; simulate later with representative history |
| Universal query language | Constrained tested queries and native adapters first; expand after semantic conformance is proven |
| AI-generated connectors and no-code custom tests | Only after manual SDK security/conformance is proven; never publish arbitrary generated code directly |
| Advanced autonomous response | Gated on adjudicated shadow outcomes, action-specific authorization, live postcondition proof, recovery readiness |
| Broad cyber-range/BAS library | Integrate reviewed third-party tools; keep test safety, authority, and proof interpretation inside OpenHuntX |
| Dark-web / identity exposure | Licensed provider integrations only; never build a stolen-credential repository or validate credentials by logging in |
| Training and phishing platforms | Integrate assignment/completion evidence; a simulated click is not evidence of account compromise |
| Secure communications | Consume/enforce supported provider controls; not a new encrypted mail gateway |
| Full CNAPP, EDR agent, firewall, email gateway | Integrate specialized providers; excluded from the native build |
| Full privacy automation | Workflow/evidence assistance; human legal decisions and verified jurisdiction packs stay authoritative |
| Predictive "digital twin" | Dated dependency/impact view only; no precise outage predictions without a calibrated model |
| 2,215 planning-catalogue tests / 640 planning-catalogue integrations | Planning capacity targets only, from the source handoff's own appendix; supported inventory grows from what's actually executable and maintained, never a quota |
| Additional framework packs beyond the initial five (SOC 2, ISO/IEC 27001:2022, HIPAA, GDPR, UK GDPR) | Versioned extension packs after licensing/applicability review; candidates named in the handoff (ISO/IEC 27701, NIST CSF, CIS Controls, NIST SP 800-53, PCI DSS, ISO/IEC 42001, Cyber Essentials, NIS2, DORA, HITRUST, CMMC) are not claims of current support |

## Concrete, currently-open blockers

- **SOC connectors** (Sentinel, Defender XDR, Entra): need real Microsoft tenant credentials. Contracts, fixtures, and permission manifests proceed without them; live validation is marked blocked, never claimed production-verified against a fixture.
- **Compliance framework packs** (SOC 2, ISO/IEC 27001:2022 + 2024 amendment, HIPAA, GDPR, UK GDPR): need authoritative legal-text verification before any legal claim ships. The source handoff itself could not fully retrieve EUR-Lex GDPR or UK legislation pages; do not ship exact statutory dates from the draft without independent verification.
- **RLS+FORCE activation** (P1-2's remaining half): needs a real, non-disposable Postgres environment this session has no standing authorization to provision or touch.
- **Object storage and secret-provider tenant isolation** (P1-13): report artifacts and authenticated-scanning secret material are both isolated by construction only (a caller-derived reference string from an already tenant-scoped database read), never independently re-enforced by the layer that actually holds the data. Traced 2026-09-15: every current caller is correct, but there is no compensating control if that discipline ever lapses in a future change. Severity Medium; a per-tenant enforcement layer versus an explicitly accepted residual is a real, unmade decision. See `docs/PROJECT_EXECUTION_LEDGER.md`'s P1-13 row for the full trace.

## Governance note

Do not stop for approval at each routine milestone within this scope. Ask only for a specific missing access, a consequential authorization (production changes, public exposure, real customer telemetry, regulatory submission), or an irreducible product decision, after the work that can already be completed has been completed. Update `docs/PROJECT_EXECUTION_LEDGER.md` after each slice rather than batching reports silently.
