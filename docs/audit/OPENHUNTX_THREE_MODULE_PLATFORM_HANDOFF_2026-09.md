> Committed to the repository 2026-09-12 for durability, verbatim from the source file the owner supplied
> (`OpenHuntX_Three_Module_Claude_Handoff.md`, outside version control until now). Content below this line is
> unmodified from that source. This is a supplied design/decision document, not independently verified
> repository or market evidence; see `docs/PLATFORM_SCOPE.md` and `docs/PROJECT_EXECUTION_LEDGER.md` for the
> reconciled, currently-tracked implementation state.

# OpenHuntX: WebGuard, SOC and Compliance — authoritative recommendation and Claude handoff

## 1. Decision and intended outcome

Build **one OpenHuntX platform with three separately usable modules**:

| Module | Product responsibility | Primary outcome |
|---|---|---|
| OpenHuntX \| WebGuard | Authorised web and API security assessment, TrustScan, coverage, findings and comparable retesting | Explain what was permitted, tested, found and verified after remediation |
| OpenHuntX \| SOC | Federated security operations, detection assurance, investigation and governed response | Explain which selected defensive paths work, where they fail and what evidence supports action |
| OpenHuntX \| Compliance | Continuous control assurance, governance, privacy workflows and audit preparation | Explain control scope, operating evidence, deficiencies, exceptions and audit-period history |

**Recommendation:** preserve WebGuard's original vision and add SOC and Compliance as an explicit, approved platform expansion. The earlier instruction to avoid building SOC or a general compliance product is superseded by this expansion. WebGuard itself must retain its identity and roadmap. These are neither three disconnected applications nor three labels over the same dashboard.

The common product promise should be: **Authorise. Observe. Validate. Remediate. Prove.** Use TrustScan for web assessment authority and safety; ProofLoop for defensive-path validation; Continuous Assurance for scoped control evidence. Treat these as product concepts, not proof of trademark clearance or unique invention.

Prioritise Microsoft-oriented SaaS businesses and security teams using Entra, Sentinel and Defender as the first validation cohort. This is a product recommendation based on ecosystem alignment and the supplied strategy, not a measured market-size conclusion. Individual users should be able to use WebGuard without buying a SOC stack; organisations should be able to start with one module. An MSSP can later manage separately authorised customer workspaces without weakening tenant isolation.

The defining demonstration should connect a web assessment to actual security telemetry, a validated detection, an authorised response or fix, a comparable retest, and scoped audit evidence. Each link must show its limitations. A product that exposes missing proof reliably is more credible than a product that claims universal protection.

## 2. Evidence basis and boundaries

This handoff analyses both supplied documents in full:

- **S:** `Pasted markdown(20260911-104443).md`, 2,194 lines, numbered SOC sections 1–53 and closing recommendations.
- **C:** `Pasted markdown (2)(4).md`, 3,598 lines, numbered Compliance sections 1–84.
- **H:** the supplied conversation history, including the WebGuard ten-pillar vision and the Phase G completion report.

The attached documents are design proposals, not implementation evidence. The source disposition register at the end accounts for every numbered section. All retained ideas are subject to the corrections and acceptance requirements in this handoff; illustrative metrics and speculative claims are not imported as facts.

Public-source checks were made on **11 September 2026**. Primary sources support the material technology and terminology decisions below. Public vendor statements demonstrate advertised overlap, not independently benchmarked effectiveness. No live customer environment, source repository, full historical chat archive or exact-commit CI log was independently inspected for this report. The previous full WebGuard master prompt was referenced in supplied history but was not attached here; Claude must retain and reconcile it if available in its project.

No document can establish zero defects or exhaustive worldwide novelty. Completion must be earned through evidence-based gates. Regulatory status must be rechecked when a framework pack is released; an inaccessible source is a verification gap, not permission to invent a deadline.

## 3. Findings that change the drafts

| Issue in source proposals | Final recommendation |
|---|---|
| Prior WebGuard-only boundary conflicts with new modules | Record a deliberate platform expansion; retain every WebGuard pillar and current remediation obligation |
| Compliance navigation omits WebGuard | Use the three named modules as the primary product navigation |
| Multiple Security/Investigation/Assurance Graphs and Evidence Vaults | One shared entity identity and evidence system, with separate domain views and permissions |
| “Autonomous” as the initial SOC description | Use evidence-driven security operations; begin with observation, investigation and recommendations |
| “SHA256 / signing key” presented as a signature | Separate content digests from asymmetric signatures; use a reviewed envelope and verifier [12] |
| Session revocation labelled reversible | Revoked sessions cannot be restored; reauthentication is recovery, not rollback. Microsoft also documents propagation delays and external-user limitations [5] |
| Isolation, disabling credentials and making storage private listed as low risk | Risk depends on the asset and business dependency. No global low-risk designation |
| Read-only seven-day assessment implies proven response capability | Report inferred readiness separately from observed execution and expressly authorised active validation |
| One-click replay implies deterministic AI | Preserve original outputs; distinguish historical reconstruction, deterministic rule replay and new-model reanalysis |
| E0–E5 presented as a universal evidence ladder | Use independent evidence dimensions; a live API is not inherently more relevant than an approved human governance record |
| A successful collector becomes a successful control | Collection, test execution, assertion outcome, scope completeness and control effectiveness are different states |
| “All applicable controls continuously verified” from enabled test count | Remove. Show supported/applicable/enabled/executed/unknown populations and observation windows |
| 87/100 defence and 99.7% confidence examples | Do not implement fabricated or uncalibrated precision. Show components, denominators and method versions |
| A green ATT&CK technique implies full coverage | Evaluate selected, versioned implementations and actual test paths; never imply all possible attacker behaviour is enumerated [1] |
| “Incident affects framework” implies legal violation | Show a potential control implication and the mapping rationale; incident response and legal determination remain separate |
| ISO amendment treated as an additional independent framework | Model ISO/IEC 27001:2022 with its 2024 amendment overlay; no duplicate counting [10,11] |
| Current/proposed HIPAA profiles both counted as current obligations | Keep future-readiness content separate. HHS still describes the examined update as a proposal [8] |
| SOC 2 report treated like a certificate with a fixed expiry | Store examination period, report date, opinion and scope; distinguish report age from certificate validity |
| 13 audit programmes treated as a required number | Keep as configurable internal templates, not a universal statutory audit requirement |
| Every collected raw event retained immutably | Define selective collection, redaction, retention, legal holds and deletion before ingestion |
| BYOS implies complete residency | Include query compute, AI processing, backups, support, metadata and exported evidence in residency controls |
| A shared tenant ID alone ensures isolation | Independently enforce boundaries across database, objects, search, queues, caches, exports and AI retrieval |
| Automatic connector/parser/query creation | Treat generated content as untrusted candidates; require semantic tests, resource limits and approved release |
| Detection precision from a static model equals real operational precision | Label model-derived quality separately from measured TP/(TP+FP) on adjudicated data |
| Security cost savings treated as guaranteed | Show assumptions, contracts, query/egress/rehydration/AI costs and uncertainty; preserve forensic requirements |
| Latest successful check rewrites historical failures | Append observations and corrections; maintain both observed time and recorded time |

Additional example corrections: the SOC illustration with 9 detected implementations out of 17 corresponds to approximately 52.9%, not 51%, if that is the intended denominator. In the 612-to-431 example, 181 scenarios without a validated final path are not necessarily 181 distinct defensive weaknesses; shared root causes must be deduplicated. Do not copy example ATT&CK IDs onto generic OAuth abuse: map the actual observed behaviour using the pinned authoritative dataset.

The arithmetic in the drafts is correct: the 20 test-category targets total **2,215** and the 14 connector-category targets total **640**. These are speculative catalogue targets, not executable inventories. Reject count-driven delivery gates. Retain the numbers only in the long-term planning appendix until individual supported items exist.

## 4. Research conclusions and competitive positioning

MITRE's September 10, 2026 publication supports implementation-level coverage and separates detection quality into robustness and precision. It provides a Detection Coverage Calculator and an implementation catalogue. This is existing research that OpenHuntX can evaluate and attribute; it is not OpenHuntX's invention. Its method does not establish that a production response succeeded or that an organisation is protected against every attack. [1,2]

The checked MITRE release page identifies ATT&CK **v19.2**, dated August 6, 2026. Pin imported datasets and mappings rather than permanently hard-coding that version. Preserve historical mappings when releases change. Do not imply that every defensive-model concept first appeared in v19.2. [3]

| Existing capability | Public evidence | Consequence for OpenHuntX |
|---|---|---|
| Vulnerability validation | Invicti describes proof-based scanning [15] | Finding validation alone is insufficient differentiation |
| Federated search, onboarding, detection engineering and investigation | Anvilogic describes these across existing data platforms [16] | Federation and AI investigation alone are insufficient differentiation |
| Detection health, validation, remediation and retesting | Picus describes a continuous validation loop [17] | “Closed loop” and detection validation alone are insufficient differentiation |
| Continuous controls, evidence collection and audit workflows | Drata and Vanta describe these capabilities [18,19] | They should not be dismissed as screenshot/checklist products |
| Behaviour-based detection coverage | MITRE CTID provides research and tooling [1,2] | Reuse reviewed methods where suitable, with attribution and licence checks |

**Recommended differentiation hypothesis:** a portable, permission-bound evidence chain across application assessment, defensive detection, response verification and audit-period control history, with explicit unknowns and independent verification. The competitive work here does not prove that no other platform offers that combination.

Validate the hypothesis with three to five design partners. Measure time to identify a genuine blind spot, time to establish whether a fix is real, time to produce reviewer-accepted evidence, onboarding effort, operational disruption and all-in operating cost. Compare the same scoped workflow in the customer's existing tools. Publish no improvement percentage until its baseline, cohort, observation window and calculation can be reproduced.

## 5. Claude execution mandate and precedence

**Claude: treat sections 5–22 as the implementation mandate.** Incorporate SOC and Compliance into the existing OpenHuntX project, and continue implementation through routine engineering milestones. Do not create a new competing application or replace the current project with a generated demo.

Precedence within product instructions:

1. Current explicit owner direction and actual security/access constraints.
2. This reconciled expansion and correction document.
3. Existing WebGuard completion instructions, for preserved WebGuard functionality and operational gates.
4. Original attached SOC and Compliance drafts as the feature-source catalogue.
5. Historical conversation estimates and illustrative examples.

Repository evidence establishes implementation state, but an insecure implementation does not override a required security property. Record conflicts and fix them. Do not erase existing roadmap items merely because they are not repeated here.

Do not stop for approval at each routine milestone. Continue authorised, reversible development, tests, documentation and private review preparation. Honour existing repository rules for commits, PRs, merges and deployment. This handoff does not newly authorise public publication, production activation, third-party scanning, customer containment or regulatory submissions. Prepare concrete reviewable deployment/action plans before asking for genuinely missing authorisation.

Maintain one durable execution ledger so work resumes without the owner relaying every intermediate report. If a connector lacks credentials, complete its contract, fixtures, permission manifest, failure tests and UI, mark live validation blocked, and continue independent work. Never convert a fixture-backed adapter into a “production verified” claim.

## 6. Preserve the engineering baseline

The latest supplied report states:

| Item | Reported baseline; verify before changing |
|---|---|
| Canonical commit | `da5da852919bcde2f8773c6cf6eae4d393734c71` |
| Phase G | Committed, pushed and CI verified |
| RLS policies | 94: 70 ordinary, 24 function-owner |
| Tenant-owned/future RLS targets | 26; policies on 25 tables |
| `crawl_checkpoints` | Intended default-deny when enforcement is enabled |
| Production RLS / FORCE RLS | OFF / OFF |
| PostgreSQL regression | 129/129 |
| Backend | 1791/1791 |
| Contracts | 59 passed, 31 skipped |
| Phase G CI | 29 tests; reported run `34506680942` |
| P1-2 | OPEN |
| Open P1 total | 6 |
| Phase H | Not started at that report |

This is a historical baseline, not an instruction to reset newer valid work. Establish the current remote, branch, worktree, HEAD and ancestry; inspect the remediation ledger and exact-commit CI. Preserve the old dirty checkout at `/Users/krishna/Documents/Portfolio` and all unrelated files. Do not reset or clean it. If newer verified work exists, build from it and update the ledger.

The supplied handoff history identifies P1-2, P1-6, P1-7, P1-8, P1-9 and P1-12-R1 as the six findings. Resolve their actual titles, evidence and current status from repository records. Their names and closure requirements must not be invented from their identifiers.

If Phase H remains outstanding, inventory repository/runtime database paths first, then convert in small coherent groups. Set tenant context from authenticated authority at transaction boundaries, use ordinary capability roles for tenant work, and narrow privileged functions for pre-tenant identity resolution and legitimate cross-tenant dispatch. Verify API, workers, scheduler, callbacks, scanner and identity flows against real disposable PostgreSQL.

RLS cannot be claimed active because policies exist. PostgreSQL documents owner and BYPASSRLS/superuser bypasses and operations outside row-security enforcement. [6] Keep runtime roles separate from migrations; deny broad role switching and table ownership. Review definer-function ownership, callable privileges, argument validation and safe search paths. [7]

An arbitrary tenant session variable is not a defence against a fully compromised application principal able to set any tenant value. Explicitly distinguish protection against omitted organisation predicates from stronger hostile-caller isolation. Validate context creation and role access accordingly; do not claim universal cross-tenant impossibility.

Prove no context leakage across pooled connections, rollbacks, retries, concurrent requests and worker reuse. Then validate actual staging credentials, ENABLE/FORCE behaviour and all runtime paths before planned production activation. Never use disabling RLS as the routine fix for application failures. Keep P1-2 open until the agreed runtime enforcement and deployment closure evidence exists.

New SOC and Compliance tenant tables need their own reviewed policies, ACLs, migrations and runtime tests. The historical count of 94 is not a future target or a reason to omit policies.

## 7. Shared architecture and ownership

Prefer extending the established architecture with explicit module boundaries. Use the existing transactional database for control-plane entities; bounded worker pools for scanning, collection, validation and actions; object storage for suitable evidence payloads; and a separately selected telemetry query/storage engine only when measurements justify it. Do not force high-volume SOC events into the operational PostgreSQL tables. Do not introduce a graph database, Kafka or microservices merely because the word “enterprise” appears in the brief.

| Shared capability | Contract |
|---|---|
| Identity and authority | Tenant, membership, legal entity, service identity, RBAC/ABAC, module entitlement, explicit delegation |
| Asset and identity registry | Stable source IDs, tenant IDs, aliases, ownership, environment, business criticality and dated relationships |
| Connectors | Scoped credentials, permission manifests, API capabilities, collection health, source versions and action capabilities |
| Evidence | Immutable versions, payload/reference metadata, observation windows, provenance, access control and retention |
| Assurance relationships | Typed, dated links between claims, observations, assets, findings, incidents, controls and remediation |
| Work management | Shared assignment, SLA, comments and external ticket links; domain-specific finding/case states |
| Authority engine | Separate permit types for scans, validation exercises and response actions; shared signing infrastructure where appropriate |
| Reporting | Scoped summaries and exports with evidence lineage and disclosure controls |
| Audit trail | Actor, authority, target, operation, result and correlation identifiers |

Shared identity does not mean flattening a vulnerability, incident, risk and audit finding into one status enum. Preserve those domain objects and link them. A scanner finding is not automatically an incident, and an incident is not automatically a failed legal requirement.

Represent graph relationships with provenance, validity period, source authority and observed/inferred status. Conflicting identity matches must remain unresolved until sufficient evidence exists. Never merge identities merely because two tenants have the same email address or hostname. Company hierarchies, framework inheritance and MSSP access must never create implicit cross-tenant disclosure.

Use durable outbox/inbox or equivalent established patterns for cross-module events, idempotent consumers, schema versions and replay. Include tenant, event ID, correlation/causation IDs, producer, occurred/observed/recorded times and source version. Sign/verify at relevant trust boundaries. Treat connector-supplied tenant fields as untrusted. Handle duplicate delivery, late events, dead-letter queues, retry storms and backpressure explicitly.

Suggested domain events include assessment completed, observation invalidated, detection validation failed, incident linked, action accepted, action outcome unknown, remediation verified and control reevaluated. Consumers must not turn their own generated events into an infinite remediation loop.

## 8. Preserve and complete WebGuard

Keep the original ten pillars, with concrete evidence requirements:

| Pillar | Required behaviour |
|---|---|
| Cryptographic Scan Permit | Bind authorising party, target authority evidence, scope, permitted methods, execution window, limits and revocation |
| Per-action authorisation | Enforce scope and policy for meaningful outbound actions, redirects, callbacks and resumed jobs |
| Execution attestation | Record runner identity, build/container and rule-pack digests, config, policy and permit versions; distinguish signed runtime claims from hardware attestation |
| Runtime Safety Receipt | Record actual request/concurrency budgets, pauses, error/latency signals, slowdown, aborts and incomplete measurement |
| Coverage Truth Map | Separate discovered, authorised, attempted, assessed, partial, unreachable, skipped and inconclusive operations by identity/test category |
| Assessment ledger | Append linked assessment events and authenticated checkpoints; disclose missing or unavailable records |
| Remediation evidence | Bind original finding, change and retest; explain comparability and residual uncertainty |
| Standards exports | Versioned SARIF, appropriate OSCAL assessment/POA&M exports and justified VEX where relevant; validate schemas |
| Provider rules of engagement | Versioned source-backed provider policies and target-owner permissions; neither substitutes for the other |
| Sovereignty | Explicit execution/storage/AI/support regions, retention, keys and customer-hosted runner controls |

Scanner depth remains essential: crawling and API inventory, authenticated sessions, role separation, web/API authorisation tests, input-handling and injection checks, configuration and information exposure checks, confidence and false-positive handling, safe out-of-band correlation and actionable remediation. Add test categories through reviewed lab fixtures and bounded safe execution. Integrate SAST, dependency, IaC, container and secret results where useful; do not market a DAST result as proof that backend source code is flaw-free.

Maintain SSRF and DNS/redirect protections, network egress restrictions, callback ownership, safe request budgets, distributed cancellation and authentication-loss detection. A public DNS ownership token alone does not establish authority over every shared-hosting tenant, vendor endpoint or discovered service. Scope expansion always requires applicable authority.

“No finding reproduced” must not close a finding when authentication expired, the application failed, the tested route changed or the test did not execute. Retest outputs need **verified fixed**, **still present**, **inconclusive**, **not comparable** and **not executed** outcomes. Record rule-version and environment differences, not just the final HTTP status.

## 9. SOC specification

### 9.1 Integration and data health

Begin federated: Sentinel, Defender XDR and Entra, with selected Intune/Azure evidence needed by initial scenarios. Inventory their APIs separately even if the commercial UI groups them under Microsoft. Expand to Splunk and other SIEMs through tested adapters. The existing SIEM remains authoritative for its native incidents and query execution until an explicit ownership/migration design says otherwise.

Use OCSF for suitable normalised security events, not as the entire business-domain model or a universal query compiler. Preserve permitted raw payloads or stable customer-side references, parser versions and mapping loss. OCSF deliberately does not prescribe storage or ETL. [13] Support source-native fields and mappings from ECS, ASIM, UDM and CIM as validated capabilities rather than universal promises.

Connector manifests must include tenant/account binding, delegated/application permissions, licence dependencies, regional availability, stable versus preview endpoints, pagination, incremental cursors, token refresh/revocation, retry policy, Retry-After handling, rate limits, backfill limits, deletion semantics and API-version support. Reject unexpected cross-account resources. Validate webhook signatures and replay protection where available.

Distinguish source silence, connector outage, parse rejection, clock skew, collection lag, missing fields and query failure. Alert when a dependent detection becomes unobservable. Quarantine invalid records with safe retention and surface lost-event counts. Empty successful API responses are not proof that a population is zero; collection completeness must be established.

### 9.2 Query and detection engineering

Offer a structured query builder and inspectable native queries before promising a universal language. Natural-language queries produce reviewable plans with time bounds, datasets, permission scope and cost limits. Declare unsupported joins, correlations, null handling, regex or time semantics; never silently weaken a query during translation.

Support a pinned, tested subset of Sigma and required backend pipelines. Sigma supplies portable detection content and conversion tooling; actual backend capability and field mapping still require validation. [14] Preserve generated query text, compiler version, dataset/schema version, semantic fixtures and native escape hatches.

Detection versions need an owner, rationale, required telemetry/fields, ATT&CK version, implementation catalogue links, positive/negative fixtures, known limitations, deployment target, performance budget and rollback record. Changes follow proposal, evaluation, approval and controlled deployment. Analyst feedback may propose tuning but cannot silently weaken production detection.

Threat intelligence and D3FEND mappings should produce reviewable hunts, validation candidates and recommendations. Preserve source/licence, timestamp, confidence, expiry and indicator handling restrictions. Do not treat AI-generated technique mappings or threat attribution as established facts.

### 9.3 ProofLoop

For each scoped scenario track independently:

1. Behaviour/implementation selected and relevant to assets.
2. Preconditions and test authorisation satisfied.
3. Telemetry generated or the replay entry point identified.
4. Telemetry collected with required fields and timestamps.
5. Parser and enrichment produced expected semantics.
6. Detection ran and matched expected evidence.
7. Alert/case arrived at the intended analyst workflow.
8. Investigation cited correct evidence and acknowledged missing data.
9. Response path was reviewed, simulated or executed, with its exact mode.
10. Postconditions, recovery and business health were checked where applicable.
11. Evidence was retained and dependent control assertions reevaluated.

Distinguish **static analysis**, **historical replay**, **synthetic log injection**, **isolated active exercise**, and **explicitly authorised production validation**. Synthetic injection after a collector cannot prove endpoint generation or the bypassed collector. A prevented attack can be a successful prevention outcome even when a downstream alert was not expected; each scenario defines prevention and detection expectations in advance.

Use stable scenario IDs, run IDs, permitted markers and time windows so a background alert cannot be mistaken for the expected validation alert. Test content must not contain a special marker required by the detection itself merely to make the test pass. Separate synthetic cases from live incident reporting, while ensuring their path is accurately reported.

Measure per-stage latency, field completeness, last validation time, failure reason and scope. Coverage is over a finite declared scenario catalogue, not all possible attacks. A response-unavailable stage stays unknown or untested even if detection succeeded. A single overall percentage must not mask a critical stage failure.

### 9.4 Investigations and AI

Show supporting evidence, contradictory evidence, missing sources, alternative explanations, recommended next actions and concise decision rationale. Link every material factual assertion to accessible evidence. Do not present an LLM's self-reported percentage as calibrated probability. No hidden chain-of-thought is needed: preserve observable inputs, tool calls, outputs, decisions and concise explanations.

Isolate tenant retrieval, prompts, memory and tool permissions. Treat logs, emails, CTI, uploaded policies and retrieved documents as untrusted data, including embedded instructions. Enforce allowed tool actions outside the model; prohibit arbitrary shell/query execution and prompt-driven permission expansion. OWASP ACS supports runtime visibility and enforceable agent controls; it does not certify the application. [20]

Use bounded queries, tool budgets, approved model routes, minimisation/redaction and customer retention settings. A tenant lacking permission to view evidence must not recover it through a summary, graph edge or AI answer. Record model availability failures honestly.

Case precedents require tenant, scope, supporting evidence, reviewer, version, expiry and revocation. Expired precedents cannot silently suppress alerts. Keep original investigation output; deterministic replay applies only to reproducible components. Reanalysis with new CTI or models creates a new revision and a diff, not a rewritten historical verdict.

Evaluate with adjudicated benign/malicious cases and attacks withheld from tuning. Measure unsupported factual claims, missed escalation, citation correctness, tool-boundary violations and analyst workload. Human agreement alone is not truth; adjudicate disagreements. Shadow mode must not close cases, modify detections or execute containment.

### 9.5 Response Guard

Maintain observation, recommendation, individual approval and explicitly bounded automation modes. Preauthorised emergency policy must still enforce tenant, assets, action types, budgets, expiry and accountable authority; it is not an unrestricted bypass.

An action permit must bind issuer, audience/executor, tenant, exact resource IDs, action type, parameter digest, approving authority, policy version, reason/case, issue/not-before/expiry times, nonce, use limit and key ID. Distinguish scan, validation and response permit types to prevent cross-use. Verify signature and policy at execution time, not only at request creation. Reject algorithm confusion, unknown keys, revoked permits and changed parameters. [12]

Record dependency information age and uncertainty. Do not invent a percentage of business disruption from an incomplete graph. Break-glass accounts, production databases, identity providers, shared services and clinical/industrial systems need explicitly stricter policies.

Action states must include proposed, authorised, queued, executing, accepted by provider, verified successful, failed, partially successful and outcome unknown. Use idempotency keys and reconciliation for retries. An external timeout after a write is not evidence of failure and must not trigger blind reexecution. Exactly-once external side effects cannot be assumed.

A provider 2xx response does not prove containment. Poll or otherwise verify supported postconditions, bounded by a deadline. Microsoft documents delay and scope limits for session revocation; implement those limitations. [5] Record recovery or compensating actions distinctly from rollback. Business recovery remains a separate outcome from security action success.

## 10. Compliance specification

### 10.1 Framework and control engine

Implement versioned framework requirements, master controls, scoped implementations, assertions/tests, evidence and mappings. A shared technical observation can support multiple frameworks, but each mapping needs rationale, scope, relationship type, reviewer and version. Evidence reuse does not imply automatic equivalence of obligations.

Initial profiles: SOC 2 readiness; ISO/IEC 27001:2022 with applicable amendment; HIPAA Security Rule readiness; EU GDPR readiness; UK GDPR readiness. Store proposed HIPAA strengthening in a visibly separate future-readiness pack. HHS does not recognise private HIPAA certifications as official approval, and SOC 2 remains an examination rather than certification. [8,9,10,21]

Add governance, risk treatment, asset inventory, access and least privilege, MFA, encryption, logging, monitoring, vulnerability management, authorised testing, incident/breach processes, vendors, continuity, backup/restore, training, secure development, minimisation, privacy notices/rights, retention, processor agreements/BAAs, internal audit and management review. Technical evidence cannot replace governance decisions.

Implement an ISO Statement of Applicability workflow with justification, implementation status and reviewer-approved inclusion/exclusion. Include ISMS management-system requirements rather than only Annex A checks. For SOC 2, record selected Trust Services Categories, system boundary, period, service commitments and applicable customer/subservice-organisation responsibilities. Do not assume every report covers all five categories.

Keep OpenHuntX's own corporate assurance separate from a customer's readiness. Framework badges require the correct entity, scope and approved external evidence. “Certified by ISO,” “HIPAA Certified” and automatic legal compliance labels are prohibited. Report qualifications, scope restrictions, withdrawal and report age must remain visible.

Treat GDPR/UK GDPR as privacy programmes as well as security safeguards. Support distinct jurisdiction/version metadata and human-reviewed applicability. The UK-specific legal commencement sources could not be fully retrieved in this review; do not ship exact new UK statutory deadlines from the illustrative drafts without authoritative verification. Missing legal verification blocks that pack's legal claims, not the underlying workflow engine.

### 10.2 Correct status and scoring model

Use separate dimensions rather than the draft's single mixed list:

| Dimension | Example states |
|---|---|
| Applicability | Applicable, not applicable with approved rationale, unresolved |
| Collection | Complete, partial, permission denied, unavailable, stale |
| Test execution | Pending, running, succeeded, failed to execute, cancelled |
| Assertion | Satisfied, violated, indeterminate, not tested |
| Control assessment | Not assessed, design gap, implementation gap, operating gap, partially effective, effective within stated scope |
| Treatment | None, remediation open, exception requested/approved/expired, compensating control under review |
| Assurance review | Unreviewed, accepted evidence, insufficient evidence, superseded |

An approved exception does not change a violated assertion into a pass. An effective compensating control is assessed separately. Inherited controls require explicit scope and responsibility. Critical failures remain visible regardless of overall rollups.

Model evidence relevance, authority, integrity, freshness, population completeness, temporal completeness, corroboration and review independently. API-retrieved evidence is not necessarily complete or truthful if the source is compromised; a human-approved access review can be the correct evidence for a human governance control.

Expose denominators. Example: 117 privileged identities discovered; 110 assessed; 105 satisfied; 5 violated; 7 unknown. Satisfaction among assessed is 105/110; assessment coverage is 110/117. Neither may be displayed as “117 protected.” Zero applicable population yields not applicable or unresolved, never a manufactured 100% pass.

Daily successful observations do not prove uninterrupted operation between observations. Show cadence, missed observations, collection coverage, known failure intervals and unknown intervals. Recovery at today's check does not erase yesterday's failure or retroactively certify the audit period.

### 10.3 Test catalogue and initial scope

Start with approximately **40–60 valuable, distinct technical assertions**, selected after capability discovery, not generated to meet a quota. Start with a small set of genuinely testable Microsoft integrations rather than the draft's 15–20 deep integrations before the first release. Build manual/governance workflows alongside them, but do not count manual tasks as executable technical tests.

Initial assertion families should cover privileged-role inventory, applicable MFA enforcement, Conditional Access policy mode/exclusions, emergency accounts, stale privileged accounts, app/service-principal ownership, credential expiry/exposure metadata, endpoint inventory and sensor freshness, required log-source health, detection enablement/execution errors, evidence retention settings and vulnerability/remediation ageing where authoritative APIs support them.

MFA needs particular care: registration, method strength, policy enforcement, exclusions and observed authentication are different facts. Microsoft documents that per-user state does not represent Conditional Access enforcement and that report-only policies do not enforce access decisions. [22,23] Do not flag every per-user-disabled account as unprotected or every registered account as protected. Use policy scope, relevant sign-in evidence and licensing/access limitations; unresolved evaluation stays indeterminate.

Each executable test needs stable ID, objective, version, source capabilities, exact required permissions, applicable population, input schema, assertion logic, output states, collection completeness rule, cadence, freshness budget, positive/negative/missing-data fixtures, owner, mappings and actionable remediation guidance. Parameter variants and repeated runs are not automatically new catalogue tests.

Support configuration, population, coverage, temporal, event, state, cross-system, telemetry, process, document, security-validation and historical assessments with accurate execution/evidence types. Cross-system offboarding needs authoritative identity joins, effective termination time, service inventory completeness and exception handling; checking four connected services does not establish offboarding from all systems.

### 10.4 Governance, privacy, vendors and audit

Provide scoped risk/exception records with owner, rationale, compensating controls, approver, expiry and reevaluation. Risk acceptance is an authorised human decision. Remediation uses the shared action system; do not build a second unrestricted executor inside Compliance.

Privacy workflows include processing inventory/ROPA, data flows, lawful-basis records, DPIA/LIA review, rights requests, retention/deletion, notices, consent records where relevant, processor/subprocessor records, transfers, contracts, breaches, complaints and automated-decision records. Support identity verification and restricted handling for rights requests. Timers must store jurisdiction, trigger, source rule, exceptions and reviewer; legal conclusions and external submissions require authorised review.

Vendor records need service owner, processed data, locations, subprocessors, contracts, assurance documents, assessment scope, renewal and risk treatment. Presence of a BAA/DPA alone cannot establish adequacy or compliance. Do not ingest unnecessary health or personnel content simply to prove a document exists.

Retain 13 optional audit templates: identity/access; endpoint; cloud; network; SIEM/logging/detection; vulnerability management; incident response/continuity; vendor/supply chain; SOC 2 readiness; ISO internal audit; HIPAA evaluation; EU GDPR readiness; UK GDPR readiness. Cadence is configurable and must be supported by applicable requirements, risk and customer policy. The platform's internal assessment is not an independent external attestation.

The audit workspace must support scope, observation period, frozen population/sampling basis, requests, evidence versions, reviewer notes, deficiencies, management response and restricted exports. Auditors receive scoped access, not access to all raw SOC evidence. External report records store body, identity, period/scope, opinion/status, verification method, redistribution restrictions and relevant dates.

Trust Center publication must require customer-approved disclosures with redaction, scope, freshness and revocation. Never publish vulnerability details, affected employee identities or raw incident records by default. A live badge must become stale/unknown when its approved underlying signal is stale.

## 11. Evidence and independent verification

Evidence is a shared substrate, not a final-stage feature. Use immutable **versions** with typed links; represent corrections and deletion events explicitly. Store only necessary payloads and authorised source references. If raw data remains in customer storage, a reference and hash alone do not guarantee future replay; track object version, retention and access availability.

An evidence envelope should contain tenant, object/type/schema version, producer/collector identity, source resource/version, observation start/end, collection and recorded time, test/query/parser/config/model versions where applicable, scope/population, result and unknowns, raw/normalised payload references, transformation/redaction provenance, content digest, signer/key ID, authorisation reference, sensitivity, retention/hold state and superseded-object links.

Use an established asymmetric signing construction and reviewed implementation, with protected algorithm/key metadata, canonical serialisation where needed, pinned trust roots and rotation. JWS and JCS are relevant building blocks, not proof that the whole evidence architecture is secure. [12,24] Do not distribute symmetric signing secrets to independent verifiers. Reject unknown algorithms and key URLs supplied by untrusted envelopes.

Cryptographic verification establishes integrity/authentication relative to a trusted key; it does not establish source truth, legal authority, completeness or audit acceptance. Hash chains without independently retained checkpoints cannot establish protection against rewriting or truncating the entire chain. Export signed manifests, counts, sequence boundaries and suitable checkpoints under a documented threat model. Do not publish customer hashes to a public ledger by default.

The independent verifier should work offline for the exported material, validate signatures/digests/schema/references and clearly state trust roots, omitted/redacted material, revocation freshness and unavailable source evidence. It must not execute uploaded code or fetch arbitrary URLs. Historical key compromise and late revocation must be representable; offline verification cannot magically know newer revocations.

Use a claim–argument–evidence structure: claim, exact scope and time, supporting observations, reasoning rule/version, contradictory evidence, assumptions, reviewer and invalidation conditions. A parser change, lost permission or deleted source can invalidate dependent assurance without changing historical evidence. Preserve append-only invalidation and reevaluation records.

NIST OSCAL supports machine-readable control and assessment information. Use the correct model/schema for catalogues/profiles, implementation, assessment plans/results and remediation information as appropriate; do not label arbitrary JSON “OSCAL compatible.” [25] Validate export structure and references and disclose lossy mappings.

## 12. Retention, sovereignty and platform security

Define region and retention per tenant, data class and workload. Include evidence payloads, metadata, backups, telemetry queries, AI inference, support exports and customer-hosted runner traffic. Support customer-managed storage through narrow object/query permissions and explicit health reporting. A disconnected customer bucket is an evidence-availability failure, not success.

Separate legal holds and immutable retention from normal deletion. Minimise sensitive content before immutable storage. Record deleted/unavailable evidence without retaining recoverable secrets in metadata. Erasure cannot honestly promise immediate deletion from immutable backups; document bounded retention and applicable exceptions. Do not rely on hashing personal data as automatic anonymisation.

Require safe handling of secrets and tokens, encryption, key rotation and revocation, module/field/object access checks, scoped exports, rate limits, evidence-access audit, and tenant isolation across caches, queues, object keys, search indexes and AI/vector retrieval. Protect offline export archives against path traversal, active content and oversized/decompression inputs.

Custom connectors, parsers and test builders are an execution boundary. Prefer declarative restricted logic. Sandbox customer code with CPU/memory/time/egress limits, read-only credentials and approved deployment; prohibit arbitrary access to host files, metadata endpoints or another tenant's network.

Maintain secure development gates: dependency/secret/SAST/IaC/container checks as applicable, signed build provenance, SBOM, authenticated application testing, API authorisation checks, frontend information-disclosure review and independent security review for consequential release scope. Test restores, credential rotation, signer outages, queue recovery, collector outages and deletion workflows.

Protect module availability: a large scan cannot starve SOC ingestion; an evidence export cannot exhaust action-verification workers. Isolate worker pools/quotas by workload and tenant. Audit infrastructure failure must leave a durable, reconcilable action/evidence state. If authority cannot be verified, deny new consequential actions while preserving allowed observation and recovery functions.

## 13. Navigation and user experience

Primary navigation: **Overview, WebGuard, SOC, Compliance, shared Assets, Evidence, Integrations and Administration**. Shared reports, workflows and activity can be surfaced contextually without creating duplicate stores.

WebGuard contains targets/authority, assessments, coverage, findings, remediation/retests and receipts. SOC contains overview, incidents, investigations, hunts, detections, validation, telemetry health, intelligence and response. Compliance contains overview, frameworks, controls, checks, evidence views, risks/exceptions, privacy, vendors, audits, regulatory changes, Trust Center and reports.

Module entitlement is separate from data permission. Unsubscribed modules must not leak sensitive summary data. A disabled module must not break evidence already used by another module; show provenance and access restrictions.

Every screen needs meaningful loading, empty, unavailable, permission-denied, stale, partial, error and retry states. “Mark verified” must show the actual verification type, reviewer, timestamp and resulting state; a human click cannot manufacture technical validation. Provide keyboard access, readable status text and clear dates/time zones. Never seed production dashboards with illustrative metrics.

Use plain outcomes: “Which selected defences lack evidence?” is defensible; “What can attack me that I cannot see?” implies exhaustive knowledge. Keep urgent incident work prominent; an assurance dashboard must not obscure active response queues.

## 14. Cross-module acceptance scenarios

| Scenario | Mandatory result |
|---|---|
| Authorised web/API test reaches monitored lab application | WebGuard request/permit links to collected telemetry, expected detection, SOC case, mapped control observation and exportable evidence |
| Web test finds no issue after authentication expires | Assessment is partial/inconclusive; finding is not closed and control receives no false positive assurance |
| Parser loses a required field | Affected SOC scenarios and control evidence become degraded/unknown with exact dependency links |
| Expected alert not created | Validation fails at the alert stage; a successful request or emitted log cannot override it |
| Prevention blocks test before later stages | Report expected prevention outcome and untested downstream stages according to the scenario contract |
| Admin appears without applicable MFA enforcement | Control finding links to identity/policy evidence; SOC investigation occurs only when justified; response is governed |
| Approved identity action times out | Outcome unknown; reconcile with provider state; no unsafe duplicate action |
| Fix succeeds but collection remains unavailable | Remediation can be recorded as performed; verification and control restoration remain pending |
| Audit period contains a one-day evidence gap | Historical view preserves the unknown interval after service recovery |
| Framework mapping changes | Current assessment can be reevaluated; historical exports retain their original mapping version |
| Tenant B requests Tenant A export or AI summary | Denied throughout object access, query, cache and retrieval paths |
| Trust Center evidence expires | Public/restricted statement becomes stale or withdrawn according to approved disclosure policy |

The first scenario is the flagship integration demonstration. If no suitable telemetry is available, explicitly report the missing link and complete isolated fixtures; do not fake an end-to-end result.

## 15. Verification gates

Before marking a capability complete, specify implementation, tests, environment and customer-visible limitations. Prioritise these adversarial cases:

- Missing/wrong tenant context, reused database connections, guessed object IDs, indirect joins, background jobs and cross-tenant exports.
- Missing/expired/revoked/mutated permits, replayed use limits, wrong executor/audience and policy changes between approval and execution.
- Incomplete pagination, expired delta cursors, source deletions, revoked scopes, out-of-order/duplicate events, malformed timestamps and schema drift.
- Stale evidence, partial inventory, zero/unknown population, conflicting sources, approved exceptions and historical corrections.
- Negative detection fixtures, benign lookalikes, query semantic mismatches, late alerts and incorrect validation correlation.
- Prompt injection in telemetry/documents, unsupported model claims, evidence permission leaks, expired case memory and unsafe tools.
- Signer/key rotation, altered payloads, missing manifest entries, truncated chains, hostile archives and offline-verifier trust failures.
- External action accepted before timeout, concurrent actors changing state, non-idempotent retries and compensating-action failure.
- Recovery from PostgreSQL/object store/queue outages, migration compatibility, restore drills and noisy-neighbour pressure.

Performance gates require measured workload assumptions: tenants, assets, events per second, burst multiplier, average event size, queries, retention, validation frequency and connector quotas. Establish budgets for p95 ingestion lag, query latency, evidence processing and action verification. Record raw measurements and resource cost. Do not invent production scale or promise an arbitrary subsecond SLO.

Every required test must run in the intended environment; skipped security or live-integration tests remain gaps. Test counts alone do not establish assurance. Use exact-commit CI evidence and real PostgreSQL for database boundary claims. Do not repeatedly run broad suites without a concrete regression risk; run required release gates and targeted follow-ups.

## 16. Delivery sequence without abandoning the full vision

The following are dependency-ordered engineering slices, not separate products or permission checkpoints:

1. **Reconcile current work.** Verify baseline and current Phase H/P1 state; preserve dirty work and existing WebGuard contracts.
2. **Finish critical shared security foundations.** Complete runtime isolation conversion and required staging/enforcement proof; record production blockers separately.
3. **Unify entity/evidence/authority contracts.** Add versioned scoped observations, claims, invalidation and cross-module events. Keep adapters backward compatible.
4. **Deliver federated observation.** Implement the Microsoft connector subset, data health, identity/asset joins, initial assertions and honest UI states.
5. **Deliver the full three-module lab workflow.** An authorised WebGuard assessment flows through SOC validation to scoped Compliance evidence and independent export verification.
6. **Complete reviewer workflows.** Investigations, audit requests, exceptions, historical views, privacy/vendor registers and comparable retest closure.
7. **Introduce governed actions.** Shadow evaluation first, followed by explicit approval execution and independent postcondition checking.
8. **Harden for scoped enterprise use.** Live connector proof, operational limits, restore tests, deployment evidence and design-partner assessment.
9. **Expand validated content.** Add ecosystems, assertion families, customer-hosted options and justified automation through the same gates.

Do not postpone all customer-visible WebGuard/scanner work until every speculative enterprise feature exists. Do not close “OpenHuntX complete” when only the first slice works. A release may be complete for a documented capability envelope while long-term scope remains clearly deferred.

## 17. Features to defer or integrate rather than build now

Retain these as explicit roadmap decisions; they are not silently lost:

| Area | Recommended disposition and entry condition |
|---|---|
| Native SIEM and OpenHuntX lake | Deferred optional product capability; require measured scale, storage economics, retention/replay, migration and operational ownership |
| Security cost engine and tiering simulation | Start with measured cost/dependency reports; later simulate with representative history and forensic/retention constraints; no automatic deletion |
| Universal query language | Begin with constrained tested queries and native adapters; expand only after semantic conformance |
| AI-generated connectors and no-code custom tests | Add after manual SDK security/conformance is proven; never publish arbitrary generated code directly |
| Advanced autonomous response | Gated on adjudicated shadow outcomes, action-specific authorisation, live postcondition proof and recovery readiness |
| Broad cyber-range/BAS library | Integrate reviewed tools where appropriate; keep test safety/authority and proof interpretation in OpenHuntX |
| Dark-web and identity exposure | Licensed provider integrations, minimisation and provenance; do not build a stolen-credential repository or validate stolen credentials by logging in |
| Training and phishing platforms | Integrate assignment/completion evidence; clicking a simulation is not evidence of account compromise |
| Secure communications | Consume/enforce supported provider controls; do not build a new encrypted mail gateway as a prerequisite |
| Full CNAPP, EDR agent, firewall, email gateway | Integrate specialised providers; excluded from the initial native build |
| Full privacy automation | Build workflow/evidence assistance; retain human legal decisions and verified jurisdiction packs |
| Predictive digital twin | Begin with a dated dependency/impact view; no precise outage predictions without calibrated models |
| 2,215 tests / 640 integrations | Planning capacity targets only; supported inventory grows from executable and maintained capabilities |
| Additional frameworks | Versioned extension packs after licensing/applicability review; no compulsory implementation of every named future framework |

Future framework candidates from C remain: ISO/IEC 27701, NIST CSF, CIS Controls, NIST SP 800-53, PCI DSS, ISO/IEC 42001, Cyber Essentials, NIS2, DORA, HITRUST and CMMC. Verify each version and legal/licensing status at implementation. Do not interpret listing as a claim of existing support.

## 18. Catalogue, audit and metric accounting

Maintain separate counts for integrations, connector/API capabilities, collectors, master controls, executable tests, parameterised variants, executions, observations and evidence objects. Report supported versions and support level. A generic REST connector is not hundreds of implemented integrations. A workflow-only connection cannot substantiate “evidence-capable” coverage of an unrelated security control.

Retain the draft's 20 planning categories: IAM 150; Microsoft 365/Entra 180; AWS 220; Azure 220; GCP 170; endpoint/MDM/EDR 130; network/firewall/DNS/SASE 110; source/CI/CD 130; Kubernetes/containers 150; vulnerability/ASM/CSPM 80; SIEM/logging 90; email/phishing 85; backup/DR 55; database/data/SaaS 100; HR 45; privacy 85; vendor/supply chain 60; IR/SOAR 45; exposure 45; AI/ML governance 65. Total 2,215. Resolve overlapping tests before any delivered count.

Retain connector planning categories: cloud 70; identity 45; endpoint 50; SIEM 45; source/CI/CD 55; vulnerability/AppSec 50; HR/training 60; business SaaS 100; email/collaboration 40; network 35; database/backup/storage 30; privacy 20; intelligence 15; workflow 25. Total 640. These categories are not evidence that 640 distinct viable API integrations exist.

A security-value report must not treat unused historical logs as valueless for future incidents. A cost estimate includes source contracts, minimum commitments, compute, duplicated retention, egress, query execution, rehydration and AI. Label estimates separately from realised savings. Proposed pricing is a commercial experiment, not a build-time promise of unlimited usage.

## 19. Durable repository handoff records

Reuse matching files if they already exist; do not spawn conflicting ledgers. Recommended records:

- `docs/PRODUCT_VISION_TRACEABILITY.md`: every WebGuard pillar plus S/C source requirements, disposition, dependencies and evidence.
- `docs/PLATFORM_SCOPE.md`: three-module contract, deferred items and commercial/marketing claim boundaries.
- `docs/EXECUTION_LEDGER.md`: current branch/HEAD, exact completed slice, results, blockers and next command/task.
- `docs/ARCHITECTURE_DECISIONS.md`: domain ownership, evidence/authority/tenant contracts and justified infrastructure decisions.
- `docs/CONNECTOR_CAPABILITIES.md`: API versions, permissions, licences, live-test state and limitations.
- `docs/RELEASE_EVIDENCE.md`: implemented/tested/staging/deployed states, CI references, known risks and rollout/rollback evidence.

Each requirement record needs source identifier, owner/module, acceptance test, implementation reference, status and limitation. Track status as proposed, designed, implemented, locally tested, integration-tested, staging-validated, production-deployed or externally verified as applicable. Do not compress all into DONE.

Write resumable checkpoints before context exhaustion. Preserve actual commands and test outcomes without storing secrets. Failed attempts stay in the history with their fixes; do not reuse historical green results for a new commit.

## 20. Definition of a credible first enterprise release

The release is credible when each offered module has a real usable workflow, the shared evidence chain works, and material limitations are visible. Specifically:

- WebGuard maintains its original permit/safety/coverage/remediation contract, with validated scanner capabilities and honest incomplete results.
- SOC connects supported live sources, identifies concrete data/detection gaps, supports evidence-backed investigation and distinguishes static, replay and active validation.
- Compliance assesses scoped technical controls, supports human governance evidence, preserves historical gaps and exports reviewer-usable records.
- The cross-module demonstration works with accessible evidence and an independent verifier.
- No critical security release blocker is concealed; the actual tenant enforcement/deployment state is documented.
- Connectors and APIs state supported versions, permissions, licensed dependencies and unresolved live-validation gaps.
- Authorised operational owners can restore service, rotate credentials, handle incidents, disable integrations and recover from failed actions.
- Marketing claims, badges, counts, readiness terminology and external disclosures match delivered evidence.

A blocked production credential, unavailable licensed framework text or missing hardware attestation does not prevent unrelated implementation. It does prevent claiming the blocked capability complete. Native SIEM scale, hundreds of connectors and all future frameworks are not first-release prerequisites.

## 21. Immediate instruction to Claude

Begin by inspecting the current repository and reconciling the reported Phase G baseline with any newer work. Preserve the existing WebGuard master instructions and ongoing build. Record the explicitly approved SOC/Compliance expansion and all corrections above in the source-of-truth roadmap.

If Phase H remains outstanding, continue its inventory/design and safe repository conversion. In parallel only where the actual execution environment and task rules permit, independent design work may proceed; no delegation is required by this document. Do not mix unrelated production activation into expansion commits.

Then execute the dependency sequence in section 16. Continue routine milestones autonomously. At each milestone, report a concise factual result and update the execution ledger rather than requiring the owner to copy outputs between assistants. Ask only for a specific missing access, consequential authorisation or irreducible product decision after preparing the work that can already be completed.

Your first report must state verified current HEAD/branch, actual P1/Phase H status, scope conflicts resolved, preserved WebGuard requirements, first implementable slice, concrete blockers and the ledger location. A plan alone is not task completion: proceed into authorised implementation.

## 22. Final product judgement

The three-module platform is a coherent expansion if its shared contract remains **permission, safety and evidence**. The best implementation is a focused working system that can show both success and uncertainty across the entire workflow. More catalogue entries, more dashboards and more AI branding do not substitute for that contract.

The key additional capability recommended here is **assurance invalidation**: when data, parsing, permissions, versions or scope change, affected claims must lose their current validity with an explanation. Combined with comparable retesting and independently verifiable evidence, this makes the platform useful during failure, not only when everything is green.

## 23. Sources and verification notes

Numbers below correspond to citations in the recommendation. Public sources were accessed on 11 September 2026. Dates are publication/version dates where established; undated product pages are current vendor descriptions, not benchmark reports.

1. MITRE Center for Threat-Informed Defense, Antonia Feffer. [Beyond the Heatmap: A New Way to Measure Detection Coverage](https://ctid.mitre.org/blog/2026/09/10/summiting-the-pyramid-2026/), 10 September 2026. Supports implementation coverage and model-derived detection quality; not production response assurance.
2. MITRE CTID. [Summiting the Pyramid — Detection Coverage Calculator](https://github.com/center-for-threat-informed-defense/summiting-the-pyramid/tree/main/DCC), repository inspected through public documentation. Evaluate the pinned implementation and licence before reuse; no code execution or independent benchmark was performed here.
3. MITRE ATT&CK. [Updates — August 2026](https://attack.mitre.org/resources/updates/). Identifies v19.2, 6 August 2026; pin releases for historical mappings.
4. Original source documents S and C, filenames and section references in section 2 and the register below. Private supplied design documents, not implementation evidence. H is the supplied historical project report, not independently verified repository state.
5. Microsoft Learn. [user: revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0), page updated 23 July 2025. Token/session effects, propagation delay, external-user limits and current permission table. The conclusion that recovery is not rollback is an engineering inference from these semantics.
6. PostgreSQL. [Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html), current documentation resolved to PostgreSQL 18. Validate against the actual project version; this does not prescribe a version upgrade.
7. PostgreSQL. [CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html), current documentation, including safe SECURITY DEFINER use. Validate deployed-version behaviour.
8. HHS. [HIPAA Security Rule NPRM](https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/index.html), proposal announced 27 December 2024. Examined HHS page remains labelled proposed; verify current rulemaking/effective dates before publishing a pack.
9. HHS. [Are we required to “certify” compliance with the Security Rule?](https://www.hhs.gov/hipaa/for-professionals/faq/2003/are-we-required-to-certify-our-organizations-compliance-with-the-standards/index.html), last reviewed 26 July 2013. HHS does not recognise private certifications as official assurance or relief from obligations.
10. ISO. [ISO/IEC 27001:2022](https://www.iso.org/standard/27001), third edition, October 2022. Official scope and certification context; publicly available overview does not license copying the standard into a product.
11. ISO. [ISO/IEC 27001:2022/Amd 1:2024](https://www.iso.org/standard/88435.html), Climate action changes, 2024. An amendment to the base standard.
12. IETF, Jones, Bradley and Sakimura. [RFC 7515 — JSON Web Signature](https://www.rfc-editor.org/info/rfc7515/), May 2015. Signature envelope building block; security depends on validated algorithms, trust and implementation.
13. Open Cybersecurity Schema Framework. [Official overview](https://ocsf.io/), accessed 11 September 2026. Vendor-agnostic schema and independence from storage/ETL implementation.
14. SigmaHQ. [Getting Started](https://sigmahq.io/docs/guide/getting-started.html), accessed 11 September 2026. Detection format, backends and conversion pipelines.
15. Invicti. [Proof-Based Scanning](https://www.invicti.com/features/proof-based-scanning), accessed 11 September 2026. Advertised vulnerability validation, not independent comparative efficacy.
16. Anvilogic. [Platform](https://www.anvilogic.com/platform), accessed 11 September 2026. Advertised onboarding, federation, detection engineering and investigation.
17. Picus. [Detection Rule Validation](https://www.picussecurity.com/use-case/detection-rule-validation), accessed 11 September 2026. Advertised detection validation, telemetry/alert/performance checks and remediation/retest loop.
18. Drata. [Platform overview](https://drata.com/), accessed 11 September 2026. Advertised continuous monitoring, evidence, remediation and trust workflows.
19. Vanta. [Automated Compliance](https://www.vanta.com/products/automated-compliance), accessed 11 September 2026. Advertised evidence collection and monitoring. Retrieved page contains unresolved catalogue placeholders; no exact test/integration count is inferred.
20. OWASP GenAI Security Project. [Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard-acs/), listed 1 September 2026. Runtime traceability and control concepts; not a certification or complete application security assessment.
21. AICPA & CIMA. [System and Organization Controls — SOC Suite of Services](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services), accessed 11 September 2026. Professional SOC examination context and guidance; readiness software is not an auditor's opinion.
22. Microsoft Learn. [Per-user multifactor authentication states](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates), accessed 11 September 2026. Distinguishes per-user state from Conditional Access enforcement.
23. Microsoft Learn. [Conditional Access report-only mode](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only), accessed 11 September 2026. Evaluation in report-only mode does not enforce policies.
24. IETF, Rundgren, Jordan and Erdtman. [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785/), June 2020. Canonical serialisation building block; use only within a precisely specified evidence format.
25. NIST. [Open Security Controls Assessment Language](https://pages.nist.gov/OSCAL/), page updated 2 June 2026. Machine-readable control/assessment interoperability; no claim of automatic certification or guaranteed audit acceptance.

Legal retrieval limitations: the attempted EUR-Lex GDPR page presented an anti-bot response; attempted ICO DUAA pages and the UK legislation page could not be read fully. Therefore this handoff deliberately provides workflow requirements rather than newly asserted GDPR/UK statutory dates. Claude must verify authoritative legal text and commencement provisions for released jurisdiction packs. Future framework versions in C are retained as candidates, not revalidated claims of current support. Survey percentages in S are not relied upon for the recommendation and should not be reused without checking their original methodology.

## 24. Complete source disposition register

This register accounts for every numbered source section. **Retain** means retain the concept subject to this handoff's corrected semantics and delivery sequence. **Revise** replaces the original claim/design. **Defer** retains a named roadmap item with gates. **Integrate** means prefer specialist provider capabilities rather than a new standalone native product. Section references point to this handoff.

### SOC source sections

| Source ID | Original subject | Disposition | Binding recommendation |
|---|---|---|---|
| S-01 | The biggest problem isn't lack of security tools | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-02 | Don't call the underlying product simply a SIEM | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-03 | What I would NOT try to build first | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-04 | The product should work WITH existing SIEMs | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-05 | OpenHuntX Universal Security Data Fabric | Retain | §§7,9.1,11: versioned schemas, field dependencies, provenance and scoped portability. |
| S-06 | Support other schemas too | Retain | §§7,9.1,11: versioned schemas, field dependencies, provenance and scoped portability. |
| S-07 | Automatic connector creation | Defer | §§9.1,12,17: generated connectors only after sandboxed SDK and semantic conformance. |
| S-08 | Parser Drift Detection | Retain | §§7,9.1,11: versioned schemas, field dependencies, provenance and scoped portability. |
| S-09 | One Search Language | Revise | §9.2: constrained inspectable query plans; unsupported backend semantics must be explicit. |
| S-10 | The interesting discovery: MITRE changed how detection coverage should be measured | Retain | §§4,9.3: versioned implementation coverage and explicit validation entry/exit points; no universal protection claim. |
| S-11 | Build this directly into OpenHuntX | Retain | §§4,9.3: versioned implementation coverage and explicit validation entry/exit points; no universal protection claim. |
| S-12 | But take it one level beyond MITRE | Retain | §§4,9.3: versioned implementation coverage and explicit validation entry/exit points; no universal protection claim. |
| S-13 | This becomes OpenHuntX ProofLoop | Retain | §§4,9.3: versioned implementation coverage and explicit validation entry/exit points; no universal protection claim. |
| S-14 | MITRE ATT&CK v19.2 should be native | Retain | §§4,9.3: versioned implementation coverage and explicit validation entry/exit points; no universal protection claim. |
| S-15 | Continuous Detection Validation | Retain | §§4,9.3: versioned implementation coverage and explicit validation entry/exit points; no universal protection claim. |
| S-16 | Every detection gets a quality score | Revise | §§9.3,10.2: component metrics and measured precision; no unexplained defence score. |
| S-17 | The next major differentiator: cost tied directly to defensive value | Defer | §§17–18: measured cost/dependency reporting before simulations or tiering changes. |
| S-18 | OpenHuntX Security Value Engine | Defer | §§17–18: measured cost/dependency reporting before simulations or tiering changes. |
| S-19 | Even better: simulate cost changes BEFORE applying them | Defer | §§17–18: measured cost/dependency reporting before simulations or tiering changes. |
| S-20 | Another major problem: AI SOC trust | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-21 | Differentiate by saying: | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-22 | OpenHuntX AI Analyst | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-23 | Have competing hypotheses | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-24 | OpenHuntX Investigation Graph | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-25 | Evidence provenance should be first-class | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-26 | OpenHuntX Evidence Vault | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-27 | One-click Incident Replay | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-28 | Response is where I think OpenHuntX can get particularly interesting | Revise | §9.5: action-specific authority, real signatures, context-dependent impact and honest recovery/rollback semantics. |
| S-29 | OpenHuntX Response Guard | Revise | §9.5: action-specific authority, real signatures, context-dependent impact and honest recovery/rollback semantics. |
| S-30 | But even blast-radius simulation isn't completely untouched | Revise | §9.5: action-specific authority, real signatures, context-dependent impact and honest recovery/rollback semantics. |
| S-31 | Signed OpenHuntX Action Permits | Revise | §9.5: action-specific authority, real signatures, context-dependent impact and honest recovery/rollback semantics. |
| S-32 | Give customers autonomy levels | Revise | §9.5: action-specific authority, real signatures, context-dependent impact and honest recovery/rollback semantics. |
| S-33 | Add a Shadow Mode | Retain | §§9.2–9.5: shadow evaluation, versioned detections, approved tuning, CTI/hunting with bounded permissions. |
| S-34 | AI must not silently change detections | Retain | §§9.2–9.5: shadow evaluation, versioned detections, approved tuning, CTI/hunting with bounded permissions. |
| S-35 | Detection-as-Code | Retain | §§9.2–9.5: shadow evaluation, versioned detections, approved tuning, CTI/hunting with bounded permissions. |
| S-36 | Add Git-style versioning | Retain | §§9.2–9.5: shadow evaluation, versioned detections, approved tuning, CTI/hunting with bounded permissions. |
| S-37 | Threat intelligence should automatically produce work | Retain | §§9.2–9.5: shadow evaluation, versioned detections, approved tuning, CTI/hunting with bounded permissions. |
| S-38 | Threat Hunting should also become continuous | Retain | §§9.2–9.5: shadow evaluation, versioned detections, approved tuning, CTI/hunting with bounded permissions. |
| S-39 | Build memory differently | Revise | §§7,9.4,11: one evidence substrate; bounded AI, scoped memory, preserved original output and distinct reanalysis. |
| S-40 | What I think the market is still missing end-to-end | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-41 | Important qualification about “nobody in the world has done it” | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-42 | The OpenHuntX SOC dashboard should be completely different | Revise | §13: actionable incident and known-gap views; no exhaustive attack/blind-spot claim. |
| S-43 | Add a “What am I blind to?” button | Revise | §13: actionable incident and known-gap views; no exhaustive attack/blind-spot claim. |
| S-44 | And another button: | Defer | §§17–18: measured cost/dependency reporting before simulations or tiering changes. |
| S-45 | Make OpenHuntX vendor-neutral by design | Retain | §§7,9.1,11: versioned schemas, field dependencies, provenance and scoped portability. |
| S-46 | Let customers own their data | Defer | §§12,17: BYOS after retention, reference availability, residency and query-compute validation. |
| S-47 | Pricing should not punish customers for collecting security data | Revise | §§4,17–18: commercial experiments; read-only assessment cannot prove unexecuted responses; cap cost and access. |
| S-48 | The perfect first sales pitch | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-49 | The OpenHuntX 7-Day SOC Assessment | Revise | §§4,17–18: commercial experiments; read-only assessment cannot prove unexecuted responses; cap cost and access. |
| S-50 | Free tier idea | Revise | §§4,17–18: commercial experiments; read-only assessment cannot prove unexecuted responses; cap cost and access. |
| S-51 | The architecture I recommend | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-52 | And I would preserve OpenHuntX's existing security philosophy | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |
| S-53 | The single feature I would make our flagship | Revise | §§1,4,7,16: three-module expansion; federated entry, bounded claims; existing features are not unique inventions. |

### Compliance source sections

| Source ID | Original subject | Disposition | Binding recommendation |
|---|---|---|---|
| C-01 | CRITICAL COMPLIANCE TERMINOLOGY | Revise | §10.1: versioned scoped readiness; amendment overlay; proposed rules separate; authoritative release review. |
| C-02 | FRAMEWORKS TO SUPPORT INITIALLY | Revise | §10.1: versioned scoped readiness; amendment overlay; proposed rules separate; authoritative release review. |
| C-03 | FRAMEWORK VERSIONING ENGINE | Revise | §10.1: versioned scoped readiness; amendment overlay; proposed rules separate; authoritative release review. |
| C-04 | REGULATORY INTELLIGENCE ENGINE | Revise | §10.1: versioned scoped readiness; amendment overlay; proposed rules separate; authoritative release review. |
| C-05 | OPENHUNTX UNIFIED CONTROL FRAMEWORK | Revise | §§7,10.1–10.2,13: shared entities, three-module navigation and orthogonal state/count models. |
| C-06 | OPENHUNTX ASSURANCE GRAPH | Revise | §§7,10.1–10.2,13: shared entities, three-module navigation and orthogonal state/count models. |
| C-07 | COMPLIANCE PRIMARY NAVIGATION | Revise | §§7,10.1–10.2,13: shared entities, three-module navigation and orthogonal state/count models. |
| C-08 | COMPLIANCE OVERVIEW | Revise | §§7,10.1–10.2,13: shared entities, three-module navigation and orthogonal state/count models. |
| C-09 | CONTROL STATUS MODEL | Revise | §§7,10.1–10.2,13: shared entities, three-module navigation and orthogonal state/count models. |
| C-10 | AUTOMATED ASSURANCE TERMINOLOGY | Revise | §§7,10.1–10.2,13: shared entities, three-module navigation and orthogonal state/count models. |
| C-11 | LONG-TERM AUTOMATED TEST TARGET | Revise | §§10.2–10.3,18: 2,215 is a planning target; unknown/applicable populations and executed coverage remain distinct. |
| C-12 | AUTOMATIC APPLICABILITY ENGINE | Revise | §§10.2–10.3,18: 2,215 is a planning target; unknown/applicable populations and executed coverage remain distinct. |
| C-13 | TEST ENGINE TYPES | Retain | §10.3: test types, risk-based cadence and IAM assertions with fixtures and capability requirements. |
| C-14 | TEST FREQUENCY ENGINE | Retain | §10.3: test types, risk-based cadence and IAM assertions with fixtures and capability requirements. |
| C-15 | AUTOMATED TEST EXAMPLES — IAM | Retain | §10.3: test types, risk-based cadence and IAM assertions with fixtures and capability requirements. |
| C-16 | MICROSOFT-FIRST DEEP INTEGRATION | Retain | §§9.1,10.3,16: Microsoft-first depth; add only API capabilities validated for selected scenarios. |
| C-17 | CLOUD ASSURANCE | Defer | §§10.3,17–18: expand cloud/endpoint assertion families after the first supported ecosystem proves reliable. |
| C-18 | ENDPOINT / EDR / MDM TESTING | Defer | §§10.3,17–18: expand cloud/endpoint assertion families after the first supported ecosystem proves reliable. |
| C-19 | SIEM / LOGGING / DETECTION ASSURANCE | Retain | §§9.2–9.3: logging health and authorised detection validation with versioned ATT&CK mappings. |
| C-20 | ACTIVE DETECTION VALIDATION | Retain | §§9.2–9.3: logging health and authorised detection validation with versioned ATT&CK mappings. |
| C-21 | MITRE ATT&CK MAPPING | Retain | §§9.2–9.3: logging health and authorised detection validation with versioned ATT&CK mappings. |
| C-22 | DARK WEB → IDENTITY EXPOSURE RESPONSE | Integrate | §17: licensed exposure, email controls, training and communications providers; no automatic compromise inference. |
| C-23 | EMAIL / PHISHING ASSURANCE | Integrate | §17: licensed exposure, email controls, training and communications providers; no automatic compromise inference. |
| C-24 | ADAPTIVE SECURITY TRAINING | Integrate | §17: licensed exposure, email controls, training and communications providers; no automatic compromise inference. |
| C-25 | SECURE COMMUNICATIONS | Integrate | §17: licensed exposure, email controls, training and communications providers; no automatic compromise inference. |
| C-26 | SOURCE CODE / DEVSECOPS | Retain | §§8,10.3,12,17: integrate AppSec/IaC/container/exposure evidence and expand tested assertions; preserve safe deployment policy. |
| C-27 | COMPLIANCE-AS-CODE | Retain | §§8,10.3,12,17: integrate AppSec/IaC/container/exposure evidence and expand tested assertions; preserve safe deployment policy. |
| C-28 | KUBERNETES / CONTAINER ASSURANCE | Retain | §§8,10.3,12,17: integrate AppSec/IaC/container/exposure evidence and expand tested assertions; preserve safe deployment policy. |
| C-29 | VULNERABILITY / EXPOSURE ASSURANCE | Retain | §§8,10.3,12,17: integrate AppSec/IaC/container/exposure evidence and expand tested assertions; preserve safe deployment policy. |
| C-30 | PRIVACY MODULE | Retain | §§10.3–10.4: privacy and vendor workflows, authoritative cross-system joins and human legal review. |
| C-31 | PRIVACY AUTOMATION BOUNDARIES | Retain | §§10.3–10.4: privacy and vendor workflows, authoritative cross-system joins and human legal review. |
| C-32 | VENDOR / THIRD-PARTY ASSURANCE | Retain | §§10.3–10.4: privacy and vendor workflows, authoritative cross-system joins and human legal review. |
| C-33 | AUTOMATED CROSS-SYSTEM TESTING | Retain | §§10.3–10.4: privacy and vendor workflows, authoritative cross-system joins and human legal review. |
| C-34 | EVIDENCE VAULT | Revise | §§10.2,11–12: shared evidence; independent quality dimensions; historical unknowns; dated dependency view, not magical twin. |
| C-35 | EVIDENCE LEVELS | Revise | §§10.2,11–12: shared evidence; independent quality dimensions; historical unknowns; dated dependency view, not magical twin. |
| C-36 | EVIDENCE CONFIDENCE | Revise | §§10.2,11–12: shared evidence; independent quality dimensions; historical unknowns; dated dependency view, not magical twin. |
| C-37 | CONTINUOUS OPERATING EVIDENCE | Revise | §§10.2,11–12: shared evidence; independent quality dimensions; historical unknowns; dated dependency view, not magical twin. |
| C-38 | ASSURANCE TIME MACHINE | Revise | §§10.2,11–12: shared evidence; independent quality dimensions; historical unknowns; dated dependency view, not magical twin. |
| C-39 | SECURITY CONTROL DIGITAL TWIN | Revise | §§10.2,11–12: shared evidence; independent quality dimensions; historical unknowns; dated dependency view, not magical twin. |
| C-40 | FINDINGS MODEL | Retain | §§7,9.5,10.4: linked domain objects, formal exceptions, governed actions and non-automatic legal impact. |
| C-41 | RISK & EXCEPTIONS | Retain | §§7,9.5,10.4: linked domain objects, formal exceptions, governed actions and non-automatic legal impact. |
| C-42 | REMEDIATION ENGINE | Retain | §§7,9.5,10.4: linked domain objects, formal exceptions, governed actions and non-automatic legal impact. |
| C-43 | INCIDENT → COMPLIANCE IMPACT | Retain | §§7,9.5,10.4: linked domain objects, formal exceptions, governed actions and non-automatic legal impact. |
| C-44 | COMPLIANCE-AWARE THREAT HUNTING | Retain | §§7,9.5,10.4: linked domain objects, formal exceptions, governed actions and non-automatic legal impact. |
| C-45 | COMPLIANCE-AWARE DETECTION ENGINEERING | Retain | §§7,9.5,10.4: linked domain objects, formal exceptions, governed actions and non-automatic legal impact. |
| C-46 | AUDIT PROGRAMMES | Revise | §10.4: thirteen optional internal templates; customer/risk/framework-specific cadence, not thirteen mandatory audits. |
| C-47 | RECOMMENDED AUDIT CADENCE | Revise | §10.4: thirteen optional internal templates; customer/risk/framework-specific cadence, not thirteen mandatory audits. |
| C-48 | AUDIT WORKSPACE | Retain | §§10.4,13: scoped auditor access, evidence-backed reporting and customer-approved disclosures with expiry. |
| C-49 | TRUST CENTER | Retain | §§10.4,13: scoped auditor access, evidence-backed reporting and customer-approved disclosures with expiry. |
| C-50 | LIVE ASSURANCE TRUST CENTER | Retain | §§10.4,13: scoped auditor access, evidence-backed reporting and customer-approved disclosures with expiry. |
| C-51 | EXECUTIVE / BOARD REPORTING | Retain | §§10.4,13: scoped auditor access, evidence-backed reporting and customer-approved disclosures with expiry. |
| C-52 | AI CAPABILITY | Retain | §§9.4,10.1,10.4: assistance grounded in evidence, with decision authority outside the model. |
| C-53 | AI SAFETY / LEGAL BOUNDARIES | Retain | §§9.4,10.1,10.4: assistance grounded in evidence, with decision authority outside the model. |
| C-54 | INTEGRATION STRATEGY | Revise | §§9.1,17–18: distinct connector capabilities and honest counts; 640 remains a target, not first-release scope. |
| C-55 | LONG-TERM INTEGRATION TARGETS | Revise | §§9.1,17–18: distinct connector capabilities and honest counts; 640 remains a target, not first-release scope. |
| C-56 | FIRST INTEGRATIONS TO PRIORITISE | Revise | §§9.1,17–18: distinct connector capabilities and honest counts; 640 remains a target, not first-release scope. |
| C-57 | CONNECTOR SDK | Defer | §§9.1,12,17: sandboxed SDK and restricted custom tests after connector contract proof. |
| C-58 | CUSTOM TESTS | Defer | §§9.1,12,17: sandboxed SDK and restricted custom tests after connector contract proof. |
| C-59 | OSCAL-COMPATIBLE ARCHITECTURE | Retain | §§9.1,11: correct OCSF/OSCAL purposes, schemas, versions and limitations. |
| C-60 | SECURITY TELEMETRY NORMALISATION | Retain | §§9.1,11: correct OCSF/OSCAL purposes, schemas, versions and limitations. |
| C-61 | SIEM MODES | Revise | §§9.1,17: federated mode first; native SIEM retained as a gated optional roadmap capability. |
| C-62 | SECURITY → COMPLIANCE FLOW | Revise | §§9.5,10.3,14: evidence-linked workflow; MFA registration differs from enforcement; API success differs from verified fix. |
| C-63 | EXAMPLE — PRIVILEGED ADMIN WITHOUT MFA | Revise | §§9.5,10.3,14: evidence-linked workflow; MFA registration differs from enforcement; API success differs from verified fix. |
| C-64 | SECURITY CONTROLS BASELINE | Retain | §§10.1,10.4: full governance baseline, reviewed mappings, proposal status and licensed framework content. |
| C-65 | FRAMEWORK-SPECIFIC LOGIC | Retain | §§10.1,10.4: full governance baseline, reviewed mappings, proposal status and licensed framework content. |
| C-66 | HIPAA FUTURE-READINESS MODE | Retain | §§10.1,10.4: full governance baseline, reviewed mappings, proposal status and licensed framework content. |
| C-67 | AUDIT/CERTIFICATION VALIDATION | Retain | §§10.1,10.4: full governance baseline, reviewed mappings, proposal status and licensed framework content. |
| C-68 | LICENSING AND COPYRIGHT | Retain | §§10.1,10.4: full governance baseline, reviewed mappings, proposal status and licensed framework content. |
| C-69 | DATABASE / DOMAIN MODEL | Retain | §§6–7,12: shared domain identity with explicit entity scope, tenant enforcement and reviewed inheritance. |
| C-70 | ENTERPRISE MULTI-ENTITY ARCHITECTURE | Retain | §§6–7,12: shared domain identity with explicit entity scope, tenant enforcement and reviewed inheritance. |
| C-71 | METRICS THAT MAY BE DISPLAYED | Revise | §§10.3,16–18: actual supported inventory, not catalogue quotas; public metadata excludes sensitive implementation. |
| C-72 | ROADMAP TARGETS | Revise | §§10.3,16–18: actual supported inventory, not catalogue quotas; public metadata excludes sensitive implementation. |
| C-73 | PUBLIC ASSURANCE TEST LIBRARY | Revise | §§10.3,16–18: actual supported inventory, not catalogue quotas; public metadata excludes sensitive implementation. |
| C-74 | OPENHUNTX OVERALL ENTERPRISE NAVIGATION | Revise | §13: WebGuard, SOC and Compliance remain the three primary modules; contextual shared views. |
| C-75 | PRODUCT DIFFERENTIATORS | Revise | §§1,3–4,10.2,11: scoped assurance claims; no universal legal/security proof or invented novelty. |
| C-76 | PROOF-OF-CONTROL MODEL | Revise | §§1,3–4,10.2,11: scoped assurance claims; no universal legal/security proof or invented novelty. |
| C-77 | OPENHUNTX POSITIONING | Revise | §§1,3–4,10.2,11: scoped assurance claims; no universal legal/security proof or invented novelty. |
| C-78 | WHAT OPENHUNTX MUST NOT DO | Revise | §§1,3–4,10.2,11: scoped assurance claims; no universal legal/security proof or invented novelty. |
| C-79 | DEVELOPMENT PRINCIPLES | Retain | §§6,12,14–16,19–21: reconcile first, prove boundaries and cross-module slice, use durable evidence gates. |
| C-80 | SECURITY OF THE COMPLIANCE PLATFORM ITSELF | Retain | §§6,12,14–16,19–21: reconcile first, prove boundaries and cross-module slice, use durable evidence gates. |
| C-81 | FIRST PRODUCTION VERTICAL SLICE | Retain | §§6,12,14–16,19–21: reconcile first, prove boundaries and cross-module slice, use durable evidence gates. |
| C-82 | BEFORE IMPLEMENTING EACH MILESTONE | Retain | §§6,12,14–16,19–21: reconcile first, prove boundaries and cross-module slice, use durable evidence gates. |
| C-83 | IMPLEMENTATION QUALITY REQUIREMENT | Retain | §§6,12,14–16,19–21: reconcile first, prove boundaries and cross-module slice, use durable evidence gates. |
| C-84 | FINAL PRODUCT VISION | Revise | §§1,7,17: three-module destination retained; training/email/EDR integration and native-SIEM deferrals explicit. |

Unnumbered SOC closing priorities and confidentiality notes are reconciled in §§4–5, 12, 16–18 and 21. Source examples are illustrative only. The existing WebGuard ten-pillar vision is preserved in §8; historical engineering state is preserved with verification limits in §6. No source document is silently promoted into implementation evidence.
