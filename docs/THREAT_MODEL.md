# OpenHuntX WebGuard Threat Model

## 1. Scope

This threat model covers the implemented Milestone 1.32 / Checkpoint 1 architecture: local API, identity/RBAC, organisation isolation, owned-target authorisation, TrustScan permits, jobs/schedules, worker leases, scanner network safety, artefacts, and signed Safety Receipts.

It is a living engineering document. A hosted control plane and separated runner fleet will require an expanded production threat model.

## 2. Security objectives

WebGuard should preserve these properties:

1. **Authorised execution**: scanner traffic occurs only when a valid permission chain exists.
2. **Tenant isolation**: one organisation cannot read or mutate another organisation's resources.
3. **Scope confinement**: runtime requests remain inside the authorised target/origin and network policy.
4. **Bounded impact**: request count, rate, concurrency, response size, execution time, and retry behaviour remain bounded.
5. **Evidence integrity**: signed permits, checkpoints, cursors, reports, and Safety Receipts cannot be silently altered without detection where cryptographic protection is defined.
6. **Secret confidentiality**: API token secrets and signing material are not exposed through ordinary product flows.
7. **Recoverable execution**: worker crashes do not permit stale workers to corrupt final state or cause unbounded retry.
8. **Auditability**: security-sensitive API actions and scan execution decisions leave useful evidence.
9. **Fail-closed ambiguity**: invalid permission, unsafe scope, or unverifiable security state blocks execution rather than broadening it.

## 3. Protected assets

High-value assets include:

- TrustScan Ed25519 private signing key;
- pagination HMAC signing key;
- raw API tokens;
- checkpoint signing keys;
- organisation and principal state;
- owned-target authorisations and assignments;
- TrustScan permits and revocation state;
- jobs, schedules, leases, and execution state;
- scan reports and findings;
- audit events;
- Safety Receipts; and
- customer target availability and integrity.

## 4. Actors

### Legitimate organisation user

A valid user or service account operating within assigned RBAC permissions.

### Malicious authenticated tenant

A tenant with a valid token attempting to cross tenant boundaries, expand target scope, escalate privileges, forge permission, or exhaust resources.

### Compromised low-privilege principal

An attacker controlling an analyst/viewer token and trying to exercise owner/administrator functions.

### Unauthenticated local attacker

A process or user on the same host attempting to reach the loopback API, steal local state, or manipulate artefacts.

### Malicious or compromised target

An authorised target returning adversarial HTTP headers, HTML, TLS state, redirects, oversized content, slow responses, or links intended to escape scope.

### Supply-chain attacker

An attacker attempting to alter dependencies, CI actions, or the laboratory image between reviewed commits.

### Compromised runner/host

An attacker with execution inside the WebGuard host or future scanner runner. This actor is considered high impact because current local signing material and scanner execution share a host boundary.

## 5. Trust boundaries

```text
TB1  Local client  -> API transport
TB2  Auth context  -> tenant-scoped service/state
TB3  Authorisation -> TrustScan permit authority
TB4  Job/schedule  -> worker execution
TB5  Runtime engine -> outbound network
TB6  Target input  -> parsers/analyzers
TB7  Execution     -> persisted artefacts
TB8  Repository/CI -> built/tested dependency set
```

## 6. Threats and controls

### T1: Unauthenticated API access

**Threat:** An attacker invokes protected job, schedule, permit, or audit routes without a valid token.

**Controls:**

- exactly one Bearer `Authorization` header is required;
- token secret is checked against scrypt-derived state;
- expired/revoked tokens are rejected;
- organisation/principal active state is checked; and
- API binding is loopback-only.

**Residual risk:** A malicious local process can still attempt authentication and may steal a token from the operator environment. Loopback is not a sandbox.

### T2: RBAC escalation

**Threat:** An analyst/viewer performs permit issuance/revocation, audit access, or mutation beyond role.

**Controls:**

- central `ApiPermission` map;
- service-level permission checks;
- denied actions are auditable; and
- unit tests cover representative role behaviour.

**Residual risk:** Future routes could omit a permission check. Audit Phase 2 must continue systematic route-to-permission review.

### T3: Cross-tenant object access / IDOR

**Threat:** Tenant A guesses an object UUID belonging to Tenant B.

**Controls:**

- tenant context comes from authenticated token state;
- jobs/schedules/authorisation assignments/permits are resolved through organisation-scoped service/store operations;
- cross-tenant resources are hidden or rejected; and
- cursors are organisation-bound.

**Residual risk:** Any newly added unscoped store method exposed through the API could reintroduce an IDOR path.

### T4: Stolen API token

**Threat:** An attacker obtains a valid raw `wgt_...` token.

**Controls:**

- raw secret is not persisted by identity store;
- bounded token lifetime;
- explicit revocation;
- role limits reduce impact for low-privilege tokens; and
- process-local per-token rate limiting.

**Residual risk:** Bearer possession is sufficient until token expiry/revocation. Production should use stronger identity/session controls and managed secret storage.

### T5: Forged or tampered TrustScan permit

**Threat:** An attacker edits target, organisation, limits, time window, or other permit claims.

**Controls:**

- canonical permit format;
- Ed25519 signatures;
- key ID validation;
- strict canonical Base64URL signature decoding;
- signature verification before use; and
- fingerprint binding into jobs/schedules.

**Residual risk:** Theft of the private signing key defeats permit authenticity until key response/rotation occurs.

### T6: Permit replay in another organisation or target

**Threat:** A valid permit is reused outside its intended tenant, target, authorisation, or mode.

**Controls:** Signed claims bind all of those values and validation checks exact equality.

**Residual risk:** Within its valid scope/window, a permit may authorise multiple bound jobs unless future policy adds one-time/nonces or usage ceilings across jobs.

### T7: Underlying authorisation changes after permit issuance

**Threat:** A previously signed permit remains usable after the authorisation document is altered.

**Controls:** Permit claims bind the authorisation SHA-256 fingerprint. Execution rejects a changed fingerprint.

### T8: Revocation or expiry during execution

**Threat:** Permission is valid at job start but revoked/expired during a crawl.

**Controls:** Runtime safety revalidates permission before each outbound request and again after rate-throttle sleeps.

**Residual risk:** A request already permitted and in flight cannot be unsent retroactively.

### T9: SSRF / internal-network access

**Threat:** An attacker supplies a URL resolving to loopback, private, link-local, metadata, reserved, or ambiguous network destinations.

**Controls:**

- canonical URL validation;
- commercial external policy requires public addresses;
- private/loopback/link-local/multicast/reserved/unspecified destinations are rejected;
- cloud-metadata and ambiguous-address protections exist in target validation;
- lab-mode local access is explicit and allowlisted; and
- redirects are not followed.

**Residual risk:** DNS and network topology can change. Continued DNS-rebinding and TOCTOU analysis is required as the transport architecture evolves.

### T10: Redirect scope escape

**Threat:** An authorised target redirects the scanner to a different host/origin.

**Controls:** Safe HTTP does not follow redirects. Redirect responses are treated as bounded responses rather than navigation authority.

### T11: Crawler link escape

**Threat:** Malicious HTML contains external, protocol-relative, destructive, fragment, or unsupported links intended to expand scan scope.

**Controls:** Bounded same-origin crawler normalisation, query policy, destructive-path filtering, allowed content-type discovery, link/page/depth limits, and request-boundary same-origin enforcement.

### T12: Method escalation / active testing

**Threat:** Scanner code sends unauthorised POST/PUT/etc. requests or active payloads.

**Controls:** Permit allowed-method claims, runtime method checks, safe HTTP approved-method enforcement, passive-only owned-target policy, and current scanner feature scope.

**Residual risk:** Future active checks will require a new authorisation level and threat-model revision; they must not be silently added under passive authority.

### T13: Resource exhaustion against target

**Threat:** Excess request volume or concurrency affects customer availability.

**Controls:** Request-attempt budgets, rate limits, concurrency `1` in permit v1, crawl limits, execution deadlines, minimum delays, retries bounded to policy, and conservative circuit breaking after repeated request failures/`429`/`5xx`.

**Residual risk:** Even one permitted request can have unexpected impact on a fragile target. Safety limits reduce risk; they do not guarantee zero impact.

### T14: Resource exhaustion against WebGuard

**Threat:** Oversized API bodies, HTTP responses, headers, crawl graphs, or queued work consume local resources.

**Controls:** API request-size limit, content-length validation, scanner body/header/count limits, crawl page/link/depth/time/request budgets, and process-local API rate limiting.

**Residual risk:** SQLite/single-host throughput and local disk exhaustion are not production-grade multi-tenant DoS controls.

### T15: Malicious HTTP response parsing

**Threat:** Target returns malformed headers, duplicate content lengths, huge bodies, adversarial HTML, or unusual TLS state.

**Controls:** Response-size limits, conflicting content-length rejection, bounded HTML analysis, controlled error taxonomy, and tests for malformed/adversarial cases.

### T16: Worker crash / duplicate execution

**Threat:** Worker dies while a job is running; a second worker starts the same job while the stale worker later resumes.

**Controls:** Renewable leases, worker identity, lease tokens, expiry recovery, bounded attempts, and stale-worker fencing on completion.

**Residual risk:** A network request already sent before a crash cannot be undone. Exactly-once network side effects are not guaranteed by queue fencing alone.

### T17: Schedule catch-up storm

**Threat:** A delayed scheduler materialises many missed runs at once or duplicates a due job.

**Controls:** Atomic schedule advance/job materialisation, duplicate protection, conservative one-job catch-up, and automatic blocking when permission becomes invalid.

### T18: Cursor tampering / cross-context pagination

**Threat:** Client changes pagination position, organisation, resource, or filters.

**Controls:** HMAC-SHA256 cursor signature, canonical decoding, expiry, and binding to organisation/resource/filters.

**Residual risk:** Current HMAC key resides in the same local database as application state.

### T19: Database theft or modification

**Threat:** Local attacker copies or alters SQLite state, including signing material.

**Controls:** Owner-only database permissions and strict migrations/foreign keys.

**Residual risk:** There is no application-layer database encryption or external key custody. A host-level compromise can access both state and TrustScan signing material. This is accepted only for the current local engineering stage and is tracked as C1-008 / production work.

### T20: Artefact disclosure

**Threat:** Reports, findings, authorisations, or Safety Receipts are exposed through permissive files, symlinks, or source control.

**Controls:** Owner-only output permissions, symlink rejection in security-sensitive file paths, private operational directories, and Git hygiene checks.

**Residual risk:** Operators can still manually copy artefacts to insecure locations.

### T21: Artefact tampering

**Threat:** Stored evidence is modified after execution.

**Controls:** Signed checkpoints and Safety Receipts, deterministic contracts/fingerprints, and stored SHA-256 references for receipt artefacts.

**Residual risk:** Not every report artefact is independently signed. The future assessment ledger/remediation-receipt architecture should strengthen end-to-end evidence provenance.

### T22: Safety Receipt overclaim

**Threat:** A verifier interprets a signed Safety Receipt as proof that the target was unaffected or completely secure.

**Controls:** Product/docs explicitly define the receipt as evidence of enforced/observed runtime policy, not zero-impact or security certification.

### T23: Dependency or CI substitution

**Threat:** Same WebGuard commit installs different dependency versions or executes mutable CI/lab components.

**Controls:** SHA-256 dependency locks, exact CI Python versions, immutable Action SHAs, fixed Ubuntu runner family, digest-pinned Juice Shop image, and a fail-closed supply-chain pin verifier.

**Residual risk:** A compromised upstream artifact with an already reviewed hash, a compromised GitHub runner, or the broader container-image transitive supply chain remain possible.

### T24: Secret leakage through development workflows

**Threat:** Tokens/private keys are pasted into commits, screenshots, logs, chat, or shell scripts.

**Controls:** documented handling rules, staged-content checks during audited changes, ignored private paths, one-time token issuance, and planned automated secret scanning under C1-003.

### T25: Signing-key compromise

**Threat:** Attacker obtains the TrustScan private key and forges permits or Safety Receipts.

**Controls today:** owner-only SQLite permissions and non-exposure through API.

**Required production controls:** KMS/HSM-backed key custody, key versions, rotation, audit, incident revocation/distrust procedures, and separation from scanner runners.

## 7. Security assumptions

The current model assumes:

- the local host and user account are not fully compromised;
- the operating system enforces owner-only file permissions;
- the Python runtime and pinned dependencies behave according to their reviewed versions;
- system time is sufficiently trustworthy for validity windows;
- operators do not deliberately bypass product controls by modifying source/state; and
- explicitly configured lab targets are authorised test systems.

If the host is fully compromised, current local key/state confidentiality is not guaranteed.

## 8. Out-of-scope guarantees

WebGuard does not currently guarantee:

- discovery of every vulnerability;
- zero false positives or false negatives;
- zero operational impact on assessed targets;
- legal sufficiency of customer-provided authorisation;
- tamper-proof operation after full host compromise; or
- production-grade availability of the local SQLite/API foundation.

## 9. Highest-priority production threats

Before hosted production, priority work includes:

1. control-plane/runner isolation;
2. managed signing-key custody and rotation;
3. production target-control/delegated-authority verification;
4. distributed authentication/session protections and rate limiting;
5. hardened multi-tenant persistence;
6. audit/evidence retention and integrity architecture;
7. runner egress/network sandboxing;
8. secret management for authenticated scanning; and
9. independent security assessment.

## 10. Review triggers

Update this threat model when any of these occur:

- a new network-active scan class is introduced;
- authentication or RBAC changes;
- a public/hosted API is introduced;
- scanner runners move off-host;
- KMS/HSM/key rotation is implemented;
- customer credentials are processed;
- a new persistence technology is adopted;
- target verification changes;
- signed evidence formats change; or
- a security incident invalidates an assumption.
