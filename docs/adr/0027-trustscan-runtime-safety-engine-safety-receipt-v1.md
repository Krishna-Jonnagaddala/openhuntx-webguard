# ADR 0027: TrustScan Runtime Safety Engine and Safety Receipt v1

## Status

Accepted for Milestone 1.32.

## Context

TrustScan Scan Permit v1 introduced a cryptographically signed, narrowly scoped execution permit. Milestone 1.31 validated that permit before worker execution and before scheduled jobs were materialised. A long-running scan, however, can outlive the state that was valid at its start: an authorisation may change, a permit may be revoked or expire, a request may attempt to leave the approved origin, or repeated target-health signals may make continued automated traffic undesirable.

Pre-execution validation alone is therefore not sufficient for OpenHuntX's authorisation-native safety model. The enforcement point must sit immediately before the scanner can emit network traffic, and the product must retain verifiable evidence of the controls that were applied.

## Decision

WebGuard introduces a TrustScan runtime safety engine between scanner orchestration and the safe HTTP client. Single-page and crawl scanners expose narrowly typed `before_request` and `after_request` hooks. The service-owned safety engine uses those hooks; scanner packages remain independent of control-plane identity and permit storage.

Immediately before each outbound request attempt, the engine:

1. records the attempted operation;
2. rejects an already-open runtime circuit breaker;
3. verifies that the request remains on the permit-authorised origin;
4. verifies the HTTP method is allowed by the permit;
5. enforces the permit request-attempt budget;
6. enforces the permit maximum concurrency;
7. reloads and revalidates the current server-side authorisation, immutable job-permit binding, persisted permit fingerprint, signature, revocation state, target, mode, and time window;
8. enforces the permit request-rate ceiling; and
9. revalidates permission again after any mandatory throttle wait before allowing network activity.

A failure at any of these checks is fail-closed and prevents the request from reaching the HTTP client.

After each controlled request attempt, the engine records bounded target-health signals. Request errors, HTTP 429 responses, and HTTP 5xx responses count as protective events. Three consecutive protective events open the local circuit breaker; the next attempted request is blocked before network activity. A successful/non-protective response resets the consecutive-event counter.

The threshold is intentionally conservative and simple. It is a scanner safety guard, not a claim of application-health monitoring or causal impact detection.

## Safety Receipt v1

Every normally returned scan and every scan terminated directly by the runtime safety engine produces an Ed25519-signed TrustScan Safety Receipt. The receipt is bound to the permit, organisation, job, scan, target, execution timestamps, and permit limits. It records observed counters including attempted/permitted/blocked requests, 429/5xx responses, controlled request errors, throttling, circuit-breaker activations, scope violations, permit revalidations, and observed peak concurrency.

The receipt is canonical JSON, has a stable SHA-256 fingerprint, and is signed using the same TrustScan Ed25519 authority used for Scan Permit v1. The public TrustScan verification key can therefore verify both permit and safety-receipt signatures. Strict loading rejects unknown/missing fields and non-canonical documents.

Safety receipts are written as owner-only (`0600`) artefacts beneath the existing private per-job artefact directory. The SQLite store records only the safe relative receipt reference and SHA-256 fingerprint in a schema-6 `job_safety_receipts` table. Receipt metadata is written transactionally with the terminal job transition and is returned as metadata by the job-result API.

## Non-claims

A Safety Receipt demonstrates what WebGuard itself enforced and observed. It does not prove that a target experienced no impact, that external infrastructure remained healthy, that the assessed system is secure, or that every relevant request was visible outside WebGuard's execution boundary.

Milestone 1.32 remains passive. It does not add exploitation, payload injection, form submission, password attacks, directory enumeration, denial-of-service testing, or redirect following.

## Consequences

Positive consequences:

- permit revocation and expiry can stop additional requests during a scan;
- request budgets, methods, origin, rate, and concurrency become runtime-enforced rather than only configuration-time limits;
- repeated adverse response signals can stop further automated requests;
- customers and future auditors can verify a signed record of observed safety enforcement;
- the scanner layer retains a generic callback boundary rather than depending on API/control-plane packages.

Trade-offs:

- permission revalidation introduces a local database/authorisation read before every request attempt;
- rate enforcement can add deliberate execution latency;
- the initial circuit breaker uses local response signals rather than independent health telemetry;
- one local Ed25519 key still requires future KMS/HSM custody, rotation, and multi-region trust design;
- unexpected internal process failures may terminate before a terminal receipt can be associated with the job and require future crash-attested receipt handling.

## Follow-up

Future milestones may add independent runner attestation, richer health-policy inputs, signed coverage-truth maps, remediation receipts, transparency-ledger integration, and an externally verifiable TrustScan assessment capsule.
