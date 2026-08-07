# ADR 0026: TrustScan Cryptographic Scan Permit v1

- Status: Accepted
- Date: 2026-08-07
- Milestone: 1.31

## Context

WebGuard already requires an owned-target authorisation document, organisation assignment, exact target confirmation, authenticated API access, and worker-side authorisation revalidation. Those controls establish a strong defensive baseline, but the job itself does not carry a cryptographically verifiable statement of the exact execution policy that was approved for that run.

As WebGuard evolves toward a global security-assurance platform, authorisation must become an enforceable machine contract rather than only a prerequisite checked at submission time. The execution plane must be able to prove which organisation, authorisation revision, target, scan modes, methods, validity window, request budget, rate ceiling, and concurrency limit were approved. Revocation and changes to the underlying authorisation must fail closed before scanner network activity.

The permit is intentionally distinct from proof of legal ownership. The existing owned-target authorisation is the server-side source of testing authority in the current local product. TrustScan v1 narrows and cryptographically binds that authority to a specific execution envelope; it does not independently establish legal ownership, delegated authority, or jurisdictional compliance.

## Decision

WebGuard introduces **TrustScan Scan Permit schema 1.0** as a signed execution permit above the existing owned-target authorisation model.

The operational rule is:

```text
NO VALID TRUSTSCAN PERMIT
        ↓
NO SCANNER NETWORK EXECUTION
```

### Separation of authority and permit

An owned-target authorisation remains mandatory and continues to define the server-side maximum scope and limits. A TrustScan permit may only narrow those limits. Permit issuance requires that:

- the authorisation is assigned to the authenticated organisation;
- the authorisation is currently valid;
- the target exactly matches the canonical authorised target;
- the permit expiry does not exceed the authorisation expiry;
- the request-attempt budget does not exceed the authorisation budget; and
- the request-rate ceiling does not exceed the rate implied by the authorisation minimum delay.

A permit records the SHA-256 fingerprint of the exact owned-target authorisation revision. If that authorisation document changes after permit issuance, the permit no longer authorises execution.

### Signed claims

The immutable signed claims contain:

- permit UUID;
- organisation UUID;
- authorisation UUID;
- authorisation SHA-256 fingerprint;
- canonical target URL;
- issuing principal UUID;
- issue time;
- not-before time;
- expiry time;
- permitted scan modes;
- permitted HTTP methods;
- maximum request attempts;
- maximum requests per second;
- maximum concurrency; and
- the mandatory prohibited-operation set.

Permit validity is at most 90 days.

TrustScan v1 is intentionally passive. `GET` is mandatory, `HEAD` is optional, and no other HTTP method may be authorised. The mandatory prohibited-operation set includes denial of service, credential attacks, autonomous exploitation, malware, persistence, data destruction, and social engineering.

### Cryptographic signature

The control plane signs canonical permit claims using Ed25519.

Database schema version 5 adds one random 32-byte Ed25519 private seed under the existing owner-only `service_secrets` store. The corresponding public key is exposed through:

```text
GET /v1/trustscan/verification-key
```

The public document contains the algorithm, a SHA-256-derived key identifier, encoding metadata, and raw public key encoded as canonical unpadded Base64URL. The private seed is never returned through the API, audit events, job records, schedules, reports, or logs.

TrustScan v1 has one local active signing key. Key rotation, external KMS/HSM custody, multi-region trust distribution, and historical verification-key sets are deferred.

### Persistence and revocation

Schema version 5 adds:

- `scan_permits` for immutable signed permit documents and mutable revocation metadata;
- `job_permits` for exact job-to-permit binding; and
- `schedule_permits` for exact recurring-schedule-to-permit binding.

Revocation does not mutate the signed claims. `revoked_at` and `revoked_by` are stored separately so the original signed statement remains reproducible.

Permit creation, job binding, and schedule binding are transactional. An idempotent job replay must use the same permit ID and permit fingerprint (the SHA-256 digest of the canonical signed claims) or it is rejected as an idempotency conflict.

### RBAC

Owner and administrator roles may issue, read, and revoke permits.

Analyst and viewer roles may read permits but cannot issue or revoke them. This keeps authority creation separate from routine assessment execution.

Existing Bearer authentication remains mandatory. A permit UUID is not a credential and does not authenticate a caller.

### API binding

`POST /v1/jobs` and `POST /v1/schedules` require exactly one canonical lower-case UUID in the `TrustScan-Permit` header.

The service verifies the permit against the authenticated organisation, current owned-target authorisation, requested target, requested mode, revocation state, and current time before accepting a job. Schedule creation verifies equivalent scope and requires the first run to fall inside the permit validity window.

Public job and schedule metadata may expose only the permit UUID and permit fingerprint (the SHA-256 digest of the canonical signed claims), not the private signing seed or owned-target authorisation body. Signature verification remains a separate mandatory check.

### Execution-time enforcement

Submission-time validation is not sufficient. Immediately before scanner network execution, the worker:

1. reloads the current owned-target authorisation;
2. confirms its fingerprint still matches the submitted job;
3. loads the job's persisted TrustScan binding;
4. loads the organisation-scoped signed permit;
5. confirms the permit fingerprint matches the job binding;
6. verifies the Ed25519 signature and active signing-key identifier;
7. rejects revoked, pending, or expired permits;
8. revalidates organisation, authorisation, target, and scan mode; and
9. derives scanner policy from the intersection of product defaults, owned-target limits, and permit limits.

Only then may target validation and network execution continue.

### Runtime safety envelope

TrustScan v1 applies the permit to the existing passive scanner controls:

- fetch methods are restricted to permit-approved `GET`/`HEAD` methods;
- crawl request-attempt budget is capped by the permit;
- crawl delay is increased when necessary to stay within the permit request-rate ceiling; and
- maximum permit concurrency is fixed at one.

The lease-aware queue enforces the v1 concurrency ceiling by refusing to lease a second queued job bound to the same permit while another job for that permit is running.

This milestone does not claim a complete adaptive runtime safety engine. Health-aware circuit breaking, target-impact telemetry, signed safety receipts, and richer policy budgets remain future work.

### Recurring schedules

The scheduler revalidates the owned-target authorisation and TrustScan permit on every due run before materialising a job.

A missing, revoked, expired, changed, or otherwise invalid permit pauses the schedule with a controlled error rather than creating an unauthorised run. Scheduled jobs inherit the exact schedule permit binding transactionally.

### Migration and legacy records

Migration from schema version 4 to 5 preserves existing jobs, schedules, identity records, cursor keys, leases, and audit history. Existing jobs and schedules cannot be retroactively assigned trustworthy execution permission, so they remain without TrustScan bindings.

They therefore fail closed:

- a legacy queued job may be claimed so the worker can terminate it with `trustscan_permit_missing` rather than leaving it queued indefinitely; and
- a legacy due schedule is paused with `trustscan_permit_missing`.

No migration fabricates permission for historical work.

## Consequences

### Positive

- Execution authority becomes cryptographically verifiable and machine-enforceable.
- Jobs cannot silently switch permits during an idempotent replay.
- Changes to the underlying authorisation invalidate previously issued execution authority.
- Revocation is durable and rechecked at execution time.
- Recurring schedules cannot continue running after their permit is revoked or expires.
- Passive network policy can now be derived from an explicit per-permit safety envelope.
- A public verification key establishes the basis for future independently verifiable assessment receipts.
- Legacy work fails closed instead of receiving fabricated permissions during migration.

### Trade-offs

- Existing schema-4 queued jobs and schedules require new permits before equivalent work can be resubmitted.
- The current private signing key is stored in the same owner-only SQLite database as other service secrets.
- Losing the database signing seed prevents new signatures from the same key identity and complicates verification of exported permits unless the public key was retained.
- There is no signing-key rotation or external key custody in v1.
- Permit concurrency is fixed at one and coordinated only on the current SQLite host.
- TrustScan v1 does not itself prove legal ownership or delegated testing authority.
- The permit currently governs passive scan modes only.

## Alternatives considered

### Reuse the owned-target authorisation document as the permit

Rejected. The authorisation is a broader server-side authority record and may outlive individual execution policies. A separate permit can cryptographically narrow authority without changing the legal/operational source record.

### Use HMAC signatures

Rejected for permits. HMAC would require sharing the verification secret with any independent verifier. Ed25519 allows the service to keep signing capability private while publishing verification material.

### Sign every job independently without a reusable permit

Deferred. Per-job signatures would prove a single dispatch but would not provide a reusable, revocable policy object for recurring schedules and future customer-runner workflows.

### Permit by UUID without a signature

Rejected. A database identifier alone does not provide portable cryptographic evidence of the approved execution claims.

### Backfill legacy jobs with a generated permit

Rejected. Migration cannot safely infer that a new cryptographic permission statement was actually approved for historical queued or scheduled work.

## Verification

Milestone tests cover:

- strict permit submission and signed-document parsing;
- canonical mode and HTTP-method ordering;
- 90-day validity limits;
- mandatory prohibited operations;
- Ed25519 signing and signature-failure cases;
- public-key projection without private seed disclosure;
- durable permit persistence and revocation;
- cross-organisation permit isolation;
- exact job-to-permit binding and idempotency conflict behaviour;
- per-permit lease concurrency of one;
- schema version 4 to 5 migration and SQLite integrity;
- signing-key persistence across database reopen;
- owner/viewer permit RBAC;
- permit limits constrained by the underlying authorisation;
- revoked and mode-mismatched job submission denial;
- required and canonical `TrustScan-Permit` HTTP handling;
- permit issue/read/revoke HTTP routes;
- worker fail-closed behaviour for missing and revoked permits;
- scheduler fail-closed behaviour for missing, revoked, and expired permits;
- authenticated service integration covering permit issue, binding, revocation, and denial after revocation.
