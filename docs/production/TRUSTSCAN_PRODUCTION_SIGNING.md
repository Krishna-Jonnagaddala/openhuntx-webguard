# TrustScan Production Signing: Key Custody Decision (Slice 14)

## Status

**Decided (this document) and implemented (Slice 18) — not deployed.** This document's Option A recommendation is now real code: `CloudHsmSigningProvider`, a dedicated `TrustScan Signing Service`, and `infra/terraform/cloudhsm.tf` all exist, are unit- and integration-tested, and preserve the exact Ed25519 contract described below with zero schema change. See `docs/production/TRUSTSCAN_SIGNING_SERVICE.md` for the full implementation, key-lifecycle operation, and — stated precisely there — exactly what has and has not been proven (no CloudHSM cluster has been provisioned, and the PKCS#11 adapter has never run against real hardware). The rest of this document is preserved as-written below: it is the decision record, not duplicated in the new document.

## The problem, precisely

TrustScan permits and Safety Receipts are signed with **Ed25519** (`LocalDevelopmentSigner`, `signing.py`) — the only provider actually wired into any running WebGuard process today, local or production. The Ed25519 private seed lives in the service's own SQLite-adjacent secret file, owner-only permissions, no rotation, no HSM, no audit trail beyond the filesystem's own. This is explicitly documented (`docs/THREAT_MODEL.md`, `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`) as one of the highest-priority production gaps: a compromised local signing key can forge permits with no rotation or revocation path.

Slice 12 built `KmsSigningProvider` to close this gap and, in doing so, surfaced a hard constraint that must be preserved, not worked around:

> **AWS KMS has no Ed25519 KeySpec.** Its asymmetric `KeySpec` values are `RSA_2048/3072/4096` and `ECC_NIST_P256/P384/P521/SECG_P256K1` — there is no Ed25519/EdDSA option, as of this writing. `KmsSigningProvider` therefore targets `ECDSA_SHA_256` as its own distinct, honestly-labeled algorithm. It has never claimed Ed25519 compatibility and is not wired as TrustScan's active signer.

Slice 13 fixed a related, subtler bug and that fix must also be preserved: `KmsSigningProvider.key_id` is derived from the SHA-256 hash of the provider's own public key material (`sha256:<64 hex chars>`, matching the same contract-validated shape `LocalDevelopmentSigner` already produces), never from the raw AWS KMS key ARN. A permit's `signing_key_id` claim identifies *which verification key* was used, structurally — it is not, and must never become, an AWS-specific resource identifier leaking into a cross-cloud-portable permit format.

**The actual open decision** is not "how do we call AWS KMS" (already built) — it is: *does production TrustScan signing stay Ed25519 via different key custody, or does it move to KMS's `ECDSA_SHA_256`, and either way, who/what actually holds the private key at launch?*

## Requirement: do not change the algorithm this slice

Per this slice's explicit instruction, **the active permit-signing algorithm is not changed here**, regardless of which option below is ultimately selected. `LocalDevelopmentSigner`/Ed25519 remains the only wired signer in every environment today. This document makes the *decision* for the next slice's scoped, reviewed, regression-tested implementation work — it does not implement it.

## Options considered

### Option A — AWS CloudHSM-backed Ed25519

A general-purpose HSM, reachable via PKCS#11, that **does** support Ed25519 natively (unlike KMS). A new `SigningProvider` implementation (e.g. `CloudHsmSigningProvider`, using a PKCS#11 client library such as `python-pkcs11`) would sign through the HSM exactly as `LocalDevelopmentSigner` signs in-process today — same algorithm, same claims, same verification code path, zero permit-schema change.

- **Preserves the existing cryptographic format entirely.** No `SignedTrustScanPermit` schema change, no dual-algorithm verification period, no risk of a permit issued under one algorithm being misverified under another.
- **Genuine HSM-backed custody**: FIPS 140-2 Level 3 hardware, non-extractable private key, matching the assurance level `docs/THREAT_MODEL.md` actually asks for ("KMS/HSM-backed key custody").
- **Cost and operational weight are real**: a CloudHSM cluster (minimum 2 HSMs for HA) runs roughly $1.60/HSM-hour — on the order of $2,300+/month — plus cluster initialization (a genuine crypto-officer/crypto-user ceremony, not a config flag), ongoing patching, and backup/recovery procedures CloudHSM itself requires operators to own.
- **New dependency**: a PKCS#11 client library, not currently in `requirements-ci.lock`'s minimal, hash-reviewed set — a deliberate addition, not a casual one, consistent with how `boto3` itself is handled (injected by the caller, never a package-level dependency of `webguard_api`).

### Option B — Dedicated signing service with a protected Ed25519 key

A small, isolated internal service (or a hardened process on a locked-down host) holding the Ed25519 private seed, decrypted only in that process's memory, encrypted at rest via envelope encryption (AWS KMS as a *data-key* encryptor — a legitimate, different KMS use case than signing directly). WebGuard's API/worker processes would call this service over an internal-only RPC to sign, rather than holding the key themselves.

- Preserves Ed25519, no schema change, same verification code.
- KMS still participates (encrypting the seed at rest), giving real defense-in-depth over today's plain owner-only file.
- **Does not reach HSM-equivalent assurance**: the private key exists in cleartext in one process's memory at signing time — extractable in principle by anyone who compromises that process, unlike CloudHSM's non-extractable key material.
- **Adds a new operational component** (a service to build, secure, monitor, patch, and keep available) without buying the security level Option A provides — worse on both the security and the operational-complexity axis unless Option A's cost is genuinely prohibitive.

### Option C — Explicit future migration to ECDSA_SHA_256 via AWS KMS

Use `KmsSigningProvider` exactly as already built and unit-tested. Formally decide that TrustScan's production signing algorithm becomes `ECDSA_SHA_256`, not Ed25519 — a real, reviewed, regression-tested permit-schema change (new `SignedTrustScanPermit` algorithm value, updated verification logic accepting the new algorithm, a decision on whether/how already-issued Ed25519 permits are handled during the cutover).

- **Zero new infrastructure and zero new dependencies** — `KmsSigningProvider` exists, is unit-tested, and AWS KMS is already the callback-service/secrets custody path this project is standardizing on.
- **Genuine HSM-backed custody** via KMS's own FIPS 140-2 validated infrastructure, with built-in rotation support `SigningKeyRegistry` already models (active/retired/disabled key states).
- **Requires an actual cryptographic-format migration** — the one thing this slice is explicitly barred from doing, and rightly so: it changes what a permit's signature *is*, not merely where the key lives. `docs/audit/trustscan-permit-schema-policy.md`'s existing decision (permits are short-lived, reissued capability tokens, never long-lived stored entities) makes this migration *simpler* than it would be for a long-lived-token system — no permit "in flight" needs dual-algorithm verification, since an unconsumed permit issued under the old scheme just expires normally and gets reissued under the new one — but "simpler" is not "already done," and it still needs its own dedicated review slice.

## Decision: recommended v1 production path

**Option A (AWS CloudHSM-backed Ed25519) is the recommended v1 production launch path.**

Reasoning:

1. It is the only option that closes the actual, named gap (`docs/THREAT_MODEL.md`'s "KMS/HSM-backed key custody, key versions, rotation, audit, incident revocation/distrust procedures") **without** also taking on a cryptographic-format migration — the two problems ("where does the key live" and "what algorithm does it use") are kept separate, which is the same discipline this project has applied everywhere else (Slice 12's KMS work never silently changed the algorithm either).
2. Option B is dominated by Option A: it costs real engineering effort to build and operate a new service, without reaching the same assurance level. There is no scenario where B is the right choice unless CloudHSM is unconditionally unavailable (e.g. a cost constraint so severe that even a minimal 2-HSM cluster is out of reach) — and even then, Option C should be evaluated before B, since C is cheaper *and* stronger than B.
3. Option C remains the credible fallback, explicitly not foreclosed: if CloudHSM's operational cost or complexity proves prohibitive after real pricing/procurement conversations, Option C should be picked up as its own dedicated, reviewed, regression-tested slice — not adopted by default now to avoid Option A's cost.

**Slice 18 update**: `CloudHsmSigningProvider` and the dedicated TrustScan Signing Service described above are now built (`docs/production/TRUSTSCAN_SIGNING_SERVICE.md`). What this decision still did not authorize, and what Slice 18 still did not do: provisioning a real CloudHSM cluster or cutting live production traffic over to it. `infra/terraform/cloudhsm.tf` is reviewed, unapplied IaC; the PKCS#11 adapter has never run against real hardware. That remains scoped, reviewed, follow-up work — an infrastructure-provisioning and cutover decision, not a code-review one.

## What this slice actually changed (recap, for traceability)

- Nothing about the active signing algorithm or provider. `LocalDevelopmentSigner`/Ed25519 remains the only wired signer everywhere.
- `KmsSigningProvider`'s existing `provider_key_id` (AWS-facing) / `key_id` (permit-facing, SHA-256-derived) split from Slice 13 is preserved and unmodified — this document does not touch it, and any future `CloudHsmSigningProvider` or `ECDSA_SHA_256` migration should follow the identical pattern: the permit-facing `key_id` is always derived from public key material, never a cloud-provider-specific resource identifier.
