# TrustScan Permit Schema — Versioning & Backward-Compatibility Policy

## Status

Current schema: **1.1**. This document must be read and followed before any real production deployment issues a permit that another version of this codebase might need to read back.

## What changed in 1.1

Schema 1.0 → 1.1 added exactly one signed claim: `active_checks: tuple[str, ...]` (empty by default). See `docs/audit/active-detection-phase2-orchestration.md` for the full rationale.

## Why 1.1 replaced 1.0 outright (and why that must not happen again casually)

`load_signed_trustscan_permit_json` and `load_trustscan_permit_submission_json` (`packages/contracts/python/src/webguard_contracts/scan_permits.py`) both use `_strict_mapping`, which requires an **exact** field set — there is no concept of an optional wire field, and no version-conditional parsing. Consequently, when 1.1 added `active_checks`, the only two options were:

1. Make every permit document (old and new) satisfy the same, expanded required-field set — i.e., stop supporting 1.0 documents at all, or
2. Build a version-aware loader that requires different field sets depending on `schema_version`.

This project took option (1): `CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION` moved from `"1.0"` to `"1.1"`, and `SUPPORTED_TRUSTSCAN_PERMIT_SCHEMA_VERSIONS` was changed from `("1.0",)` to `("1.1",)` — 1.0 is no longer loadable at all.

**This was only acceptable because it is true, verified, and stated here explicitly: WebGuard has never been deployed as a publicly hosted production service** (README: "Private commercial product under active development... not yet a publicly hosted production service"). There is no real, deployed 1.0 permit anywhere that this change could invalidate. This was a deliberate, reviewed engineering decision for a pre-production system, not an oversight, and it is recorded here so a future contributor does not repeat it by accident once that assumption stops being true.

## The policy going forward

**Before WebGuard is deployed anywhere a real, persisted permit could outlive a code deployment** (i.e., before "real production deployment" in the sense the Definition of Done documents require), the next schema change to `TrustScanPermitClaims` — whatever it is — **must not** repeat the 1.0→1.1 replace-in-place approach. Instead it must do one of:

- **Build a version-aware loader.** `load_signed_trustscan_permit_json` would need to branch its required-field set (and corresponding `TrustScanPermitClaims` construction) on `schema_version`, so both the old and new schema can be read. `SUPPORTED_TRUSTSCAN_PERMIT_SCHEMA_VERSIONS` would list both versions during the transition.
- **Or provide an explicit, tested migration** that re-signs every persisted permit under the new schema at deploy time (only possible because the signing key is available at deploy time; it is not possible to "migrate" a permit after the fact without re-signing it, since any claims change invalidates the existing signature — see the tampering test in `test_active_checks_permit_control.py` for exactly why).
- **Or, at minimum, explicitly accept and document** that old permits become unloadable/unusable after the upgrade, with a plan for what happens to any permit that was `active`/`pending` at cutover (does it need to be reissued? does the operator need advance notice?). Silent breakage is not acceptable once real permits exist.

Whichever approach is chosen, it must be decided *before* the schema changes, not discovered afterward — this document exists specifically so that decision isn't skipped.

## What does NOT require a schema bump

Nothing else in the permit contract has non-versioned wire flexibility either (same `_strict_mapping` mechanism applies to every field), so **any** future field addition or removal to `TrustScanPermitClaims` triggers this exact same question. This is not unique to `active_checks`.

## Verification that this policy is currently satisfied

- `CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION = "1.1"`, `SUPPORTED_TRUSTSCAN_PERMIT_SCHEMA_VERSIONS = ("1.1",)` — single supported version, consistent, no partial support gap.
- No persisted 1.0 permits exist in this repository's test fixtures, lab environment, or (to the best of this audit's knowledge) anywhere else, since the product has never been deployed.
- The safety-receipt contract (`TrustScanSafetyReceiptClaims`, schema `"1.0"`, unchanged this slice) was deliberately **not** touched, since its existing fields already account for active-probe activity without needing new ones (see the orchestration audit doc) — so this policy does not currently apply to it, but would under the identical reasoning if it ever needs a field added.
