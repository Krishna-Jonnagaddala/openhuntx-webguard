# Active Detection — Slice 3: Operator-Facing Control Surface

## Status

Complete. The reflected-XSS detector (Slice 1) and its orchestration wiring (Slice 2) are now genuinely operator-reachable: a real CLI command, real RBAC enforcement stricter than ordinary permit issuance, real audit trail, and one true end-to-end test proving the entire chain — CLI → HTTP API → worker → executor → active-detector registry → detector → normalized finding in the persisted report — over real sockets, real TLS, and real permit/RBAC enforcement.

This closes the gap Slice 2 explicitly flagged as not done: *"No CLI/API surface exists yet to actually request active_checks when issuing a permit... the capability is real but not operator-reachable without hand-writing JSON."*

## What was built

### RBAC: a stricter permission for active-capability permits

New `ApiPermission.PERMIT_ISSUE_ACTIVE`, granted only to `OrganizationRole.OWNER` — not `ADMINISTRATOR`, which retains ordinary `PERMIT_ISSUE` (and every other permission) unchanged. This is a genuine, deliberate narrowing: before this slice, `ADMINISTRATOR` held every `ApiPermission` value; now one specific, more consequential action is reserved to the owner. `service.py`'s `issue_permit` checks this *before* touching authorization lookup or permit construction whenever the submission's `active_checks` is non-empty — an unauthorized request never gets far enough to reveal anything about the authorization it referenced.

One pre-existing test (`test_owner_and_administrator_permission_sets_are_complete`) asserted administrators hold every permission; it was updated, not weakened, to assert the new, narrower, intentional boundary explicitly (including that administrators still hold everything else).

### Service layer: the missing wire-through

Slice 2 added `active_checks` to the permit *contract* and the *executor*, but `service.py`'s `issue_permit` never actually passed `submission.active_checks` into the `TrustScanPermitClaims` it constructed — the field was accepted over the wire and then silently dropped. This was the actual root cause of "not reachable." Fixed: `active_checks=submission.active_checks` now flows through, and the RBAC check above gates it.

### Audit trail: decision recorded, never secrets

Permit issuance already had a full audit-event mechanism (`identity.record_audit_event`, action `"permits.issue"`, tenant-scoped, pre-existing from earlier phases) — this was not built new. What was missing was any record of *which* active checks were authorized. A new `_active_checks_audit_detail()` helper encodes the sorted, joined detector IDs into the audit event's `detail_code` field (e.g. `active_checks_active.xss.reflected`) — detector IDs are structural names, never evidence, payload, or target data, so this satisfies "including active-check IDs but never sensitive payload/evidence data" without needing a new audit-event schema field. `detail_code` is a strictly bounded identifier (`packages/contracts/python/src/webguard_contracts/tenancy.py`, 128 chars, canonical lowercase); if a future detector-ID list would exceed that, the helper falls back to a generic `active_checks_authorized` marker rather than truncating silently. A denied `permits.issue_active` request is audited as `DENIED` with the same action name, distinguishable from a denial at the more basic `permits.issue` gate (a viewer, who lacks even that, is denied there instead and never reaches the active-checks check at all — both paths are tested separately).

### CLI: `webguard-api permit issue`

New subcommand (`apps/api/src/webguard_api/cli.py`). It does not reimplement permit construction or validation — it authenticates the supplied `--token` via the same `ApiTokenAuthenticator` the HTTP API uses, builds the same submission JSON, and calls `WebGuardJobService.issue_permit()` directly, the exact method the HTTP endpoint calls. This was a deliberate design choice specifically so CLI and HTTP-API issuance cannot drift apart — proven, not just asserted, by `test_cli_and_service_produce_identical_canonical_claims`.

`--active-check` (repeatable) requests one active-detector ID; omitting it entirely issues a passive-only permit (`active_checks=[]`), the default and the fail-closed behavior. Duplicate `--active-check` values are rejected outright by the CLI before any request reaches the service, with a clear error — not silently deduplicated.

One real bug was found and fixed while building this: `not_before` computed as exactly "now" on the CLI side raced against the service's own, microseconds-later clock read, spuriously producing `trustscan_permit_start_in_past` on almost every issuance. Fixed with a small (500ms) forward buffer — enough to absorb realistic local latency without making a freshly issued permit meaningfully unusable. This is a general permit-issuance timing property this slice happened to be the first thing to exercise with a real (unmocked) clock end-to-end; it is not specific to active checks.

### Permit schema 1.0 → 1.1

Already covered in Slice 2; this slice adds `docs/audit/trustscan-permit-schema-policy.md`, the explicitly requested backward-compatibility policy, covering why the replace-in-place approach was acceptable only because WebGuard has never been deployed, and exactly what must happen differently before the *next* schema change once that stops being true.

## What was deliberately not built

- **API response/report metadata beyond the permit's own claims.** The permit issuance/read response already includes `active_checks` (via the unmodified `TrustScanPermitClaims.to_dict()`), and findings already carry `source="webguard-active"`. No additional summary field was added to the job/report response specifically listing "checks that ran" — the permit is the authoritative record of what was *authorized*, and per-finding `source` plus `identifiers` already show what actually *fired*. Revisit only if a real operator workflow needs a single "did active detection run" flag that's cheaper than checking the permit.
- **Cross-tenant job/execution attack surface beyond permit read.** The cross-tenant test in this slice covers permit *read* across tenants (an existing, general tenant-isolation property, reconfirmed for active-checks permits specifically); it does not re-derive the full cross-tenant job-submission/execution test matrix, which is Phase 2/4's established, already-audited territory and was not touched by this slice.

## Regression suite

- `tests/unit/test_active_checks_permit_control.py` — 13 tests: missing-field rejection, empty-list passive-only, valid detector request, unknown detector rejection, duplicate rejection, administrator/viewer RBAC denial (with administrator still able to issue passive permits), cross-tenant permit-read denial, target/authorization mismatch, signed-claims tampering (Ed25519 verification failure), and both the successful and denied audit-event content (with an explicit check that no secret/target/signature material leaks into the audit record).
- `tests/unit/test_active_checks_cli.py` — 7 tests: the CLI-specific versions of the omit/request/unknown/duplicate/RBAC scenarios above, plus the CLI-vs-service canonical-claims parity test.
- `tests/integration/test_active_checks_e2e_lab.py` — 1 test, opt-in (`WEBGUARD_RUN_INTEGRATION=1`): the true end-to-end chain against a purpose-built local reflected-XSS fixture (self-submitting form on `127.0.0.1`, real TLS via a freshly generated self-signed certificate) — CLI bootstrap → CLI authorization assignment → CLI permit issuance with `--active-check active.xss.reflected` → real HTTP API job submission → real worker claiming and executing the job through the real `ScanJobExecutor` → real active-detector registry lookup → real `run_reflected_xss_detector` → a `CWE-79` finding with `source="webguard-active"` in the persisted report, retrieved back through the HTTP API's job-result endpoint.

Three narrow, explicitly documented mocks make the end-to-end test possible (loopback scope validation, the owned-target preflight's independent public-address re-check, and the TLS trust anchor) — see the test file's own module docstring for exactly why each one exists and why nothing broader was mocked. Everything else in the chain — permit binding and revalidation, the runtime safety engine, owned-target preflight's non-address checks, discovery, and detection — runs for real.

Full repository regression after this slice: **1124/1124 unit tests**, **19/19 integration tests** (14 Juice Shop + 4 Slice-1 live-fixture + 1 new true-E2E), all three security gates (secret scan, static analysis, dependency audit) passing.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** CLI permit issuance with `--active-check`; stricter owner-only RBAC for active-capability permits; audit trail recording the authorization decision and detector IDs without secrets; the missing service-layer wire-through that made Slice 2's contract/executor work actually reachable.

**Tested:** every scenario explicitly requested for this slice (see the two new unit test files above) — omitted/empty active_checks, valid/unknown/duplicate detector IDs, RBAC (owner/administrator/viewer), cross-tenant denial, target/authorization mismatch, signature tampering, CLI/API parity, and audit content.

**Proven:** the full CLI-to-report chain works end-to-end against a real target under real TLS, real permit/RBAC enforcement, and the real runtime safety engine — not simulated, not through a fake executor.

**Not Proven:** a genuine, independently-discovered vulnerability was not produced by this end-to-end run — the fixture is a controlled, known-vulnerable synthetic page, exactly as Slice 1/2 already established is the honest state of lab validation for this detector (no real app in this project's current lab set has a server-side reflection surface for this detector's methodology).

**Remaining risks:**
- The permit-schema replace-in-place approach (1.0→1.1) is explicitly documented as *only* acceptable pre-production; `docs/audit/trustscan-permit-schema-policy.md` states the required approach before it happens again with real deployed permits.
- The CLI's `permit issue` command has no equivalent for `permit revoke`/`permit read` yet — only issuance was requested and built.
- The 500ms `not_before` buffer is a heuristic, not a proof; under sufficiently degraded local conditions (a heavily loaded machine, an unusually slow SQLite write) a freshly issued permit could theoretically still race. This is a pre-existing timing property of the permit-issuance design, now visible for the first time because this slice is the first real end-to-end (unmocked-clock) test of it, not something introduced by this slice.

**Next:** proceed to SQL injection detection, per the original instruction, now with an operator-usable control surface already in place for it to plug into.
