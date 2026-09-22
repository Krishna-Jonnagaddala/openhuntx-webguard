# Active Detection, Slice 13: XML External Entity Injection (CWE-611)

## Status

Complete for this detector's own scope. A seventh active detector (out-of-band/blind XXE, confirmed via the existing `CallbackBroker`) is implemented, unit-tested (mocked connection plus the real in-memory callback broker, no real network), registered/permit-gated, (Slice 18) real-network validated against a purpose-built local fixture that genuinely resolves an external entity, and (Slice 19) taken through a true end-to-end CLI → API → worker → executor → report test. Unlike Slice 12's two additions, this one does not fit `ACTIVE_DETECTOR_REGISTRY`'s generic synchronous calling convention: it needed the same `CallbackBroker`-dependent orchestration path `active.ssrf.callback` already required, so it lives in `CALLBACK_ACTIVE_CHECK_IDS` and its own executor function. **Not yet run against any live/public target.** Added after the same Slice 11 feature freeze Slice 12 was added after, at the user's continued request; see `docs/CWE_COVERAGE.md`'s Slice 13 note.

## Design decision: why out-of-band only

Before writing any code, three independent design proposals were produced and compared. Two (`reuse-oob`, `reuse-signature`) independently, with high confidence, recommended an out-of-band-only v1 via the existing `CallbackBroker`. The third (`skeptic`) proposed in-band file-disclosure (reusing `path_traversal_detector.py`'s own `/etc/passwd` signature) instead, but its own analysis conceded the out-of-band variant proves a stronger, more general claim and only avoided building it for that lens's own scope discipline, not because it was wrong. This detector follows the two-lens majority.

The reasoning that decided it: every existing content-based detector here (SQLi, path traversal, command injection) holds the request shape constant and changes one value, so a difference in the response is attributable to that value. XXE cannot do that safely, since it has to replace the entire body and content type. A parser that safely, correctly rejects an external entity (the modern secure default across libxml2, .NET, Java, defusedxml) throws an error that routinely reuses the same vocabulary ("DOCTYPE", "external entity", "not allowed") that a parser failing to resolve one because it genuinely is vulnerable would also produce. There is no in-band signature this detector could match on without risking exactly the false positive the command-injection detector's own reflection bug already demonstrates is a real failure mode in this codebase, except here it would be structural, not a fixable classification bug: there may be no reliable phrase that only a vulnerable parser can produce. Out-of-band sidesteps the problem by never reading the response body for classification at all.

In-band file-disclosure and parameter-entity-based exfiltration are both named and excluded, not silently dropped: see the module's own docstring and "v1 scope" below.

## What was built

### Detector (`workers/scanner/src/webguard_scanner/xxe_callback_detector.py`)

One probe per selected candidate, no baseline request (mirroring `run_ssrf_callback_detector`, which is also single-probe: the callback arriving or not is the entire signal). The probe is a crafted `application/xml` document:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE wgxxe [
  <!ENTITY wgxxe SYSTEM "{callback_url}">
]>
<wgxxe>&wgxxe;</wgxxe>
```

`{callback_url}` is `CallbackToken.url` from a fresh `callback_broker.register()` call, the identical primitive `active.ssrf.callback` already uses. Exactly one entity, referenced exactly once; no parameter entity, no nested or self-referential definition, no `file://` or local path anywhere.

This document is sent as the entire request body via a `MutatedRequest` built directly (`_build_xxe_probe`), not through `mutate()`: `mutate()`'s contract is to substitute one value into an existing FORM/JSON body, the opposite of what XXE needs (replace the whole body and content type). `MutatedRequest` has no validation on `content_type` or `body` beyond field types, and `issue_templated_request` never requires that a `MutatedRequest` came from `mutate()`, so this is a direct, legitimate use of an already-public constructor, confirmed by reading `request_template.py` and `safe_http.py`'s `_perform_request` directly rather than assumed. One new named constant, `ContentType.XML`, was added for readability; nothing validates against it, same as the three constants already there.

Candidate selection (`select_xxe_candidates`) narrows a discovery result to POST-form/JSON-body templates only (a GET candidate carries no body, so it is never selected) and dedupes by `(endpoint, method)` rather than by parameter, since the crafted document discards whichever field originally discovered the endpoint. Probing once per discovered parameter would otherwise resend an identical request N times against one endpoint.

### Registry and contracts catalog

`active.xxe.callback` joins `CALLBACK_ACTIVE_CHECK_IDS` (now `{"active.ssrf.callback", "active.xxe.callback"}`), not `ACTIVE_DETECTOR_REGISTRY`. `webguard_contracts.KNOWN_TRUSTSCAN_ACTIVE_CHECKS` extended to a 7-tuple. `apps/api/src/webguard_api/executor.py` gained `_apply_xxe_callback_detection`, a close mirror of `_apply_ssrf_callback_detection`: same page fetch, same `discover_page_attack_surface`/`to_request_templates` discovery call, same `_ScanScopedCallbackBroker` adapter reused unmodified, same single-page-only restriction, same fail-closed "not in active_checks → return report unchanged" gate, and one call-site addition alongside the existing SSRF call. `test_active_detector_registry.py`'s sync assertions pass unmodified against the new set membership.

### Candidate discovery and transports

Discovery is entirely reused: the same `to_request_templates(allow_post=, allow_json=)` pipeline every other POST/JSON-capable detector already relies on. No new discovery code, no XML-aware media-type sniffing. A pure SOAP/XML-only endpoint never discovered as a POST-form or JSON-body candidate in the first place remains invisible to this detector, the same kind of gap already honestly documented for SQLi against Juice Shop's JS-bundle-only API surface.

## False-positive controls

Covered by `tests/unit/test_xxe_callback_detector.py` (mocked connection plus the real in-memory `CallbackBroker`, no real network):

| Scenario | Mechanism that prevents a false positive | Verified |
|---|---|---|
| Genuine callback observed within the primary window | (positive control) | mocked + real broker |
| Hardened parser rejects the document, response text says "DOCTYPE is disallowed" | response text is never inspected for classification; no callback arrives -> NOT_VULNERABLE | mocked + real broker |
| Target reflects the raw request body (including the callback URL) back into an error page | same: response text never inspected -> NOT_VULNERABLE | mocked + real broker |
| Callback observed for a different scan's token | token correlation is exact and scan-bound; an unrelated observation never satisfies this candidate's wait | real broker |
| Duplicate callback delivery for the same token | still exactly one finding per candidate | real broker |
| Generic 500 with no callback | NOT_VULNERABLE | mocked + real broker |
| Probe-budget exhaustion | `enforce_probe_budget` with `requests_per_candidate=1` rejects before any request is sent | mocked |

## Safety boundaries

Entity expansion / denial of service is structurally impossible with this payload, not merely avoided by policy: exactly one entity, referenced exactly once, no parameter entity, no nested or self-referential definition, so there is nothing resembling a "billion laughs" chain for even a maximally naive parser to expand. `docs/ROADMAP.md` excludes denial-of-service testing from scope; this design does not use resource exhaustion as a signal in either direction.

Arbitrary file read is equally impossible: the SYSTEM identifier is always and only a WebGuard-issued `http://`/`https://` callback URL, never `file://` or any local path. Even a fully vulnerable target can only be induced to make one outbound HTTP GET to WebGuard's own receiver; it is never asked to open, read, or transmit any of its own files. This is a stronger property than `path_traversal_detector.py`'s own claim (which does read one real, world-readable target file); this detector reads nothing from the target at all.

Same-origin enforcement, probe budget, cancellation checks, and `before_request`/`after_request` hooks are inherited unmodified from `issue_templated_request`, identical to every other active detector. Evidence sanitization: the finding's provenance string never contains the raw callback URL or token, only a truncated SHA-256 fingerprint of the token, mirroring `_build_finding` in `ssrf_callback_detector.py` line for line. `FindingIdentity.parameter` is always `None` for this detector, a deliberate deviation from every other active detector here, since XXE replaces the entire request body and there is no single parameter the evidence is about; this is tested directly (`test_confirmed_when_callback_observed_within_primary_window` asserts `finding.identity.parameter is None`). Fingerprint determinism: `test_finding_fingerprint_determinism.py::XxeFingerprintDeterminismTests` proves the fingerprint ignores the fresh callback token entirely (two runs against the same candidate produce the identical fingerprint; a different endpoint produces a different one).

Cross-detector authorization independence has not been re-proven with a dedicated test for this specific detector, the same open gap path traversal's and command injection's own audit docs record, relying on the shared, already-tested `active_checks` claim-matching mechanism.

## v1 scope

Stated directly, matching how every prior detector states its own limits:

- Out-of-band only. In-band file-disclosure and in-band error-signature detection are both deliberately excluded (see "Design decision" above), not silently dropped.
- No parameter-entity-based two-stage exfiltration: that technique requires inducing the target to actually read and transmit one of its own files, exactly the risk this detector is built to never create.
- Exactly one payload shape: a single DOCTYPE, one general entity, referenced once in element content. No parameter entities, no nested DOCTYPE, no XInclude, no SOAP-envelope wrapping, no alternate encodings.
- Candidate selection reuses the existing POST-form/JSON-body discovery heuristic as a proxy for "this endpoint might also accept XML," as unproven as SSRF's own URL-shaped-parameter-name heuristic.
- Single-page scans only, matching the identical restriction `_apply_ssrf_callback_detection` already states for itself.
- No DNS-only out-of-band channel: only a completed inbound HTTP request at the WebGuard receiver counts as proof. A target whose egress permits DNS but blocks outbound HTTP is classified NOT_VULNERABLE, a false negative inherited from the CallbackBroker/receiver architecture, not introduced by this detector.

## Real-network validation

Done (Slice 18). `tests/integration/test_xxe_callback_detector_live.py` runs the unmodified detector against a real `ThreadingHTTPServer` and the real `CallbackHttpReceiver`/`InMemoryCallbackBroker` (the identical classes the SSRF live test already uses). Python's own standard-library XML parsers do not resolve external entities by default, so the fixture's vulnerable route deliberately uses `xml.parsers.expat` directly with an `ExternalEntityRefHandler` assigned that performs a real, blocking `urllib.request.urlopen` on the entity's SYSTEM identifier before returning, mirroring exactly how the existing SSRF live fixture's own vulnerable route works. The safe route parses the identical posted document with no handler assigned at all, which is Python's actual secure-by-default behavior, not a simulated one, so no outbound fetch happens no matter what the document declares.

## True end-to-end test

Done (Slice 19). `tests/integration/test_xxe_callback_e2e_lab.py` closes the gap this section previously recorded: it is a near line-for-line mirror of `test_ssrf_callback_e2e_lab.py`, exercising `_apply_xxe_callback_detection`'s own wiring in `executor.py`'s call sequence directly, real CLI bootstrap through the real permit/job/worker/executor pipeline, against a fixture reusing the identical `xml.parsers.expat`/`ExternalEntityRefHandler` mechanism the Slice 18 real-network test already proved works, over the real `CallbackHttpReceiver`/`CallbackRepository`.

One real, non-obvious requirement surfaced while building this: the permit's `allowed_http_methods` claim must include `POST`, not only `GET`/`HEAD`. `_apply_xxe_callback_detection`'s own candidate discovery (`to_request_templates(..., allow_post=...)`) gates on `"POST" in fetch_policy.allowed_methods`, and `fetch_once` separately re-checks the same set before ever sending the probe; without `POST` in that claim, discovery silently produces zero candidates and the detector runs across nothing, no error, no finding, a clean-looking scan that never actually exercised the detector. This is existing, correct fail-closed behavior (an active check can only reach methods the permit explicitly authorizes), not a bug in this slice's own code, but worth stating plainly for anyone issuing a permit for this check.

## Live-target investigation

**Not attempted this slice.**

## Regression

`tests/unit/test_xxe_callback_detector.py`: 21/21 pass. `tests/unit/test_finding_fingerprint_determinism.py`: 14/14 pass (12 pre-existing + 2 new, including this detector's own). `tests/unit/test_active_detector_registry.py`: 3/3 pass unchanged. Full `tests/unit` discover run: 1948/1948 pass (up from 1925 before this slice), no regressions in any pre-existing detector's own test file. `tests/contract`: 99/99 pass (63 skipped, PostgreSQL-backed). `ruff check --select S --ignore S101` against `packages/contracts/python/src`, `workers/scanner/src`, `apps/api/src` (the exact scope `scripts/run-security-gates.sh` checks): clean. `scripts/scan-secrets.py`: clean.

**Slice 18 addendum:** `tests/integration/test_xxe_callback_detector_live.py`: 1/1 pass with `WEBGUARD_RUN_INTEGRATION=1`; skips cleanly without it. Re-ran the full `tests/unit` suite (2031/2031 pass, current total, not the 1948 figure above) and the full security-gates script (secret scan, ruff, dependency audit) at the same time as the other four Slice 18 additions; see `docs/CWE_COVERAGE.md`'s own Slice 18 section for the combined run.

**Slice 19 addendum:** `tests/integration/test_xxe_callback_e2e_lab.py`: 1/1 pass with `WEBGUARD_RUN_INTEGRATION=1` (ran three times to rule out flakiness, identical every time); skips cleanly without it. Re-ran the full `tests/unit` suite (2031/2031 pass), the full `tests/integration` suite (312/312 pass, 243 skipped), and the full security-gates script (secret scan, ruff, dependency audit) at the same time as the other four Slice 19 additions; see `docs/CWE_COVERAGE.md`'s own Slice 19 section for the combined run.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** out-of-band XXE detector (CWE-611), independently permit-gated (`active.xxe.callback`), registered in `CALLBACK_ACTIVE_CHECK_IDS`, wired into the executor's call sequence, evidence-sanitized.

**Tested:** payload shape (exactly one entity, no `file://`, correct callback URL substitution, correct content-type header, full body replacement not merge), classification logic including a hardened-parser-rejection false-positive control, callback token/scan correlation, evidence sanitization, `FindingIdentity.parameter` always `None`, fingerprint determinism, and the same-origin/budget/cancellation/hook safety-boundary suite every other active detector already requires. All against a fake connection and the real in-memory `CallbackBroker`.

**Proven:** the out-of-band design's core safety claims (structurally cannot expand entities, structurally cannot read a local file) hold by construction of the payload itself, not by policy alone; the classification logic never reads response text, so it is structurally immune to the reflection/hardened-rejection false-positive class this slice specifically investigated. As of Slice 18, also proven against a real, genuinely vulnerable local server whose own XML parser actually resolves an external entity and performs a real outbound fetch, and correctly abstains against a real parser using Python's own secure-by-default configuration. As of Slice 19, also proven to survive the full, real CLI → HTTP API → worker → executor → report pipeline unmodified, including the executor-layer wiring (`_apply_xxe_callback_detection`) itself, exercised directly for the first time.

**Not Proven:** that this detector correctly fires against a real, genuinely vulnerable HTTP server beyond this project's own fixture, or correctly abstains against a real hardened parser in the wild; that any real-world target is actually detectable by it.

**Remaining risks:**
- Detection is limited to one payload shape and to endpoints already discoverable as POST-form/JSON-body candidates; a target reachable only through a genuinely XML-native, undiscovered endpoint produces neither a true positive nor a false positive, it is simply never probed.
- A target with egress that permits DNS resolution but blocks outbound HTTP produces a false negative (NOT_VULNERABLE), inherited from the CallbackBroker/receiver architecture this shares with SSRF.
- Cross-detector authorization independence for this specific detector is inferred, not independently reconfirmed.

**Next steps:** live/public-target investigation, the same next step now recorded for every detector besides CWE-639 and CWE-306, and the one that would let a fourth real-world reproduction (after CWE-639's Juice Shop confirmation) be attempted for this technique specifically.
