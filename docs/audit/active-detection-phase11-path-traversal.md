# Active Detection, Slice 12: Path Traversal (CWE-22)

## Status

Partial. A fifth active detector (conservative, /etc/passwd-content-signature-based path traversal detection) is implemented, unit-tested (mocked connection, no real network), registered/permit-gated through the exact same infrastructure the original four active detectors already use, and (Slice 18) real-network validated against a purpose-built local fixture over real sockets. **Not yet taken through a true end-to-end CLI → API → worker → executor → report test.** This slice is added after `docs/scanner/SCANNER_V1_CAPABILITIES.md`'s own stated "Scanner v1 feature freeze" (Slice 11), at the user's explicit request; see `docs/CWE_COVERAGE.md`'s own Slice 12 note for that framing.

## What was built

### Detector (`workers/scanner/src/webguard_scanner/path_traversal_detector.py`)

Per-candidate methodology, deliberately mirroring `sqli_error_detector.py`'s own shape: exactly two bounded requests, a **baseline** (the candidate's original value, or `"baseline.txt"` if empty) and a **diagnostic** (`../../../../../../etc/passwd`, six levels deep, read-only and non-destructive even against a genuinely vulnerable target).

A finding is produced **only** when one of three `/etc/passwd` root-entry-line signatures (`root:x:0:0:`, `root:!:0:0:`, `root:*:0:0:`, covering the password-placeholder variants seen across Linux distributions) appears in the diagnostic response and is **absent** from the baseline. Two outcomes:

| Outcome | Condition | Finding? | Severity / Confidence |
|---|---|---|---|
| CONFIRMED | new signature in diagnostic, absent from baseline, and status code changed | yes | High / Confirmed |
| PROBABLE | new signature in diagnostic, absent from baseline, status code unchanged | yes | High / High |
| INCONCLUSIVE | everything else | no | N/A |

v1 scope, stated in the module's own docstring and repeated here rather than left implicit: Unix/Linux targets only, one payload, one traversal depth. No Windows-target variant (`..\..\windows\win.ini`), no alternate encodings (URL-encoded slashes, null-byte suffixes, absolute-path bypasses), no depth sweep. A target needing a different depth, OS, or bypass technique to reach a readable file is not flagged by this detector; that is a real, documented coverage limit.

### Registry and contracts catalog

`ACTIVE_DETECTOR_REGISTRY["active.pathtraversal.disclosure"] = run_path_traversal_detector`. `webguard_contracts.KNOWN_TRUSTSCAN_ACTIVE_CHECKS` extended to include it, an addition to the existing whitelist tuple, not a claims-schema change (no permit schema version bump needed, same reasoning as Slice 4's SQLi addition). `test_active_detector_registry.py`'s existing sync assertions (`test_registry_matches_contracts_catalog`, `test_registry_keys_plus_comparison_checks_match_known_ids`) pass unmodified against the six-entry registry.

### Candidate discovery and transports: reused unmodified

Same dual-path shape as SQLi/XSS: legacy `DetectionCandidate` (GET) and `RequestTemplate` (POST form / JSON body via the Slice 6 mutation engine), both built on the identical `issue_probe`/`issue_templated_request`/`mutate` primitives. No new candidate-discovery code; the executor's existing per-page detector loop already dispatches to any registry entry generically.

## False-positive controls

Covered by `tests/unit/test_path_traversal_detector.py` (mocked connection, no real network):

| Scenario | Mechanism that prevents a false positive | Verified |
|---|---|---|
| Genuine `/etc/passwd` disclosure, status changed | (positive control) | mocked |
| Genuine disclosure, status unchanged | PROBABLE tier, still a finding | mocked |
| Generic 404, no signature | no attributable signature -> INCONCLUSIVE | mocked |
| Reflected probe string, no file content | reflection alone is not a signature | mocked |
| Passwd-looking text already in baseline | signature present in both baseline and diagnostic -> treated as pre-existing, INCONCLUSIVE | mocked |
| Multiple parameters | classified fully independently per candidate | mocked |
| Probe-budget exhaustion | `enforce_probe_budget` with `requests_per_candidate=2` rejects before any request is sent | mocked |

## Safety boundaries

Identical to SQLi's, inherited unmodified: same-origin enforcement (`issue_probe`'s fail-closed check), GET-only legacy candidates (`DetectionCandidate` rejects non-GET at construction, `test_non_get_candidate_is_rejected`), the shared `before_request`/`after_request` runtime-safety hooks, redirect/connection-failure handling surfaced as probe errors rather than findings, cancellation checked before every candidate. Evidence sanitization: the matched signature text itself is never retained in the finding (`test_finding_evidence_never_contains_raw_signature_text`). Fingerprint determinism: `test_finding_fingerprint_determinism.py::PathTraversalFingerprintDeterminismTests` proves two runs against the same vulnerable candidate produce the same fingerprint and a different endpoint produces a different one.

Cross-detector authorization independence (does a permit authorizing only `active.sqli.error` also, incorrectly, let path traversal fire?) has not been re-proven with a dedicated test the way SQLi-vs-XSS independence was in Slice 4; this relies on the same generic, already-tested `active_checks` claim-matching mechanism every other detector uses (`test_active_checks_cross_detector_authorization.py`'s own existing coverage of that shared mechanism), not a per-detector-pair retest. Recorded as a real, not-yet-closed gap rather than assumed proven.

## Real-network validation

Done (Slice 18). `tests/integration/test_path_traversal_detector_live.py` runs the unmodified detector against a real `ThreadingHTTPServer`, mirroring SQLi's own `test_sqli_error_detector_live.py`. The fixture serves files from a real temporary directory created in `setUpClass`: the vulnerable route's `os.path.join` plus `open()`, with no sanitization, genuinely walks out of that directory when given the six-level payload and reads the actual `/etc/passwd` file on whatever machine runs the test, confirmed byte-for-byte equal to a direct read in a dedicated test. The safe route canonicalizes with `os.path.realpath` and rejects anything outside the base directory's own resolved path, a real containment check, not a stand-in.

One honest result this surfaced: a successful traversal read and a successful intended read both return HTTP 200 over this fixture, so the detector's own `_classify` lands on PROBABLE rather than CONFIRMED (`baseline_status == diagnostic_status`). This is not a bug; it is what the module's own classification table already predicts for this exact shape, now exercised for real rather than only reasoned about.

## True end-to-end test

**Not done this slice.** No CLI -> HTTP API -> worker -> executor -> report test exists for this detector yet, unlike SQLi's `test_sqli_checks_e2e_lab.py`.

## Live-target investigation

**Not attempted this slice.**

## Regression

`tests/unit/test_path_traversal_detector.py`: 13/13 pass. `tests/unit/test_finding_fingerprint_determinism.py`: 12/12 pass (10 pre-existing + 2 new). `tests/unit/test_active_detector_registry.py`: 3/3 pass unchanged against the six-entry registry. `tests/integration/test_path_traversal_detector_live.py` (Slice 18): 5/5 pass with `WEBGUARD_RUN_INTEGRATION=1`; skips cleanly without it. Full `tests/unit` discover run clean, no regressions in any pre-existing detector's own test file.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** path-traversal detector (CWE-22), independently permit-gated (`active.pathtraversal.disclosure`), registered, candidate-discovery-integrated, evidence-sanitized.

**Tested:** classification logic (positive/probable/inconclusive, false-positive resistance), same-origin/budget/redirect/connection-failure/cancellation/hook safety boundaries, evidence sanitization, fingerprint determinism. All against a fake connection.

**Proven:** the classification logic itself is correct against every scenario a fake connection can construct, and now also against a real, unmocked local fixture: the vulnerable route genuinely discloses this machine's own `/etc/passwd` and the safe route's canonicalize-then-check-containment fix genuinely blocks it, over a real TCP socket.

**Not Proven:** that this detector correctly fires against a real, genuinely vulnerable HTTP server beyond this project's own fixture, or correctly abstains against a real near-miss one in the wild; that it survives the full CLI/API/worker/executor pipeline; that it correctly cannot be triggered by a permit that only authorizes a different check; that any real-world target (lab or otherwise) is actually detectable by it.

**Remaining risks:**
- Detection is limited to Unix/Linux `/etc/passwd` disclosure via one payload and one depth; a target reachable only through Windows-path traversal, a different depth, or an encoding bypass produces a false negative, not a false positive.
- No true end-to-end test exists yet: the real-network fixture test proves the detector behaves correctly against an actual TCP connection and actual filesystem traversal, but not that it survives the actual executor/permit/worker pipeline.
- Cross-detector authorization independence for this specific detector is inferred from the shared mechanism's existing tests, not independently reconfirmed with this detector as one of the two compared.

**Next steps:** a true end-to-end lab test (mirroring `test_sqli_checks_e2e_lab.py`'s shape), before this detector should be considered as verified as the original four.
