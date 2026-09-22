# Active Detection, Slice 12: OS Command Injection (CWE-78)

## Status

Complete for this detector's own scope. A sixth active detector (marker-based OS command injection detection) is implemented, unit-tested (mocked connection, no real network), registered/permit-gated through the exact same infrastructure the original four active detectors already use, (Slice 18) real-network validated against a purpose-built local fixture that genuinely shells out, and (Slice 19) taken through a true end-to-end CLI → API → worker → executor → report test. **Investigated (Slice 20) against a live Juice Shop container: no compatible surface exists at all.** Built in the same pass as `active-detection-phase11-path-traversal.md`; see that document and `docs/CWE_COVERAGE.md`'s Slice 12 note for the "added after the stated Scanner v1 feature freeze" framing, which applies identically here.

## What was built

### Detector (`workers/scanner/src/webguard_scanner/command_injection_detector.py`)

Per-candidate methodology: exactly two bounded requests, a **baseline** (the candidate's original value, or `"1"` if empty) and a **diagnostic** (`<baseline>; echo <fresh-random-marker> #`, a POSIX shell chain-and-comment payload). The marker is a fresh, unpredictable `wgcmdi<16 hex chars>` string generated once per candidate (`_new_marker`, mirroring `xss_reflected_detector.py`'s own `_new_marker` pattern), never reused across candidates in one run.

A false positive was found and fixed during this slice's own test-writing, not caught later: checking only "does the marker appear in the response" flags a target that merely reflects an invalid parameter value verbatim into an error message (e.g. `"Invalid host: 1; echo wgcmdi... #"`) as CONFIRMED, since the marker is technically present inside the untouched, unexecuted payload string. Fixed by requiring the marker to appear **and** the full raw diagnostic payload string to be **absent** from the response: a genuine execution strips the shell metacharacters and comment marker away, leaving only the marker (and whatever the baseline command's own real output was); the literal payload text does not survive intact when a shell actually interprets it. `tests/unit/test_command_injection_detector.py::test_unmodified_reflection_of_the_raw_payload_is_inconclusive` pins this exact scenario.

Two outcomes only, no PROBABLE tier, per the module's own docstring reasoning: unlike a database-error phrase or a file's own content, a freshly random marker either comes back on its own, as command output, or it does not; there is no meaningful middle ground once reflection is ruled out by the check above.

v1 scope, stated in the module's own docstring and repeated here: the `;`-plus-`#` POSIX chaining pattern only, targeting shells (`sh`/`bash`/`zsh`) that treat it as "end the original command, run mine, ignore the rest." No `|`, `&&`, backtick, or `$()` separators; no Windows `cmd.exe`/PowerShell chaining (`&`); no quote-breaking prefix for injection points nested inside a quoted string in the vulnerable command line.

### Registry and contracts catalog

`ACTIVE_DETECTOR_REGISTRY["active.cmdi.marker"] = run_command_injection_detector`. `webguard_contracts.KNOWN_TRUSTSCAN_ACTIVE_CHECKS` extended to include it, same additive, no-schema-bump treatment as every prior addition. `test_active_detector_registry.py`'s sync assertions pass unmodified against the six-entry registry.

### Candidate discovery and transports: reused unmodified

Same dual-path shape (legacy `DetectionCandidate` GET, `RequestTemplate` POST/JSON) as every other detector in the registry, built on the identical shared primitives. No new candidate-discovery code.

## False-positive controls

Covered by `tests/unit/test_command_injection_detector.py` (mocked connection, no real network):

| Scenario | Mechanism that prevents a false positive | Verified |
|---|---|---|
| Genuine command execution, isolated marker in output | (positive control) | mocked |
| Verbatim reflection of the raw payload into an error message | marker present, but so is the untouched payload -> INCONCLUSIVE | mocked |
| Generic error, no marker | marker absent -> INCONCLUSIVE | mocked |
| Multiple candidates | a fresh, independent marker per candidate; markers proven never to collide within one run (`test_marker_is_unique_per_candidate`) | mocked |
| Probe-budget exhaustion | `enforce_probe_budget` with `requests_per_candidate=2` rejects before any request is sent | mocked |

## Safety boundaries

Identical to the other GET/POST/JSON detectors', inherited unmodified: same-origin enforcement, GET-only legacy candidates rejected at construction, shared `before_request`/`after_request` hooks, redirect/connection-failure handling as probe errors, cancellation checked before every candidate. Evidence sanitization: the marker itself is never retained in the finding's provenance string (`test_finding_evidence_never_contains_raw_marker_text`). Fingerprint determinism: `test_finding_fingerprint_determinism.py::CommandInjectionFingerprintDeterminismTests` proves the fingerprint ignores the marker entirely (two runs against the same candidate, each with its own fresh random marker, produce the identical fingerprint; a different endpoint produces a different one), the one property this whole module exists to check, and the one most specific to this detector's own marker-based design, not just a copy of the SQLi/path-traversal version.

Cross-detector authorization independence has not been re-proven with a dedicated test for this specific detector, same open gap as path traversal's own audit doc records, relying on the shared, already-tested `active_checks` claim-matching mechanism rather than a per-pair retest.

**Non-destructiveness, worth stating plainly given this is command execution, not just data disclosure:** the only command ever sent is `echo <marker>`, which prints its argument and exits. It reads no file, writes no file, starts no other process, and has no side effect beyond producing output. This was a deliberate choice, not an afterthought, made when picking the diagnostic payload.

## Real-network validation

Done (Slice 18). `tests/integration/test_command_injection_detector_live.py` runs the unmodified detector against a real `ThreadingHTTPServer` with three routes, each doing something genuinely different with the value: `/vulnerable` calls `subprocess.run(f"echo {value}", shell=True, ...)`, so a real POSIX shell on the machine running the test genuinely splits the diagnostic payload on `;` and comments out the rest with `#` (confirmed by a module-level self-check that runs before the test class, failing loudly at import time if this machine's shell ever behaved differently); `/safe` calls `subprocess.run(["echo", value], shell=False, ...)`, so the identical string arrives at `/bin/echo` as one inert argv element and comes back completely intact; `/reflects-input` executes nothing at all and echoes the raw value into an `Invalid input: <value>` string, proving the detector's marker-plus-payload-absence check for real against the exact reflection shape it exists to rule out (the marker is genuinely present in that response body, and the detector still correctly produces no finding).

## True end-to-end test

Done (Slice 19). `tests/integration/test_command_injection_checks_e2e_lab.py` mirrors SQLi's own `test_sqli_checks_e2e_lab.py` exactly: real CLI bootstrap, real permit issuance with `--active-check active.cmdi.marker`, a real HTTP job submission claimed by a real worker, the real `ScanJobExecutor`, against a fixture reusing the identical `subprocess.run(shell=True)` mechanism the Slice 18 real-network test already proved works. The persisted report's finding carries exactly `CWE-78` and a `rule_id` starting with `active.cmdi.marker`.

## Live-target investigation

Done (Slice 20). Investigated against the pinned Juice Shop lab container (v20.1.1) by reading its actual server source inside the running container (`docker exec ... node -e`), not by probing blindly: an exhaustive search of every built server-side `.js` file for `child_process`, `execSync`, `spawn(`, or a bare `exec(` call found exactly one match, inside `lib/codingChallenges.js`, and that match is `RegExp.prototype.exec()` (a regex call, matched only because the search pattern's `exec(` substring also matches `.exec(`), not process execution. No other match exists anywhere in the codebase.

This is a definitive negative, not merely "no vulnerable endpoint found": the underlying mechanism this technique requires (passing user-controlled input to a system shell) does not exist anywhere in this application's server-side code. Juice Shop's own actual code-execution challenges (`b2bOrder.js`'s `node:vm` sandbox, gated behind `notevil`) are a different vulnerability class (VM sandbox escape, categorized "Insecure Deserialization" in Juice Shop's own challenge catalog), not OS command injection via shell metacharacters.

## Regression

`tests/unit/test_command_injection_detector.py`: 13/13 pass. `tests/unit/test_finding_fingerprint_determinism.py`: 12/12 pass (10 pre-existing + 2 new, including this detector's own). `tests/unit/test_active_detector_registry.py`: 3/3 pass unchanged. `tests/integration/test_command_injection_detector_live.py` (Slice 18): 4/4 pass with `WEBGUARD_RUN_INTEGRATION=1`; skips cleanly without it. Full `tests/unit` discover run clean, no regressions in any pre-existing detector's own test file.

**Slice 19 addendum:** `tests/integration/test_command_injection_checks_e2e_lab.py`: 1/1 pass with `WEBGUARD_RUN_INTEGRATION=1` (ran twice to rule out flakiness, identical both times); skips cleanly without it. Re-ran the full `tests/unit` suite (2031/2031 pass), the full `tests/integration` suite (312/312 pass, 243 skipped), and the full security-gates script (secret scan, ruff, dependency audit) at the same time as the other four Slice 19 additions; see `docs/CWE_COVERAGE.md`'s own Slice 19 section for the combined run.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** OS command injection detector (CWE-78), independently permit-gated (`active.cmdi.marker`), registered, candidate-discovery-integrated, evidence-sanitized.

**Tested:** classification logic including the reflection-vs-execution distinction found and fixed this slice, marker uniqueness, same-origin/budget/redirect/connection-failure/cancellation/hook safety boundaries, evidence sanitization, fingerprint determinism. All against a fake connection.

**Proven:** the reflection-vs-execution distinction is real and tested, not assumed, now against a real shell as well as a mocked one; the classification logic correctly fires against a real, genuinely vulnerable local server that actually executes the injected command, and correctly abstains against both a real properly-fixed route and a real reflection-only route carrying the marker text. As of Slice 19, also proven to survive the full, real CLI → HTTP API → worker → executor → report pipeline unmodified.

**Not Proven:** that this detector correctly fires against a real, genuinely vulnerable HTTP server beyond this project's own fixture; that it correctly cannot be triggered by a permit that only authorizes a different check. As of Slice 20, it is now known that the one live target investigated (Juice Shop) has no shell-execution surface at all, source-confirmed, so no claim about detectability there is possible in either direction.

**Remaining risks:**
- Detection is limited to the single `;`-plus-`#` POSIX separator; a target vulnerable only through `|`, `&&`, backticks, `$()`, Windows chaining, or requiring a quote-breaking prefix produces a false negative.
- Cross-detector authorization independence for this specific detector is inferred, not independently reconfirmed.

**Next steps:** none specific to live-target investigation; a genuinely shell-backed target would need to be found or built separately to ever confirm this detector's real-world reach, and given its CRITICAL severity and the fact that it demonstrates actual code execution rather than only data disclosure, any such target should stay a fully controlled, disposable one.
