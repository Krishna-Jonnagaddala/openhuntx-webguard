# Scanner v1 False-Positive Review

## Status

An adversarial review of every active detector's classification logic, applying one standard throughout: **uncertain evidence must produce `INCONCLUSIVE` or no finding, never a vulnerability claim.** This document records, per detector, exactly which classification states exist, what evidence each one actually requires, and which specific false-positive scenario each guard was built to prevent, including two real false-positive bugs found and fixed during development (Slice 8). Both are kept here as a record of the discipline actually being applied, not just claimed.

## Reflected XSS (`active.xss.reflected`)

States: CONFIRMED, PROBABLE, INFORMATIONAL, NOT_VULNERABLE, ERROR.

- **CONFIRMED** requires the injected marker to appear in the response with both angle brackets unescaped.
- **PROBABLE** requires exactly one bracket unescaped (partial escaping): genuinely ambiguous evidence, deliberately not promoted to CONFIRMED.
- **INFORMATIONAL** (no CWE attached) covers full HTML-encoding of the marker. The marker round-tripped, but safely, so this is recorded as "reflection observed, escaped correctly," not a vulnerability.
- **NOT_VULNERABLE**: no reflection at all.
- **ERROR**: the probe request itself failed at the transport level, never silently treated as either a finding or a clean result.

Never conflated: a response that merely contains the marker text (fully escaped) never produces a CWE-79 finding. This is the exact "uncertain to no finding" discipline in practice.

## SQL injection (`active.sqli.error`)

States: CONFIRMED, PROBABLE, INCONCLUSIVE, NOT_VULNERABLE, ERROR.

- **CONFIRMED** requires a database-engine-attributable error signature present in the diagnostic response **and** a status-code change from the baseline.
- **PROBABLE**: the signature is present but the status code didn't change, weaker evidence that is still real, never CONFIRMED.
- **INCONCLUSIVE** (not NOT_VULNERABLE) covers every genuinely ambiguous case: a generic 500 with no database signature; an application-level validation error (400) with no signature; a plain apostrophe appearing in ordinary legitimate content ("It's a great day..."); the probe string reflected verbatim without any sign of interpretation; database-shaped text that appears in the baseline regardless of whether the probe was even sent; a response that changed for reasons unrelated to database evidence. Each of these is a real scenario this detector's own test suite deliberately constructs and asserts produces **no finding**.
- Deliberately conservative: no boolean-differential, time-based, UNION, or stacked-query technique exists. Each of those techniques trades false-positive resistance for detection breadth, and this project chose not to make that trade for v1.

## IDOR/BOLA (`active.authorization.idor`)

States: CONFIRMED, PROBABLE, INCONCLUSIVE, NOT_VULNERABLE, ERROR.

- **CONFIRMED** requires an *exact* SHA-256 content-fingerprint match between the cross-identity response and the victim's own baseline, not a generic 200, not a coincidental response-length match. A length-based fallback was tried during development, found to produce a real false positive (a 35-byte generic page coincidentally matching a 35-byte real baseline), and removed. That failure is kept here as a concrete record that this discipline was tested against a real bug, not merely asserted.
- **PROBABLE** is reachable only via an explicit, operator-configured marker string, never inferred automatically from any structural coincidence.
- **INCONCLUSIVE**, not NOT_VULNERABLE, whenever a baseline itself fails or returns non-200: a broken baseline means "we cannot establish ownership," not "access is denied as expected." This exact distinction was also a real bug found and fixed during development. The original classifier only checked `.succeeded` (transport-level success) and let a genuine HTTP 500 baseline fall through to NOT_VULNERABLE.
- Shared/public resources (`ResourceOwnership.SHARED`/`PUBLIC`) are permanently unreportable regardless of observed HTTP status, proven directly with a fixture resource both identities can legitimately access, asserting zero findings even though both receive 200.
- Discovered (not explicitly supplied) resources get an additional, structural false-positive control for free: a resource discovered identically by both identities (same endpoint, same identifier value, because it's genuinely the same shared object) is automatically excluded by the "distinct identifier values" eligibility rule. No separate shared/public classification signal was even needed for this case.

## SSRF (`active.ssrf.callback`)

States: CONFIRMED, PROBABLE, INCONCLUSIVE, NOT_VULNERABLE, ERROR.

- **CONFIRMED** requires a callback observation for the *exact* token this run issued, within the primary wait window.
- **PROBABLE**: the same exact-token observation, but only within a secondary grace window, never a different or approximate token.
- **NOT_VULNERABLE**: the probe succeeded and the full wait+grace window elapsed with nothing observed.
- **INCONCLUSIVE**: callback registration itself failed, or the wait was cancelled mid-flight. The detector explicitly declines to make either a positive or negative claim when it could not actually complete the test.
- **A target response containing, reflecting, mentioning, or validating the callback URL is never SSRF evidence by itself.** This is structurally impossible to violate, not merely policy: the classification function never inspects the probe's own response body at all, only whether a callback was independently observed. Proven directly against a reflect-only fixture route and against a response that merely mentions the callback service's domain in an unrelated context.

## Passive checks

Passive analyzers do not have a confirmation-level state machine: each check either fires on a structurally observable condition (a missing header, an insecure cookie flag, an expired certificate) or does not. False-positive risk here is lower by construction: these are checks against the scanner's *own* observation of the response, not inferences about server-side behavior. The one identified gap (`web.html.meta_refresh.*` carrying no CWE identifier) is a documentation completeness gap, not a false-positive risk. The finding itself remains real and unambiguous.

## Cross-cutting discipline

Every active detector shares three properties that structurally suppress false positives beyond their individual classification logic:

1. No detector's CONFIRMED path depends on response length, generic status codes, or timing alone. Every one requires either exact content correlation (XSS marker, IDOR fingerprint), an independently verifiable out-of-band signal (SSRF callback), or a specific, attributable error signature (SQLi).
2. Ambiguous evidence degrades to INCONCLUSIVE/PROBABLE, never CONFIRMED, verified per detector above and directly enforced by each detector's own test suite asserting zero findings for every ambiguous fixture scenario it constructs.
3. A probe-level transport failure is always ERROR, never silently treated as either a finding or a clean pass, consistent across all four detectors.

## What this review did not find

No detector was found to promote uncertain evidence to a vulnerability claim. The two real false-positive bugs on record (IDOR's length-based fallback, IDOR's baseline-failure misclassification) were both caught by this project's own test-writing discipline before shipping, not discovered later in production. Both are now permanent regression tests (`test_generic_200_response_is_not_a_finding`, `test_failed_baseline_is_inconclusive_not_vulnerable`).
