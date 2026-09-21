# Active Detection, Slice 16: CSRF Token-Presence Heuristic (CWE-352)

## Status

Partial, by design, permanently. Unlike every prior post-freeze slice, this is not an active detector heading toward eventual real-network and end-to-end verification; it is a passive, heuristic-only check inside `html_analyzer.py`, and it will remain PARTIAL in `docs/CWE_COVERAGE.md`'s own status vocabulary regardless of how much more testing is added, because the underlying signal (a recognized field name in static HTML) can never be upgraded into proof that a form is protected or unprotected. Added at the user's continued request to keep expanding CWE coverage; the shape of the deliverable changed from every prior "keep going" request in this session because CSRF itself does not fit the active-detector mold the other five did.

## Why this is passive, not active

Every active detector added in Slices 12 through 15 (path traversal, command injection, XXE, open redirect, LDAP injection) sends a diagnostic payload engineered to be non-destructive regardless of whether the target turns out to be vulnerable: a syntax-breaking character that produces a parse error either way, a callback to WebGuard's own infrastructure that the target's own outbound request targets, a redirect the transport layer deliberately never follows. None of them can, even in the worst case, cause the underlying action to actually happen.

CSRF does not have an equivalent payload shape. Proving a state-changing endpoint accepts a request without valid CSRF validation requires submitting a well-formed state-changing request that is missing only the token, and observing whether the action completes. If the target is genuinely vulnerable, that observation *is* the action completing for real, with no way to make it otherwise: a password gets changed, an item gets purchased, a resource gets deleted, or whatever the endpoint does. `docs/ROADMAP.md` states plainly: "Active exploitation, denial-of-service testing, password attacks, persistence, destructive testing, or unverified third-party testing are not part of the current initial release scope." A real active CSRF probe is destructive testing by construction, not an edge case of it.

This was checked against the actual code, not assumed. `attack_surface.py`'s `_classify_safety` function classifies a POST candidate as `POTENTIALLY_STATE_CHANGING` (permanently excluded from every active detector's candidate set) only when its path or field names match one of a fixed keyword list (`delete`, `purchase`, `payment`, `logout`, `admin`, etc.). A great many genuinely state-changing forms, an "update profile" form, an "add comment" form, a "change email" form that never mentions any of those keywords, are classified `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION` instead and are already reachable by every existing mutation-based active detector today. So the reason CSRF cannot be an active detector here is not that discovery blocks it; it is that the technique itself, regardless of which endpoints happen to be reachable, cannot stay non-destructive the way every other active detector's payload can.

## What was built

### Passive check (`workers/scanner/src/webguard_scanner/html_analyzer.py`)

Extends the module's existing bounded HTML parser (`_BoundedHtmlParser`, already used for the password-transport and cross-origin-form-action checks) rather than adding new discovery or transport code. `_FormRecord` gained one field, `has_recognized_csrf_token: bool`, set while parsing whenever a `type="hidden"` `<input>` inside the currently-open form has both a name matching a recognized anti-CSRF convention and a real (non-empty, non-template-placeholder) value. After parsing, every form whose method is POST and whose `has_recognized_csrf_token` is still `False` produces one MEDIUM-severity, LOW-confidence finding (`web.html.csrf_token.absent`, CWE-352).

### Pre-implementation verification

Before any code was written, the drafted token-naming-convention list and matching approach were reviewed by two independent lenses: one researching real, current default CSRF field names across mainstream frameworks using live web search (not relying on possibly-outdated memory), the other reading the actual `_BoundedHtmlParser` code and this project's own `Confidence`/PARTIAL conventions before hunting for false positives.

**Confirmed accurate and kept** (matched via a substring regex, safe because none of these strings occur as an ordinary English word or unrelated abbreviation): Django's `csrfmiddlewaretoken`, Rails' `authenticity_token`, ASP.NET's `__RequestVerificationToken`, Spring Security's `_csrf`, Flask-WTF's `csrf_token`, Play's `csrfToken`, CodeIgniter's `csrf_test_name`, CakePHP's `_csrfToken`, Yii2's `_csrf`, Quarkus's `csrf-token`, and Phoenix's `_csrf_token` are all real, currently-accurate defaults, confirmed against source/docs, and all contain `csrf` or `xsrf` as a substring.

**Confirmed accurate and kept, exact-matched, never substring-matched**: Laravel's and Symfony's bare `_token`. The exact-match (not substring) choice is deliberate: a substring match on `_token` would also match a completely unrelated one-time-link field like `reset_token` or `api_token`, both real, common field names for password-reset codes or API-key management, neither of which is a CSRF token.

**Added after this review, closing real gaps both lenses independently confirmed**: WordPress's `_wpnonce` (the single highest-impact addition given WordPress's roughly 40% share of all websites), Drupal's `form_token`, Magento's `form_key`, and ThinkPHP's `__token__`. `form_token` is exact-matched, not substring-matched, for the identical `reset_token`/`api_token`-style collision reason as `_token`.

**Considered and deliberately excluded**: Apache Struts 2's own default field name, the bare word `token`. Both lenses independently, without prompting each other, identified the same concrete risk: a password-reset link, email-verification link, or webhook-setup form commonly carries an unrelated one-time link token in a field literally named `token`, and Struts 2 is legacy and shrinking. Adding it would trade real Struts 2 coverage for a confirmed, common false-suppression risk in the dangerous direction; it was left out.

**A real design gap the review caught before it shipped**: the original draft matched only on field *name*, never on the field's *value*. A stale CDN-cached page, a broken templating pipeline, or a static export can ship the exactly-right field name with an empty value or an unrendered template placeholder (`{{ csrf_token }}`, `<%= csrf_token %>`), which is not a live, session-bound secret. The shipped check requires the matched field's value to be non-empty and free of unresolved template syntax (`{{`, `{%`, `<%`, `${`) before treating a name match as evidence of protection; a name match with a placeholder or empty value still produces the finding.

**Confidence/severity sanity-checked, not just asserted**: one reviewer noted this MEDIUM/LOW pairing (matching this file's own precedent for a heuristic marker check, `web.html.sensitive_comment.secret_marker`, which pairs MEDIUM severity with MEDIUM confidence for a *presence*-based signal) is, if anything, still generous: WordPress's and Drupal's own security guidance actively recommends developers rename the token field away from the platform default specifically so neither an attacker nor a scanner can rely on it, meaning a "no recognized name" result on either platform can mean "correctly hardened per the platform's own best-practice advice," not "vulnerable." LOW confidence, one tier below that precedent, is the deliberately more cautious choice for an *absence*-based signal, which both reviewers agreed is inherently weaker evidence than a presence-based one.

## False-positive and false-negative controls

Covered by 12 new tests in `tests/unit/test_html_analyzer.py`:

| Scenario | Mechanism | Verified |
|---|---|---|
| POST form, no recognized token field | flagged (positive control) | unit |
| GET form, no recognized token field | never checked at all | unit |
| Recognized substring name (`csrfmiddlewaretoken`) with a real value | suppresses the finding | unit |
| Recognized exact name (`_token`) with a real value | suppresses the finding | unit |
| WordPress's `_wpnonce` with a real value | suppresses the finding | unit |
| `reset_token`/`api_token`/`invite_token` (the exact-match collision case) | still flagged, not mistaken for a CSRF token | unit |
| Recognized name, empty value | still flagged | unit |
| Recognized name, unrendered template placeholder value | still flagged | unit |
| Recognized name on a *visible* (non-hidden) input | still flagged, only `type="hidden"` counts | unit |
| Multiple forms on one page | classified independently | unit |
| Evidence sanitization | field names and values never retained in the finding text | unit |

Three existing tests were affected by adding this check to a file whose form-parsing every other check already shares: `test_check_registry_is_canonical`'s expected `HTML_CHECKS` count moved from 9 to 10, and `test_https_post_password_form_is_not_reported` (whose actual scope is proving the password-transport/method checks stay silent on an already-secure form, not proving anything about CSRF) now includes a token field so its original intent still holds without incidentally exercising the new check. Both are expected, correct consequences of the new check firing on forms that genuinely have no recognized token field, not regressions.

## Inherited limitations, named directly

- **SameSite-cookie-based protection** is invisible to this check; it is already covered separately by `cookie_analyzer.py` under CWE-1275, and this check does not attempt to cross-reference that analyzer's results.
- **Origin/Referer header validation** and **custom-header-based protection** (a value set by JavaScript before an AJAX submission) are server-side or client-script behaviors, never visible to static HTML inspection.
- **SPA double-submit patterns** (a cookie plus a JS-set request header, e.g. Angular's `XSRF-TOKEN`/`X-XSRF-TOKEN` convention) and **`<meta>`-tag-plus-fetch patterns** (a token in a `<meta name="csrf-token">` tag read by JS and sent as a header on a `fetch`/`XHR` call, with no traditional form submission at all) both place the token entirely outside any `<form>` element this parser tracks.
- **Deliberately renamed token fields**: WordPress's and Drupal's own documentation recommends renaming the token field away from the platform default specifically to defeat name-based recognition; a miss on either platform is at least as likely to mean "correctly hardened" as "vulnerable."
- **Joomla's rotating field-name scheme** (`JHtml::_('form.token')` renders a hidden input whose *name*, not just its value, is the rotating per-request secret) cannot be recognized by any fixed name list in principle, since the field never has a fixed name to list.
- **Symfony's namespaced Form-component field** (`<form_name>[_token]` rather than the bare `_token` this check matches) is a real, accepted miss: widening the match to catch it would reopen the exact `reset_token`/`api_token` collision the exact-match choice exists to avoid.
- **Nested/malformed `<form>` markup** (for example a third-party widget's own unclosed `<form>` snippet appearing inside the page's real form) can, in principle, cause `_BoundedHtmlParser`'s existing `_form_stack` attribution to assign a later field to the wrong form record. This is a pre-existing property of the shared parser (it would affect the `has_password` check identically), not something this check introduces, and is not fixed here; a separate, dedicated hardening pass on the parser's own form-nesting behavior is a better-scoped follow-up than folding it into this change.
- **A custom or in-house field naming convention this list has never seen** produces a false "absent" reading no matter how far the list grows; this is the inherent ceiling of any name-based allowlist, not a bug in this one.

## Regression

`tests/unit/test_html_analyzer.py`: 51/51 pass (39 pre-existing, 2 adjusted for the new check's presence, 12 new for the check itself). Full `tests/unit` discover run and `tests/contract` suite: clean, no regressions in any other analyzer's own tests. `ruff check --select S --ignore S101` against `packages/contracts/python/src`, `workers/scanner/src`, `apps/api/src`: clean. `scripts/scan-secrets.py`: clean.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** a passive anti-CSRF-token-presence heuristic inside `html_analyzer.py` (CWE-352), running as part of every existing passive HTML scan with no new permit gating (passive checks are not permit-gated in this project).

**Tested:** every naming-convention match, the value-placeholder guard, the collision-avoidance the exact-match choice exists for, per-form independence, and evidence sanitization.

**Proven:** the 9 recognized naming conventions are real and current, fact-checked against live sources rather than assumed; the exact-match-versus-substring split correctly avoids the specific collision (`reset_token`/`api_token`) it was designed to avoid, verified directly by test.

**Not Proven, and not provable by this technique:** that a flagged form is actually exploitable (it may be protected by a mechanism this check cannot see); that an unflagged form is actually protected (a name match only proves a plausible-looking field is present with a real-looking value, never that the server actually validates it against the session).

**Remaining risks:**
- This check's positive signal (a finding) is only ever a heuristic prompt for human review, never a confirmed vulnerability, and its absence-of-finding is only ever a heuristic "looks fine," never confirmed protection. Both directions are stated plainly in the finding's own description text, not just in this doc.
- The naming-convention list, however carefully surveyed, cannot be exhaustive; a custom or unrecognized convention always produces a false "absent" reading.
- The shared `_BoundedHtmlParser`'s nested/malformed-form attribution limitation (noted above) is inherited, not fixed, and could in principle affect this check's accuracy on pages with malformed third-party widget markup.

**Next steps:** none planned specifically for this check; it is complete for what a passive, name-based heuristic can responsibly claim. If genuine active CSRF verification is ever wanted, it would need an explicit, separately-authorized, operator-acknowledged "this may cause a real state change" consent flow, a materially different feature from anything this project's active-detection framework does today, not an extension of it.
