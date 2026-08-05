# ADR 0017: Bounded Passive HTML Security Analysis

- **Status:** Accepted
- **Date:** 2026-08-05
- **Milestone:** 1.21

## Context

OpenHuntX WebGuard already performs bounded passive analysis of response
headers, cookies, CORS policy, and information-disclosure headers. The
same-origin crawler also makes each already-fetched response available to the
passive analyser pipeline without issuing a second request.

The scanner needs page-content checks before its first controlled owned-site
pilot. HTML analysis introduces additional risks that are not present in
header-only analysis:

- HTML can be malformed or intentionally adversarial.
- A bounded HTTP response can still contain a very large number of elements,
  references, comments, or text fragments.
- Form fields, comments, stack traces, URLs, and inline content may contain
  credentials or personal data.
- Executing JavaScript, submitting forms, following refresh instructions, or
  fetching referenced resources would change a passive scan into active
  behaviour.
- Findings must remain page-owned, deterministic, and compatible with the
  existing single-page and crawl report contracts.

## Decision

WebGuard will add one registered passive analyser with analyser ID `html`,
finding namespace `web.html`, and nine owned check families:

1. `web.html.password_transport`
2. `web.html.password_method`
3. `web.html.form_action`
4. `web.html.insecure_subresource`
5. `web.html.mixed_active_content`
6. `web.html.meta_refresh`
7. `web.html.directory_listing`
8. `web.html.debug_exposure`
9. `web.html.sensitive_comment`

The analyser uses Python's standard-library `HTMLParser`. No third-party HTML
or browser runtime dependency is introduced.

### Passive-only behaviour

The analyser:

- consumes only the response already returned by the safe HTTP client;
- does not send another request;
- does not execute JavaScript;
- does not submit forms;
- does not follow form actions, resource references, or meta refreshes;
- does not fetch scripts, stylesheets, frames, objects, or embedded content;
- does not infer client-side routes; and
- does not persist the response body.

### Bounded parsing

The following hard limits apply to each response:

- 1,048,576 body bytes;
- 20,000 HTML elements;
- 256 forms;
- 4,096 resource references;
- 128 meta-refresh elements;
- 512 comments;
- 65,536 comment characters; and
- 262,144 visible-text characters.

Exceeding a limit raises a controlled `HtmlAnalysisError`. The analyser
pipeline records `analysis.html`, marks every HTML check as skipped, preserves
findings from other analysers, and returns `completed_with_errors`.

### HTML eligibility

The analyser processes `text/html` and `application/xhtml+xml`. When the
Content-Type header is absent, it may recognise a document only from a small,
bounded set of leading HTML markers. A response explicitly identified as a
non-HTML media type is not parsed.

### Data minimisation

The parser retains only temporary structural facts required for evaluation.
Findings never retain:

- form field names or values;
- password values;
- complete form-action destinations;
- complete resource URLs;
- comment text;
- candidate credentials or tokens;
- stack-trace text;
- file names from directory listings; or
- response bodies.

Evidence records only safe categories, counts, element kinds, and whether a
relationship was same-origin, cross-origin, HTTP, or HTTPS.

### Detection confidence

High-impact deterministic conditions such as a password form on HTTP, a
password form using GET, or an HTTP script on an HTTPS page are reported with
confirmed confidence.

Heuristic conditions are deliberately narrower:

- directory listings require a directory-index title or a combination of
  recognised listing markers;
- debug exposure requires a high-confidence framework or stack-trace
  signature; and
- sensitive comments report marker categories rather than assuming that a
  live secret was exposed.

### Compatibility

The existing `run_passive_header_scan` entry point and `passive-http-headers`
scan type are retained for schema and CLI compatibility in the 0.1 series.
The analyser registry grows from four analysers and 24 checks to five
analysers and 33 checks.

For an HTTP HTML page, HSTS remains the only pre-skipped check, producing
32 executed checks and 96.97 percent check completion. HTTPS HTML pages can
execute all 33 checks.

The crawl orchestrator requires no second-fetch or report-schema change. It
already passes each page response through the default registered analyser
pipeline and persists only validated findings and audit metadata.

## Consequences

### Positive

- WebGuard can identify important page-level issues before active scanning is
  introduced.
- The same implementation serves both single-page and crawl scans.
- No new runtime dependency or browser engine is required.
- Findings preserve exact page ownership and deterministic fingerprints.
- Sensitive response material remains outside reports and checkpoints.
- Controlled parser limits prevent one page from consuming unbounded memory.

### Negative

- JavaScript-rendered forms and routes are not visible.
- HTML heuristics can still require human review.
- A body larger than the HTML analysis limit causes all HTML checks for that
  page to be skipped rather than partially analysed.
- The legacy scan type name is broader than its original header-only meaning.

## Rejected alternatives

### Execute a headless browser

Rejected for this milestone because browser execution adds JavaScript side
effects, network requests, significantly larger resource requirements, and a
new attack surface.

### Parse only with regular expressions

Rejected because forms, attributes, comments, and malformed nesting require a
stateful parser. Regular expressions would also make bounded structural
accounting more difficult.

### Store response bodies as report evidence

Rejected because bodies may contain credentials, tokens, personal data, and
proprietary content. The current report and checkpoint contracts intentionally
store only non-secret evidence summaries.

### Silently truncate oversized HTML

Rejected because partial markup can produce misleading conclusions. A
controlled failure with exact skipped-check accounting is more defensible.

## Verification

Milestone verification includes:

- dedicated unit tests for all nine check families;
- false-positive controls for non-HTML responses, ordinary error pages,
  relative resources, same-origin actions, and ordinary comments;
- parser limit and validated-target mismatch tests;
- evidence-redaction tests;
- pipeline tests proving no second request is made;
- controlled analyser-failure isolation tests;
- single-page and crawl coverage updates; and
- an opt-in OWASP Juice Shop integration test confirming HTML check execution
  without response-body persistence.
