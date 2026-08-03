# ADR 0014: Page-Aware Crawl Scan Contract and CLI Integration

- Status: Accepted
- Date: 2026-08-03

## Context

ADR 0013 introduced a bounded same-origin crawler that records page request
outcomes without persisting response bodies. It intentionally did not place
multiple pages into the existing `ScanResult` contract.

`ScanResult` has single-target semantics:

- one target URL;
- one check plan and coverage object;
- one finding collection owned by that target;
- one request-attempt sequence.

Reusing it for a crawl would make it unclear which URL owned a finding, error,
skipped check, HTTP status, or request attempt. It would also make a failed
child page indistinguishable from a failed root request.

The crawler already exposes a synchronous `on_page` callback while the bounded
response is available. This permits passive analysis without making a second
request or retaining the response body.

## Decision

### Separate crawl report contract

Add a dedicated shared contract with:

- `CrawlScanPolicy`;
- `CrawlLinkSkip`;
- `CrawlPageScanResult`;
- `CrawlScanCoverage`;
- `CrawlScanResult`.

A crawl report uses:

- `report_type: "crawl_scan"`;
- `schema_version: "1.0"`;
- `scan_type: "passive-http-crawl"`.

The existing single-page `ScanResult` remains schema `1.1` and is not changed.

### Policy snapshot

Every crawl report stores the effective bounded policy:

- maximum pages;
- maximum depth;
- maximum links considered per page;
- maximum canonical URL length;
- minimum delay between page requests;
- query handling mode;
- allowed discovery content types;
- blocked path segments.

This makes the report independently auditable and prevents hidden runtime
configuration from changing its interpretation.

### Page ownership

Each attempted URL has one `CrawlPageScanResult` containing:

- canonical URL, depth, and parent URL;
- page status;
- page-local check coverage;
- normalized findings and controlled errors;
- content type, connected address, and HTTP status when successful;
- discovery and queue counts;
- page-local request-attempt history.

The contract requires:

- the first page to be the depth-zero root;
- no second depth-zero page;
- exact same origin for every page;
- each non-root parent to appear earlier at the preceding depth;
- non-decreasing breadth-first depth order;
- non-overlapping page request windows;
- the same planned check set for every page;
- every finding to match the page origin, path, and GET method;
- unique page URLs and finding fingerprints;
- page count and depth to remain within the stored policy.

A successful page must account for every planned check as executed or skipped.
A failed request page retains its request error and may leave non-applicable
analysis checks unexecuted.

### Aggregate coverage

`CrawlScanCoverage` derives, rather than accepts, aggregate values from the
page records:

- pages attempted, succeeded, partially completed, and failed;
- requests attempted and succeeded;
- check executions planned, executed, and skipped;
- unaccounted check executions;
- aggregate completion percentage.

Check coverage is counted per page. For example, 24 checks across two pages
means 48 planned check executions.

### Lifecycle status

The overall status is derived from page outcomes:

- a failed root request produces `failed` and no child pages;
- a successful root with any failed child or controlled page-analysis error
  produces `completed_with_errors`;
- all pages completing without controlled errors produces `completed`.

Unexpected analyser exceptions and analyser output-contract violations still
surface and do not become valid reports.

### Request-attempt audit

Request attempts remain page-local and restart at one for each page. The
serialized report also includes a derived combined audit projection with:

- global sequence number;
- page URL;
- page-local attempt number;
- the existing bounded, non-secret attempt fields.

The strict loader recomputes this projection and rejects tampering.

### Analysis without duplicate requests

`run_passive_crawl_scan` passes each already-fetched successful response
through the registered passive analyser pipeline inside the crawler callback.
It does not fetch the page again.

Controlled analyser failures are isolated to the affected page. Findings from
successful analysers and other pages are retained.

Response bodies remain transient and are not included in the page or crawl
report contract.

### Strict loading and compatibility

Add strict crawl report loaders and generic dispatch helpers:

- `load_crawl_scan_result*` loads only crawl reports;
- `load_scan_result*` continues to load existing single-page schemas;
- `load_webguard_report*` dispatches between both report families.

The crawl loader rejects:

- unsupported schema or report types;
- missing or unexpected fields;
- duplicate JSON keys;
- incorrect count and derived coverage values;
- incorrect page ownership or ordering;
- altered combined request-attempt projections;
- non-canonical values or ordering.

Existing schema `1.0` single-page migration to schema `1.1` remains unchanged.

### CLI integration

Add `webguard scan --crawl` with bounded options:

- `--crawl-max-pages`;
- `--crawl-max-depth`;
- `--crawl-max-links`;
- `--crawl-delay`;
- `--crawl-query-mode {drop,reject}`.

Crawl-specific options are rejected unless `--crawl` is present. Existing
commercial and explicit laboratory scope validation is unchanged.

`webguard report validate` and `webguard report inspect` accept both report
families. The JSON inspection path emits the canonical stored contract.

The CLI returns success only for `completed`. `completed_with_errors` and
`failed` remain non-zero so automation can detect incomplete assessment.

## Consequences

### Positive

- Page findings, errors, coverage, and attempts have explicit ownership.
- A failed child page does not discard successful page results.
- Aggregate coverage counts real page/check executions rather than collapsing
  them into one check set.
- The stored policy makes crawl limits reviewable after execution.
- Passive analysis reuses the crawler response and adds no duplicate request.
- Existing single-page reports and their migration path remain compatible.
- Generic report commands can validate and inspect both report families.
- Strict derived projections make report tampering detectable.

### Negative

- Consumers must support two top-level report families.
- Crawl reports are larger because they preserve page-level evidence and audit
  records.
- A failed child request lowers aggregate completion and produces a non-zero
  CLI result.
- The crawler remains HTML-anchor based and does not discover JavaScript SPA
  routes, forms, APIs, robots files, or sitemaps.
- Authentication and active testing remain outside scope.

## Security boundary

This decision does not broaden target authorization. The crawler still uses
exact same-origin URLs, the root target's approved address set, blocked
redirects, bounded response limits, destructive-path exclusions, query-value
removal, and no form submission or active payloads.

Integration testing remains limited to the explicitly authorised local OWASP
Juice Shop environment.
