# ADR 0013: Safe Same-Origin Crawler Foundation

- Status: Accepted
- Date: 2026-08-03

## Context

OpenHuntX WebGuard currently performs one bounded request and applies the
registered passive analyser pipeline to that response. A useful web
assessment eventually needs to discover additional pages without weakening
the existing scope, DNS-pinning, response-size, retry, or redirect controls.

Crawling introduces new risks:

- leaving the authorised origin;
- following logout, deletion, checkout, payment, or other state-changing
  navigation;
- query-string explosion and accidental retention of tokens;
- unbounded page, depth, and link growth;
- JavaScript execution or form submission;
- redirect-based scope escape;
- storing response bodies or sensitive cookie values;
- losing request-attempt ownership when several pages are fetched.

The current shared `ScanResult` contract is intentionally single-target and
its coverage model is check-wide rather than page-aware. Aggregating multiple
pages directly into that contract would make page-level coverage and attempt
ownership ambiguous.

## Decision

Add a scanner-level same-origin crawler foundation with these public types:

- `CrawlPolicy`;
- `CrawlQueryMode`;
- `CrawlPageOutcome`;
- `CrawlPageRecord`;
- `CrawlSkipReason`;
- `CrawlSkipSummary`;
- `CrawlExecution`;
- `crawl_same_origin`.

The crawler does not yet replace or change the `webguard scan` command.
Page-aware persisted results and CLI integration will be introduced only
after a dedicated crawl-result contract exists.

### Origin and network integrity

Every discovered URL must retain the root target's exact:

- scheme;
- canonical hostname;
- effective port.

The crawler constructs each page target with the root target's already
approved address set. It does not perform a new unreviewed DNS resolution and
therefore retains the existing pinned-address model.

Automatic redirects remain blocked by `fetch_once`.

### Navigation sources

Only HTML anchor `href` attributes are considered.

The crawler deliberately ignores:

- forms and form actions;
- scripts;
- images;
- stylesheets;
- iframes;
- JavaScript navigation;
- client-side SPA routes;
- API discovery;
- sitemap or robots fetching.

No form is submitted and no active payload is sent.

### Content types

Links are extracted only from bounded responses whose canonical media type is:

- `text/html`;
- `application/xhtml+xml`.

Missing, ambiguous, malformed, or other content types are not parsed for
navigation.

### Limits

Defaults and hard maximums are:

| Control | Default | Hard maximum |
|---|---:|---:|
| Pages attempted | 10 | 50 |
| Crawl depth | 1 | 3 |
| Anchor links retained per page | 100 | 500 |
| Delay between page requests | 0.1 seconds | 5 seconds |
| Canonical URL length | 2048 | 2048 |

The queue is breadth-first and candidates are ordered deterministically.

### Query strings and fragments

Fragments are never requested.

The default query mode is `drop`. Query values are removed before a URL is
queued, which reduces crawl explosion and prevents accidental persistence of
tokens or personal data.

The alternative mode is `reject`, which excludes every discovered URL that
contains a query string. Query preservation is intentionally unsupported.

### Destructive paths

A conservative default set of path segments is blocked, including logout,
account deletion, destruction, unsubscribe, checkout, payment, purchase, and
order-confirmation actions.

Checks are also applied after percent-decoding the path so simple encoding
does not bypass the denylist.

### Retry and pacing

Each page uses the existing:

- `FetchPolicy`;
- `RetryPolicy`;
- reviewed error taxonomy;
- `SafeRequestError` handling.

Only taxonomy-approved transient request failures may be retried.

A failed child page does not stop other already queued sibling pages. A failed
root is returned as a one-page failed crawl execution.

### Audit and data retention

Each page has a `CrawlPageRecord` containing:

- canonical same-origin URL;
- depth and parent URL;
- success or failure outcome;
- content type;
- connected address and HTTP status;
- local request-attempt history;
- final controlled error metadata;
- bounded link-discovery counts.

Attempt numbering restarts at one for each page, so request ownership remains
unambiguous.

Response bodies are available only during bounded link extraction and an
optional synchronous `on_page` callback. They are not retained in
`CrawlExecution`.

Skipped external, malformed, destructive, or unsupported links are counted
by reason. Their raw URLs are not retained.

## Consequences

### Positive

- Same-origin crawling can be developed without weakening commercial scope
  enforcement.
- Crawl growth is bounded and deterministic.
- DNS-pinned addresses are reused for every discovered page.
- Query values and external URLs are not retained.
- Destructive navigation, forms, scripts, and active behavior are excluded.
- Per-page attempts remain attributable.
- The callback provides a safe integration point for future passive analysis.

### Negative

- Single-page `ScanResult` reports do not yet contain crawl executions.
- The public CLI does not yet expose crawl options.
- JavaScript-heavy applications such as OWASP Juice Shop may expose few or no
  additional anchor-discoverable pages.
- A segment denylist can conservatively skip harmless routes.
- Robots, sitemaps, authenticated navigation, APIs, and browser rendering are
  outside this milestone.

## Next step

Introduce a versioned page-aware crawl-result contract, strict loader, and CLI
integration. That contract will contain one validated passive page result per
crawled URL instead of weakening the semantics of the existing single-page
`ScanResult`.
