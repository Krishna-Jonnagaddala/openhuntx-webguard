# ADR 0015: Crawl Cancellation, Execution Budgets, and Termination Reasons

- **Status:** Accepted
- **Date:** 2026-08-03
- **Decision owners:** OpenHuntX WebGuard engineering
- **Scope:** Authorised passive same-origin crawl scans

## Context

Milestone 1.18 introduced page-aware crawl reports and CLI integration. The
crawler remained bounded by page count, depth, links per page, and request
retry policy, but it had no crawl-wide execution deadline, no crawl-wide
request-attempt budget, and no graceful way to stop between requests.

For a commercial security assurance product, a crawl must remain predictable
when a target is slow, unstable, unexpectedly large, or manually interrupted.
A saved partial report must also explain why no further requests were started.

The existing crawl report schema was version 1.0. Adding policy budgets,
termination metadata, pending-page accounting, and cancellation status changes
the persisted contract and therefore requires a schema revision.

## Decision

### 1. Add two crawl-wide execution budgets

`CrawlPolicy` now includes:

- `maximum_execution_seconds`
- `maximum_request_attempts`

The defaults are 300 seconds and 150 total attempts. The enforced hard limits
are 3,600 seconds and 150 attempts.

The attempt budget counts every actual HTTP attempt, including retry attempts.
It is independent of the page limit and the per-page retry policy.

### 2. Use a monotonic soft deadline

The execution deadline uses `time.monotonic()` so wall-clock adjustments cannot
extend or shorten a running crawl.

The deadline is checked before every new request and before crawl delays or
retry backoff. WebGuard does not forcibly terminate an in-flight HTTP request.
The existing per-request timeout remains responsible for bounding that request.
After the request returns, no new request is started when the deadline has
expired.

A delay or retry backoff is not started when the full delay cannot fit inside
the remaining execution budget.

### 3. Add cooperative cancellation

`CrawlCancellationToken` is a thread-safe cancellation signal. The crawler
checks it before each new request and after bounded waits.

The CLI converts `SIGINT` into a cancellation request during crawl mode. This
allows the current request or analysis callback to finish and produces a
contract-valid partial report. Single-page scan behaviour is unchanged.

### 4. Persist an explicit termination reason

Every crawl report contains a `termination` object with:

- `reason`
- `pages_pending`

Supported reasons are:

- `completed`
- `page_limit_reached`
- `root_request_failed`
- `time_limit_reached`
- `request_attempt_limit_reached`
- `cancelled`

`pages_pending` counts already-queued same-origin pages that were not attempted
because cancellation or an execution budget stopped the crawl. Links excluded
before queueing continue to be represented by `skipped_links`.

### 5. Define status semantics

The overall crawl status is derived as follows:

- `cancelled` termination produces `ScanStatus.CANCELLED`.
- Time-limit or request-attempt-limit termination produces
  `ScanStatus.COMPLETED_WITH_ERRORS`.
- A normal root request failure produces `ScanStatus.FAILED`.
- Page-local request or controlled analysis failures produce
  `ScanStatus.COMPLETED_WITH_ERRORS`.
- Page-limit termination is an expected policy boundary and can remain
  `ScanStatus.COMPLETED`.
- A fully exhausted queue produces `ScanStatus.COMPLETED`.

Abnormal termination produces a derived, non-retryable crawl-stage error.
Termination errors are not duplicated as mutable free-form report fields.

### 6. Preserve request audit truth

A failed request attempt is marked `retry_scheduled=true` only when WebGuard
actually intends to perform the retry after the backoff.

If cancellation or a budget prevents the retry, the final attempt remains
`retry_scheduled=false` with zero scheduled backoff. This prevents terminal
reports from claiming that a retry is still pending.

### 7. Revise the crawl report schema to 1.1

Crawl report schema 1.1 adds:

- policy execution and request-attempt budgets
- termination metadata
- aggregate `pages_pending` coverage

The strict loader accepts crawl schemas 1.0 and 1.1. A 1.0 report is migrated
in memory using the new bounded defaults, zero pending pages, and a derived
legacy termination reason. Input mappings are not mutated.

Single-page report schema 1.1 is unchanged.

### 8. Add CLI controls

Crawl mode adds:

- `--crawl-time-limit`
- `--crawl-request-budget`

These options are rejected unless `--crawl` is present. Existing scope,
same-origin, content-type, destructive-path, redirect, body-retention, and
authorisation controls remain unchanged.

## Security properties

- No request starts after cancellation is observed.
- No request starts after the request-attempt budget is exhausted.
- No request starts after the monotonic deadline is observed.
- Cancellation does not weaken target validation or same-origin enforcement.
- Partial reports retain completed page findings and request history.
- Response bodies and cookie values remain absent from crawl reports.
- Unexpected programming exceptions and analyser contract violations still
  surface instead of being converted into partial success.

## Compatibility

- Existing Python constructors remain compatible because the new policy fields
  use bounded defaults and termination defaults to `completed`.
- Saved crawl schema 1.0 reports load and normalize to schema 1.1.
- Existing single-page reports and commands remain unchanged.

## Alternatives considered

### Forcefully interrupt the active HTTP request

Rejected. It complicates socket cleanup and can corrupt request audit history.
The existing request timeout already bounds an in-flight request.

### Treat the page limit as an error

Rejected. The page limit is an intentional policy boundary rather than an
unexpected execution failure.

### Serialize a free-form termination error

Rejected. A reason enum and derived error keep reports deterministic and reduce
tampering surface.

### Implement resumable crawl state in this milestone

Deferred. Resume requires a signed or strictly validated queue snapshot,
visited-URL state, policy identity, and protection against stale target
resolution. It will be designed separately rather than combining it with
cancellation and budget semantics.

## Consequences

The crawl contract and loader are more complex, but every bounded stop is now
auditable. Operators can set predictable execution budgets, interrupt a crawl
without losing completed findings, and distinguish normal page-limit completion
from cancellation or exhausted resources.
