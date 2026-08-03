# ADR 0006: Bounded Retry Execution

- Status: Accepted
- Date: 2026-08-03

## Context

ADR 0005 introduced a reviewed taxonomy that identifies which controlled
request errors are safe to retry. The passive scanner still performed exactly
one request regardless of that classification.

A worker may need to recover from brief network failures, but unrestricted or
implicit retries would create operational and security risks:

- unexpected additional traffic to a customer target;
- long-running scans caused by excessive attempts or delays;
- retrying deterministic TLS, policy, protocol, or response-limit failures;
- inaccurate request accounting;
- hidden analysis defects.

## Decision

The scanner uses a dedicated immutable `RetryPolicy`.

Retries are disabled by default:

- `maximum_attempts` defaults to `1`;
- the initial request counts as an attempt;
- callers must explicitly set `maximum_attempts` above `1`.

The following hard limits apply:

- no more than three total request attempts;
- no more than five seconds for any single backoff delay;
- a backoff multiplier between `1.0` and `4.0`;
- all delay values must be finite and non-negative.

Backoff is exponential and capped:

`min(initial_delay * multiplier ** (failed_attempt - 1), maximum_delay)`

A retry occurs only when all conditions are true:

1. `fetch_once` raised a controlled `SafeRequestError`;
2. the request error taxonomy marks its code retryable;
3. the configured maximum attempt count has not been reached.

The scanner never retries:

- non-retryable request errors;
- unknown error codes;
- TLS, policy, target-integrity, protocol, redirect, response-format, or
  response-limit failures;
- `HeaderAnalysisError`;
- unexpected exceptions;
- a request after a response has been successfully analysed.

`ScanCoverage.requests_attempted` records every call to `fetch_once`.
`requests_succeeded` is `1` only when one bounded response was returned and is
`0` when every attempt failed. Only the final controlled request error is
stored in the failed `ScanResult`.

The laboratory command runner exposes `--max-attempts`. Its default remains
one, so merely upgrading WebGuard does not increase target traffic.

## Consequences

### Positive

- Brief taxonomy-approved network failures can be recovered safely.
- Request traffic and delay are strictly bounded.
- Default scan behaviour remains one request.
- Coverage accurately describes attempts and successful responses.
- Deterministic failures stop immediately.
- The final error remains available in the versioned result contract.

### Negative

- Earlier transient error details are not retained in the current contract.
- Backoff blocks the current worker thread.
- Retry configuration is intentionally narrow.
- A distributed scheduler may later need asynchronous delay handling.
