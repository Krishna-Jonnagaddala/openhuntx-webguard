# ADR 0007: Request Attempt Audit Trail

- Status: Accepted
- Date: 2026-08-03

## Context

ADR 0006 introduced bounded retry execution. `ScanCoverage` recorded only the
aggregate numbers of attempted and successful requests, while `ScanResult`
retained only the final controlled error.

That was sufficient for execution control but not for operational review. A
completed scan could report two attempts without explaining why the first
attempt failed, whether a retry was approved, or how long the scanner waited.
A failed scan could not show the sequence of transient failures that exhausted
the retry budget.

A commercial scanner needs a compact audit trail that is useful for support,
incident review, billing verification, and later asynchronous worker design,
without storing response bodies, request headers, credentials, or exception
text from every attempt.

## Decision

The shared scan contract adds two public types:

- `RequestAttemptOutcome`, with `succeeded` and `failed` values;
- `RequestAttempt`, representing one bounded HTTP attempt.

Each attempt records only:

- its one-based attempt number;
- timezone-aware start and completion timestamps;
- computed duration in milliseconds;
- outcome;
- connected IP address and HTTP status when available;
- controlled error code and retryability for failures;
- whether another attempt was scheduled;
- the bounded backoff delay before that retry.

The audit record deliberately excludes URLs beyond the existing canonical scan
target, request and response headers, bodies, cookies, credentials, exception
messages, and stack traces.

`ScanResult` adds an optional `request_attempts` tuple. The schema version moves
from `1.0` to `1.1` because this is an additive serialized field. Existing code
that constructs `ScanResult` without attempt history remains valid; an empty
history is permitted even when aggregate coverage counters are non-zero.

When history is supplied, the contract validates that:

- attempt numbers are contiguous and begin at one;
- history length matches `coverage.requests_attempted`;
- successful outcomes match `coverage.requests_succeeded`;
- attempt timestamps remain inside the scan lifecycle;
- a terminal result does not end with a scheduled retry;
- attempt addresses and statuses match the aggregate result metadata;
- successful attempts contain response metadata and no error metadata;
- failed attempts contain a controlled error code and retryability decision;
- non-retryable failures cannot schedule retries;
- backoff is finite, non-negative, and zero when no retry is scheduled.

The passive scanner creates an attempt record around every call to
`fetch_once`. Retry decisions and backoff values are recorded before sleeping.
A successful response is recorded before header analysis, so an analysis
failure still preserves the successful request attempt.

The laboratory runner prints a concise attempt summary and persists the full
history through `ScanResult.to_dict()`.

## Consequences

### Positive

- Every retry decision is visible and auditable.
- Aggregate coverage counters can be checked against detailed history.
- Successful scans show transient failures that were recovered.
- Failed scans show the sequence that exhausted the retry budget.
- Analysis failures retain evidence that the HTTP request itself succeeded.
- Sensitive HTTP content is not copied into audit records.
- Existing constructors remain source-compatible because history is optional.

### Negative

- Serialized reports are larger.
- Schema consumers must recognise version `1.1` and the new additive fields.
- Earlier exception messages are not retained for each failed attempt.
- The current sequence models one passive request operation; a future
  multi-request scanner may need operation identifiers in addition to attempt
  numbers.
