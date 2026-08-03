# ADR 0005: Controlled Error Taxonomy and Retry Policy

- Status: Accepted
- Date: 2026-08-03

## Context

ADR 0004 introduced structured failed `ScanResult` records, but every
`ScanError` was initially marked `retryable: false`. That conservative default
was safe, but it did not distinguish temporary transport failures from
configuration, policy, TLS, malformed-response, or analysis failures.

The safe HTTP client also collapsed `OSError`, `ssl.SSLError`, and
`http.client.HTTPException` into the single code `connection_failed`. A TLS
certificate failure therefore could not be distinguished from a temporary
timeout or connection refusal.

A retry policy must not retry failures that require configuration changes,
target changes, certificate remediation, or scanner fixes. It must also fail
closed whenever an error code has not been reviewed.

## Decision

WebGuard introduces a central controlled-error taxonomy with these categories:

- `configuration`
- `target-integrity`
- `network-transient`
- `tls`
- `http-protocol`
- `response-policy`
- `response-limit`
- `response-format`
- `analysis`
- `mixed`
- `unknown`

Only reviewed transient network codes are retryable:

- `connection_timeout`
- `connection_refused`
- `connection_interrupted`
- `network_unreachable`
- `connection_failed`

The following groups are non-retryable:

- invalid scanner configuration;
- validated-target integrity failures;
- prohibited schemes, methods, fragments, or proxy tunnels;
- TLS certificate and handshake failures;
- HTTP protocol failures;
- blocked redirects;
- response safety-limit violations;
- invalid or ambiguous response metadata;
- analysis consistency failures;
- mixed failure sets that include any non-transient category;
- unknown stage/code combinations.

Unknown errors always resolve to the `unknown` category with
`retryable: false`.

The safe HTTP client maps transport exceptions to stable codes before
aggregating failures across approved destination addresses. Multiple failures
aggregate to `connection_failed` only when every constituent code is a reviewed
transient network failure. Any mixed set containing TLS, protocol, or unknown
failures becomes `connection_failed_mixed`.

No automatic retry loop is introduced by this decision. The taxonomy records
whether a retry is permitted; a later scheduler or worker policy will define
attempt limits, backoff, jitter, and cancellation semantics.

## Consequences

### Positive

- `ScanError.retryable` now reflects reviewed policy rather than a hard-coded
  default.
- TLS certificate failures are not mislabelled as temporary network failures.
- Multi-address failures are aggregated conservatively.
- New unreviewed error codes fail closed.
- Unit tests detect literal controlled error codes that lack taxonomy entries.
- Future queue workers can consume a stable retryability signal.

### Negative

- A generic `OSError` that cannot be classified more precisely remains
  `connection_failed` and is treated as transient.
- HTTP protocol failures are conservatively non-retryable even though a small
  subset may be temporary.
- Retry execution, delay, and attempt limits remain out of scope.
