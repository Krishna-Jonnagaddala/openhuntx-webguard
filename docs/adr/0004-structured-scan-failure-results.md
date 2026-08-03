# ADR 0004: Structured Passive Scan Failure Results

- Status: Accepted
- Date: 2026-08-03

## Context

The passive header scanner originally returned a validated `ScanResult` only
when the HTTP request and header analysis both succeeded. Controlled
`SafeRequestError` and `HeaderAnalysisError` exceptions escaped to the command
runner, which emitted a separate temporary error dictionary.

That produced two incompatible output shapes:

1. a versioned `ScanResult` for successful scans; and
2. an unversioned error object for controlled runtime failures.

A commercial scanner needs one stable result envelope so storage, reporting,
API, and user-interface components can process success and failure records
without guessing their shape.

## Decision

The passive scan orchestration converts only these controlled scanner errors
into a validated `ScanResult` with status `FAILED`:

- `SafeRequestError`, recorded with stage `request`;
- `HeaderAnalysisError`, recorded with stage `analysis`.

The original bounded error code and message are copied into `ScanError`.
`retryable` remains `false` until a separate reviewed error taxonomy defines
which exact error codes can be retried safely.

Request failures record:

- one request attempted;
- zero requests succeeded;
- no connected address;
- no HTTP status;
- no executed checks.

Analysis failures record:

- one request attempted;
- one request succeeded;
- the connected address;
- the HTTP response status;
- no successfully executed checks.

Checks that are inherently not applicable remain explicitly skipped. For an
HTTP target, the HSTS check is skipped even when the request or analysis fails.
All remaining unfinished checks stay unaccounted, which is valid for a failed
scan and makes incomplete coverage visible.

Unexpected exceptions are not converted into `ScanError`. They continue to
surface as programming or infrastructure faults so defects are not silently
misclassified as normal scan failures.

The command runner always persists the returned `ScanResult`. It exits with
status code `1` when the result status is `FAILED`.

Target-validation failures occur before a valid scan target exists. They remain
preflight rejections rather than `ScanResult` records because the contract
requires a canonical validated target URL.

## Consequences

### Positive

- Successful and controlled failed scans use the same versioned envelope.
- Failure stage, code, message, coverage, and response metadata are explicit.
- Downstream components can rely on the `ScanResult` contract.
- Controlled failures no longer lose scan identity or timing information.
- Unexpected defects remain visible to CI and operators.

### Negative

- Preflight target rejections still use a separate small error response.
- Retryability is deliberately conservative until error codes are formally
  classified.
- Failed scans can contain unaccounted checks, so consumers must inspect both
  status and coverage.
