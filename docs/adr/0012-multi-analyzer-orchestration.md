# ADR 0012: Multi-Analyser Orchestration and Partial Failure Isolation

- Status: Accepted
- Date: 2026-08-03

## Context

The passive scanner now evaluates HTTP security headers, cookies, CORS, and
information-disclosure headers. These analysers previously ran as direct
function calls inside `run_passive_header_scan` and shared one broad exception
handler.

That design had several drawbacks:

- analyser identity and check ownership were implicit;
- one controlled analyser failure discarded findings from analysers that had
  already succeeded;
- a controlled analysis failure returned the same `failed` status used for a
  request that never produced a response;
- coverage could not distinguish successful analyser groups from failed ones;
- extending the pipeline required editing orchestration-specific exception
  handling;
- duplicate findings from separate analysers were detected only when the final
  `ScanResult` was constructed.

The HTTP request layer is already bounded and safe. This decision changes only
post-response orchestration and does not add requests, redirects, crawling, or
active payloads.

## Decision

### Registered analyser contract

A passive analyser is represented by an immutable `PassiveAnalyzer` containing:

- a stable lowercase analyser ID;
- the check IDs it owns;
- the finding namespace it is allowed to emit;
- its analysis callable;
- the exact controlled exception type it may raise.

The default registry contains four analysers in deterministic execution order:

1. `headers`;
2. `cookies`;
3. `cors`;
4. `disclosure`.

Registry validation rejects empty registries, invalid IDs, duplicate analyser
IDs, duplicate or overlapping check ownership, checks outside an analyser's
finding namespace, non-callable functions, and invalid controlled-error types.

The 24 existing passive check IDs remain the default planned check set.

### Pipeline execution

`execute_analyzers` executes each registered analyser against the same bounded
`SafeHttpResponse`.

A successful analyser:

- contributes its normalized findings;
- marks its applicable owned checks as executed;
- does not alter checks that were already marked not applicable.

When an analyser raises its declared controlled exception:

- the exception is converted to a non-retryable `ScanError`;
- the error stage is `analysis.<analyzer-id>`;
- only that analyser's applicable checks are marked skipped;
- findings from earlier successful analysers are preserved;
- later analysers continue to run;
- no additional HTTP request is made.

The skipped-check reason records only the stable analyser ID and controlled
error code. It does not copy arbitrary response data.

### Scan lifecycle

A request-stage controlled failure continues to return `failed`.

When the request succeeds and every analyser succeeds, the scan returns
`completed`.

When the request succeeds and one or more registered analysers raise controlled
errors, the scan returns `completed_with_errors`. This also applies if every
registered analyser raises a controlled error: the response was obtained and
all planned checks are explicitly accounted as skipped rather than left
unaccounted.

`completed_with_errors` reports preserve:

- findings from successful analysers;
- all controlled analyser errors;
- connected address and HTTP status metadata;
- complete request-attempt history;
- exact executed and skipped check coverage.

### Fail-fast software defects

Only the declared controlled exception type is isolated. Unexpected exceptions
continue to surface so programming defects are not converted into apparently
valid scan reports.

The pipeline also fails fast with `AnalyzerOutputError` when an analyser:

- returns a non-tuple result;
- returns a value that is not a `NormalizedFinding`;
- emits a finding outside its registered namespace;
- emits a finding for a pre-skipped check;
- produces a duplicate finding fingerprint.

Duplicate fingerprints are rejected before constructing `ScanResult`.

### Compatibility

The public `run_passive_header_scan` function name and the existing
`passive-http-headers` scan-type identifier are retained for compatibility,
even though the pipeline now covers the full passive HTTP response. They may be
renamed only through a separate compatibility decision.

The CLI continues to return a non-zero scan result for any status other than
`completed`, including `completed_with_errors`, so automation can detect a
degraded assessment.

## Consequences

### Positive

- New analysers can join a validated registry instead of expanding one large
  exception block.
- Controlled analyser failures no longer discard successful findings.
- Reports distinguish request failure from partial analysis failure.
- Coverage identifies exactly which analyser-owned checks executed or were
  skipped.
- Analyser-specific error stages improve report auditability.
- Duplicate and out-of-namespace findings fail before final result creation.
- No network behaviour or target-scope control changes.

### Negative

- The registry and output contract add implementation complexity.
- A controlled analyser failure lowers execution coverage because its checks
  are skipped rather than executed.
- A faulty analyser that raises an unexpected exception still terminates the
  command without a report; this is intentional fail-fast behaviour.
- Check IDs and finding namespaces become compatibility-sensitive public
  identifiers.
