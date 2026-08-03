# ADR 0003: Versioned Scan Result Contract

## Status

Accepted

## Context

OpenHuntX WebGuard needs one result format for native passive checks, ZAP,
TLS analysis, dependency scanning, source-code scanning, vulnerability
intelligence, and future customer-controlled scanner agents.

A raw list of findings is insufficient because commercial operation also needs
scan identity, lifecycle state, timestamps, execution coverage, bounded errors,
connected addresses, and observed HTTP status codes.

## Decision

Every scan execution will produce a versioned `ScanResult`.

The contract records:

- A UUID scan identifier;
- Scan type and engine identity;
- Canonical target URL;
- Lifecycle status;
- Timezone-aware start and completion times;
- Explicit planned, executed, skipped, and unaccounted checks;
- Request-attempt and request-success counts;
- Normalized findings;
- Bounded non-secret errors;
- Connected IP addresses; and
- Observed HTTP status codes.

Completed scans must account for every planned check. A check can be executed,
skipped with a reason, or remain unaccounted only while a scan is incomplete,
failed, or cancelled.

A completed scan cannot contain errors. `completed_with_errors` and `failed`
statuses require at least one bounded error record.

Every finding in a scan result must belong to the scan target origin, and
duplicate finding fingerprints are rejected.

## Consequences

Scanner adapters must explicitly report coverage rather than imply it from the
number of findings.

Secrets, raw responses, stack traces, and sensitive customer data must not be
placed in `ScanError`. Protected artifacts will use separate storage.

Future incompatible changes require a new schema version and migration plan.
