# ADR 0008: Scan Report Loading and Schema Compatibility

- Status: Accepted
- Date: 2026-08-03

## Context

OpenHuntX WebGuard can persist deterministic JSON `ScanResult` documents.
Schema version 1.0 stored scan identity, lifecycle, coverage, findings, errors,
connected addresses, and HTTP statuses. Schema version 1.1 added the bounded
request-attempt audit trail.

Writing reports is not sufficient for a commercial scanner. Stored reports
must also be loaded safely for APIs, dashboards, exports, migrations, queues,
and historical analysis.

A permissive JSON-to-object conversion would permit corrupted or ambiguous
records to enter the system. Examples include duplicate JSON keys, incorrect
finding fingerprints, mismatched summary counts, incorrect derived coverage,
invalid timestamps, unknown fields, and unsupported future schemas.

## Decision

The shared contracts package provides these public loading functions:

- `load_scan_result`;
- `load_scan_result_json`;
- `load_scan_result_file`.

It also provides controlled errors:

- `ScanReportLoadError`;
- `MalformedScanReportError`;
- `UnsupportedSchemaVersionError`.

The loader accepts scan report schema versions 1.0 and 1.1.

### Schema 1.1

Version 1.1 reports are reconstructed into the current `ScanResult` contract,
including complete request-attempt history. The reconstructed object's
canonical dictionary must exactly match the supplied report.

### Schema 1.0

Version 1.0 reports are reconstructed without request-attempt history. The
result is returned as the current 1.1 contract with an empty
`request_attempts` tuple. Reserializing the result therefore performs an
explicit additive migration to 1.1.

### Strict validation

The loader rejects:

- invalid or non-UTF-8 JSON;
- duplicate JSON object keys;
- non-object report roots;
- missing or unexpected fields at every supported level;
- unsupported scan or finding schema versions;
- invalid enum values and timestamps;
- malformed findings, evidence, identifiers, errors, coverage, and attempts;
- corrupted finding fingerprints;
- incorrect finding, error, or request-attempt counts;
- incorrect derived coverage, duration, and unaccounted-check values;
- request counters that disagree with attempt history;
- noncanonical ordering or serialization;
- reports larger than 16 MiB;
- unreadable report files.

JSON `NaN`, positive infinity, and negative infinity are rejected.

Unknown future schema versions are never guessed or silently downgraded.
They raise `UnsupportedSchemaVersionError`.

The loader does not mutate caller-supplied dictionaries.

## Consequences

### Positive

- Persisted reports can be trusted only after full contract reconstruction.
- Schema 1.0 history remains readable.
- Version 1.0 reports have a deterministic migration path to 1.1.
- Corrupted fingerprints and derived summary fields are detected.
- Duplicate-key ambiguity and non-standard JSON numbers are rejected.
- Future versions fail explicitly instead of being misinterpreted.
- APIs, dashboards, and exporters can consume validated `ScanResult` objects.

### Negative

- Semantically equivalent but noncanonical reports are rejected.
- Strict unknown-field rejection requires deliberate loader updates for every
  future schema version.
- Legacy 1.0 reports cannot reconstruct request-attempt history that was never
  recorded.
- The 16 MiB limit may need review when future report payloads grow, although
  large raw artifacts should remain outside the report contract.
