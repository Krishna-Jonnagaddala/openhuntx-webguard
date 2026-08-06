# ADR 0020: Professional Security Reporting and Remediation Verification

- Status: Accepted
- Date: 2026-08-05

## Context

WebGuard already writes strict machine-readable single-page and crawl scan reports. Those reports are suitable for storage, validation, automation, and audit, but they are not intended to be delivered directly to customers or executives.

A commercial security product also needs a readable assessment document and a deterministic way to verify remediation between two scans. Reporting must not weaken WebGuard's data-minimisation or output-path controls.

## Decision

WebGuard will provide two complementary reporting artifacts:

1. A self-contained, JavaScript-free HTML assessment report generated from a strictly loaded WebGuard report.
2. A versioned JSON comparison document that classifies findings as `new`, `remaining`, or `fixed` by stable finding fingerprint.

The professional HTML report includes:

- customer and report metadata;
- executive summary and severity distribution;
- scan scope, status, timing, coverage, requests, and crawl termination;
- technical finding descriptions, bounded evidence summaries, affected locations, confidence, identifiers, references, and remediation;
- skipped checks, execution errors, and explicit limitations;
- optional remediation-comparison results.

The comparison contract uses schema version `1.0`. Findings that retain the same stable identity fingerprint are `remaining`. Findings present only in the current report are `new`. Findings present only in the baseline are `fixed`. Changes to presentation fields such as title, severity, description, evidence, or remediation are recorded on a remaining finding without changing its identity disposition.

## Safety and integrity properties

- Both source reports are strictly loaded before rendering or comparison.
- Baseline and current reports must use the same canonical target.
- The current scan must not complete before the baseline scan.
- HTML values are escaped before insertion.
- The HTML contains no JavaScript and loads no external styles, fonts, or images.
- Raw response bodies, cookies, credentials, TLS certificates, and arbitrary headers are not added to the professional report.
- Output files are created with owner-only `0600` permissions where POSIX permissions apply.
- Symbolic-link output destinations are rejected.
- Existing outputs require explicit `--overwrite`.
- Comparison JSON is deterministic, bounded, versioned, and strictly reloadable.

## CLI

```text
webguard report render REPORT \
  --organization ORGANIZATION \
  --output REPORT.html

webguard report render CURRENT \
  --baseline BASELINE \
  --organization ORGANIZATION \
  --output REMEDIATION.html

webguard report compare BASELINE CURRENT \
  --output comparison.json

webguard report validate-comparison comparison.json
```

## Limitations

The report describes only the recorded WebGuard scope and execution conditions. Full check coverage for a fetched response does not prove that the entire application was assessed or that it is vulnerability-free. Passive scanning does not execute JavaScript, submit forms, authenticate, brute-force credentials, enumerate directories, or send exploit payloads.

## Consequences

Customer-readable reporting and repeat-scan remediation verification are now available without changing scanner traffic. PDF export remains a presentation-layer concern for a later milestone; the self-contained HTML document can be printed to PDF by an approved customer or platform workflow.
