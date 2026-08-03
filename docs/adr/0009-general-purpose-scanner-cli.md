# ADR 0009: General-Purpose Scanner CLI

- Status: Accepted
- Date: 2026-08-03

## Context

OpenHuntX WebGuard has a safe passive scanner engine and a laboratory runner,
but it does not yet expose an installable end-user command. The existing
`scripts/run-passive-lab-scan.py` script is intentionally fixed to laboratory
scope and is unsuitable as the public interface for commercial targets,
report inspection, or automation.

A public CLI must reuse the existing target validator, safe HTTP client,
retry policy, scan-result contracts, and strict report loader. It must not
create a second scanning path that bypasses those controls.

## Decision

The scanner package registers this console entry point:

```text
webguard = webguard_scanner.cli:main
```

The same interface is available through:

```text
python -m webguard_scanner
```

The first CLI release provides:

```text
webguard --version
webguard scan TARGET
webguard report validate REPORT
webguard report inspect REPORT
```

### Scan mode

Commercial validation is the default. Laboratory validation must be selected
explicitly with `--lab` and requires at least one repeated `--allow-host`
value. `--allow-host` is rejected outside laboratory mode.

The CLI invokes only `run_passive_header_scan`. It does not crawl, submit
forms, mutate server state, brute-force paths, or run active vulnerability
checks.

### Request controls

The CLI exposes bounded configuration for:

- request timeout;
- maximum body bytes;
- maximum header bytes;
- maximum header count;
- maximum request attempts;
- initial retry backoff;
- retry multiplier;
- maximum retry backoff.

Existing `RetryPolicy` limits remain authoritative. The CLI also applies
upper bounds of:

- 60 seconds per request;
- 16 MiB response body;
- 1 MiB response headers;
- 1,000 response headers.

These CLI ceilings prevent a user-supplied configuration from removing the
bounded nature of the scanner.

### Report output

Each scan writes a canonical UTF-8 JSON `ScanResult` report. When `--output`
is omitted, the path is:

```text
scan-results/<scan-id>.json
```

Existing output files are never overwritten implicitly. Replacement requires
`--overwrite`. Symbolic-link output paths and non-regular existing paths are
rejected even when overwrite is requested. New reports are created with mode
`0600` where supported.

The scan identifier is generated before execution and passed into the scanner,
so the default filename and report identity are identical.

### Report commands

`report validate` loads a file through the strict shared report loader and
returns success only after complete contract reconstruction.

`report inspect` also uses the strict loader. It prints a human-readable
summary by default and canonical normalized JSON with `--json`. Loading a
legacy schema 1.0 report therefore displays its validated schema 1.1
normalization.

### Exit statuses

Expected outcomes use deterministic statuses:

| Status | Meaning |
|---:|---|
| 0 | Scan completed successfully, or report is valid |
| 1 | Scan returned a non-success terminal status |
| 2 | Argument parsing or command usage error |
| 3 | Target, mode, or bounded-policy preflight failure |
| 4 | Invalid, unreadable, or unsupported report |
| 5 | Output path or report-write failure |

Unexpected programming errors are not converted into controlled scan results;
they continue to surface for diagnosis.

## Consequences

### Positive

- WebGuard has an installable public command.
- Commercial scanning remains the safe default.
- Private and loopback laboratory access requires explicit mode and allowlist.
- The CLI cannot bypass target validation, pinned HTTP, retry, or result
  contracts.
- Report files are protected from accidental replacement and symlink writes.
- Saved reports can be validated and inspected without running a new scan.
- Shell automation receives stable exit statuses.
- The lab runner remains available for existing integration workflows.

### Negative

- Changing `[project.scripts]` requires reinstalling the editable scanner
  package before the `webguard` command appears in an existing virtual
  environment.
- The CLI currently runs one passive header request only.
- There is no crawler, authentication, scheduling, API, database, or active
  scanner in this milestone.
- Existing regular files can be replaced when the operator explicitly supplies
  `--overwrite`.
