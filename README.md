# WebGuard

A terminal-only tool for authorized passive web security assessment: point it at a target you own or are authorized to test, and it checks HTTP headers, cookies, CORS, TLS/certificate configuration, and common disclosure issues, then produces a signed-checkpoint-safe, resumable scan report and a professional HTML write-up.

> **Status:** active development, pre-1.0. No hosted service, no account, no telemetry. Everything runs on your machine against targets you specify.

## Who this is for

Developers, freelance security practitioners, and small teams who want a quick, scriptable, authorized-only check of a web asset's passive security posture — from a terminal, in CI, or as a building block in a larger authorized assessment workflow — without standing up a server, a database, or an account anywhere.

This is **not** a vulnerability-exploitation tool, a SaaS platform, or a replacement for a full penetration test. It does not submit forms, run JavaScript, inject payloads, brute-force anything, or follow redirects during a scan.

## What it actually does today

WebGuard v1 is **passive-only**:

- fetches the target once (`scan`) or crawls bounded same-origin pages (`scan --crawl`)
- analyzes HTTP response headers (CSP, HSTS, X-Content-Type-Options, frame protection, Referrer-Policy, Server-header disclosure, cookie flags, CORS configuration)
- analyzes TLS/certificate configuration for HTTPS targets (protocol, cipher, chain, hostname match, expiry)
- produces a deterministic, fingerprint-stable findings report you can diff between runs (`report compare`) to prove remediation
- never submits forms, executes JavaScript, injects payloads, brute-forces, or follows redirects

The scanner library (`webguard_scanner`) also contains active-detection modules (reflected XSS, SQL error-based injection, SSRF callback confirmation, IDOR, login-workflow analysis) — but as of this release they are **not wired into the CLI's `scan` command**. They exist today only inside the archived multi-tenant SaaS orchestration layer (`apps/api/`, see [Project history](#project-history) below), which required a signed execution permit and a callback-receiving service neither of which a local CLI has. Exposing them from the CLI (for example behind an explicit `--active-check` flag, with its own authorization and callback-handling story) is tracked as the main piece of future work — see [Known limitations](#known-limitations--whats-next).

## Install

WebGuard is not yet published to PyPI (see [Project status / owner decisions](#project-status--owner-decisions-still-needed)). Until it is, install it from a locally built wheel — this is the exact sequence exercised by this repository's own CI (`.github/workflows/ci.yml`, the `cli-packaging` job) and by `pipx` on macOS and Linux during this release:

```bash
git clone <this-repository-url>
cd openhuntx-webguard

python3 -m pip wheel packages/contracts/python -w dist --no-deps
python3 -m pip wheel workers/scanner -w dist --no-deps

pipx install dist/openhuntx_webguard_scanner-0.1.0-py3-none-any.whl \
  --pip-args="--no-index --find-links dist"
```

This installs a single `webguard` command. Once published, the same result will be `pipx install openhuntx-webguard-scanner`.

Requires Python 3.11–3.14. No other runtime dependency — `openhuntx-webguard-scanner` depends only on `openhuntx-webguard-contracts` (shared data types, zero third-party dependencies of its own).

## Quickstart

```bash
# 1. Check your environment (no network calls — just Python version,
#    package versions, write permissions, and free disk space).
webguard doctor

# 2. Scaffold a local workspace: authorizations/, scan-results/, reports/,
#    each created with 0700 permissions.
webguard init

# 3a. Scanning your own machine or an isolated lab target (e.g. a local
#     OWASP Juice Shop instance)? Use --lab with an explicit allowlist —
#     no authorization document required.
webguard scan http://127.0.0.1:3000/ --lab --allow-host 127.0.0.1 \
  --output scan-results/lab.json

# 3b. Scanning a real external target you are authorized to assess?
#     Create a self-attested, fingerprinted authorization record first,
#     then scan with it and the exact authorization ID as confirmation.
webguard authorization create https://example.com \
  --organization "Example, Inc." \
  --authorized-by "you@example.com" \
  --purpose "Quarterly external header/TLS review" \
  --output authorizations/example.json
webguard scan https://example.com \
  --authorization-file authorizations/example.json \
  --confirm-authorization <authorization-id-from-the-file> \
  --output scan-results/example.json

# 4. See what's stored locally.
webguard results list
webguard results list --json   # machine-readable

# 5. Render a shareable HTML report.
webguard report render scan-results/example.json \
  --output reports/example.html \
  --organization "Example, Inc."

# 6. Re-scan later and prove what changed.
webguard report compare scan-results/example.json scan-results/example-rescan.json \
  --output reports/remediation-comparison.json

# 7. Clean up old local results (dry run by default; --yes to delete).
webguard results clean --older-than-days 30
```

### Terminal demo

```
$ webguard scan http://127.0.0.1:8921/ --lab --allow-host 127.0.0.1 --output scan-results/example.json
Scan ID: c4fb8d27-3d16-4145-90a7-a97eb69817e0
Status: completed
Target: http://127.0.0.1:8921/
Engine: webguard-native 0.1.0
Connected addresses: 127.0.0.1
HTTP statuses: 200
Requests: 1 attempted, 1 succeeded
Coverage: 80.0%
Findings: 5
Errors: 0
- [LOW] Server header exposes software version information (web.disclosure.server.version)
- [MEDIUM] Content-Security-Policy header missing (web.headers.csp.missing)
- [MEDIUM] Clickjacking frame protection missing (web.headers.frame_protection.missing)
- [LOW] X-Content-Type-Options header missing (web.headers.x_content_type_options.missing)
- [LOW] Referrer-Policy header missing (web.headers.referrer_policy.missing)
- [ATTEMPT 1] succeeded: 127.0.0.1, HTTP 200, 3 ms
Saved report: scan-results/example.json
```

A full, reproducible synthetic example — the exact commands above run against a static local HTTP server, plus the resulting JSON report and rendered HTML — lives in [`examples/`](examples/). No paid infrastructure or external target is needed to reproduce it; see [`examples/README.md`](examples/README.md).

## Every command

```
webguard --version
webguard doctor    [--directory PATH]
webguard init      [--directory PATH]
webguard scan      <target-url> [--lab --allow-host HOST | --authorization-file PATH --confirm-authorization ID]
                    [--crawl] [--checkpoint PATH --checkpoint-key-file PATH] [--preflight-only] ...
webguard authorization create   <target-url> --organization ... --authorized-by ... --purpose ... --output PATH
webguard authorization validate <authorization-file>
webguard authorization inspect  <authorization-file> [--json]
webguard report validate  <report-file>
webguard report inspect   <report-file> [--json]
webguard report render    <report-file> --output PATH --organization NAME [--baseline PATH]
webguard report compare   <baseline-report> <current-report> --output PATH
webguard report validate-comparison <comparison-file>
webguard results list  [--directory PATH] [--json]
webguard results clean [--directory PATH] [--older-than-days N] [--yes]
```

Run `webguard <command> --help` or `webguard <command> <subcommand> --help` for the full flag reference; every destructive or scope-widening flag (`--lab`, `--confirm-authorization`, `--overwrite`, `results clean --yes`) requires an explicit, exact value — there are no silent defaults that widen scope.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Scan failed |
| `2` | Usage error (bad arguments) |
| `3` | Preflight failed (authorization/scope/policy rejected before any request was sent) |
| `4` | Report invalid (failed strict schema/signature validation) |
| `5` | Output failed (couldn't write a file — permissions, existing file without `--overwrite`, disk full) |
| `6` | Unexpected error (an unhandled exception — reported with its type and message, never silently swallowed) |
| `7` | `doctor` found a problem with the local environment |
| `130` | Cancelled (Ctrl-C) |

These are stable and intended to be scripted against.

## How it stores things locally

There is no database, background service, or daemon. `webguard init` creates three plain-file directories (`authorizations/`, `scan-results/`, `reports/`) with `0700` permissions; every file `webguard` writes into them is created `0600` (owner read/write only, refusing to follow a symlink at the destination). `webguard results list`/`clean` just read and delete files in a directory you point it at — there's no hidden index to get out of sync.

Nothing is sent anywhere except the HTTP(S) request to the target you ask it to scan. There is no telemetry, no update check, no account, and no network call of any kind besides that one.

## Authorization model

Every scan against a real external target requires a self-attested authorization document (`webguard authorization create`): organization, authorized-by, purpose, allowed hosts, an expiry, and a set of effective limits, written out as fingerprinted JSON and re-validated (hostname canonicalization, expiry, exact ID confirmation) at scan time. It is **not cryptographically signed** — there's deliberately no PKI or central identity service behind it. For a tool one person runs locally against targets they assert they're authorized to test, a signed, fingerprinted local record that the scanner refuses to proceed without is the right amount of ceremony; a centrally-attested identity system is the right tool for a multi-tenant service brokering trust between strangers, which is what the archived SaaS layer in `apps/api/` built instead (see below). Don't read "self-attested" as "unenforced" — the CLI still fails closed on a missing, expired, mismatched, or non-exact-match authorization before sending a single byte.

Isolated lab targets (`--lab --allow-host ...`, e.g. a local OWASP Juice Shop container) skip the authorization-document requirement entirely, since there is no second party whose authorization needs recording.

## Security decisions and trade-offs

- **Fail closed, not fail open.** Preflight (scope validation, authorization checks, policy limits) runs and can reject a scan *before* any network request is sent. `main()` now has a catch-all exception boundary (exit `6`) so an unexpected bug surfaces as a reported error, not a silent partial scan or a raw traceback.
- **Passive-only by design, not by accident.** v1 deliberately ships without active payload injection. The detection modules for that exist in the library (see above) and are deferred, not abandoned — shipping them requires designing a local callback-receiving story that doesn't depend on the archived SaaS layer's tenant-scoped callback broker.
- **Restrictive file permissions over access control.** Since this is a single-user local tool, authorization records, scan results, and reports are protected with filesystem permissions (`0600`/`0700`) rather than an application-level access-control layer, which would be the wrong tool for a single OS user.
- **No background service, no attack surface when idle.** `webguard` only runs when invoked and only makes outbound requests to the target you name.
- **Signed, resumable crawl checkpoints.** A crawl's progress checkpoint is HMAC-signed with a key you control, so a resumed crawl can't be tampered with or resumed against a different scan.

## Tested platforms

- **Linux** (GitHub Actions `ubuntu-24.04`) — Python 3.11.15, 3.12.13, 3.13.14, 3.14.6, exercised on every push via this repository's CI, including a clean wheel-build-and-install smoke test (`cli-packaging` job).
- **macOS** (Darwin 25.6, Python 3.14.7) — manually verified during this release, including a real `pipx install` from locally built wheels and the full `doctor` → `init` → `scan --lab` → `results list/clean` → `report render` journey from outside the repository checkout.
- **Windows** — **not tested**. Nothing in the scanner's code is deliberately POSIX-only (it's stdlib `socket`/`ssl`/`pathlib`), but the `0600`/`0700` permission model and symlink-refusal checks rely on POSIX file-mode semantics that behave differently under Windows' ACL model, and no one has actually run it there. Treat Windows as unsupported until someone verifies it.

## Known limitations / what's next

- Active detection (XSS, SQLi, SSRF-callback confirmation, IDOR, path traversal, command injection, and more) exists in `webguard_scanner` as a library but has no CLI command wiring it up yet.
- Authorization is self-attested and fingerprinted, not cryptographically signed — there is no delegated-authority verification proving the person running `authorization create` actually has the legal right to authorize testing of the target, only that they asserted it.
- No PyPI package yet — see [Project status](#project-status--owner-decisions-still-needed).
- No license file yet — same section.
- Windows is untested.
- `results clean --older-than-days` and `list` work on one flat directory; there's no cross-directory or recursive index.
- Solo-maintainer project: issue/PR response times are best-effort.

## Project history

WebGuard started as part of a three-module hosted SaaS platform (WebGuard + SOC + Compliance, a multi-tenant web application with its own PostgreSQL-backed API and React frontend). That direction has been **retired**. The hosted web app (`apps/web/`), the multi-tenant API's SaaS-specific layers (tenancy, billing-shaped entitlements, TrustScan permits, the SOC/Compliance modules) in `apps/api/`, and the deployment/infrastructure work under `infra/` are preserved in this repository's history as archived context — they are not deleted, not actively maintained, and not part of the distributed CLI package — but they are no longer the product. `docs/` still contains the platform-era design documents; see [`docs/LEGACY_PLATFORM.md`](docs/LEGACY_PLATFORM.md) for what's archived versus current.

The active product is exactly what's in `packages/contracts/` and `workers/scanner/`, installed as the single `openhuntx-webguard-scanner` package with its `webguard` entry point. See [`docs/CLI_ARCHITECTURE.md`](docs/CLI_ARCHITECTURE.md) for the architecture diagram and the reasoning behind that split, and [`docs/CASE_STUDY.md`](docs/CASE_STUDY.md) for a portfolio write-up of this pivot.

## Project status / owner decisions still needed

This is pre-release engineering work, not a public release:

- **No license chosen yet.** Nothing in this repository is currently licensed for reuse by anyone other than the copyright holder. This needs an explicit decision (MIT/Apache-2.0/other) before any public use is invited — it is intentionally not silently defaulted here.
- **Not published to PyPI.** `webguard`, `webguard-cli`, and `openhuntx-webguard` are all currently unclaimed package names there (checked during this release); which name to use is an open decision.
- **No GitHub release has been cut.** Install today by building from source as shown above.

## Responsible use

Only run WebGuard against systems you own or have explicit, documented authorization to assess. A reachable hostname or working HTTP endpoint is not, by itself, permission to test it. This tool performs no exploitation, brute-forcing, or active payload injection in its current form — but authorization is still required for passive scanning, including header and TLS analysis.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues: see [`SECURITY.md`](SECURITY.md) — do not open a public issue with exploit details or target information.
