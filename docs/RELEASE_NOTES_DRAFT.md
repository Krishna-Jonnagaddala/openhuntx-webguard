# v0.1.0 (draft)

Not tagged yet. This is a draft to review and adjust once the open owner decisions in [`docs/CLI_RELEASE_CHECKLIST.md`](CLI_RELEASE_CHECKLIST.md) are settled, then publish as the actual GitHub release notes for the first tag.

## WebGuard: a terminal-only, authorized passive web security scanner

First release of WebGuard as a standalone CLI tool, pivoted from an earlier three-module hosted SaaS platform (see [`docs/CASE_STUDY.md`](CASE_STUDY.md) for that story).

### Install

```bash
git clone https://github.com/openhuntx/openhuntx.git
cd openhuntx
python3 -m pip wheel packages/contracts/python -w dist --no-deps
python3 -m pip wheel workers/scanner -w dist --no-deps
pipx install dist/openhuntx_webguard-0.1.0-py3-none-any.whl --pip-args="--no-index --find-links dist"
```

See the [README](../README.md) for the full quickstart.

### What's in it

- `webguard scan`: passive single-page and bounded same-origin crawl assessment (headers, cookies, CORS, TLS/certificate, disclosure checks)
- `webguard authorization create/validate/inspect`: self-attested, fingerprinted authorization records required before scanning an external target
- `webguard report validate/inspect/render/compare/validate-comparison`: deterministic findings, a professional HTML report, and remediation-comparison diffing
- `webguard init`, `webguard doctor`, `webguard results list/clean`: the local workspace and environment-diagnostic commands new in this release
- Stable, documented exit codes (`0` through `7`, `130`), including a fail-closed top-level exception boundary

### What's not in it

- Active detection (XSS, SQLi, SSRF-callback confirmation, etc.): present in the scanner library, not wired into the CLI yet
- Windows support: untested
- Anything from the retired hosted SaaS platform (accounts, a web dashboard, SOC/Compliance modules): archived, not shipped; see [`docs/LEGACY_PLATFORM.md`](LEGACY_PLATFORM.md)

### Known gaps in this release

See [`docs/CLI_RELEASE_CHECKLIST.md`](CLI_RELEASE_CHECKLIST.md)'s "Owner decisions" section: no license is chosen yet, the PyPI package name is proposed but not confirmed, and the package isn't published yet.
