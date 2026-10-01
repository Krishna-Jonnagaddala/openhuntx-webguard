# WebGuard CLI v1 release checklist

A single, finite list. When everything here is checked, v1 is ready to publish, not before, and nothing is added to this list to extend scope. See [`docs/CASE_STUDY.md`](CASE_STUDY.md) for why this exists and the root [README](../README.md) for what the shipped product actually does.

## Engineering (done)

- [x] Terminal UX complete: `init`, `doctor`, `scan`, `authorization create/validate/inspect`, `report validate/inspect/render/compare/validate-comparison`, `results list/clean`, `--version`, `--help` on every (sub)command
- [x] Fail-closed top-level exception boundary in `cli.py`'s `main()` (exit `6`), `130` on Ctrl-C
- [x] Documented, stable exit codes (`0` through `7`, `130`)
- [x] No mandatory database or background service; local file storage only, `0600`/`0700` permissions, symlink-destination refusal
- [x] Scanner-engine hardening from `audit/checkpoint1-phase6-exception-network-safety` merged in as this branch's base
- [x] Focused tests for the new commands (`tests/unit/test_cli_workspace.py`), full existing CLI test suite still green
- [x] Full local verification gate (`./scripts/verify.sh`) green
- [x] Full-history secret scan (`python scripts/scan-secrets.py`) green

## Packaging (done)

- [x] `openhuntx-webguard-contracts` and `openhuntx-webguard` build as standalone wheels with `pip wheel` (the scanner package was renamed from `openhuntx-webguard-scanner` to `openhuntx-webguard` once it became the distributed product rather than one component among several; the `webguard` command name is unchanged)
- [x] Wheel contents verified clean (only `webguard_scanner/*.py` + standard dist-info, no tests/caches/dev artifacts)
- [x] Clean-environment install verified: `pip install --no-index --find-links dist ...` and a real `pipx install` from local wheels, both outside the repo checkout, and again after the rename
- [x] Full documented journey exercised against the installed binary: `doctor` then `init` then `scan --lab` then `results list/clean` then `report render`
- [x] CI packaging smoke test (`cli-packaging` job) added, building and installing the same way on every push

## Documentation (done)

- [x] README rewritten for the CLI product: problem/audience, install, quickstart, every command, exit codes, local storage model, authorization model, security trade-offs, tested platforms, known limitations
- [x] `docs/CLI_ARCHITECTURE.md`: architecture diagram and package-boundary reasoning
- [x] `docs/LEGACY_PLATFORM.md`: explicit index marking the retired SaaS-era docs as archived, not current
- [x] `docs/CASE_STUDY.md`: portfolio write-up, including an honest AI-assistance disclosure
- [x] `CONTRIBUTING.md`, `SECURITY.md` rewritten for the CLI product
- [x] `examples/`: a reproducible, synthetic, offline demo (no paid infra, no external target)

## Repository (done)

- [x] Migrated to `openhuntx/openhuntx` with full branch history preserved, original repository untouched
- [x] Native secret scanning + push protection, Dependabot security updates, vulnerability alerts enabled
- [x] Required-status-checks ruleset on `main` (matching the pre-migration repository's, plus the new `cli-packaging` check), non-fast-forward and deletion protection
- [x] Actions SHA-pinning requirement enabled
- [x] Issue and PR templates added

## Owner decisions (blocking publish, not engineering)

- [ ] **License.** Nothing in this repository is currently licensed for reuse. Pick one (MIT/Apache-2.0/other) before any public "go ahead and use this" claim.
- [ ] **PyPI package name.** `openhuntx-webguard` is the proposed name (already in `workers/scanner/pyproject.toml`); confirm it or pick a different one, then re-check availability right before publishing.
- [ ] **PyPI publishing credentials/trusted publisher.** No publish workflow exists yet; setting one up (ideally via PyPI's trusted-publisher OIDC flow rather than a long-lived API token) is a deliberate, separate step from everything in this checklist.
- [ ] **First GitHub release / tag.** Not cut. Once the above are decided, tag `v0.1.0` (or whatever version is chosen) and attach the built wheels.

## Explicitly out of scope for v1 (not blockers, just not promised)

- Active detection (XSS/SQLi/SSRF-callback/etc.) wired into the CLI
- Windows support (untested, not deliberately broken)
- Any hosted/SaaS functionality (retired; see `docs/LEGACY_PLATFORM.md`)
