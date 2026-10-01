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
- [x] Authorization path coverage, and exactly what each piece establishes: a real local `--lab` scan against a local HTTP server exercises the full scan/report/results pipeline over real sockets, but `--lab` bypasses the owned-target authorization machinery entirely, so it does not by itself verify the normal (non-lab) authorization path. That path is covered separately: `test_real_owned_scan_writes_audit_before_scanner_and_matches_report` runs a complete, successful, non-expired, exactly-matching authorization through the real `cli.main()` entry point with only the two network-touching functions (DNS resolution, the HTTP scan itself) replaced by deterministic fixtures, proving authorization loading, preflight validation, confirm-ID matching, and audit-before-scan ordering all work; three further tests (`test_malformed_authorization_json_is_rejected_before_dns_resolution`, `test_expired_authorization_is_rejected_before_dns_resolution`, `test_target_mismatch_is_rejected_before_dns_resolution`) assert `validate_target_url.assert_not_called()` to prove those three rejections happen before any DNS lookup, not just before the scan. Independently, outside unit tests, the same three rejections were run against the real installed CLI binary using `*.invalid` hostnames (RFC 2606, guaranteed unresolvable) and completed in ~0.1s with the correct error code rather than a DNS-resolution-failure error, which would be the observable result if a lookup had actually been attempted. None of this scans a real external target; no live authorized-target scan against a real third-party host has been performed.
- [x] Full-history secret scan (`python scripts/scan-secrets.py`) green

## Packaging (done)

- [x] `openhuntx-webguard-contracts` and `openhuntx-webguard` build as standalone wheels with `pip wheel` (the scanner package was renamed from `openhuntx-webguard-scanner` to `openhuntx-webguard` once it became the distributed product rather than one component among several; the `webguard` command name is unchanged)
- [x] Wheel contents verified clean (only `webguard_scanner/*.py` + standard dist-info, no tests/caches/dev artifacts)
- [x] Clean-environment install verified three ways: `pip install --no-index --find-links dist ...`, a real `pipx install` from local wheels (both outside the repo checkout, and again after the rename), and, more rigorously, a real `pip install openhuntx-webguard --index-url ...` against a hand-built PEP 503 simple index serving the two wheels, with no `--find-links`/`--no-index` at all. The last one is the one that actually proves the eventual `pip install openhuntx-webguard` against real PyPI will auto-resolve `openhuntx-webguard-contracts` as a declared dependency; the wheel's own METADATA carries `Requires-Dist: openhuntx-webguard-contracts==0.1.0`, confirmed by inspecting the built wheel directly.
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

- [ ] **License.** Nothing in this repository is currently licensed for reuse. Pick one before any public "go ahead and use this" claim; see [`docs/LICENSE_OPTIONS.md`](LICENSE_OPTIONS.md) for a comparison and a recommendation (MIT), not yet applied.
- [ ] **PyPI package name.** `openhuntx-webguard` is the proposed name (already in `workers/scanner/pyproject.toml`); confirm it or pick a different one, then re-check availability right before publishing.
- [ ] **PyPI publishing credentials/trusted publisher.** `.github/workflows/publish.yml` exists, is manual-dispatch-only, and uses PyPI's trusted-publisher OIDC flow (no API token stored in this repo), but it cannot succeed until that trusted publisher is actually configured on PyPI's side, pointing at this repository and the `pypi-publish` environment. Registering the project name on PyPI and setting that up is a deliberate, separate step from everything else in this checklist.
- [ ] **First GitHub release / tag.** Not cut. Once the above are decided, tag `v0.1.0` (or whatever version is chosen), review and publish [`docs/RELEASE_NOTES_DRAFT.md`](RELEASE_NOTES_DRAFT.md) as the release notes, and attach the built wheels.

## Explicitly out of scope for v1 (not blockers, just not promised)

- Active detection (XSS/SQLi/SSRF-callback/etc.) wired into the CLI
- Windows support (untested, not deliberately broken)
- Any hosted/SaaS functionality (retired; see `docs/LEGACY_PLATFORM.md`)
