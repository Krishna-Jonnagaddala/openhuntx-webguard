# WebGuard CLI v1 release checklist

A finite list. When everything here is checked, v1 is ready to publish; nothing gets added to it to extend scope. [`docs/RELEASING.md`](RELEASING.md) has the step-by-step release sequence, [`docs/CASE_STUDY.md`](CASE_STUDY.md) explains why this project looks the way it does, and the root [README](../README.md) describes what the tool actually does.

CI results are not recorded in this file. A commit cannot contain its own CI result, so the current state of the required checks is on the pull request and in the release handoff.

## Where things stand

Implemented and verified locally, on CI at the previous head, and re-run on every push. Not merged. Not published. In particular:

- **Source installation** (build both wheels, `pipx install`): works today. Run through `pipx` on macOS, and on every pull request in a clean Linux environment by the `cli-packaging` job.
- **Public PyPI installation** (`pipx install openhuntx-webguard`): unverified until publication. What exists is a simulation: both wheels served from a local PEP 503 index, installed with no `--find-links`, with pip resolving `openhuntx-webguard-contracts==0.1.0` from the wheel's own metadata. That proves the mechanism, not the real index.
- **Platforms actually tested**: Linux (GitHub Actions `ubuntu-24.04`; unit tests on Python 3.11.15, 3.12.13, 3.13.14, 3.14.6, and the packaging job on 3.13.14) and macOS (Python 3.14.7, by hand). Windows is untested and not supported.

## Engineering (done)

- [x] Terminal UX: `init`, `doctor`, `scan`, `authorization create/validate/inspect`, `report validate/inspect/render/compare/validate-comparison`, `results list/clean`, `--version`, and `--help` on every command
- [x] Fail-closed top-level exception boundary in `main()` (exit `6`, and `130` on Ctrl-C); documented, stable exit codes `0` through `7`
- [x] No database or background service; local files only, `0600`/`0700` permissions, symlink-destination refusal
- [x] Scanner-engine hardening from `audit/checkpoint1-phase6-exception-network-safety` is this branch's base
- [x] A malformed, expired, confirmation-mismatched, or target-mismatched authorization is rejected before any DNS lookup; destination validation (resolution, private and reserved address rejection) still runs in full and still gates every connection
- [x] `init` prints next steps with the real flags (`--authorization-file`, `--confirm-authorization`), covered by a test
- [x] Full local gate (`./scripts/verify.sh`), full-history secret scan, supply-chain pin check, and governance check all green

What the authorization tests establish, so one result isn't read as covering another:

- A `--lab` scan runs the whole scan, report, and results pipeline over real sockets, but `--lab` skips the authorization machinery entirely. It says nothing about the normal path.
- `test_real_owned_scan_writes_audit_before_scanner_and_matches_report` runs a valid, exactly-matching authorization through the real `cli.main()` entry point, with only DNS resolution and the HTTP scan replaced by fixtures. It shows authorization loading, preflight, confirmation matching, and audit-before-scan ordering work.
- Three tests assert `validate_target_url.assert_not_called()` for a malformed, an expired, and a mismatched authorization, which is what shows those rejections happen before DNS rather than merely before the scan.
- Outside the unit tests, the same rejections were run against the installed CLI using `*.invalid` hostnames (RFC 2606, guaranteed unresolvable). They finished in about 0.1 seconds with the correct error code, where an attempted lookup would have produced a DNS failure.
- The README's authorization walkthrough runs against `example.com` to `--preflight-only`: it reaches "Owned-target readiness: approved" and sends no HTTP request. Its one network activity is a DNS lookup.
- No scan of a real third-party target has been performed.

## Packaging (done)

- [x] `openhuntx-webguard-contracts` and `openhuntx-webguard` build as standalone wheels (the scanner package was renamed from `openhuntx-webguard-scanner` when it became the distributed product; the `webguard` command is unchanged)
- [x] `scripts/verify-release-artifacts.py` checks the exact files a release would upload: only the two wheels in the directory, correct names and a shared version in each wheel's own metadata, the contracts pin, a contents allowlist, a clean-environment install, `pip check`, a synthetic CLI scan, and unchanged checksums afterward. It runs in the `cli-packaging` pull-request job and in the publish workflow's build job
- [x] Wheels are built with `SOURCE_DATE_EPOCH` set to the commit time and are byte-reproducible from a commit on the same toolchain
- [x] `.github/workflows/publish.yml`: manual dispatch only, defaults to a dry run, builds and verifies in a job with no OIDC permission, then hands the verified files to a separate publish job without rebuilding them; the publish job re-checks checksums, refuses to upload a version PyPI already has, uploads contracts before the CLI, and has a `publish-webguard-only` recovery mode. The `pypi-publish` environment allows only `main`
- [x] `scripts/verify-supply-chain-pins.py` fails if that workflow gains a trigger other than `workflow_dispatch`, gives the build job `id-token`, rebuilds in the publish job, or uses an action that is not SHA-pinned and reviewed

## Documentation (done)

- [x] README: install (source now, PyPI later and unverified), a quick-start whose two blocks run verbatim, every command, exit codes, storage model, authorization model, tested platforms, known limitations
- [x] `docs/RELEASING.md`, `docs/CLI_ARCHITECTURE.md`, `docs/LEGACY_PLATFORM.md`, `docs/CASE_STUDY.md`, `docs/LICENSE_OPTIONS.md`, `docs/RELEASE_NOTES_DRAFT.md`, `CONTRIBUTING.md`, `SECURITY.md`
- [x] `examples/`: a reproducible, synthetic, offline demo

## Repository (done)

- [x] Migrated to `openhuntx/openhuntx` with branch history preserved; the original repository is untouched
- [x] Secret scanning with push protection, Dependabot security updates, and vulnerability alerts enabled
- [x] Ruleset on `main`: eleven required checks, non-fast-forward and deletion protection, Actions SHA-pinning required
- [x] Issue and PR templates

## Owner decisions (blocking publish, not engineering)

- [ ] **License.** Nothing in this repository is currently licensed for reuse. Pick one before any public "go ahead and use this" claim; see [`docs/LICENSE_OPTIONS.md`](LICENSE_OPTIONS.md) for the comparison and a recommendation (MIT), not applied. The change is prepared: `python scripts/apply-license.py --license <MIT|Apache-2.0> --holder "<name>" --dry-run` prints the exact diff, and `--apply` writes it. The only inputs are the license and, for MIT, the copyright holder's name.
- [ ] **Merge.** Pull request review and merge, then check CI on the resulting `main` commit.
- [ ] **PyPI trusted publishers.** Two pending publishers, one per project name, with the fields listed in [`docs/RELEASING.md`](RELEASING.md). Confirm both names are still unclaimed immediately beforehand.
- [ ] **Publish.** Authorize the `publish` run, after a clean dry run.
- [ ] **First GitHub release and tag.** Not cut. After a verified public install, tag `v0.1.0`, publish [`docs/RELEASE_NOTES_DRAFT.md`](RELEASE_NOTES_DRAFT.md) as the notes, and attach the built wheels.

## Explicitly out of scope for v1

- Active detection (XSS, SQLi, SSRF-callback, and the rest) wired into the CLI
- Windows support
- Any hosted or SaaS functionality (retired; see `docs/LEGACY_PLATFORM.md`)
