# ADR 0032: Automated CI Security Gates

- Status: Accepted
- Date: 2026-08-07
- Audit finding: C1-003

## Context

Checkpoint 1 found that WebGuard CI provided strong functional and authorised-integration coverage but did not automatically reject probable committed credentials, known vulnerabilities in exact locked Python dependencies, or common Python security anti-patterns.

For a security-assurance product, these checks must be blocking controls rather than occasional manual review. The controls also need to preserve the reproducibility guarantees introduced by ADR 0028: security tooling must not be installed from floating versions or moving CI actions.

## Decision

WebGuard CI adds a dedicated `Security gates` job with read-only repository permissions and the same fixed Ubuntu, Python, pip, checkout-action and setup-python pins used by the existing workflow.

The job runs three independent controls.

### 1. Repository secret scanning

`scripts/scan-secrets.py` scans Git-tracked files plus non-ignored untracked files in the current source tree. It rejects strong credential indicators including WebGuard API tokens, private-key PEM blocks, GitHub tokens, AWS access keys, Slack tokens, Google API keys, OpenAI API keys and live Stripe secret/restricted keys.

The scanner executes deterministic self-tests before scanning the repository. It reports rule identifier, file and line number, but never prints the matched secret value.

Ignored operational directories remain outside the source-tree scan because they are excluded by Git and must not be committed in the first place.

### 2. Static Python security analysis

Ruff `0.16.2` runs the `S` rule family, which re-implements flake8-bandit security checks, across WebGuard first-party package source code.

Ruff is installed from `requirements-security.lock` using exact versioning, SHA-256 hashes, `--require-hashes`, `--no-deps`, and binary-only installation. The reviewed hashes cover the GitHub-hosted Linux x86-64 CI runner and the supported macOS ARM64 developer path.

`S101` (use of `assert`) is the only baseline exception. Checkpoint 1 separately verified the WebGuard unit suite with Python optimisation enabled, which removes assertions, and the suite still passed. Assertions are therefore treated as internal invariant/debug checks rather than security-enforcement controls. Any additional Ruff security-rule exception requires explicit review rather than a broad ignore.

### 3. Locked-dependency vulnerability audit

`scripts/audit-dependencies.py` reads the exact package versions from `requirements-bootstrap.lock`, `requirements-ci.lock`, and `requirements-security.lock`, then queries the official PyPI JSON endpoint for vulnerability records associated with those exact releases.

Active advisories fail the security job. Withdrawn advisories do not. A network failure, malformed advisory response, missing vulnerability field, or version mismatch also fails closed rather than silently declaring the dependency set safe.

The tool versions are reproducibly pinned, while advisory intelligence is intentionally current and therefore time-varying. A previously green commit can correctly become blocked later if a new vulnerability is disclosed for a locked dependency.

## Supply-chain controls

`scripts/verify-supply-chain-pins.py` now verifies the security-tool lock, exact Ruff wheel hashes, the presence of the security CI job, the reviewed install/run scripts, and the complete set of GitHub Actions used by the workflow. Adding a new GitHub Action therefore requires deliberate review and an update to the verifier instead of silently expanding the CI supply chain.

The authorised Juice Shop integration job depends on both the unit-test matrix and the security job, so network integration does not proceed after a failed security gate.

## Rejected baseline alternative

A third-party secret-scanning GitHub Action was not added. The Checkpoint 1 review found that adding another action would enlarge the trusted CI action set, and a public upstream report documents a secret-detection regression in the then-latest Gitleaks `v8.30.1` release. The baseline therefore uses a small first-party, self-testing source scanner. A broader external scanner may be adopted later only after its release, licence, integrity and detection behaviour are independently reviewed and pinned.


## Validation findings and reviewed exceptions

### Dependency advisory discovered during remediation

The first live execution of the dependency-vulnerability gate identified active security advisories affecting the previously locked `cryptography==46.0.7` dependency.

No advisory waiver was accepted. The runtime dependency and reviewed wheel hashes were upgraded to `cryptography==50.0.0`, which contains the fixes required by the active advisories observed during Checkpoint 1 validation.

This demonstrates an intended property of the security gate: a previously accepted exact dependency pin must become blocking when current advisory intelligence identifies that release as vulnerable.

### Ruff security-rule review

Six findings from the initial Ruff security analysis were individually reviewed.

Two `S105` findings are non-secret identifiers:

- `TOKEN_PREFIX = "wgt"` is a public API-token format prefix, not credential material.
- `API_TOKEN_METADATA_TYPE = "api_token_metadata"` is a contract/schema discriminator, not a password.

Four `S608` findings are controlled SQL construction sites. The interpolated portions are internally selected SQL syntax fragments such as fixed predicates and clause combinations. External values continue to be supplied through SQLite `?` parameter binding.

These reviewed locations use narrow inline `noqa` annotations. `S105` and `S608` are not globally disabled; new occurrences remain blocking and require independent review.


## Consequences

- Every pull request receives a blocking automated security check.
- Probable source-tree credentials are rejected without echoing their values.
- Common Python security anti-patterns are statically checked.
- Exact locked Python dependencies are evaluated against current advisory data.
- Security tooling itself follows the repository's reproducible supply-chain policy.
- CI gains one additional job; the expected workflow is four unit-test checks, one security check and one authorised integration check.
- The dependency advisory gate requires network access to PyPI and intentionally fails closed when advisory data cannot be obtained.

## Verification

The remediation is complete only when:

1. `scripts/verify-supply-chain-pins.py` passes;
2. the secret scanner self-test and repository scan pass;
3. Ruff security analysis passes or individual findings are explicitly remediated/reviewed;
4. the locked-dependency advisory audit passes against live PyPI data;
5. the existing WebGuard verification gate passes; and
6. all six GitHub CI checks are green on the remediation pull request.
