# ADR 0028: Reproducible CI and Supply-Chain Pins

## Status

Accepted as Checkpoint 1 audit remediation C1-001.

## Context

Checkpoint 1 identified that the same WebGuard commit could resolve different build tools, Python dependencies, GitHub Action implementations, or authorised-lab container content over time. The repository used dependency ranges, moving major-version Action tags, an unconstrained packaging-tool upgrade, and a mutable container tag. Functional tests reduced risk but did not make the tested software supply chain reproducible.

A security-assurance product should make dependency changes explicit review events. CI must not silently consume a new third-party implementation merely because a tag or compatible version moved.

## Decision

WebGuard adopts reviewed supply-chain pins for the current CI and development baseline:

1. `pip` is bootstrapped to an exact reviewed version using a SHA-256-verified wheel.
2. External Python dependencies used by WebGuard CI are exact-version and SHA-256 locked in `requirements-ci.lock`.
3. Repository-owned packages are installed with `--no-deps` and `--no-build-isolation` after the external lock is satisfied, preventing editable package installation from resolving or downloading additional dependencies.
4. Every package build backend pins `setuptools` to the reviewed version rather than a lower-bound range.
5. The API's direct `cryptography` dependency is exact-version pinned so package metadata does not silently widen the cryptographic runtime used by WebGuard.
6. GitHub Actions are referenced by immutable 40-character commit SHAs, with human-readable release versions retained in comments.
7. CI uses the explicit `ubuntu-24.04` runner family rather than the moving `ubuntu-latest` alias, and each tested Python interpreter is pinned to an exact patch release (`3.11.15`, `3.13.14`, `3.14.6`).
8. The OWASP Juice Shop lab image is referenced by its multi-platform OCI index digest as well as its release tag, preserving both AMD64 CI and ARM64 local development while preventing tag drift.
9. `scripts/verify-supply-chain-pins.py` runs inside the normal verification gate and fails closed if these reviewed invariants drift.

The current hash lock intentionally covers the GitHub-hosted Linux x86-64 Python 3.11/3.13/3.14 matrix and the project's current macOS ARM64 Python 3.14 development path. Supporting another platform requires adding its reviewed artifact hash rather than allowing an unreviewed fallback.

## Consequences

Positive consequences:

- the same commit resolves the same reviewed external Python versions;
- downloaded Python artifacts are checked against repository-held SHA-256 values;
- CI Action implementations and selected Python patch releases cannot move underneath an unchanged WebGuard commit;
- the authorised lab image cannot change underneath the `v20.1.1` tag;
- build isolation cannot introduce unreviewed build-time Python dependencies;
- supply-chain updates become visible diffs that receive normal code review.

Trade-offs:

- dependency upgrades now require intentionally refreshing versions and hashes;
- new developer/CI platforms may fail until their wheel hashes are reviewed and added;
- the `ubuntu-24.04` hosted-runner image still receives GitHub-managed image updates, so this ADR does not claim bit-for-bit operating-system reproducibility;
- the repository does not vendor third-party wheels, so availability still depends on the configured package index.

## Update procedure

A dependency update must:

1. select the intended upstream release;
2. verify release provenance from the authoritative upstream source;
3. update exact versions and repository-held SHA-256 hashes;
4. update immutable Action SHAs or OCI image digest where applicable;
5. run `./scripts/verify.sh` locally;
6. run the full authorised integration suite; and
7. pass the complete GitHub CI matrix before merge.
