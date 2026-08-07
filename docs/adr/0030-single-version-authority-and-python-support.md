# ADR 0030: Single API Version Authority and Explicit Python Support

- Status: Accepted
- Date: 2026-08-07
- Audit findings: C1-004, C1-007

## Context

Checkpoint 1 identified two consistency risks. The API version existed independently in both `apps/api/pyproject.toml` and `webguard_api.__init__`, so a release could update one value while leaving the other stale. The packages also declared `requires-python = ">=3.11"` while CI did not exercise every Python minor implied by that open-ended claim.

## Decision

1. `apps/api/src/webguard_api/_version.py` is the single source of truth for the API version.
2. `webguard_api.__init__` re-exports that value instead of defining another literal.
3. Setuptools reads the same value through dynamic project metadata, so built distribution metadata, the module version, and the CLI version share one authority.
4. WebGuard packages explicitly support Python 3.11 through 3.14 with `requires-python = ">=3.11,<3.15"`.
5. CI exercises every supported Python minor using reviewed exact patch releases: 3.11.15, 3.12.13, 3.13.14, and 3.14.6.
6. Exact patch pins remain supply-chain review inputs and may be advanced deliberately without changing the supported minor range.
7. The Python 3.12 Linux x86-64 CFFI wheel hash is included in the reviewed dependency lock so the new matrix member remains hash-locked.

## Consequences

A version bump now changes one canonical file. Packaging and CLI version drift becomes detectable. The declared Python compatibility window matches the minors exercised in CI, while future Python 3.15 support requires an explicit code, dependency, and CI review rather than being claimed automatically.

## Verification

The supply-chain verifier fails if the project reintroduces a static API version, if the dynamic version attribute changes, if a package widens or narrows the reviewed Python range unexpectedly, or if the CI matrix stops covering a supported minor. Unit coverage also compares installed distribution metadata with the package version exported to the CLI.
