# Releasing WebGuard

How a release goes from a merged `main` to a package on PyPI, what each step proves, and what to do when an upload goes wrong. Nothing here has been run against the real PyPI yet; the first release is also the first test of steps 4 through 6.

Two distributions are released together, and the order matters: `openhuntx-webguard-contracts` (the dependency) and `openhuntx-webguard` (the CLI, which pins `openhuntx-webguard-contracts==<same version>`). A user who installs the CLI while the contracts upload is missing gets an unresolvable install, so contracts always goes first.

## The sequence

1. **Review and merge the release pull request.** Branch protection requires all eleven CI checks, but not a human review; a review is the owner's call. Merge with a merge commit so the commit history stays readable.
2. **Check CI on the resulting `main` commit.** The pull request's checks ran on the PR head, not on the merge commit. Open the push-to-`main` run for the merge commit and confirm it is green before going further.
3. **Decide the license, then apply it.** Run `python scripts/apply-license.py --license <MIT|Apache-2.0> --holder "<name>" --dry-run`, read the diff, then rerun with `--apply`, open that as its own pull request, and let CI pass. Do this before the first upload: PyPI files are permanent, and a release published without a license cannot be corrected in place. (Skipping this step is a decision too; the workflow does not require it.)
4. **Configure the two PyPI trusted publishers.** See below. Both need the project name registered, which for a new project happens through a *pending* publisher: PyPI creates the project on the first upload that matches it.
5. **Rehearse.** Actions, "Publish to PyPI", Run workflow, branch `main`, mode `dry-run` (the default). It builds both wheels from `main`, runs the release validation on exactly those files, passes them to the publish job, re-verifies their checksums there, stages one directory per project, and queries PyPI for what already exists. It stops before any upload. Read the job summary: it lists the commit and the SHA-256 of each wheel.
6. **Publish, after explicit authorization.** Same workflow, mode `publish`, confirmation `publish`. The publish job uploads `openhuntx-webguard-contracts`, then `openhuntx-webguard`, each from its own single-file directory, with Sigstore attestations.
7. **Verify a fresh public install.** From a clean machine or container, no checkout and no `--find-links`:

   ```bash
   pipx install openhuntx-webguard
   webguard --version
   webguard doctor
   python3 -m http.server 8931 --bind 127.0.0.1 > /dev/null 2>&1 &
   webguard scan http://127.0.0.1:8931/ --lab --allow-host 127.0.0.1 --output demo.json
   kill $!
   ```

   Only after this passes can the README say the PyPI install path is verified. Until then it says it is not.

## What the workflow checks before it uploads anything

`scripts/verify-release-artifacts.py` runs in the build job, and the same script runs in the pull-request `cli-packaging` job, so a regression shows up before release day.

- The build directory holds exactly the two expected wheels and nothing else: no sdist, no checksum file, no subdirectory, no symlink.
- Each wheel's own METADATA has the right distribution name, a version matching its filename, and the same version as the other wheel. The contracts wheel has no dependencies. The CLI wheel depends on exactly `openhuntx-webguard-contracts==<that version>`.
- Wheel contents are an allowlist: `.py` files under the package directory, and the standard files under `dist-info` (plus a `licenses/` directory once a license is applied). The `webguard` console script is declared exactly once.
- Both wheels install into a fresh virtual environment from those files only, with no index. `pip check` passes, the imports resolve inside that environment and not in the checkout, and the installed CLI completes a synthetic scan, a results listing, and a report render from a directory outside the repository.
- The files are unchanged after all of that, and their SHA-256 checksums are written to `SHA256SUMS`.

The publish job never rebuilds. It downloads the artifact (a digest mismatch is a hard error), checks the file listing is exactly the two wheels plus the checksum file, and compares each wheel's SHA-256 to values the build job passed through a separate channel (job outputs, not the artifact), before copying each wheel into its own staging directory and checking again.

Wheels are built with `SOURCE_DATE_EPOCH` set to the commit time, which makes them byte-reproducible from a commit on the same toolchain. To check a published file later, check out the same commit, set `SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"`, run the two `pip wheel` commands from the workflow, and compare the SHA-256 against the job summary. A different Python or setuptools build can in principle produce different bytes, so a mismatch calls for a look, not an alarm.

## PyPI trusted publishers

**Known problem, not yet fixed in this branch.** An independent review of this release candidate found that PyPI refuses to register two *pending* publishers whose owner, repository, workflow, and environment are identical (its uniqueness constraint ignores the project name). The table below is therefore not registrable as written, and a single `publish` run would upload contracts and then fail on the CLI upload, because the first upload consumes the pending publisher. Before the first publish, pick one fix and change the workflow, `scripts/verify-supply-chain-pins.py`, and this document together: either two environments (`pypi-publish-contracts` and `pypi-publish-webguard`, each limited to `main`) with one publish job per project, or a two-phase first release (register contracts only, add a contracts-only mode and run it, then register the CLI publisher and run `publish-webguard-only`). Do not treat the `publish` mode as ready until that is done.

Register at <https://pypi.org/manage/account/publishing/> (a pending publisher, because neither project exists yet). As currently designed the fields are identical except for the project name.

| Field | `openhuntx-webguard-contracts` | `openhuntx-webguard` |
|---|---|---|
| PyPI project name | `openhuntx-webguard-contracts` | `openhuntx-webguard` |
| Owner | `openhuntx` | `openhuntx` |
| Repository name | `openhuntx` | `openhuntx` |
| Workflow name | `publish.yml` | `publish.yml` |
| Environment name | `pypi-publish` | `pypi-publish` |

The GitHub side already exists: the `pypi-publish` environment, with a deployment-branch policy that allows only `main`. That server-side policy is the control that holds even if someone edits the workflow on another branch. Two optional hardening steps live in the same settings page and are the owner's call: adding yourself as a required reviewer on the environment (the publish job then pauses for an explicit approval after the rehearsal-grade checks have run), and, on PyPI, 2FA on the account that owns the projects.

## When an upload goes wrong

PyPI never lets a filename be uploaded twice, even after the release is deleted, so none of the recovery paths below overwrite anything.

- **Contracts upload fails.** Nothing is on PyPI (the CLI upload only starts after contracts succeeds). Fix the cause and run `publish` again. The pre-upload PyPI check confirms both versions are still absent.
- **Contracts uploads, the CLI upload fails.** PyPI now has `openhuntx-webguard-contracts` at this version and no CLI. Nothing can install the CLI yet, so no user is affected. Fix the cause (usually trusted-publisher configuration or a transient PyPI error) and run mode `publish-webguard-only`. It refuses to run unless contracts is already on PyPI at that version and the CLI is not. The rebuilt contracts wheel is not uploaded, so it does not matter that it may differ byte-for-byte from the one already published.
- **A published file turns out to be wrong.** Do not try to replace it. Yank the bad release on PyPI (hides it from resolvers without deleting it), bump the version in both `pyproject.toml` files and in the contracts pin, merge, and release the new version as a fresh pair. The version bump is required because the old filenames are gone for good.
- **The workflow fails partway through the publish job for a reason that is not obvious.** Read the PyPI project pages for both names before rerunning. The pre-upload check exists so a rerun refuses cleanly instead of guessing, but it only sees the JSON API, which can lag an upload by a moment.

## What is not covered

The publish job runs as the `pypi-publish` environment on `main` and nothing else. Nothing in this workflow verifies that CI passed on the exact commit being published; the sequence above does, by hand, in step 2. The build backend (`setuptools==83.0.0`) is pinned by version in each `pyproject.toml` but fetched from PyPI at build time without hash-pinning, as it is in every other build in this repository.
