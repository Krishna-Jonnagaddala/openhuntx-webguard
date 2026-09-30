# Customer Platform, Phase III: Production Customer Infrastructure I: Transactional Email, Object Storage & Report Delivery (Slice 17)

## 0. Scope confirmation

Scanner v1 remains feature-frozen: no detector logic changed, no new
vulnerability class added. The customer application's visual design is
unchanged; only wording/error-handling in two existing pages
(`ScanDetailPage.tsx`'s report-request panel, `ReportsPage.tsx`'s
download error message) was touched, and only because their underlying
backend behavior became real this slice.

This slice replaces the two highest-value remaining development-only
seams identified at the end of Slice 16: transactional email (logged,
never delivered) and object storage (an honest `object_storage_not_implemented`
stub). Both are now real, provider-backed implementations, reached
through the same duck-typed-client abstraction pattern this project
already established for KMS (Slice 12) and Secrets Manager (Slice 14),
never a vendor SDK imported into domain logic, never a new
dependency added to `requirements-ci.lock` for either.

See `docs/production/TRANSACTIONAL_EMAIL.md` and
`docs/production/ARTIFACT_STORAGE.md` for the full design of each; this
document is the implementation record.

## 1. Mail: `ProductionMailProvider` (Postmark)

`apps/api/src/webguard_api/mail.py`: `LoggingMailProvider` renamed to
`DevelopmentMailProvider` (matching the brief's explicit naming), plus
three new pieces: `MailDeliveryError` (a `category`-carrying exception:
`temporary`/`permanent`/`configuration`/`rate_limited`/`timeout`),
`PostmarkClientProtocol`/`PostmarkHttpClient` (a real HTTPS transport
built entirely on `http.client`/`json` (no vendor SDK, no new
dependency), and `ProductionMailProvider` (payload construction,
classification, and a single bounded retry for
`temporary`/`timeout` failures only, reusing the identical
already-built payload so a retry never regenerates the embedded
one-time token).

Every verification/reset/invitation email now contains a real
clickable link (`{web_app_base_url}/verify-email?token=...`, etc.)
instead of Slice 16's bare token text: the frontend's own
`VerifyEmailPage`/`ResetPasswordPage`/`AcceptInvitationPage` already
read `?token=` from the URL (built anticipating exactly this), so
**zero frontend code needed to change** for this to work end to end;
confirmed by the new Playwright specs below. `web_app_base_url` is a
new required, fail-closed `ProductionServiceConfig` field
(`WEBGUARD_WEB_APP_BASE_URL`), threaded through
`WebGuardJobService.__init__` and used nowhere else.

Added, as the brief's own "optional if already supported cleanly"
allowance: a `password_changed` security notification, sent from both
`change_password()` (in-session change) and `confirm_password_reset()`
(token-based reset), a standard security practice, cheap to add given
the mail infrastructure this slice already builds.

Anti-enumeration under delivery failure (requirement 4): a new
`_send_mail_best_effort()` choke point in `service.py` is the single
place every mail-send call goes through: it catches
`MailDeliveryError` and never re-raises it, uniformly across
registration, password-reset-request, resend-verification, and
invitation. No caller's HTTP response ever differs based on whether
the underlying send succeeded, closing the one new way a delivery
failure could otherwise have reintroduced an enumeration signal.

## 2. Object storage: `ObjectStorageArtifactStore` (S3)

`apps/api/src/webguard_api/artifact_store.py`: the Slice 14 stub is
replaced with a real implementation reached through a new
`S3ClientProtocol` (structurally satisfied by `boto3.client("s3")`,
never imported by this module): `put`/`get_reference`/`exists`/
`delete`/`checksum`, every write SSE-KMS-encrypted with a specific
customer-managed key (never SSE-S3's AWS-managed default, see
`ARTIFACT_STORAGE.md` §3 for the deliberate choice), every vendor
error translated into a fixed, non-leaking `ArtifactStoreError` before
it ever reaches a caller.

**A real, pre-existing gap closed, not just a new backend added**:
before this slice, `ScanJobExecutor` never actually called
`ArtifactStore.put()` at all: it wrote completed reports directly to
local disk via its own hand-rolled `_write_report` function, meaning
`ObjectStorageArtifactStore` could never have held real data even once
implemented. `executor.py` now accepts an injected `artifact_store`
(defaulted to `LocalArtifactStore(self.artifact_directory)`, every
pre-Slice-17 call site is byte-for-byte unaffected: identical
permissions, identical paths) and writes the completed report through
it; production wiring passes the *same* `ObjectStorageArtifactStore`
instance to both the executor (writes) and the service (reads). This
was found by reading `artifact_store.py`'s own Slice 14 module
docstring closely: it names `_write_report` as the exact behavior
`LocalArtifactStore` was extracted from, but the wiring back into the
executor was never completed until now.

Object keys are unchanged from the existing scheme
(`organizations/<org-id>/jobs/<job-id>/report.json`) rather than
adopting the brief's suggested `scans/.../reports/...` nesting: the
existing scheme already satisfies every real security property that
hierarchy exists for (tenant-scoped prefix, server-generated UUIDs,
never a customer filename); changing it would only migrate already-
persisted values for no security benefit. `_reject_unsafe_reference`
(shared with `LocalArtifactStore`) rejects path traversal for both
backends identically.

Report download integrity (requirement 14, a genuine gap this slice
closes): `download_report()` now re-computes SHA-256 over the bytes it
is about to serve and compares against the checksum persisted at
`create_report()` time, before this slice never checked at all. A
mismatch fails closed with `report_integrity_check_failed` (500)
rather than silently serving corrupted or truncated bytes. Tested
directly by tampering with an artifact after registration
(`test_customer_platform_api.py`) and proven for real end-to-end
against the fake-S3-backed store (`test_production_runtime_completion_e2e.py`,
downloading through real HTTP and asserting the SHA-256 match).

Secure download (requirement 11): authenticated API streaming was
chosen over a short-lived signed S3 URL: every download re-authorizes
on every call, and no bearer-credential-shaped URL is ever handed to
the customer. Full reasoning in `ARTIFACT_STORAGE.md` §8.

## 3. Infrastructure as code (requirement 23)

`infra/terraform/storage.tf` (new): one S3 bucket (versioned, SSE-KMS
encrypted with a dedicated key mirroring `postgres.tf`'s own pattern,
public access fully blocked, a bucket policy denying insecure/
unencrypted writes independent of the application), one lifecycle
policy (transition + expiration + incomplete-multipart-upload
cleanup, all operator-tunable via new `variables.tf` entries), and one
standalone, least-privilege `aws_iam_policy` (S3 + KMS actions scoped
to exactly this bucket/key, not attached to anything, since no
compute/IAM role exists in this directory to attach it to, matching
every other resource here). **No account created, nothing provisioned**,
reviewed, syntactically-complete IaC only, exactly like every prior
slice's Terraform work; no `terraform` binary is available in this
environment to run `validate`/`plan` (unchanged limitation from Slice
12). Redis was not touched, per the brief's own explicit instruction.

## 4. Browser E2E: registration, password reset, invitation, and a real report download (requirements 15-18, 24)

`tests/integration/webguard_production_harness.py` gained
`FakeS3Client` and `FakePostmarkTransport` (mirroring the existing
`FakeKmsClient` pattern exactly: fake only the AWS/Postmark network
boundary, real `webguard_api` code otherwise) and now constructs
`ObjectStorageArtifactStore`/`ProductionMailProvider` for real in every
dev/E2E stack it starts, matching production wiring. `webguard_e2e_server.py`
publishes a new `mail_sink_path`, a JSON Lines file
`FakePostmarkTransport` mirrors every "sent" message to, and
`apps/web/e2e/mail-sink.ts` (new) reads it from the separate Node/
Playwright process, recovering the exact verification/reset/invitation
link a browser action just caused the server to send.

Three new spec files, each entirely through the real UI:

- `registration.spec.ts`: register → real verification email →
  opening its link verifies the account → Settings reflects the
  verified state.
- `password-reset.spec.ts`: register → forgot password → real reset
  email → reset link → new password → the *old* session is
  provably revoked (a fresh load of a protected page redirects to
  `/login`) → the old password no longer works → the new password
  signs in.
- `invitation.spec.ts`: register (as owner) → invite a teammate with
  a role → real invitation email → sign the owner out (correctly
  simulating a *different* browser/person, since `AcceptInvitationPage`
  itself redirects an already-signed-in visitor away, per its own
  correct guard) → accept → the granted role is visible and RBAC
  enforces it → sign out → an independent fresh login with the
  invitee's own chosen password succeeds.

`full-flow.spec.ts`'s report step (requirement 24) no longer expects
"object-storage artifact persistence is not implemented": it now
requests a report, confirms success, then downloads it through the
real UI download button (Playwright's download interception, since the
UI triggers it via a Blob URL + synthetic `<a download>` click) and
parses the downloaded bytes as the real `WebGuardReport` this scan
actually produced (`target` matches, `findings` is a non-empty array)
, proof the whole generate → store → register → download pipeline
works against real (if network-substituted) object storage through the
actual customer UI.

All four specs pass together, one worker, against a single
disposable-Postgres-backed stack: `4 passed`.

## 5. Frontend UX (requirement 19)

Most of the states the brief names already existed from Slice 16
(email-sent/verify-your-email/resend-verification/reset-email-sent/
invitation-accepted pages were built anticipating exactly the link
shape this slice's emails now produce, confirmed, not assumed, by the
new registration/password-reset/invitation E2E specs above). Two small
wording/error-handling changes closed the remaining gap:

- `ScanDetailPage.tsx`'s report-request button now reads "Generating
  report…" while pending (was the generic "Requesting…"), and its
  error state shows the backend's own sanitized message rather than a
  hardcoded string.
- `ReportsPage.tsx`'s download failure path now surfaces the backend's
  own error message (parsed from the JSON error envelope, falling back
  to a generic message if parsing fails) instead of a single fixed
  string, satisfying requirement 20 (no vendor leakage) automatically,
  since the backend's own `ApiServiceError` messages never contain
  vendor detail in the first place (verified by
  `test_mail_provider.py`'s and `test_object_storage_artifact_store.py`'s
  own "vendor detail never leaks" assertions at the source).

## 6. Known limitations (stated honestly, not silently worked around)

- **No per-organization artifact retention policy**: one uniform S3
  lifecycle policy today (`ARTIFACT_STORAGE.md` §7); the natural
  extension point (object tagging) is named but not implemented.
- **Audit/safety-receipt files remain local-filesystem-only**: the
  object-storage migration this slice is scoped to reports
  specifically (requirement 8's "where applicable" for evidence
  artifacts); migrating the `webguard_contracts`-level
  path-based write helpers those use is a materially larger, riskier
  change this slice's own scope does not require.
- **Scan-result notification emails are not sent**: the notification
  model itself (what, how often, opt-out) is not yet defined, per the
  brief's own instruction not to guess at it.
- **No `terraform validate`/`plan` was run**: no Terraform binary is
  available in this environment (unchanged limitation since Slice 12).
- **Vitest could not be run this regression pass**: a session-local
  environment issue (every Vitest worker, fork or thread pool, timed
  out waiting to start, even on a completely unmodified test file with
  zero relation to this slice's changes) that `tsc --noEmit`, `vite
  build`, and a plain Node `child_process.fork()` sanity check were all
  unaffected by. This is not treated as a passing result; it is
  reported as not run. Confidence in the two frontend files this slice
  actually changed (`ScanDetailPage.tsx`, `ReportsPage.tsx`) instead
  comes from: neither has ever had dedicated Vitest coverage (confirmed
  by grep against all 7 existing frontend test files, zero
  references), and both are now exercised for real by the Playwright
  E2E suite (§4), which passed.
- **No real Juice-Shop-lab integration run this slice**: those tests
  are unrelated to identity/mail/storage and were not re-run (the lab
  Docker Compose stack was not started this session), matching the
  same documented, unrelated gap already named in Slice 16's own audit
  doc.

## 7. Test counts

- Backend unit tests: 1,560 passed (`tests/unit`), 32 new: 10 in
  `test_mail_provider.py` (Postmark payload construction, retry-once
  for temporary/timeout only, no-retry for permanent/configuration/
  rate-limited, no-vendor-leakage), 13 in
  `test_object_storage_artifact_store.py` (encryption parameters,
  round-trip, missing-object, path-traversal rejection, access-denied
  translation, no-vendor-leakage, cross-tenant-key isolation), 1 in
  `test_job_executor.py` (report routed through an injected
  `ArtifactStore`, audit/safety-receipt untouched), 1 in
  `test_customer_platform_api.py` (download fails closed on a
  tampered/corrupted artifact), 7 in `test_production_config.py` (new
  required mail/object-storage fields, each rejected when
  missing/invalid).
- Backend contract tests: 59 passed, 0 skipped (run against a real,
  disposable PostgreSQL).
- Backend PostgreSQL integration tests (non-lab): 42 passed, including
  both production E2E files rewritten this slice to construct/exercise
  the real (fake-S3/fake-Postmark-backed) `ObjectStorageArtifactStore`/
  `ProductionMailProvider` code paths, and a new real-download-plus-
  checksum assertion in `test_production_runtime_completion_e2e.py`.
- Frontend build (`tsc -b && vite build`): passes.
- Frontend lint (`oxlint`): passes (only pre-existing warnings,
  unrelated to this slice).
- Frontend browser E2E (Playwright): 4 passed: the full product flow
  (now including a real report download + bytes validation) plus the
  three new registration/password-reset/invitation specs.
- Frontend unit/component tests (Vitest): not run this pass, see
  Known limitations.

## 8. Security gates

Repository secret scan (450 files, 6 generated artifacts, 931
reachable Git blobs, clean), `ruff --select S` static analysis
(clean), locked-dependency advisory audit (12 exact-pinned packages,
unchanged from Slice 16, no new dependency added), supply-chain pin
verification (clean), governance-doc verification (clean), `git diff
--check` (clean).
