# Customer Platform, Phase I (Slice 15)

## 0. Scope confirmation

Scanner v1 remains feature-frozen — no detector logic changed. This slice
built the first genuine frontend-facing API surface (dashboard, assets,
ownership verification, team, API keys, settings, secured report download)
and the first real customer-facing application (`apps/web`) on top of it,
plus everything needed to prove the whole thing end-to-end against a real
production-mode API, real PostgreSQL, and a real browser.

## 1. Backend API surface added

- `GET /v1/dashboard/summary` — real tenant-scoped counts only (assets,
  scans by status, findings by severity/status, recent scans, recent
  high/critical findings). No fabricated risk score: none exists yet, so
  none is exposed.
- `GET/POST /v1/assets`, `GET/PATCH /v1/assets/{id}` — asset CRUD with
  verification/authorization/last-scan/finding-count aggregation
  (`_asset_public_dict` in `service.py`). Existing authorization and
  TrustScan boundaries remain the sole thing that authorizes a scan; a
  `default_mode` field is a pre-fill for the Start Scan workflow, never a
  standing authorization.
- `POST /v1/assets/{id}/verification`, `POST /v1/assets/{id}/verification/check`
  — server-side-only `.well-known` HTTP token ownership verification
  (`target_verification.py`), reusing the scanner's own SSRF-safe
  `validate_target_url`/`fetch_once` rather than a second HTTP client. DNS
  TXT verification is a named, deferred gap (no DNS resolver library in
  this project's dependencies).
- `GET /v1/team`, `POST /v1/team/invitations`, `PATCH/DELETE /v1/team/{id}`
  — existing RBAC roles, not a frontend-invented role model. Self-lockout
  and privilege-escalation guards are enforced at the service layer: a
  principal cannot change their own role or deactivate themselves, and
  granting/revoking `owner` requires the caller to already be `owner`.
  Invitation issues an initial token directly (no email infrastructure
  exists this slice).
- `GET/POST /v1/api-keys`, `DELETE /v1/api-keys/{id}` — self-service,
  scoped to the calling principal's own tokens. Raw token returned exactly
  once; only its verifier/hash and metadata persist.
- `GET /v1/settings` — organization and account fields that are genuinely
  backed; no placeholder settings invented to fill a screen.
- Secured report download (`GET /v1/reports/{id}/download`) — report ID +
  tenant authorization + `ArtifactStore` abstraction; never a filesystem
  path.
- `do_PATCH`/`do_DELETE` on `http_api.py`'s `Handler` were, before this
  slice, aliased to `do_PUT` and always returned 405 — this slice's asset
  update, team update/remove, and API key revoke routes are the first
  real `PATCH`/`DELETE` handlers this API has ever had.

## 2. Frontend built (`apps/web`)

React 19 + TypeScript + Vite 8 + React Router 7 + TanStack Query 5 +
Tailwind v4, consuming `/v1/...` directly — no second backend, no BFF. See
`docs/product/WEB_APP_ARCHITECTURE.md` for the full stack rationale and
`docs/product/WEB_APP_DESIGN_SYSTEM.md` for the token/component system.
Thirteen pages (Login, Dashboard, Assets, Asset detail, Scans, Scan
detail, Findings, Finding detail, Reports, Schedules, Team, API Keys,
Audit Log, Settings), one app shell, one brand seam, one data layer
(`src/lib/api.ts` + `src/hooks/queries.ts`).

Two real gaps found and closed while building the UI, not left as
"future work":

- `ScanDetailPage` had no way to request a report at all, even though
  `ReportsPage`'s own empty state told the user to request one from
  there. Added a `RequestReportPanel` gated on `scan.status === "completed"`.
- `permitsApi.issue()`'s hardcoded `maximum_request_attempts: 20` exceeds
  `OwnedTargetLimits`'s own default cap of 15 — every real authorization
  using default limits would have rejected the Start Scan workflow
  outright with `trustscan_permit_request_budget_too_high`. Lowered to 10.

## 3. A real backend bug the browser E2E found that no prior test caught

`PostgresTargetVerificationRepository.get_current()` never populated
`expected_token` (always `None`), unlike the in-memory repository, which
correctly returns it while a verification is still pending. Every existing
test of this feature (`test_customer_platform_api.py`) runs against the
in-memory backend, so this never surfaced. The practical effect: a client
re-fetching the asset after `POST /v1/assets/{id}/verification` — which is
exactly what the frontend does, since `useStartVerification()` invalidates
and refetches rather than reusing the mutation's own response — received a
verification record with no `instructions`, so the "Check now" UI never
appeared and a real Postgres-backed deployment could never complete
ownership verification through the UI at all.

Fixed by recovering the token from the `evidence` column's
`"expecting:{token}"` placeholder whenever status is genuinely still
`pending` — not "returning it once a check has run" (which never happens;
`record_result` overwrites `evidence` with a real outcome the moment a
check executes), so this still matches the "one-time proof, not an ongoing
secret" contract the module docstring describes. Regression-covered by
`tests/integration/test_postgres_target_verification.py` (new, gated on
`WEBGUARD_RUN_INTEGRATION=1` + a real Postgres, matching every other
Postgres-only test in this repository).

This is the clearest evidence in this slice that "run the real, disposable
production API/PostgreSQL stack" (requirement 27/28) was not a
formality — it caught something a unit-test-only strategy structurally
could not.

## 4. CORS

The API had no browser caller before this slice and sent no CORS headers
at all. `http_api.py`'s `build_handler`/`create_server` now accept an
explicit `allowed_origins: frozenset[str]` allowlist; a `do_OPTIONS`
handler answers preflights; `_send_json` and the raw report-download
response both echo `Access-Control-Allow-Origin` only for a listed origin.
No wildcard support — `Authorization` is a real credential header, and
pairing it with `Access-Control-Allow-Origin: *` is precisely the mistake
this design avoids. `cli.py`'s `serve` command reads
`WEBGUARD_WEB_ALLOWED_ORIGINS` (comma-separated); nothing is allowed by
default.

## 5. Authentication status

The API has no browser session/cookie layer, only Bearer API tokens issued
via CLI bootstrap or `/v1/api-keys`. Per the brief's own anticipation of
this scenario, the frontend "login" is a paste-your-token screen validated
once against `GET /v1/me` before persisting (`src/lib/auth.tsx`) — not
invented insecure authentication, and not a placeholder blocked on future
work. Login/logout/session-expiry (via the global `webguard:unauthorized`
event) and access-denied states all work correctly today. Password reset
and email verification remain out of scope, as named in the brief, since
no email infrastructure exists.

## 6. Frontend security review

- **XSS**: React escapes all interpolated text by default; the codebase
  contains no `dangerouslySetInnerHTML`. The one place raw text renders
  inside an attribute-like context (finding evidence/remediation) is
  plain text content, not markup.
- **CSP readiness**: no inline `<script>`, no inline event handlers, no
  `eval`/`Function` string execution anywhere in the app — a CSP with
  `script-src 'self'` would work today without modification once actually
  deployed with headers (headers themselves are an infra/deployment
  concern out of this slice's scope).
- **CSRF**: not applicable in the current model — the API uses Bearer
  tokens in an `Authorization` header, never cookies, so there is no
  ambient credential a cross-site request could ride along with. This is
  the correct CSRF posture for a bearer-token API; it is not a
  workaround.
- **Cookies**: none are set or read by this application.
- **Token storage**: `sessionStorage`, not `localStorage` — deliberate,
  documented in `src/lib/auth-storage.ts`'s own docstring. Smaller exposure
  window (cleared on tab close, never sent cross-origin) at the cost of
  re-authenticating per browser session. This is an interim choice, named
  as such; the correct long-term fix (a real session-cookie + CSRF-token
  model) needs backend work this slice did not do.
- **No secrets in localStorage**: confirmed — nothing is written to
  `localStorage` anywhere in the app.
- **Dependency security**: no new runtime dependency was added beyond the
  stack listed in the architecture doc; all are current major-version
  releases from their respective ecosystems (React 19, Vite 8, TanStack
  Query 5, Tailwind v4).
- **Sensitive error handling**: every page renders the API's own
  `ApiError.message` — never a raw exception, stack trace, or internal
  identifier the API itself did not already decide was safe to return.
- **URL parameter handling**: the one place a value from application state
  is placed into a URL is `encodeURIComponent` around the asset URL used
  for cross-page filtering (`/findings?asset=...`); no user input is
  otherwise reflected into a URL, query string, or DOM without going
  through React's normal escaping.
- **Report download authorization**: goes through `GET /v1/reports/{id}/
  download` with the caller's own Bearer token — the same tenant-scoped
  authorization every other route enforces; the frontend never constructs
  or guesses a filesystem or storage path.
- No browser security control (autocomplete off where relevant on the
  token field, `rel="noreferrer noopener"` on external links, no
  `target="_blank"` without it) was disabled for convenience anywhere in
  this codebase.

## 7. Accessibility

- Semantic landmarks: `<header>`, `<nav aria-label="Primary">`, `<main
  id="main-content">`.
- A skip-to-content link (`Skip to main content`, visually hidden until
  focused) was added this slice — `id="main-content"` existed as a target
  before the link itself did.
- Every icon-only control has an `aria-label` (mobile nav toggle,
  disabled notifications bell, user menu via `aria-haspopup`/
  `aria-expanded`).
- The user menu closes on outside click and `Escape` (added this slice —
  it previously only closed via its own toggle button) and uses
  `role="menu"`/`role="menuitem"`.
- `LoadingState`/`ErrorState` use `role="status"`/`role="alert"` so screen
  readers announce state changes without polling.
- All form inputs use real `<label htmlFor>` associations.
- A global `:focus-visible` outline is defined once and never suppressed
  per-component.
- Contrast: text tokens (`#e9e7e2` primary, `#a3a9b2` secondary) against
  the canvas/surface tokens (`#0b0d10`/`#111418`) meet WCAG AA for normal
  text; this was checked by inspection against the token values, not
  measured with an automated contrast tool this slice.
- Not done this slice: a full automated axe/Lighthouse accessibility
  audit, and screen-reader manual testing. Named here as a real gap, not
  silently skipped.

## 8. Responsive behavior

Desktop is the primary target (dense tables, multi-column grids). Verified
manually at desktop viewport width via the browser E2E and a manual
click-through of every page. Tablet/mobile behavior (sidebar collapse,
mobile nav toggle) exists in the CSS/markup (`AppShell`'s `md:` breakpoints)
but was not separately exercised at reduced viewport widths this slice —
named as a gap rather than asserted as verified.

## 9. Browser E2E (requirement 28)

`apps/web/e2e/full-flow.spec.ts`, driven by Playwright/Chromium against a
real, disposable production-mode API + PostgreSQL + worker (started by
`apps/web/e2e/global-setup.ts` via
`tests/integration/webguard_e2e_server.py`, itself a thin wrapper around
`tests/integration/webguard_production_harness.py` — the same "real
Postgres, no AWS" startup sequence `test_production_mode_e2e.py` already
proved). One test, entirely through the real UI:

sign in → add a controlled HTTPS fixture asset → verify ownership through
the real server-side `.well-known` check (the fixture's own responder reads
the live pending token straight out of the running API's own repository —
no mocked token comparison) → confirm the pre-assigned authorization is
visible → start a real passive `single_page` scan → wait for the real
worker to complete it → confirm real, persisted findings (a
`webguard-passive` header-analysis finding is genuine here, since the
fixture deliberately sends no security headers) → open a finding and
change its lifecycle status → request a report and get the real, honest
"object-storage artifact persistence is not implemented" error (§10) → the
dashboard and reports pages both reflect real state throughout.

The only thing patched anywhere in this path is the "resolved address must
be public" SSRF gate for the fixture's loopback address — the same
substitution `test_production_mode_e2e.py` already makes, and the fixture
still undergoes a real TLS handshake, a real HTTP fetch, and a real
Postgres round trip for every step.

Two real environment issues were found and fixed while wiring this up, not
worked around:

- Python 3.14's new "skip hidden `.pth` files" behavior, combined with
  this machine's editable-install `.pth` files carrying the macOS
  `UF_HIDDEN` flag, silently broke every `webguard_api`/`webguard_scanner`/
  `webguard_contracts` import. Fixed by reinstalling the three editable
  packages with `--config-settings editable_mode=compat`.
- Vite's dev server binds only to the IPv6 loopback (`::1`) by default on
  this machine; Playwright's `webServer.url`/`use.baseURL` pointed at
  `127.0.0.1`, which nothing was listening on. Fixed with an explicit
  `--host 127.0.0.1` in the Playwright config's `webServer.command`.

## 10. Known limitations (stated honestly, not silently worked around)

- **Object-storage artifact persistence is not implemented** — a
  pre-existing Slice 14 decision (`ObjectStorageArtifactStore` raises
  `object_storage_not_implemented` explicitly). Requesting a report
  through the UI surfaces this real error rather than a fabricated
  success; the E2E test asserts on that real error message.
- **DNS TXT ownership verification is not implemented** — only
  `.well-known` HTTP token verification exists this slice, a named
  deferral (no DNS resolver library in this project's dependencies).
- **Schedule "edit" is enable/disable only** — there is no backend route
  to rename a schedule or change its interval, so the UI does not offer
  one; fabricating a non-existent backend capability was rejected in favor
  of this honest scope.
- **No password reset / email verification** — no email infrastructure
  exists this slice (requirement 29's own constraint); team invitation
  issues an initial token directly instead.
- **No automated accessibility audit tool was run** (axe/Lighthouse) —
  the accessibility work in §7 was verified by code inspection and manual
  interaction, not an automated scanner.
- **Tablet/mobile viewports were not separately exercised** — the
  responsive CSS exists; it was not driven at reduced viewport widths this
  slice.
- **Vitest component coverage is representative, not exhaustive** — 34
  tests across API contract, auth, routing, permission-gating, and the
  three most state-heavy pages (Assets, Asset detail, Finding detail);
  the remaining pages (Scans, Reports, Team, API Keys, Audit Log,
  Settings, Schedules) are exercised by the browser E2E and manual
  click-through but do not each have a dedicated component test file.

## 11. Test counts

- Backend unit tests: 1,492 passed (`tests/unit`, including 15 new
  customer-platform-API tests and 4 updated RBAC permission tests).
- Backend contract tests: 59 passed (31 skipped — environment-gated,
  pre-existing).
- Backend Postgres integration tests exercised this slice: 18 passed
  (`test_production_mode_e2e`, `test_postgres_tenant_isolation_slice13`,
  `test_postgres_connection_pool`, `test_production_runtime_completion_e2e`,
  plus 2 new in `test_postgres_target_verification.py`).
- Frontend unit/component tests (Vitest): 34 passed across 7 files.
- Frontend browser E2E (Playwright): 1 passed, covering the full product
  flow end to end.
