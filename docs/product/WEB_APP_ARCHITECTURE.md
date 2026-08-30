# WebGuard Web App Architecture (Slice 15; updated Slices 16-17)

## 1. What this is

`apps/web` is the OpenHuntX WebGuard customer platform: a browser SPA that
lets a signed-in organization manage assets, run scans, and review findings
against the existing production `webguard-api` service. It is the first
customer-facing surface built on top of the API contract documented in
`WEB_APP_API_CONTRACT_V1.md`.

```
Browser (React SPA, apps/web)
    │  fetch, Bearer token
    ▼
WebGuard API  (/v1/... — apps/api/src/webguard_api)
    │
    ├── PostgreSQL (identity, targets, scans, jobs, findings, ...)
    ├── ScanJobWorker (real threads, renewable leases)
    └── Scanner v1 (workers/scanner — unchanged, feature-frozen)
```

There is no second backend. Every mutation the UI performs is a call to an
existing or newly-added `/v1/...` route, authenticated the same way any
other API client would be. The frontend cannot construct or bypass a
TrustScan permit, cannot mark an asset verified, and cannot see a raw
secret or API token it did not just create.

## 2. Stack decision

| Concern | Choice | Why |
|---|---|---|
| Framework | React 19 + TypeScript | Already the dominant frontend stack; large ecosystem, first-class TS support. |
| Build tool | Vite 8 | Matches the backend's own "avoid unnecessarily heavy dependencies" ethos while remaining genuinely production-viable; fast dev loop. |
| Routing | React Router 7 | The de facto standard; nested layout routes match the app-shell/page structure directly. |
| Server-state | TanStack Query 5 | The API has no client-side cache of its own; Query owns loading/error/refetch/invalidation instead of hand-rolled `useEffect` fetch logic. |
| Styling | Tailwind CSS v4 (`@tailwindcss/vite`, CSS-first `@theme`) | Design tokens live in one CSS file (`src/index.css`); no separate JS theme object to keep in sync. |
| Testing | Vitest + React Testing Library (component) / Playwright (E2E) | Vitest shares Vite's config and transform pipeline; Playwright's Chromium build was already viable in this environment. |
| Lint | oxlint | Bundled with the Vite scaffold; fast, zero-config baseline. |

No state-management library, no CSS-in-JS runtime, no component library was
added. The app is small enough that TanStack Query plus local component
state covers every real need.

## 3. Authentication model (rewritten in Slice 16)

The web app now authenticates with a real, server-side browser session —
not a pasted API token. `POST /v1/auth/login` sets an `HttpOnly` `wg_session`
cookie (the frontend never reads, stores, or even sees the raw session
credential) plus a separate, non-`HttpOnly` `wg_csrf` cookie used only to
echo an `X-CSRF-Token` header back on state-changing requests. Every
`fetch` call in `src/lib/api.ts` sets `credentials: "include"`, so the
browser attaches `wg_session` automatically; there is nothing for this
codebase to store in `sessionStorage`/`localStorage`/`IndexedDB` at all —
`src/lib/auth-storage.ts` (Slice 15's interim sessionStorage-token module)
was deleted outright, not deprecated.

`src/lib/auth.tsx`'s `AuthProvider` derives all session state from
`GET /v1/auth/session` (never from browser storage): `refresh()` calls it
on mount, `login()`/`register()`/`acceptInvitation()` each call their own
`/v1/auth/...` endpoint and adopt its response directly. The existing
global `webguard:unauthorized` event (dispatched by `api.ts` on any 401)
still clears local state, but is now guarded so a session that was never
established (the very first, expected 401 on a fresh visit) does not
surface a spurious "you were signed out" message — only a 401 that
invalidates an *already-established* session does.

Full lifecycle — registration, login/logout/logout-everywhere, password
change/reset, email verification, and invitation acceptance — is now real
and documented in `docs/product/CUSTOMER_AUTH_ARCHITECTURE.md` (product
model) and `docs/security/BROWSER_SESSION_SECURITY.md` (session/CSRF/
cookie security design). API-token paste-based login no longer exists
anywhere in the product; the old `GET /v1/me` Bearer-token path remains
available unchanged for CLI/API clients, and the web app's own
self-service API-key management (Slice 15) is unaffected.

## 4. Application shell and routing

`src/App.tsx` defines two branches: a public `/login` route, and everything
else behind a `RequireAuth` gate that renders `AppShell` (`src/components/
layout/AppShell.tsx` — top bar, sidebar, `<Outlet/>`). `RequireAuth` reads
`useAuth().status` (`"checking" | "signed-out" | "signed-in"`) and redirects
to `/login` for a signed-out visitor; an unknown path falls back to the
dashboard.

Pages: Dashboard, Assets, Asset detail, Scans, Scan detail, Findings,
Finding detail, Reports, Schedules, Team, API Keys, Audit Log, Settings —
one file each under `src/pages/`, each backed by one or more hooks in
`src/hooks/queries.ts`.

## 5. Data layer

`src/lib/api.ts` is the single point of contact with the API: one `request()`
function attaches the Bearer token, builds query strings, and normalizes
every non-2xx response into a typed `ApiError` (status, code, message,
request ID) that pages render directly — the same error surface the API
itself produces, never a generic frontend-invented message. Resource-scoped
objects (`assetsApi`, `scansApi`, `findingsApi`, ...) wrap `request()` per
route; `src/hooks/queries.ts` wraps each of those in a TanStack Query hook
(query key, refetch interval, and mutation invalidation rules live there,
in one place, organized by resource).

## 6. The TrustScan boundary, from the browser

`permitsApi.issue()` issues a deliberately narrow, fixed-shape permit: the
requested target, the caller-selected authorization, a single permitted
mode (`single_page` or `crawl`), GET/HEAD only, `active_checks: []`. The
frontend never grants an authenticated-scanning context, an active check,
or an authorization-comparison plan — those remain operator/API-only
capabilities this UI does not expose. Every scan the UI can start goes
through the exact same `/v1/permits` → `/v1/jobs` pair any other API client
uses; there is no shortcut.

Two real timing constants matter here and are documented inline where they
live (`api.ts`'s `permitsApi.issue`, `hooks/queries.ts`'s
`useIssuePermitAndSubmitJob`/`useCreateSchedule`): a permit's `not_before`
must be far enough in the future to still be ahead of the server's clock
once real network/render latency has elapsed, and the caller's post-issue
wait before submitting the job must in turn exceed that offset — get either
one wrong and the API correctly rejects the job as "permit pending" or the
permit issuance itself as "not_before in the past." This was tuned against
the real, disposable production stack (§8), not guessed.

`maximum_request_attempts` in the issued permit (10) is also deliberately
kept under `OwnedTargetLimits`' own default cap (15) — a permit requesting
more than its authorization allows is rejected outright, so the UI's
default must never assume a larger authorization than a real one might
carry.

## 7. CORS (credentials added in Slice 16)

`apps/api/src/webguard_api/http_api.py` accepts an explicit
`allowed_origins` allowlist (`build_handler`/`create_server`), answers
`OPTIONS` preflights, and echoes `Access-Control-Allow-Origin` only for a
listed origin — no wildcard, since both `Authorization` and the new
`wg_session` cookie are real credentials. `cli.py`'s `serve` command reads
`WEBGUARD_WEB_ALLOWED_ORIGINS` (comma-separated); nothing is allowed by
default, so a production deployment must opt an origin in explicitly.

Slice 16 added `Access-Control-Allow-Credentials: true` to both the actual
response and the `OPTIONS` preflight — required for `fetch(..., {credentials:
"include"})` to work cross-origin at all, and only ever paired with a
reflected, allowlisted origin (never `*`). See
`docs/security/BROWSER_SESSION_SECURITY.md` §3 for the full cross-origin
threat model, including why a denied origin's preflight response omits
these headers entirely rather than rejecting with an error status (the
browser itself is what enforces the block; the server's job is only to
withhold permission).

## 8. Real-backend testing infrastructure

`tests/integration/webguard_production_harness.py` extracts the
"real-Postgres, no-AWS" startup sequence already proven by
`test_production_mode_e2e.py` into an importable `run_production_stack()`
context manager (real HTTP server, real worker thread, one bootstrapped
organization/owner/token). Slice 17 extended the same pattern to object
storage and email: `FakeS3Client` and `FakePostmarkTransport` fake only
the AWS/Postmark network boundary, exactly like the existing
`FakeKmsClient` does for signing -- the real
`ObjectStorageArtifactStore`/`ProductionMailProvider` code paths run
unmodified against them, so this harness (and everything built on it)
proves the actual production wiring, not a substitute. Three things
consume it:

- `scripts/dev/run_local_webguard_api.py` — a manual dev helper that prints
  a ready-to-use email/password login for exercising the frontend against a genuine
  backend during development.
- `apps/web/e2e/global-setup.ts` — spawns
  `tests/integration/webguard_e2e_server.py` (a thin wrapper around the
  harness plus one controlled HTTPS fixture asset) as a subprocess before
  the Playwright suite runs, and publishes its base URL / bootstrapped
  credentials / fixture target URL / a mail-sink file path into
  `process.env` for each spec to read. `apps/web/e2e/mail-sink.ts`
  reads that file to recover the exact verification/reset/invitation
  link a browser action just caused the server to "send" -- see
  `registration.spec.ts`, `password-reset.spec.ts`, and
  `invitation.spec.ts`, none of which reach around the UI to poke the
  API directly.
- `tests/integration/test_production_mode_e2e.py` / `test_production_runtime_completion_e2e.py`
  — the backend's own production E2E proofs, now including a real
  report download against the fake-S3-backed object store with a
  SHA-256 checksum assertion (Slice 17 requirement 15).

The fixture asset intentionally sends no security headers, so a genuine
*passive* `single_page` scan (the only kind the UI's Start Scan workflow
ever requests) trips real `webguard-passive` findings — no active checks,
no mocked scanner output. Its `.well-known/webguard-verification.txt`
responder reads the live pending token straight out of the same process's
`target_verifications` repository, so ownership verification is exercised
for real too. The only thing patched is the "resolved address must be
public" SSRF gate (the same one `test_production_mode_e2e.py` already
patches) — a loopback fixture standing in for a target that would
otherwise have to be a real public host.

## 9. What is deliberately not here

- No server-side rendering, no BFF layer — a second backend was explicitly
  out of scope.
- No client-side routing guard beyond `RequireAuth`; RBAC visibility (hiding
  actions a role cannot perform) is a UX courtesy, never the security
  boundary — the API remains authoritative and re-checks every request.
- No offline support, no service worker.
