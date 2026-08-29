# WebGuard Web App Architecture (Slice 15)

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

## 3. Authentication model

The API has no browser session or cookie layer — only Bearer API tokens,
issued via CLI bootstrap or `POST /v1/api-keys`. There is no password to
authenticate with. Given that, "login" here means: paste an existing API
token, and the app validates it once against `GET /v1/me` before persisting
anything (`src/lib/auth.tsx`). This is not a placeholder for a future real
login — it is the honest frontend adaptation of the API's actual auth
model, matching the brief's own anticipation of this exact scenario
("if full customer browser-auth infrastructure does not yet exist, build a
functional frontend shell... rather than inventing insecure browser
authentication").

The validated token is stored in `sessionStorage`, not `localStorage` (see
`src/lib/auth-storage.ts`'s docstring and §7 of
`docs/audit/customer-platform-phase1.md` for the full tradeoff). A global
`webguard:unauthorized` event, dispatched by `src/lib/api.ts` on any 401,
clears the session and returns the user to `/login` — this is the only
place session state is cleared other than an explicit sign-out.

There is no password reset or email-based flow (no email infrastructure
exists — see requirement 29's "no production email" constraint); team
invitation issues an initial token directly instead (§10a of the API
contract doc).

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

## 7. CORS

The API previously had no browser caller and sent no CORS headers.
`apps/api/src/webguard_api/http_api.py` now accepts an explicit
`allowed_origins` allowlist (`build_handler`/`create_server`), answers
`OPTIONS` preflights, and echoes `Access-Control-Allow-Origin` only for a
listed origin — no wildcard, since `Authorization` is a real credential
header. `cli.py`'s `serve` command reads `WEBGUARD_WEB_ALLOWED_ORIGINS`
(comma-separated); nothing is allowed by default, so a production
deployment must opt an origin in explicitly.

## 8. Real-backend testing infrastructure

`tests/integration/webguard_production_harness.py` extracts the
"real-Postgres, no-AWS" startup sequence already proven by
`test_production_mode_e2e.py` into an importable `run_production_stack()`
context manager (real HTTP server, real worker thread, one bootstrapped
organization/owner/token). Two things consume it:

- `scripts/dev/run_local_webguard_api.py` — a manual dev helper that prints
  a ready-to-paste API token for exercising the frontend against a genuine
  backend during development.
- `apps/web/e2e/global-setup.ts` — spawns
  `tests/integration/webguard_e2e_server.py` (a thin wrapper around the
  harness plus one controlled HTTPS fixture asset) as a subprocess before
  the Playwright suite runs, and publishes its base URL / bootstrapped
  token / fixture target URL into `process.env` for the spec to read.

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
