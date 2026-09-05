# WebGuard Web App API Contract (v1)

## Purpose and scope

This is **not a frontend design document.** It is the contract the WebGuard web app builds against: which `/v1/...` endpoints exist today, what they return, what stability guarantee each carries, and which UI surfaces they support. Nothing here is aspirational: every endpoint listed is implemented and tested. As of Slice 15, every UI surface the brief names has a real backing endpoint except where stated explicitly as a gap (Assets/Team/Settings backends were completed in Slice 15; a small number of narrower gaps remain, named in each section below and in §10's summary).

**Stability markers**, per endpoint or field group:

- `STABLE_V1`: the shape is committed; a frontend can build against it now, and a breaking change would require a new version or an explicit migration note in this document.
- `EXPERIMENTAL`: implemented and tested, but the shape may still change based on real frontend usage (most of what shipped this slice: findings lifecycle, reports, scans-as-a-resource).
- `INTERNAL`: exists for the platform's own use (audit, health/readiness) and is not intended as a primary UI data source, though a UI may still read it.

All endpoints below require `Authorization: Bearer <token>` **or** an authenticated `wg_session` browser cookie (§0) unless marked public. All are tenant-scoped to the authenticated caller's organization; cross-organization access fails closed as 404 (see `docs/ARCHITECTURE.md` Boundary B). All list endpoints share one pagination/filtering contract (§9).

## 0. Authentication: `STABLE_V1` (new in Slice 16)

Two independent, always-available authenticator paths, both resolving into the identical RBAC `AuthContext` (see `docs/security/BROWSER_SESSION_SECURITY.md` §1 for the full design rationale: there is exactly one authorization model, never a separate "browser" permission set):

- **`Authorization: Bearer <token>`**: unchanged from Slice 12, for CLI/API/automation clients. Never subject to CSRF checks (§0d).
- **`wg_session` cookie** (`HttpOnly`, `Secure` in production, `SameSite=Lax`): for the web app. The raw cookie value is never readable by JavaScript and never appears in a JSON response body.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/auth/register` | Public. Body: `{"organization_name", "display_name", "email", "password"}`. Creates a new organization + `owner` principal + password credential, issues an email-verification token (§0c), and establishes a session immediately (auto-login, no separate post-registration login step). 409 on a duplicate email. Rate-limited by IP. |
| `POST` | `/v1/auth/login` | Public. Body: `{"email", "password"}`. Returns the same session shape as `GET /v1/auth/session` and sets the session/CSRF cookies. **Identical generic 401 (`invalid_credentials`)** whether the email does not exist or the password is wrong: no account-enumeration signal. Rate-limited per `email+IP`. |
| `POST` | `/v1/auth/logout` | Revokes the current session only. |
| `POST` | `/v1/auth/logout-all` | Revokes every session for the calling principal, including the current one ("sign out everywhere"). |
| `GET` | `/v1/auth/session` | The session-aware replacement for `GET /v1/me` (still available, unchanged, for Bearer clients). Fields: `organization_id`, `organization_name`, `principal_id`, `principal_name`, `role`, `auth_method` (`"api_token"` \| `"browser_session"`), `token_id` (the session ID for browser sessions, never a secret), and, only when `auth_method == "browser_session"`, a nested `session` object (`session_id`, `assurance_level`, `issued_at`, `idle_expires_at`, `absolute_expires_at`, `last_used_at`). No secret or hash ever appears here either. |

### 0a. Password lifecycle

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/auth/password/change` | Authenticated. Body: `{"current_password", "new_password"}`. Revokes every **other** session for the caller (keeps the session used to make the change): a role/credential-strength change is a session-rotation boundary. |
| `POST` | `/v1/auth/password/reset/request` | Public. Body: `{"email"}`. **Always** returns the same generic message regardless of whether the address matches an account: no enumeration signal, no distinguishable timing-sensitive branch in the response shape. Rate-limited by IP. |
| `POST` | `/v1/auth/password/reset/confirm` | Public. Body: `{"token", "new_password"}`. Single-use, expiry-bounded (1 hour) token. Revokes **every** session for the account (a password reset is a full "sign out everywhere" boundary, unlike an in-session password change). Rate-limited by IP. |

### 0b. Email verification

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/auth/email/verify/request` | Authenticated. Re-sends a verification email (resend). Rate-limited by IP. |
| `POST` | `/v1/auth/email/verify/confirm` | Public. Body: `{"token"}`. Single-use, expiry-bounded (24 hours). Rate-limited by IP. |

### 0c. Invitations

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/team/invitations` | See the revised §10a below: issues a mailed invitation token, not a raw API token. |
| `POST` | `/v1/auth/invitations/accept` | Public. Body: `{"token", "password"}`. Single-use, expiry-bounded (7 days) token. Sets the invited principal's password, marks their email verified (accepting a mailed link is treated as proof of mailbox control), and establishes a session immediately (auto-login). Rate-limited by IP. |

### 0d. CSRF

Every state-changing (`POST`/`PATCH`/`DELETE`) request authenticated via the `wg_session` cookie must echo the separate, non-`HttpOnly` `wg_csrf` cookie's value back as an `X-CSRF-Token` header, or the request fails with `403 csrf_token_invalid` (distinct from `401`, which means "not authenticated at all"). `GET` requests never require it. A request authenticated via `Authorization: Bearer` is never subject to this check, regardless of whether it happens to also carry a stray session cookie. See `docs/security/BROWSER_SESSION_SECURITY.md` §2 for the full threat model this defends against, including why `SameSite=Lax` alone is not treated as sufficient.

No endpoint in this section ever returns a raw session secret, CSRF secret, password, or reset/verification/invitation token in a JSON body: tokens are delivered exclusively via the mail provider (§0's docs) or, for the session/CSRF pair, exclusively via `Set-Cookie`.

## 1. Dashboard: `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/dashboard/summary` | Tenant-scoped aggregate. No query parameters. |

Response fields: `total_assets`, `verified_assets`, `active_scans`, `completed_scans`, `failed_scans`, `findings_by_severity` (object keyed by severity), `findings_by_status` (object keyed by lifecycle status), `recent_scans` (up to 5, same shape as §3's scan object), `recent_high_or_critical_findings` (up to 5, same shape as §5's finding object), `counts_capped_at` (an integer: the underlying scan/finding counts are computed from up to this many most-recent records, not the organization's true lifetime total, to keep the endpoint's cost bounded; a large organization's dashboard reflects its most recent activity accurately but its all-time totals only approximately). **No fabricated risk score**: only real counts, per the brief's own instruction; a defensible risk-scoring model, if one is ever built, would be an additive field here, never a replacement for these counts. RBAC: `jobs.read`.

## 2. Assets (targets): `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/assets` | Body: `{"url": "...", "label": "<optional>", "default_mode": "single_page"\|"crawl"\|null}`. 409 on a duplicate URL within the organization. |
| `GET` | `/v1/assets` | Paginated (§9's standard contract). No filters yet. |
| `GET` | `/v1/assets/{target_id}` | Full detail (see fields below). |
| `PATCH` | `/v1/assets/{target_id}` | Body may include `label` and/or `default_mode` (either `null` or omitted to leave unchanged vs. omitted entirely: omit a key to leave it untouched, send it explicitly as `null` to clear it). |

List-response fields: `target_id`, `organization_id`, `url`, `label`, `default_mode`, `created_at`, `archived_at`. Detail-response fields add: `verification` (the current `TargetVerificationRecord`, or `null` if never started, see §2a), `authorization` (`{"authorization_id", "issued_at", "expires_at", "state": "active"|"expiring_soon"|"expired"}`, or `null` if no assigned authorization currently covers this exact URL, matched by exact URL string, since targets and authorizations are deliberately separate entities with no foreign key between them), `last_scan` (§3's scan object, or `null`), `finding_counts` (object keyed by severity, computed from up to 100 most-recent findings for this asset, see `finding_count_is_capped`). **Registering an asset never grants scan permission**: the existing authorization/TrustScan boundaries are entirely unchanged and remain the only thing that can actually authorize a scan; `default_mode` only pre-fills what the "Start Scan" workflow offers. RBAC: `assets.read` for the two `GET` routes, `assets.manage` for `POST`/`PATCH`.

### 2a. Ownership verification: `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/assets/{target_id}/verification` | Starts (or restarts) verification. No body. Returns `{"verification_id", "method": "well_known_http", "status": "pending", "expires_at", "instructions": {"path": "/.well-known/webguard-verification.txt", "expected_content": "<token>"}}`. The `instructions`/token are returned **only** while status is `pending` and only from this call and the immediately-following detail read before a check runs, never re-derivable afterward. |
| `POST` | `/v1/assets/{target_id}/verification/check` | No body. The server fetches `{scheme}://{host[:port]}/.well-known/webguard-verification.txt` from the asset's own origin (via the same safe-fetch machinery the scanner itself uses: public-address-only resolution, bounded response) and compares it against the expected token. Returns the updated verification record. 409 if no verification is currently pending. |

Only `method: "well_known_http"` is implemented; DNS TXT verification is a named, deferred gap (see `docs/audit/customer-platform-phase1.md`). **The frontend can never mark an asset verified directly**: `status` only ever becomes `verified` as the return value of a real server-side fetch performed by the `/verification/check` call above. RBAC: `assets.manage` for both routes (starting or checking verification is a management action, not a read).

## 10a. Team: `EXPERIMENTAL` (new in Slice 15, invitation flow revised in Slice 16)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/team` | Lists every principal in the organization (all roles, including inactive/removed members). |
| `POST` | `/v1/team/invitations` | Body: `{"display_name": "...", "email": "...", "role": "owner"\|"administrator"\|"analyst"\|"viewer"}`. **Revised in Slice 16**: `email` is now required. Creates the principal (no password yet) and sends a real invitation email via the identity-token/mail-provider layer (`docs/product/CUSTOMER_AUTH_ARCHITECTURE.md` §4); it no longer returns a raw `initial_token` to relay out-of-band. The recipient sets their own password via `POST /v1/auth/invitations/accept` (§0c). Granting `owner` requires the caller to already be `owner`. |
| `PATCH` | `/v1/team/{principal_id}` | Body: `{"role": "..."}`. A principal cannot change their own role (self-lockout prevention); granting or revoking `owner` requires the caller to already be `owner`. **New in Slice 16**: also revokes every browser session belonging to the target principal, forcing re-authentication under the new role. |
| `DELETE` | `/v1/team/{principal_id}` | Deactivates (`active: false`), never a row deletion, matching this API's standing revoke-over-delete convention everywhere else (permits, tokens, authentication contexts). A principal cannot deactivate themselves; removing an `owner` requires the caller to already be `owner`. **New in Slice 16**: also revokes every browser session belonging to the target principal. |

Response fields: `principal_id`, `organization_id`, `display_name`, `principal_type`, `role`, `active`, `created_at`, `email` (`string \| null`), `email_verified_at` (`string \| null`, a `null` value is the UI's "pending" signal for an unaccepted invitation), `last_login_at` (`string \| null`). RBAC: `team.read` for `GET` (all four roles), `team.manage` for the other three (`owner`/`administrator` only). Role names are the existing domain roles exactly (`owner`, `administrator`, `analyst`, `viewer`), no frontend-only role model.

## 10b. API keys: `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/api-keys` | Lists the **calling principal's own** tokens only: self-service, no cross-principal visibility, matching how personal-access tokens work in most developer-facing products. No RBAC permission beyond authentication. |
| `POST` | `/v1/api-keys` | Body: `{"label": "...", "validity_days": <optional int>}`. Returns the metadata plus `token`, the raw bearer token, **returned exactly once**, never retrievable again. Only the scrypt hash is persisted. |
| `DELETE` | `/v1/api-keys/{token_id}` | Revokes. 404 (not 403) if the token belongs to a different principal: cross-principal existence is not distinguishable from not-found. |

Response fields (excluding the one-time `token`): `token_id`, `label`, `created_at`, `expires_at`, `revoked_at`, `last_used_at`.

## 10c. Settings: `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/settings` | No query parameters. |

Response: `{"organization": {"organization_id", "name", "status", "created_at"}, "account": {<the calling principal's own §10a fields>}}`. **Intentionally minimal**: no notification preferences, scan-defaults, or session-preference storage exists in the backend yet, and this endpoint does not invent placeholder fields for settings that are not real. There is no write route this slice (no genuine settings value is currently mutable beyond what §2/§10a already cover: an asset's `default_mode`, a team member's role).

## 10d. Report download: `STABLE_V1` (new in Slice 15; production object storage completed in Slice 17)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/reports/{report_id}/download` | Not JSON, returns the raw artifact bytes with `Content-Type` matching the report's format and `Content-Disposition: attachment`. Tenant-checked identically to every other report route. Never exposes `report_ref`, a bucket name, or an S3 URL, signed or otherwise: only the bytes, streamed through the API after a real integrity check (see below). |

Production is now real, S3-backed object storage (`docs/production/ARTIFACT_STORAGE.md`); the Slice 15/16 placeholder 503 (`object_storage_not_implemented`) no longer occurs. Before returning bytes, the server re-computes the artifact's SHA-256 and compares it against the checksum persisted at report-creation time; a mismatch (a corrupted or truncated object) fails closed with `report_integrity_check_failed` (500) rather than serving bad bytes. **Authenticated API streaming was chosen over a short-lived signed S3 URL** (`docs/production/ARTIFACT_STORAGE.md` §8 has the full reasoning): every report request is re-authorized on every call, and no bearer-credential-shaped URL is ever handed to the client.

## 3. Scans: `STABLE_V1` for read shape, `EXPERIMENTAL` overall (new this slice)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/scans` | Paginated, tenant-scoped. Filters: `status` (enum: `queued`\|`running`\|`completed`\|`completed_with_errors`\|`failed`\|`cancelled`), `target` (free-form, exact match). |
| `GET` | `/v1/scans/{scan_id}` | Single scan record. |

Response fields (both endpoints): `scan_id`, `organization_id`, `job_id`, `target`, `authorization_id`, `mode`, `status`, `scanner_version`, `permit_id`, `requested_checks` (array), `finding_count`, `report_ref`, `cancellation_requested`, `created_at`, `started_at`, `completed_at`, `cancelled_at`. RBAC: `jobs.read` (scans share the job-read permission; there is no separate scan permission, see §10).

A scan is the durable record of one *execution* (distinct from a job, which is the queue/lease entity, see `docs/ARCHITECTURE.md` §7). A UI "Scans" list/detail page should read from here, not from `/v1/jobs`, once a scan record exists; `/v1/jobs/{id}/result` remains the mechanism for polling an in-flight job to completion.

## 4. Jobs: `STABLE_V1`

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/jobs` | Submit a scan job. Requires `Idempotency-Key` and `TrustScan-Permit` headers. |
| `GET` | `/v1/jobs` | Paginated. Filters: `state` (enum), `mode` (enum: `single_page`\|`crawl`). |
| `GET` | `/v1/jobs/{job_id}` | Single job record. |
| `GET` | `/v1/jobs/{job_id}/result` | Poll until terminal; 409 while still running. |
| `POST` | `/v1/jobs/{job_id}/cancel` | Request cancellation. |

This is the oldest, most heavily regression-tested surface in the API (Slices 1-13). No shape changes this slice.

## 5. Findings: `EXPERIMENTAL` (lifecycle/history new this slice; read shape stable since Slice 13)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/findings` | Paginated. Filters: `status` (enum), `severity` (enum: `informational`\|`low`\|`medium`\|`high`\|`critical`), `scan_id` (free-form), `cwe_id` (free-form), `asset` (free-form, exact match). |
| `GET` | `/v1/findings/{finding_id}` | Single finding. |
| `POST` | `/v1/findings/{finding_id}/status` | Lifecycle transition. Body: `{"status": "confirmed"\|"false_positive"\|"accepted_risk"\|"resolved", "reason": "<optional string, ≤2000 chars>"}`. `reopened` is rejected with `finding_status_not_client_settable`: it is reachable only by scanner re-detection. Idempotent: repeating the identical status is a 200 no-op, not an error. |
| `GET` | `/v1/findings/{finding_id}/events` | Append-only lifecycle history: `{"finding_id": ..., "events": [{"event_id", "previous_status", "new_status", "reason", "changed_by" (principal ID or null for scanner-driven reopen), "created_at"}, ...]}`, chronological. |

**A finding-detail page's full picture is `GET /v1/findings/{id}` + `GET /v1/findings/{id}/events` together**: the first gives current state (severity, evidence, remediation, first/last seen), the second gives the "why did this become CONFIRMED / who accepted the risk / when did it reopen" narrative. Neither alone is sufficient for the "finding detail/lifecycle" UI surface the brief names.

RBAC: `findings.read` (OWNER/ADMINISTRATOR/ANALYST/VIEWER) for the two `GET` routes; `findings.update` (OWNER/ADMINISTRATOR/ANALYST, not VIEWER) for the status-change route.

## 6. Schedules: `STABLE_V1` for CRUD, `EXPERIMENTAL` for the underlying execution guarantee (live-wired to PostgreSQL this slice)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/schedules` | Create. Requires `TrustScan-Permit` header. |
| `GET` | `/v1/schedules` | Paginated. Filters: `state` (enum: `active`\|`paused`), `target` (free-form, exact match, new this slice). |
| `GET` | `/v1/schedules/{schedule_id}` | Single schedule. |
| `POST` | `/v1/schedules/{schedule_id}/pause` | No body. |
| `POST` | `/v1/schedules/{schedule_id}/resume` | No body. |

There is no hard-delete endpoint for schedules: `pause` is the disable mechanism, matching this codebase's existing pattern of revocation over deletion everywhere else (permits, authentication contexts, comparison plans all use `revoke`, never `DELETE`). A UI "disable schedule" action maps to `pause`, not to a destructive delete.

## 7. Reports: `EXPERIMENTAL` (new this slice)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/reports` | Body: `{"scan_id": "<uuid>"}`. Registers the completed scan's existing report artifact as a tracked entity; 409 if the scan has not completed. Returns metadata including a SHA-256 `checksum` computed from the artifact's actual bytes. |
| `GET` | `/v1/reports` | Paginated. Filter: `scan_id` (free-form). |
| `GET` | `/v1/reports/{report_id}` | Single report record. |

Response fields: `report_id`, `organization_id`, `scan_id`, `format`, `state`, `report_ref` (an internal artifact reference, not a public download URL), `checksum`, `created_at`, `completed_at`. **`report_ref` is never directly exposed or fetchable by a browser**: the bytes it resolves to are retrieved only through `GET /v1/reports/{report_id}/download` (§10d), which re-authorizes the request and streams the artifact through the API; production's artifact backend is real, S3-backed object storage as of Slice 17 (`docs/production/ARTIFACT_STORAGE.md`).

## 8. Authentication contexts and comparison plans: `INTERNAL`/`EXPERIMENTAL`, not primary UI surfaces yet

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/authentication-contexts` | Owner-only. Local/dev: raw credential fields in body (`bearer_token`/`cookies`/`basic_username`/`basic_password`). Production: `secret_reference_id` only; raw credential fields are rejected with `authentication_context_raw_secret_not_accepted`. |
| `POST` | `/v1/authentication-contexts/{id}/revoke` | No body. |
| `POST` | `/v1/authorization-comparisons` | Owner-only (comparison-plan registration is reserved, matching the active-check RBAC pattern). |
| `POST` | `/v1/authorization-comparisons/{id}/revoke` | No body. |

These exist to support authenticated scanning and IDOR/BOLA workflows (permit issuance references them by ID) but there is no `GET` list/detail route for either today: an operator sets these up once per identity/plan, generally via API/CLI as part of scan configuration, not as an ongoing-management UI surface. If a future "Authenticated Scanning" settings page is built, it needs new `GET` routes added first.

## 9. Pagination and filtering: `STABLE_V1`

Every list endpoint above shares one contract:

- `?limit=<1-100>` (default 50).
- `?cursor=<opaque signed token>` from a previous response's `page.next_cursor`.
- Response shape: `{"<resource>": [...], "page": {"limit": <int>, "next_cursor": <string|null>}}`.
- Cursors are HMAC-signed and bound to: the authenticated organization, the resource type, and the exact filter set in effect when issued. Changing the filters, switching organizations (impossible for a single token, but relevant if a cursor is somehow replayed against a different token), or tampering with the cursor all fail closed with a 400, never silently returning a different page.
- Filters come in two shapes: **enum filters** (`state`, `status`, `severity`, `mode`, `outcome`) validated against a fixed accepted-value set, and **free-form filters** (`target`, `asset`, `scan_id`, `cwe_id`) accepted as any bounded, control-character-free string. Both are bound into the signed cursor identically: a UI does not need to treat them differently when building "next page" requests, only when building the *initial* filter form (enum filters should render as a fixed choice list; free-form filters as free text).

## 10. Audit log: `STABLE_V1`

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/audit-events` | Paginated. Filter: `outcome` (enum: `succeeded`\|`failed`\|`denied`). |

Fields: `event_id`, `action`, `resource_type`, `resource_id`, `outcome`, `detail_code`, `occurred_at`, `principal_id`, `token_id`, `request_id`. `detail_code` is always a canonical identifier, never free text or a secret-bearing payload: every internal event that could otherwise carry sensitive detail (e.g. a verification check's raw response body) is reduced to a fixed code before being audited. RBAC: `audit.read`.

**Summary for frontend planning (updated Slice 17)**: Authentication (real email/password browser sessions, registration, password reset, email verification, invitation acceptance, §0, now with real Postmark-delivered email, `docs/production/TRANSACTIONAL_EMAIL.md`), Scans, Findings (including lifecycle/history), Schedules, Reports (including download, now real S3-backed object storage, `docs/production/ARTIFACT_STORAGE.md`), Dashboard, Assets (including ownership verification), Team, API Keys, Settings, and Audit Log all have real, tested API surfaces and can be built against now. Remaining named gaps, none of which block the UI surfaces above: DNS TXT verification (only `.well-known` HTTP is implemented, §2a); no organization-settings write route beyond what §2/§10a already cover; no true multi-organization support (a principal still belongs to exactly one organization, a deliberate Slice 16 scope decision, see `docs/product/CUSTOMER_AUTH_ARCHITECTURE.md` §6); no per-organization artifact retention policy (one uniform S3 lifecycle policy today, see `docs/production/ARTIFACT_STORAGE.md` §7); scan-result notification emails are not sent (the notification model itself is not yet defined, see `docs/production/TRANSACTIONAL_EMAIL.md` §4).

## 11. What this document is not

It does not specify response HTTP headers beyond what §9 states, error-response shapes beyond the existing `{"error": {"code", "message", "request_id"}}` convention used everywhere in this API, or any visual/interaction design. It reflects implemented, tested behavior as of Slice 17 (`docs/audit/customer-platform-phase3-production-delivery.md`) and should be updated in the same slice that changes any endpoint it describes, not left to drift.
