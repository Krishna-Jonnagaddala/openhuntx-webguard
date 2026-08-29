# WebGuard Web App API Contract (v1)

## Purpose and scope

This is **not a frontend design document.** It is the contract the WebGuard web app builds against: which `/v1/...` endpoints exist today, what they return, what stability guarantee each carries, and which UI surfaces they support. Nothing here is aspirational — every endpoint listed is implemented and tested. As of Slice 15, every UI surface the brief names has a real backing endpoint except where stated explicitly as a gap (Assets/Team/Settings backends were completed in Slice 15; a small number of narrower gaps remain, named in each section below and in §10's summary).

**Stability markers**, per endpoint or field group:

- `STABLE_V1` — the shape is committed; a frontend can build against it now, and a breaking change would require a new version or an explicit migration note in this document.
- `EXPERIMENTAL` — implemented and tested, but the shape may still change based on real frontend usage (most of what shipped this slice: findings lifecycle, reports, scans-as-a-resource).
- `INTERNAL` — exists for the platform's own use (audit, health/readiness) and is not intended as a primary UI data source, though a UI may still read it.

All endpoints below require `Authorization: Bearer <token>` unless marked public. All are tenant-scoped to the authenticated token's organization; cross-organization access fails closed as 404 (see `docs/ARCHITECTURE.md` Boundary B). All list endpoints share one pagination/filtering contract (§9).

## 1. Dashboard — `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/dashboard/summary` | Tenant-scoped aggregate. No query parameters. |

Response fields: `total_assets`, `verified_assets`, `active_scans`, `completed_scans`, `failed_scans`, `findings_by_severity` (object keyed by severity), `findings_by_status` (object keyed by lifecycle status), `recent_scans` (up to 5, same shape as §3's scan object), `recent_high_or_critical_findings` (up to 5, same shape as §5's finding object), `counts_capped_at` (an integer — the underlying scan/finding counts are computed from up to this many most-recent records, not the organization's true lifetime total, to keep the endpoint's cost bounded; a large organization's dashboard reflects its most recent activity accurately but its all-time totals only approximately). **No fabricated risk score** — only real counts, per the brief's own instruction; a defensible risk-scoring model, if one is ever built, would be an additive field here, never a replacement for these counts. RBAC: `jobs.read`.

## 2. Assets (targets) — `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/assets` | Body: `{"url": "...", "label": "<optional>", "default_mode": "single_page"\|"crawl"\|null}`. 409 on a duplicate URL within the organization. |
| `GET` | `/v1/assets` | Paginated (§9's standard contract). No filters yet. |
| `GET` | `/v1/assets/{target_id}` | Full detail (see fields below). |
| `PATCH` | `/v1/assets/{target_id}` | Body may include `label` and/or `default_mode` (either `null` or omitted to leave unchanged vs. omitted entirely — omit a key to leave it untouched, send it explicitly as `null` to clear it). |

List-response fields: `target_id`, `organization_id`, `url`, `label`, `default_mode`, `created_at`, `archived_at`. Detail-response fields add: `verification` (the current `TargetVerificationRecord`, or `null` if never started — see §2a), `authorization` (`{"authorization_id", "issued_at", "expires_at", "state": "active"|"expiring_soon"|"expired"}`, or `null` if no assigned authorization currently covers this exact URL — matched by exact URL string, since targets and authorizations are deliberately separate entities with no foreign key between them), `last_scan` (§3's scan object, or `null`), `finding_counts` (object keyed by severity, computed from up to 100 most-recent findings for this asset — see `finding_count_is_capped`). **Registering an asset never grants scan permission** — the existing authorization/TrustScan boundaries are entirely unchanged and remain the only thing that can actually authorize a scan; `default_mode` only pre-fills what the "Start Scan" workflow offers. RBAC: `assets.read` for the two `GET` routes, `assets.manage` for `POST`/`PATCH`.

### 2a. Ownership verification — `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/assets/{target_id}/verification` | Starts (or restarts) verification. No body. Returns `{"verification_id", "method": "well_known_http", "status": "pending", "expires_at", "instructions": {"path": "/.well-known/webguard-verification.txt", "expected_content": "<token>"}}`. The `instructions`/token are returned **only** while status is `pending` and only from this call and the immediately-following detail read before a check runs — never re-derivable afterward. |
| `POST` | `/v1/assets/{target_id}/verification/check` | No body. The server fetches `{scheme}://{host[:port]}/.well-known/webguard-verification.txt` from the asset's own origin (via the same safe-fetch machinery the scanner itself uses — public-address-only resolution, bounded response) and compares it against the expected token. Returns the updated verification record. 409 if no verification is currently pending. |

Only `method: "well_known_http"` is implemented; DNS TXT verification is a named, deferred gap (see `docs/audit/customer-platform-phase1.md`). **The frontend can never mark an asset verified directly** — `status` only ever becomes `verified` as the return value of a real server-side fetch performed by the `/verification/check` call above. RBAC: `assets.manage` for both routes (starting or checking verification is a management action, not a read).

## 10a. Team — `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/team` | Lists every principal in the organization (all roles, including inactive/removed members). |
| `POST` | `/v1/team/invitations` | Body: `{"display_name": "...", "role": "owner"\|"administrator"\|"analyst"\|"viewer"}`. **No email-based invitation flow exists** (no production email this slice, per the brief's own instruction) — this creates the principal and issues an initial API token directly, returned once as `initial_token`; the inviter relays it out-of-band, exactly as CLI bootstrap already requires. Granting `owner` requires the caller to already be `owner`. |
| `PATCH` | `/v1/team/{principal_id}` | Body: `{"role": "..."}`. A principal cannot change their own role (self-lockout prevention); granting or revoking `owner` requires the caller to already be `owner`. |
| `DELETE` | `/v1/team/{principal_id}` | Deactivates (`active: false`) — never a row deletion, matching this API's standing revoke-over-delete convention everywhere else (permits, tokens, authentication contexts). A principal cannot deactivate themselves; removing an `owner` requires the caller to already be `owner`. |

Response fields: `principal_id`, `organization_id`, `display_name`, `principal_type`, `role`, `active`, `created_at` (plus `initial_token` on the invitation response only). RBAC: `team.read` for `GET` (all four roles), `team.manage` for the other three (`owner`/`administrator` only). Role names are the existing domain roles exactly — `owner`, `administrator`, `analyst`, `viewer` — no frontend-only role model.

## 10b. API keys — `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/api-keys` | Lists the **calling principal's own** tokens only — self-service, no cross-principal visibility, matching how personal-access tokens work in most developer-facing products. No RBAC permission beyond authentication. |
| `POST` | `/v1/api-keys` | Body: `{"label": "...", "validity_days": <optional int>}`. Returns the metadata plus `token` — the raw bearer token, **returned exactly once**, never retrievable again. Only the scrypt hash is persisted. |
| `DELETE` | `/v1/api-keys/{token_id}` | Revokes. 404 (not 403) if the token belongs to a different principal — cross-principal existence is not distinguishable from not-found. |

Response fields (excluding the one-time `token`): `token_id`, `label`, `created_at`, `expires_at`, `revoked_at`, `last_used_at`.

## 10c. Settings — `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/settings` | No query parameters. |

Response: `{"organization": {"organization_id", "name", "status", "created_at"}, "account": {<the calling principal's own §10a fields>}}`. **Intentionally minimal** — no notification preferences, scan-defaults, or session-preference storage exists in the backend yet, and this endpoint does not invent placeholder fields for settings that are not real. There is no write route this slice (no genuine settings value is currently mutable beyond what §2/§10a already cover — an asset's `default_mode`, a team member's role).

## 10d. Report download — `EXPERIMENTAL` (new in Slice 15)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/reports/{report_id}/download` | Not JSON — returns the raw artifact bytes with `Content-Type` matching the report's format and `Content-Disposition: attachment`. Tenant-checked identically to every other report route. Never exposes `report_ref` (an internal artifact reference, never a filesystem path or public URL) — only the bytes it resolves to, through `ArtifactStore`. In production, before object storage exists (Slice 14 §6), this fails closed with 503 (`object_storage_not_implemented`), not a fabricated success. |

## 3. Scans — `STABLE_V1` for read shape, `EXPERIMENTAL` overall (new this slice)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/scans` | Paginated, tenant-scoped. Filters: `status` (enum: `queued`\|`running`\|`completed`\|`completed_with_errors`\|`failed`\|`cancelled`), `target` (free-form, exact match). |
| `GET` | `/v1/scans/{scan_id}` | Single scan record. |

Response fields (both endpoints): `scan_id`, `organization_id`, `job_id`, `target`, `authorization_id`, `mode`, `status`, `scanner_version`, `permit_id`, `requested_checks` (array), `finding_count`, `report_ref`, `cancellation_requested`, `created_at`, `started_at`, `completed_at`, `cancelled_at`. RBAC: `jobs.read` (scans share the job-read permission; there is no separate scan permission — see §10).

A scan is the durable record of one *execution* (distinct from a job, which is the queue/lease entity — see `docs/ARCHITECTURE.md` §7). A UI "Scans" list/detail page should read from here, not from `/v1/jobs`, once a scan record exists; `/v1/jobs/{id}/result` remains the mechanism for polling an in-flight job to completion.

## 4. Jobs — `STABLE_V1`

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/jobs` | Submit a scan job. Requires `Idempotency-Key` and `TrustScan-Permit` headers. |
| `GET` | `/v1/jobs` | Paginated. Filters: `state` (enum), `mode` (enum: `single_page`\|`crawl`). |
| `GET` | `/v1/jobs/{job_id}` | Single job record. |
| `GET` | `/v1/jobs/{job_id}/result` | Poll until terminal; 409 while still running. |
| `POST` | `/v1/jobs/{job_id}/cancel` | Request cancellation. |

This is the oldest, most heavily regression-tested surface in the API (Slices 1-13). No shape changes this slice.

## 5. Findings — `EXPERIMENTAL` (lifecycle/history new this slice; read shape stable since Slice 13)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/findings` | Paginated. Filters: `status` (enum), `severity` (enum: `informational`\|`low`\|`medium`\|`high`\|`critical`), `scan_id` (free-form), `cwe_id` (free-form), `asset` (free-form, exact match). |
| `GET` | `/v1/findings/{finding_id}` | Single finding. |
| `POST` | `/v1/findings/{finding_id}/status` | Lifecycle transition. Body: `{"status": "confirmed"\|"false_positive"\|"accepted_risk"\|"resolved", "reason": "<optional string, ≤2000 chars>"}`. `reopened` is rejected with `finding_status_not_client_settable` — it is reachable only by scanner re-detection. Idempotent: repeating the identical status is a 200 no-op, not an error. |
| `GET` | `/v1/findings/{finding_id}/events` | Append-only lifecycle history: `{"finding_id": ..., "events": [{"event_id", "previous_status", "new_status", "reason", "changed_by" (principal ID or null for scanner-driven reopen), "created_at"}, ...]}`, chronological. |

**A finding-detail page's full picture is `GET /v1/findings/{id}` + `GET /v1/findings/{id}/events` together** — the first gives current state (severity, evidence, remediation, first/last seen), the second gives the "why did this become CONFIRMED / who accepted the risk / when did it reopen" narrative. Neither alone is sufficient for the "finding detail/lifecycle" UI surface the brief names.

RBAC: `findings.read` (OWNER/ADMINISTRATOR/ANALYST/VIEWER) for the two `GET` routes; `findings.update` (OWNER/ADMINISTRATOR/ANALYST — not VIEWER) for the status-change route.

## 6. Schedules — `STABLE_V1` for CRUD, `EXPERIMENTAL` for the underlying execution guarantee (live-wired to PostgreSQL this slice)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/schedules` | Create. Requires `TrustScan-Permit` header. |
| `GET` | `/v1/schedules` | Paginated. Filters: `state` (enum: `active`\|`paused`), `target` (free-form, exact match — new this slice). |
| `GET` | `/v1/schedules/{schedule_id}` | Single schedule. |
| `POST` | `/v1/schedules/{schedule_id}/pause` | No body. |
| `POST` | `/v1/schedules/{schedule_id}/resume` | No body. |

There is no hard-delete endpoint for schedules — `pause` is the disable mechanism, matching this codebase's existing pattern of revocation over deletion everywhere else (permits, authentication contexts, comparison plans all use `revoke`, never `DELETE`). A UI "disable schedule" action maps to `pause`, not to a destructive delete.

## 7. Reports — `EXPERIMENTAL` (new this slice)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/reports` | Body: `{"scan_id": "<uuid>"}`. Registers the completed scan's existing report artifact as a tracked entity; 409 if the scan has not completed. Returns metadata including a SHA-256 `checksum` computed from the artifact's actual bytes. |
| `GET` | `/v1/reports` | Paginated. Filter: `scan_id` (free-form). |
| `GET` | `/v1/reports/{report_id}` | Single report record. |

Response fields: `report_id`, `organization_id`, `scan_id`, `format`, `state`, `report_ref` (an internal artifact reference — not a public download URL; see the note below), `checksum`, `created_at`, `completed_at`. **`report_ref` is not directly fetchable by a browser** — no `GET /v1/reports/{id}/download`-shaped endpoint exists yet, and production's artifact backend (`ObjectStorageArtifactStore`) is explicitly unimplemented (Slice 15), so there is nowhere for such an endpoint to read from in production today. A "download report" UI button has no backing endpoint yet — a real, named gap, not a UI decision to defer.

## 8. Authentication contexts and comparison plans — `INTERNAL`/`EXPERIMENTAL`, not primary UI surfaces yet

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/authentication-contexts` | Owner-only. Local/dev: raw credential fields in body (`bearer_token`/`cookies`/`basic_username`/`basic_password`). Production: `secret_reference_id` only — raw credential fields are rejected with `authentication_context_raw_secret_not_accepted`. |
| `POST` | `/v1/authentication-contexts/{id}/revoke` | No body. |
| `POST` | `/v1/authorization-comparisons` | Owner-only (comparison-plan registration is reserved, matching the active-check RBAC pattern). |
| `POST` | `/v1/authorization-comparisons/{id}/revoke` | No body. |

These exist to support authenticated scanning and IDOR/BOLA workflows (permit issuance references them by ID) but there is no `GET` list/detail route for either today — an operator sets these up once per identity/plan, generally via API/CLI as part of scan configuration, not as an ongoing-management UI surface. If a future "Authenticated Scanning" settings page is built, it needs new `GET` routes added first.

## 9. Pagination and filtering — `STABLE_V1`

Every list endpoint above shares one contract:

- `?limit=<1-100>` (default 50).
- `?cursor=<opaque signed token>` from a previous response's `page.next_cursor`.
- Response shape: `{"<resource>": [...], "page": {"limit": <int>, "next_cursor": <string|null>}}`.
- Cursors are HMAC-signed and bound to: the authenticated organization, the resource type, and the exact filter set in effect when issued. Changing the filters, switching organizations (impossible for a single token, but relevant if a cursor is somehow replayed against a different token), or tampering with the cursor all fail closed with a 400, never silently returning a different page.
- Filters come in two shapes: **enum filters** (`state`, `status`, `severity`, `mode`, `outcome`) validated against a fixed accepted-value set, and **free-form filters** (`target`, `asset`, `scan_id`, `cwe_id`) accepted as any bounded, control-character-free string. Both are bound into the signed cursor identically — a UI does not need to treat them differently when building "next page" requests, only when building the *initial* filter form (enum filters should render as a fixed choice list; free-form filters as free text).

## 10. Audit log — `STABLE_V1`

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/audit-events` | Paginated. Filter: `outcome` (enum: `succeeded`\|`failed`\|`denied`). |

Fields: `event_id`, `action`, `resource_type`, `resource_id`, `outcome`, `detail_code`, `occurred_at`, `principal_id`, `token_id`, `request_id`. `detail_code` is always a canonical identifier, never free text or a secret-bearing payload — every internal event that could otherwise carry sensitive detail (e.g. a verification check's raw response body) is reduced to a fixed code before being audited. RBAC: `audit.read`.

**Summary for frontend planning (updated Slice 15)**: Scans, Findings (including lifecycle/history), Schedules, Reports (including download), Dashboard, Assets (including ownership verification), Team, API Keys, Settings, and Audit Log all have real, tested API surfaces and can be built against now. Remaining named gaps, none of which block the UI surfaces above: DNS TXT verification (only `.well-known` HTTP is implemented, §2a); no organization-settings write route beyond what §2/§10a already cover; no browser session/cookie authentication layer (see `docs/audit/customer-platform-phase1.md`'s authentication-status section) — the web app authenticates with the same Bearer API tokens this document already describes.

## 11. What this document is not

It does not specify response HTTP headers beyond what §9 states, error-response shapes beyond the existing `{"error": {"code", "message", "request_id"}}` convention used everywhere in this API, or any visual/interaction design. It reflects implemented, tested behavior as of Slice 15 (`docs/audit/customer-platform-phase1.md`) and should be updated in the same slice that changes any endpoint it describes — not left to drift.
