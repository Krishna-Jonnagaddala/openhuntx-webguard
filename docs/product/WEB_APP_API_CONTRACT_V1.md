# WebGuard Web App API Contract (v1)

## Purpose and scope

This is **not a frontend design document.** It is the contract a future WebGuard dashboard builds against: which `/v1/...` endpoints exist today, what they return, what stability guarantee each carries, and which UI surfaces they support. Nothing here is aspirational — every endpoint listed is implemented and tested as of Slice 14. Where a UI surface the brief names (Dashboard, Assets, Team, API Keys, Settings) has no backing endpoint yet, that is stated plainly as a gap, not papered over.

**Stability markers**, per endpoint or field group:

- `STABLE_V1` — the shape is committed; a frontend can build against it now, and a breaking change would require a new version or an explicit migration note in this document.
- `EXPERIMENTAL` — implemented and tested, but the shape may still change based on real frontend usage (most of what shipped this slice: findings lifecycle, reports, scans-as-a-resource).
- `INTERNAL` — exists for the platform's own use (audit, health/readiness) and is not intended as a primary UI data source, though a UI may still read it.

All endpoints below require `Authorization: Bearer <token>` unless marked public. All are tenant-scoped to the authenticated token's organization; cross-organization access fails closed as 404 (see `docs/ARCHITECTURE.md` Boundary B). All list endpoints share one pagination/filtering contract (§9).

## 1. Dashboard

**No dedicated dashboard endpoint exists.** A dashboard view is expected to compose from the list endpoints below (`/v1/scans`, `/v1/findings`, `/v1/jobs`) rather than a single aggregate. Building a purpose-specific aggregation/summary endpoint (counts by severity, recent activity feed, etc.) is explicitly **not** in scope for this slice or the next — it is dashboard-shaped work the brief itself defers ("do not begin broad web-dashboard development"). Treat this section as a known gap, not an oversight.

## 2. Assets (targets)

Target creation/listing exists at the repository layer (`PostgresTargetRepository`/`InMemoryTargetRepository`, live since Slice 13) but **has no HTTP route today.** Targets are currently created only as a side effect of authorization assignment in test/CLI flows. An "Assets" page needs `POST /v1/targets`, `GET /v1/targets`, `GET /v1/targets/{id}` added — real, scoped work for a future slice, not represented in the table below because it does not exist yet.

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

## 10. Team, API keys, audit log, settings

| Surface | Status |
|---|---|
| **Team / members** | `INTERNAL` only. Principal/membership creation exists at the repository and CLI layer (`identity.create_principal`, `organization principal create`) but has no `/v1/...` HTTP route. A "Team" page needs `POST /v1/principals`, `GET /v1/principals`, and a role-update route added. |
| **API keys** | `INTERNAL` only, same gap. Token issuance exists via CLI (`webguard-api token create`) and at the repository layer, not via HTTP. A "API Keys" page needs `POST /v1/tokens`, `GET /v1/tokens`, `POST /v1/tokens/{id}/revoke`. |
| **Audit log** | `STABLE_V1`. `GET /v1/audit-events`, paginated, filter `outcome` (enum: `succeeded`\|`failed`\|`denied`). Fields: `event_id`, `action`, `resource_type`, `resource_id`, `outcome`, `detail_code`, `occurred_at`, `principal_id`, `token_id`, `request_id`. This is the one "settings-adjacent" surface that is fully ready today. |
| **Settings** (org name, org-level policy, etc.) | No endpoint exists. Organization creation is CLI/repository-only. |

**Summary for frontend planning**: Scans, Findings (including lifecycle/history), Schedules, Reports, and Audit Log have real, tested API surfaces today and can be built against now. Dashboard, Assets, Team, API Keys, and Settings have partial or no HTTP surface — building those UI screens requires new, scoped API work first, named explicitly here rather than discovered mid-frontend-build.

## 11. What this document is not

It does not specify response HTTP headers beyond what §9 states, error-response shapes beyond the existing `{"error": {"code", "message", "request_id"}}` convention used everywhere in this API, or any visual/interaction design. It reflects implemented, tested behavior as of Slice 14 (`docs/audit/production-platform-phase3-runtime-completion.md`) and should be updated in the same slice that changes any endpoint it describes — not left to drift.
