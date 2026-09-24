export const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  "http://127.0.0.1:8765";

export class ApiError extends Error {
  status: number;
  code: string;
  requestId?: string;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

/** Dispatched on any 401 so the auth layer can react without api.ts
 * importing the auth module (avoids a circular dependency). */
export const UNAUTHORIZED_EVENT = "webguard:unauthorized";

export interface PageResult<T> {
  items: T[];
  nextCursor: string | null;
}

function buildQuery(params?: Record<string, string | number | undefined>): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

const CSRF_COOKIE_NAME = "wg_csrf";
const CSRF_HEADER_NAME = "X-CSRF-Token";
const STATE_CHANGING_METHODS = new Set(["POST", "PATCH", "DELETE", "PUT"]);

/** The CSRF token lives in a deliberately non-HttpOnly cookie (see
 * docs/security/BROWSER_SESSION_SECURITY.md) precisely so this can
 * read it and echo it back as a header -- the session cookie itself
 * is never read here, and never could be (HttpOnly). */
function readCsrfCookie(): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${CSRF_COOKIE_NAME}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function request<T>(
  method: string,
  path: string,
  options: {
    body?: unknown;
    query?: Record<string, string | number | undefined>;
    raw?: boolean;
    extraHeaders?: Record<string, string>;
  } = {},
): Promise<T> {
  const headers: Record<string, string> = { ...options.extraHeaders };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (STATE_CHANGING_METHODS.has(method)) {
    const csrf = readCsrfCookie();
    if (csrf) headers[CSRF_HEADER_NAME] = csrf;
  }

  const response = await fetch(`${API_BASE_URL}${path}${buildQuery(options.query)}`, {
    method,
    headers,
    // Session auth is an HttpOnly cookie (Slice 16) -- there is no
    // token in JS-reachable storage to attach as a header. This is
    // what makes the browser actually send and receive it.
    credentials: "include",
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });

  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
  }

  if (options.raw) {
    if (!response.ok) {
      throw new ApiError(response.status, "download_failed", "Unable to download the report.");
    }
    return (await response.arrayBuffer()) as unknown as T;
  }

  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;

  if (!response.ok) {
    const errorBody = payload?.error ?? {};
    throw new ApiError(
      response.status,
      errorBody.code ?? "unknown_error",
      errorBody.message ?? "An unexpected error occurred.",
      errorBody.request_id,
    );
  }

  return payload as T;
}

export const api = {
  get: <T>(path: string, query?: Record<string, string | number | undefined>) =>
    request<T>("GET", path, { query }),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, { body: body ?? {} }),
  postNoBody: <T>(path: string) => request<T>("POST", path),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, { body }),
  del: <T>(path: string) => request<T>("DELETE", path),
  download: (path: string) => request<ArrayBuffer>("GET", path, { raw: true }),
};

// -- Domain types (mirrors docs/product/WEB_APP_API_CONTRACT_V1.md) ------

export interface SessionMetadata {
  session_id: string;
  assurance_level: string;
  issued_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  last_used_at: string | null;
}

export interface SessionResponse {
  organization_id: string;
  organization_name: string;
  principal_id: string;
  principal_name: string;
  role: "owner" | "administrator" | "analyst" | "viewer";
  auth_method: "browser_session" | "api_token";
  token_id: string;
  session?: SessionMetadata;
}

/** @deprecated use SessionResponse -- kept as an alias so any lingering
 * reference to the old /v1/me response shape still type-checks. */
export type MeResponse = SessionResponse;

export interface DashboardSummary {
  total_assets: number;
  verified_assets: number;
  active_scans: number;
  completed_scans: number;
  failed_scans: number;
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
  recent_scans: ScanRecord[];
  recent_high_or_critical_findings: FindingRecord[];
  counts_capped_at: number;
}

export type VerificationMethod = "well_known_http" | "dns_txt";

export interface AssetVerification {
  verification_id: string;
  target_id: string;
  method: VerificationMethod;
  status: "pending" | "verified" | "failed" | "expired";
  checked_at: string;
  evidence: string | null;
  expires_at?: string;
  instructions?:
    | { path: string; expected_content: string }
    | { record_type: string; record_prefix: string; expected_content: string };
  // Present only on the response to a check that neither matched nor
  // expired: the verification itself stays pending (same value, same
  // deadline) and this reports the attempt's own outcome without
  // being persisted, so "check again" never requires a new value.
  last_check_detail?: string;
  last_checked_at?: string;
}

export interface CoverageRow {
  path: string;
  http_method: string;
  identity_label: string;
  check_id: string;
  status: "completed" | "blocked" | "unreachable";
  scanner_version: string;
  check_version: string | null;
  last_scan_id: string | null;
  last_finding_id: string | null;
  first_observed_at: string;
  last_observed_at: string;
}

export interface AssetCoveragePage extends PagePayload {
  asset: string;
  coverage: CoverageRow[];
  status_counts: { completed: number; blocked: number; unreachable: number };
  // Vision states this v1 read surface never populates (no signal
  // exists today to distinguish them honestly); surfaced so the UI
  // can say so rather than implying a smaller, already-complete map.
  not_populated_states: string[];
}

export interface AssetAuthorization {
  authorization_id: string;
  issued_at: string;
  expires_at: string;
  state: "active" | "expiring_soon" | "expired";
}

export interface AssetRecord {
  target_id: string;
  organization_id: string;
  url: string;
  label: string | null;
  default_mode: "single_page" | "crawl" | null;
  created_at: string;
  archived_at: string | null;
  verification?: AssetVerification | null;
  authorization?: AssetAuthorization | null;
  last_scan?: ScanRecord | null;
  finding_counts?: Record<string, number>;
  finding_count_is_capped?: boolean;
}

export interface ScanRecord {
  scan_id: string;
  organization_id: string;
  job_id: string;
  target: string;
  authorization_id: string;
  mode: string;
  status: string;
  scanner_version: string;
  permit_id: string | null;
  requested_checks: string[];
  finding_count: number;
  report_ref: string | null;
  cancellation_requested: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
}

export interface FindingRecord {
  finding_id: string;
  organization_id: string;
  scan_id: string;
  fingerprint: string;
  check_id: string;
  scanner_version: string;
  check_version: string | null;
  title: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  confidence: string;
  asset: string;
  endpoint: string;
  http_method: string;
  parameter: string | null;
  cwe_id: string | null;
  owasp_category: string | null;
  evidence: string | null;
  remediation: string | null;
  references: string[];
  status: "open" | "confirmed" | "false_positive" | "accepted_risk" | "resolved" | "reopened";
  first_seen_at: string;
  last_seen_at: string;
}

export interface FindingEvent {
  event_id: string;
  previous_status: string;
  new_status: string;
  reason: string | null;
  changed_by: string | null;
  created_at: string;
}

export interface JobRecord {
  job_id: string;
  target: string;
  authorization_id: string;
  mode: string;
  state: string;
  cancellation_requested: boolean;
  submitted_at: string;
  started_at: string | null;
  completed_at: string | null;
  scan_id: string | null;
  result_status: string | null;
  error_code: string | null;
  error_message: string | null;
}

export interface ScheduleRecord {
  schedule_id: string;
  organization_id: string;
  name: string;
  target: string;
  authorization_id: string;
  mode: string;
  interval_seconds: number;
  state: "active" | "paused";
  created_at: string;
  updated_at: string;
  next_run_at: string | null;
  last_enqueued_at: string | null;
  last_job_id: string | null;
  last_error_code: string | null;
}

export interface ReportRecord {
  report_id: string;
  organization_id: string;
  scan_id: string;
  format: string;
  state: string;
  report_ref: string;
  checksum: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface TeamMember {
  principal_id: string;
  organization_id: string;
  display_name: string;
  principal_type: string;
  role: "owner" | "administrator" | "analyst" | "viewer";
  active: boolean;
  created_at: string;
  email: string | null;
  email_verified_at: string | null;
  last_login_at: string | null;
}

export interface ApiKeyRecord {
  token_id: string;
  label: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  token?: string;
}

export interface AuditEvent {
  event_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  outcome: "succeeded" | "failed" | "denied";
  detail_code: string | null;
  occurred_at: string;
  principal_id: string;
  token_id: string | null;
  request_id: string;
}

export interface SettingsResponse {
  organization: { organization_id: string; name: string; status: string; created_at: string };
  account: TeamMember;
}

export interface PagePayload {
  page: { limit: number; next_cursor: string | null };
}

// -- Resource calls --------------------------------------------------------

export const meApi = {
  get: () => api.get<SessionResponse>("/v1/me"),
};

export const authApi = {
  register: (body: { organization_name: string; display_name: string; email: string; password: string }) =>
    api.post<SessionResponse>("/v1/auth/register", body),
  login: (body: { email: string; password: string }) => api.post<SessionResponse>("/v1/auth/login", body),
  logout: () => api.postNoBody<{ status: string }>("/v1/auth/logout"),
  logoutAll: () => api.postNoBody<{ revoked_count: number }>("/v1/auth/logout-all"),
  session: () => api.get<SessionResponse>("/v1/auth/session"),
  changePassword: (body: { current_password: string; new_password: string }) =>
    api.post<{ status: string }>("/v1/auth/password/change", body),
  requestPasswordReset: (email: string) =>
    api.post<{ message: string }>("/v1/auth/password/reset/request", { email }),
  confirmPasswordReset: (body: { token: string; new_password: string }) =>
    api.post<{ message: string }>("/v1/auth/password/reset/confirm", body),
  requestEmailVerification: () => api.postNoBody<{ message: string }>("/v1/auth/email/verify/request"),
  confirmEmailVerification: (token: string) =>
    api.post<{ message: string }>("/v1/auth/email/verify/confirm", { token }),
  acceptInvitation: (body: { token: string; password: string }) =>
    api.post<SessionResponse>("/v1/auth/invitations/accept", body),
};

export const dashboardApi = {
  summary: () => api.get<DashboardSummary>("/v1/dashboard/summary"),
};

export const assetsApi = {
  list: (cursor?: string) =>
    api.get<{ assets: AssetRecord[] } & PagePayload>("/v1/assets", { cursor }),
  get: (id: string) => api.get<AssetRecord>(`/v1/assets/${id}`),
  create: (body: { url: string; label?: string; default_mode?: string | null }) =>
    api.post<AssetRecord>("/v1/assets", body),
  update: (id: string, body: { label?: string | null; default_mode?: string | null }) =>
    api.patch<AssetRecord>(`/v1/assets/${id}`, body),
  startVerification: (id: string, method: VerificationMethod) =>
    api.post<AssetVerification>(`/v1/assets/${id}/verification`, { method }),
  checkVerification: (id: string) =>
    api.postNoBody<AssetVerification>(`/v1/assets/${id}/verification/check`),
  coverage: (id: string, cursor?: string) =>
    api.get<AssetCoveragePage>(`/v1/assets/${id}/coverage`, { cursor }),
};

export const scansApi = {
  list: (params?: { cursor?: string; status?: string; target?: string }) =>
    api.get<{ scans: ScanRecord[] } & PagePayload>("/v1/scans", params),
  get: (id: string) => api.get<ScanRecord>(`/v1/scans/${id}`),
};

export interface PermitClaims {
  permit_id: string;
  target: string;
  authorization_id: string;
  active_checks: string[];
  allowed_http_methods: string[];
  expires_at: string;
}

export interface PermitRecord {
  permit: { claims: PermitClaims; permit_sha256: string };
  state: string;
}

export const permitsApi = {
  /** Passive-only, conservative defaults -- the frontend never
   * constructs an active-check or authenticated-scanning permit; the
   * "Start Scan" workflow only ever issues the minimal passive
   * permission a guided scan needs (requirement 13: the frontend must
   * never construct or bypass TrustScan authorization itself -- it
   * only ever calls the same /v1/permits endpoint any API client
   * would, with a narrow, fixed request shape). */
  issue: (params: { target: string; authorizationId: string; mode: "single_page" | "crawl" }) => {
    const now = new Date();
    // Must be far enough ahead to still be in the future once the
    // request actually reaches the server -- real network/render
    // latency, plus session-cookie auth's per-request DB touch and
    // CSRF verification, can eat well over a second under load -- and
    // comfortably under the caller's post-issue wait (see
    // useIssuePermitAndSubmitJob / useCreateSchedule's buffer) or the
    // job submission arrives before the permit's own not_before and
    // is rejected as "pending".
    const notBefore = new Date(now.getTime() + 3000);
    const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    return api.post<PermitRecord>("/v1/permits", {
      target: params.target,
      authorization_id: params.authorizationId,
      confirm_authorization: params.authorizationId,
      permitted_modes: [params.mode],
      allowed_http_methods: ["GET", "HEAD"],
      not_before: notBefore.toISOString().replace(/\.\d+Z$/, ".000000Z"),
      expires_at: expiresAt.toISOString().replace(/\.\d+Z$/, ".000000Z"),
      // Kept below OwnedTargetLimits' own default cap (15) -- a permit
      // requesting more than the underlying authorization allows is
      // rejected outright (trustscan_permit_request_budget_too_high),
      // so this must never exceed the lowest default limit an
      // authorization is likely to carry.
      maximum_request_attempts: 10,
      maximum_requests_per_second: 1,
      maximum_concurrency: 1,
      active_checks: [],
      authentication_context_id: null,
      authorization_comparison_plan_id: null,
    });
  },
};

export const jobsApi = {
  list: (params?: { cursor?: string; state?: string; mode?: string }) =>
    api.get<{ jobs: JobRecord[] } & PagePayload>("/v1/jobs", params),
  get: (id: string) => api.get<JobRecord>(`/v1/jobs/${id}`),
  result: (id: string) => api.get<JobRecord>(`/v1/jobs/${id}/result`),
  submit: (params: {
    target: string;
    authorizationId: string;
    mode: "single_page" | "crawl";
    permitId: string;
    idempotencyKey: string;
  }) =>
    request<{ job_id: string; state: string }>("POST", "/v1/jobs", {
      body: {
        target: params.target,
        authorization_id: params.authorizationId,
        confirm_authorization: params.authorizationId,
        mode: params.mode,
      },
      extraHeaders: {
        "Idempotency-Key": params.idempotencyKey,
        "TrustScan-Permit": params.permitId,
      },
    }),
  cancel: (id: string) => api.postNoBody<JobRecord>(`/v1/jobs/${id}/cancel`),
};

export const findingsApi = {
  list: (params?: {
    cursor?: string;
    status?: string;
    severity?: string;
    scan_id?: string;
    cwe_id?: string;
    asset?: string;
  }) => api.get<{ findings: FindingRecord[] } & PagePayload>("/v1/findings", params),
  get: (id: string) => api.get<FindingRecord>(`/v1/findings/${id}`),
  updateStatus: (id: string, status: string, reason?: string) =>
    api.post<FindingRecord>(`/v1/findings/${id}/status`, { status, reason }),
  events: (id: string) => api.get<{ finding_id: string; events: FindingEvent[] }>(`/v1/findings/${id}/events`),
};

export const schedulesApi = {
  list: (params?: { cursor?: string; state?: string; target?: string }) =>
    api.get<{ schedules: ScheduleRecord[] } & PagePayload>(
      "/v1/schedules",
      params,
    ),
  get: (id: string) => api.get<ScheduleRecord>(`/v1/schedules/${id}`),
  pause: (id: string) => api.postNoBody<ScheduleRecord>(`/v1/schedules/${id}/pause`),
  resume: (id: string) => api.postNoBody<ScheduleRecord>(`/v1/schedules/${id}/resume`),
  create: (params: {
    name: string;
    target: string;
    authorizationId: string;
    mode: "single_page" | "crawl";
    intervalSeconds: number;
    permitId: string;
  }) =>
    request<ScheduleRecord>("POST", "/v1/schedules", {
      body: {
        name: params.name,
        target: params.target,
        authorization_id: params.authorizationId,
        confirm_authorization: params.authorizationId,
        mode: params.mode,
        interval_seconds: params.intervalSeconds,
        starts_at: new Date(Date.now() + 60_000).toISOString().replace(/\.\d+Z$/, ".000000Z"),
      },
      extraHeaders: { "TrustScan-Permit": params.permitId },
    }),
};

export const reportsApi = {
  list: (params?: { cursor?: string; scan_id?: string }) =>
    api.get<{ reports: ReportRecord[] } & PagePayload>("/v1/reports", params),
  get: (id: string) => api.get<ReportRecord>(`/v1/reports/${id}`),
  create: (scanId: string) => api.post<ReportRecord>("/v1/reports", { scan_id: scanId }),
  downloadUrl: (id: string) => `/v1/reports/${id}/download`,
};

export const teamApi = {
  list: () => api.get<{ members: TeamMember[] }>("/v1/team"),
  invite: (body: { display_name: string; email: string; role: string }) =>
    api.post<TeamMember>("/v1/team/invitations", body),
  updateRole: (id: string, role: string) => api.patch<TeamMember>(`/v1/team/${id}`, { role }),
  remove: (id: string) => api.del<TeamMember>(`/v1/team/${id}`),
};

export const apiKeysApi = {
  list: () => api.get<{ api_keys: ApiKeyRecord[] }>("/v1/api-keys"),
  create: (label: string, validityDays?: number) =>
    api.post<ApiKeyRecord>("/v1/api-keys", { label, validity_days: validityDays }),
  revoke: (id: string) => api.del<ApiKeyRecord>(`/v1/api-keys/${id}`),
};

export const auditApi = {
  list: (params?: { cursor?: string; outcome?: string }) =>
    api.get<{ events: AuditEvent[] } & PagePayload>("/v1/audit-events", params),
};

export const settingsApi = {
  get: () => api.get<SettingsResponse>("/v1/settings"),
};

// -- Platform: module entitlements, SOC, Compliance ------------------------
// Mirrors docs/PLATFORM_SCOPE.md: WebGuard/SOC/Compliance are one
// platform's three modules. SOC and Compliance return real backend
// data (connector manifests, the framework catalog, the assertion
// catalog and an organization's own collection history) -- nothing
// here is a live vendor connection, since no SOC connector in this
// codebase has a live HTTP client yet.

export type PlatformModuleId = "webguard" | "soc" | "compliance";
export type ModuleEntitlementStatus = "enabled" | "disabled" | "trial";

export interface ModuleEntitlement {
  module: PlatformModuleId;
  status: ModuleEntitlementStatus;
  updated_at: string;
  enabled_at: string | null;
  // Deployment-wide, not per-organization: false means no one, not
  // even this organization's own owner, can turn this module on right
  // now. Distinct from `status`, which an owner genuinely controls
  // when this is true.
  available: boolean;
}

export const moduleEntitlementsApi = {
  list: () => api.get<{ entitlements: ModuleEntitlement[] }>("/v1/module-entitlements"),
  set: (module: PlatformModuleId, status: ModuleEntitlementStatus) =>
    api.patch<ModuleEntitlement>(`/v1/module-entitlements/${module}`, { status }),
};

export type ConnectorLiveValidationState =
  | "not_started"
  | "contract_designed"
  | "fixture_tested"
  | "blocked_on_credentials"
  | "live_validated";

export interface SocConnectorPermission {
  name: string;
  permission_type: "application" | "delegated" | "azure_rbac_role";
  purpose: string;
}

export interface SocConnector {
  connector_id: string;
  display_name: string;
  vendor: string;
  api_family: string;
  licensing_dependency: string;
  live_validation_state: ConnectorLiveValidationState;
  permissions: SocConnectorPermission[];
  endpoint_count: number;
  known_limitations: string[];
}

export const socApi = {
  connectors: () => api.get<{ connectors: SocConnector[] }>("/v1/soc/connectors"),
};

export type FrameworkStatus = "placeholder" | "current" | "proposed" | "future_readiness" | "superseded";

export interface ComplianceFramework {
  framework_id: string;
  name: string;
  version: string;
  status: FrameworkStatus;
  source_reference: string;
  created_at: string;
  updated_at: string;
  control_count: number;
}

export interface TechnicalAssertion {
  assertion_id: string;
  title: string;
  objective: string;
  version: string;
  source_connector_id: string;
  required_permissions: string[];
  evaluatable: boolean;
}

export type EvidenceSource = "fixture" | "manual";
export type CollectionStatus = "succeeded" | "failed";
export type AssertionOutcome = "satisfied" | "violated" | "indeterminate" | "not_tested";

export interface AssertionCollection {
  collection_id: string;
  assertion_id: string;
  assertion_version: string;
  evidence_source: EvidenceSource;
  evidence_provenance: string;
  collection_status: CollectionStatus;
  collection_error: string | null;
  collected_by: string;
  collected_at: string;
  outcome: AssertionOutcome | null;
  outcome_detail: string | null;
  evaluated_at: string | null;
}

export const complianceApi = {
  frameworks: () => api.get<{ frameworks: ComplianceFramework[] }>("/v1/compliance/frameworks"),
  assertions: () =>
    api.get<{ assertions: TechnicalAssertion[]; fixture_evidence_sets: string[] }>("/v1/compliance/assertions"),
  collections: (assertionId: string) =>
    api.get<{ collections: AssertionCollection[] }>(`/v1/compliance/assertions/${assertionId}/collections`),
  collect: (
    assertionId: string,
    body: { evidence_source: "fixture"; fixture_name: string } | { evidence_source: "manual"; manual_evidence: unknown[] },
  ) => api.post<AssertionCollection>(`/v1/compliance/assertions/${assertionId}/collections`, body),
};
