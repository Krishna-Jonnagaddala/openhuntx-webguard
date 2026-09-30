import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { AuthProvider } from "./lib/auth";

function renderApp(initialEntry: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter initialEntries={[initialEntry]}>
          <App />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const SESSION_PAYLOAD = {
  organization_id: "org-1",
  organization_name: "Acme",
  principal_id: "p-1",
  principal_name: "Ada",
  role: "owner",
  auth_method: "browser_session",
  token_id: "session-1",
};

const DASHBOARD_PAYLOAD = {
  total_assets: 0,
  verified_assets: 0,
  active_scans: 0,
  completed_scans: 0,
  failed_scans: 0,
  findings_by_severity: {},
  findings_by_status: {},
  recent_scans: [],
  recent_high_or_critical_findings: [],
};

/** A tiny router over `fetch` keyed by URL suffix -- the real backend
 * is not running in these tests, but different routes under test need
 * different canned responses within the same render. */
function mockSignedOutFetch() {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      if (url.endsWith("/v1/auth/session")) return Promise.resolve(jsonResponse(401, { error: { code: "session_invalid", message: "Not signed in." } }));
      return Promise.resolve(jsonResponse(200, {}));
    }),
  );
}

function mockSignedInFetch(extra: Record<string, unknown> = {}) {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      if (url.endsWith("/v1/auth/session")) return Promise.resolve(jsonResponse(200, SESSION_PAYLOAD));
      if (url.includes("/v1/assets")) return Promise.resolve(jsonResponse(200, { assets: [], page: { limit: 20, next_cursor: null } }));
      if (url.includes("/v1/dashboard/summary")) return Promise.resolve(jsonResponse(200, DASHBOARD_PAYLOAD));
      const [key] = Object.keys(extra);
      if (key && url.includes(key)) return Promise.resolve(jsonResponse(200, extra[key]));
      return Promise.resolve(jsonResponse(200, {}));
    }),
  );
}

describe("App routing", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("redirects an unauthenticated visitor away from a protected route to /login", async () => {
    mockSignedOutFetch();
    renderApp("/app/webguard/assets");
    await waitFor(() => expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument());
  });

  it("renders the login form directly when visiting /login", async () => {
    mockSignedOutFetch();
    renderApp("/login");
    await waitFor(() => expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument());
  });

  it("shows the public platform home to a signed-out visitor at the root path", async () => {
    mockSignedOutFetch();
    renderApp("/");
    await waitFor(() => expect(screen.getByRole("link", { name: "Create an account" })).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "Sign in" })).not.toBeInTheDocument();
  });

  it("renders the app shell for a signed-in visitor on a protected route", async () => {
    mockSignedInFetch();

    renderApp("/app/webguard/assets");

    await waitFor(() => expect(screen.getByRole("heading", { name: "Assets" })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Overview" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sign in" })).not.toBeInTheDocument();
  });

  it("redirects an unknown protected path back to the WebGuard dashboard", async () => {
    mockSignedInFetch();

    renderApp("/app/this-route-does-not-exist");

    await waitFor(() => expect(screen.getByRole("heading", { name: "Dashboard" })).toBeInTheDocument());
  });
});
