import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { AuthProvider } from "./lib/auth";
import { clearSession, saveSession } from "./lib/auth-storage";

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

describe("App routing", () => {
  beforeEach(() => {
    clearSession();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("redirects an unauthenticated visitor away from a protected route to /login", async () => {
    renderApp("/assets");
    await waitFor(() => expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument());
  });

  it("renders the login form directly when visiting /login", async () => {
    renderApp("/login");
    await waitFor(() => expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument());
  });

  it("renders the app shell for a signed-in visitor on a protected route", async () => {
    saveSession({
      token: "wgt_test",
      organizationId: "org-1",
      organizationName: "Acme",
      principalId: "p-1",
      principalName: "Ada",
      role: "owner",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(200, { assets: [], page: { limit: 20, next_cursor: null } })),
    );

    renderApp("/assets");

    await waitFor(() => expect(screen.getByRole("heading", { name: "Assets" })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sign in" })).not.toBeInTheDocument();
  });

  it("redirects an unknown protected path back to the dashboard", async () => {
    saveSession({
      token: "wgt_test",
      organizationId: "org-1",
      organizationName: "Acme",
      principalId: "p-1",
      principalName: "Ada",
      role: "owner",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(200, {
          total_assets: 0,
          verified_assets: 0,
          active_scans: 0,
          completed_scans: 0,
          failed_scans: 0,
          findings_by_severity: {},
          findings_by_status: {},
          recent_scans: [],
          recent_high_or_critical_findings: [],
        }),
      ),
    );

    renderApp("/this-route-does-not-exist");

    await waitFor(() => expect(screen.getByRole("heading", { name: "Dashboard" })).toBeInTheDocument());
  });
});
