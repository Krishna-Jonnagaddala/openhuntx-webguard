import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, useAuth } from "./auth";
import { UNAUTHORIZED_EVENT, authApi } from "./api";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return { ...actual, authApi: { ...actual.authApi, session: vi.fn(), login: vi.fn(), logout: vi.fn() } };
});

const SESSION = {
  organization_id: "org-1",
  organization_name: "Acme",
  principal_id: "p-1",
  principal_name: "Ada",
  role: "owner" as const,
  auth_method: "browser_session" as const,
  token_id: "session-1",
};

function Probe() {
  const { status, session, error, login, signOut } = useAuth();
  return (
    <div>
      <p data-testid="status">{status}</p>
      <p data-testid="role">{session?.role ?? ""}</p>
      <p data-testid="error">{error ?? ""}</p>
      <button onClick={() => login("ada@example.com", "a very long password 123").catch(() => {})}>sign in</button>
      <button onClick={signOut}>sign out</button>
    </div>
  );
}

describe("AuthProvider", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("starts signed-out when the session endpoint rejects", async () => {
    vi.mocked(authApi.session).mockRejectedValueOnce(new Error("not signed in"));
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-out"));
  });

  it("becomes signed-in when the session endpoint resolves on mount", async () => {
    vi.mocked(authApi.session).mockResolvedValueOnce(SESSION);
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-in"));
    expect(screen.getByTestId("role")).toHaveTextContent("owner");
  });

  it("login sets signed-in state from the response, without storing any token", async () => {
    vi.mocked(authApi.session).mockRejectedValueOnce(new Error("not signed in"));
    vi.mocked(authApi.login).mockResolvedValueOnce(SESSION);

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-out"));

    await act(async () => {
      await userEvent.click(screen.getByText("sign in"));
    });

    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-in"));
    expect(screen.getByTestId("role")).toHaveTextContent("owner");
    // Nothing this file could store a session credential in: no
    // sessionStorage/localStorage/IndexedDB write happens anywhere in
    // auth.tsx (requirement 18) -- the session lives only in the
    // HttpOnly cookie the browser (mocked away here) would hold.
    expect(window.sessionStorage.length).toBe(0);
    expect(window.localStorage.length).toBe(0);
  });

  it("surfaces a login failure without becoming signed-in", async () => {
    vi.mocked(authApi.session).mockRejectedValueOnce(new Error("not signed in"));
    vi.mocked(authApi.login).mockRejectedValueOnce(new Error("invalid credentials"));

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-out"));

    await act(async () => {
      await userEvent.click(screen.getByText("sign in"));
    });

    await waitFor(() => expect(screen.getByTestId("error")).not.toHaveTextContent(""));
    expect(screen.getByTestId("status")).toHaveTextContent("signed-out");
  });

  it("clears session state when the unauthorized event fires", async () => {
    vi.mocked(authApi.session).mockResolvedValueOnce(SESSION);
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-in"));

    act(() => {
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    });

    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-out"));
  });

  it("sign out calls the logout endpoint and clears local state even if it fails", async () => {
    vi.mocked(authApi.session).mockResolvedValueOnce(SESSION);
    vi.mocked(authApi.logout).mockRejectedValueOnce(new Error("network error"));

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-in"));

    await act(async () => {
      await userEvent.click(screen.getByText("sign out"));
    });

    expect(authApi.logout).toHaveBeenCalled();
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-out"));
  });
});
