import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, useAuth } from "./auth";
import { UNAUTHORIZED_EVENT, meApi } from "./api";
import { clearSession, loadSession } from "./auth-storage";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return { ...actual, meApi: { get: vi.fn() } };
});

function Probe() {
  const { status, session, error, signIn, signOut } = useAuth();
  return (
    <div>
      <p data-testid="status">{status}</p>
      <p data-testid="role">{session?.role ?? ""}</p>
      <p data-testid="error">{error ?? ""}</p>
      <button onClick={() => signIn("wgt_new-token").catch(() => {})}>sign in</button>
      <button onClick={signOut}>sign out</button>
    </div>
  );
}

describe("AuthProvider", () => {
  afterEach(() => {
    clearSession();
    vi.clearAllMocks();
  });

  it("starts signed-out when no session is stored", async () => {
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-out"));
  });

  it("validates the token against /v1/me before persisting a session", async () => {
    vi.mocked(meApi.get).mockResolvedValueOnce({
      organization_id: "org-1",
      organization_name: "Acme",
      principal_id: "p-1",
      principal_name: "Ada",
      role: "owner",
    } as never);

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
    expect(loadSession()?.token).toBe("wgt_new-token");
  });

  it("does not persist a session when the token is rejected", async () => {
    vi.mocked(meApi.get).mockRejectedValueOnce(new Error("rejected"));

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
    expect(loadSession()).toBeNull();
  });

  it("clears the session and signs out when the unauthorized event fires", async () => {
    vi.mocked(meApi.get).mockResolvedValueOnce({
      organization_id: "org-1",
      organization_name: "Acme",
      principal_id: "p-1",
      principal_name: "Ada",
      role: "owner",
    } as never);

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await act(async () => {
      await userEvent.click(screen.getByText("sign in"));
    });
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-in"));

    act(() => {
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    });

    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("signed-out"));
    expect(loadSession()).toBeNull();
  });
});
