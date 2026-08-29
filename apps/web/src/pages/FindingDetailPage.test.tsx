import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetailPage } from "./FindingDetailPage";

const mutateAsync = vi.fn().mockResolvedValue({});
const useAuthMock = vi.fn();

vi.mock("../lib/auth", () => ({ useAuth: () => useAuthMock() }));

vi.mock("../hooks/queries", () => ({
  useFinding: () => ({
    data: {
      finding_id: "f-1",
      check_id: "reflected-xss",
      title: "Reflected XSS in search",
      asset: "https://app.example.com",
      endpoint: "/search",
      severity: "high",
      confidence: "confirmed",
      status: "open",
      cwe_id: "CWE-79",
      owasp_category: null,
      http_method: "GET",
      parameter: "q",
      evidence: null,
      remediation: null,
      references: [],
      first_seen_at: "2026-01-01T00:00:00Z",
      last_seen_at: "2026-01-02T00:00:00Z",
    },
    isLoading: false,
    error: null,
  }),
  useFindingEvents: () => ({ data: { events: [] } }),
  useUpdateFindingStatus: () => ({ mutateAsync, isPending: false, isError: false, error: null }),
}));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/findings/f-1"]}>
      <Routes>
        <Route path="/findings/:findingId" element={<FindingDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("FindingDetailPage permission gating", () => {
  beforeEach(() => {
    mutateAsync.mockClear();
  });

  it("hides lifecycle actions and explains why for a viewer", () => {
    useAuthMock.mockReturnValue({ session: { role: "viewer" } });
    renderPage();
    expect(screen.getByText(/can view but not change finding status/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Confirm" })).not.toBeInTheDocument();
  });

  it("shows lifecycle actions for an analyst and submits a status change", async () => {
    useAuthMock.mockReturnValue({ session: { role: "analyst" } });
    renderPage();

    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));

    expect(mutateAsync).toHaveBeenCalledWith({ id: "f-1", status: "confirmed", reason: undefined });
  });

  it("shows lifecycle actions for an owner and an administrator", () => {
    useAuthMock.mockReturnValue({ session: { role: "owner" } });
    const { unmount } = renderPage();
    expect(screen.getByRole("button", { name: "Confirm" })).toBeInTheDocument();
    unmount();

    useAuthMock.mockReturnValue({ session: { role: "administrator" } });
    renderPage();
    expect(screen.getByRole("button", { name: "Confirm" })).toBeInTheDocument();
  });
});
