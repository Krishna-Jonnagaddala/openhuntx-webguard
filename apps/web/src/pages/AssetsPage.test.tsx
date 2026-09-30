import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AssetsPage } from "./AssetsPage";
import { ApiError } from "../lib/api";

const useAssetsMock = vi.fn();

vi.mock("../hooks/queries", () => ({
  useAssets: () => useAssetsMock(),
  useCreateAsset: () => ({ mutateAsync: vi.fn(), isPending: false, error: null }),
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <AssetsPage />
    </MemoryRouter>,
  );
}

describe("AssetsPage loading/error/empty/list states", () => {
  it("shows a loading indicator while the query is pending", () => {
    useAssetsMock.mockReturnValue({ data: undefined, isLoading: true, error: null });
    renderPage();
    expect(screen.getByRole("status")).toHaveTextContent(/loading assets/i);
  });

  it("shows the server's error message when the query fails", () => {
    useAssetsMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(500, "internal_error", "The assets service is unavailable."),
    });
    renderPage();
    expect(screen.getByRole("alert")).toHaveTextContent("The assets service is unavailable.");
  });

  it("shows guidance in the empty state when there are no assets", () => {
    useAssetsMock.mockReturnValue({ data: { assets: [], page: { limit: 20, next_cursor: null } }, isLoading: false, error: null });
    renderPage();
    expect(screen.getByText("No assets yet")).toBeInTheDocument();
  });

  it("renders a row per asset with its verification state", () => {
    useAssetsMock.mockReturnValue({
      data: {
        assets: [
          {
            target_id: "t-1",
            url: "https://app.example.com/",
            label: "Marketing site",
            verification: { status: "verified" },
            created_at: "2026-01-01T00:00:00Z",
          },
          {
            target_id: "t-2",
            url: "https://shop.example.com/",
            label: null,
            verification: undefined,
            created_at: "2026-01-02T00:00:00Z",
          },
        ],
        page: { limit: 20, next_cursor: null },
      },
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.getByRole("link", { name: "https://app.example.com/" })).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
    expect(screen.getByText("unverified")).toBeInTheDocument();
  });
});
