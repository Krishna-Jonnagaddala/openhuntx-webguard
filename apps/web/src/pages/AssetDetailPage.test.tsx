import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AssetDetailPage } from "./AssetDetailPage";

const useAssetMock = vi.fn();
const submitMutateAsync = vi.fn().mockResolvedValue({ job_id: "job-1" });
const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock("../hooks/queries", () => ({
  useAsset: () => useAssetMock(),
  useAssetCoverage: () => ({ data: undefined, isLoading: false, error: null }),
  useStartVerification: () => ({ mutate: vi.fn(), isPending: false }),
  useCheckVerification: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
  useIssuePermitAndSubmitJob: () => ({ mutateAsync: submitMutateAsync, isPending: false, isError: false }),
}));

function baseAsset(overrides: Record<string, unknown> = {}) {
  return {
    target_id: "t-1",
    url: "https://app.example.com/",
    label: null,
    verification: undefined,
    authorization: null,
    finding_counts: {},
    ...overrides,
  };
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/assets/t-1"]}>
      <Routes>
        <Route path="/assets/:targetId" element={<AssetDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("AssetDetailPage verification + scan-creation gating", () => {
  beforeEach(() => {
    submitMutateAsync.mockClear();
    navigateMock.mockClear();
  });

  it("blocks scanning and explains why when the asset is unverified", () => {
    useAssetMock.mockReturnValue({ data: baseAsset(), isLoading: false, error: null });
    renderPage();
    expect(screen.getByText(/verify ownership of this asset before scanning/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start scan" })).not.toBeInTheDocument();
  });

  it("blocks scanning when verified but not authorized", () => {
    useAssetMock.mockReturnValue({
      data: baseAsset({ verification: { status: "verified" }, authorization: null }),
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.getByText(/no active authorization currently covers this exact url/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start scan" })).not.toBeInTheDocument();
  });

  it("treats an expired authorization as not authorized", () => {
    useAssetMock.mockReturnValue({
      data: baseAsset({
        verification: { status: "verified" },
        authorization: { authorization_id: "auth-1", state: "expired", expires_at: "2020-01-01T00:00:00Z" },
      }),
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.getByText(/no active authorization currently covers this exact url/i)).toBeInTheDocument();
  });

  it("allows starting a scan once verified and authorized, and submits the chosen mode", async () => {
    useAssetMock.mockReturnValue({
      data: baseAsset({
        verification: { status: "verified" },
        authorization: { authorization_id: "auth-1", state: "active", expires_at: "2030-01-01T00:00:00Z" },
      }),
      isLoading: false,
      error: null,
    });
    renderPage();

    const crawlOption = screen.getByLabelText(/crawl/i);
    await userEvent.click(crawlOption);
    await userEvent.click(screen.getByRole("button", { name: "Start scan" }));

    expect(submitMutateAsync).toHaveBeenCalledWith({
      target: "https://app.example.com/",
      authorizationId: "auth-1",
      mode: "crawl",
    });
    expect(navigateMock).toHaveBeenCalledWith("/scans?justSubmitted=job-1");
  });
});
