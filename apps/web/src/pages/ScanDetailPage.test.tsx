import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ScanDetailPage } from "./ScanDetailPage";

const useScanMock = vi.fn();
const useFindingsMock = vi.fn();
const useReportsMock = vi.fn();
const useCreateReportMock = vi.fn();

vi.mock("../hooks/queries", () => ({
  useScan: () => useScanMock(),
  useFindings: () => useFindingsMock(),
  useReports: () => useReportsMock(),
  useCreateReport: () => useCreateReportMock(),
}));

function baseScan(overrides: Record<string, unknown> = {}) {
  return {
    scan_id: "scan-1",
    target: "https://example.com/",
    mode: "single_page",
    scanner_version: "1.0.0",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:01:00Z",
    requested_checks: ["active.ssrf.callback"],
    finding_count: 0,
    status: "completed",
    ...overrides,
  };
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/scans/scan-1"]}>
      <Routes>
        <Route path="/scans/:scanId" element={<ScanDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ScanDetailPage surfaces a callback-outage-affected scan honestly", () => {
  beforeEach(() => {
    useFindingsMock.mockReturnValue({ data: { findings: [] } });
    useReportsMock.mockReturnValue({ data: { reports: [] } });
    useCreateReportMock.mockReturnValue({ mutate: vi.fn(), isPending: false, isError: false, error: null });
  });

  it("still offers the report-request panel for a completed_with_errors scan, not the 'can be requested once completed' placeholder", () => {
    // M21/P1-12-R1: a sustained callback-persistence outage now reports
    // completed_with_errors rather than a silent completed. The report
    // itself (which carries the ssrf_callback_pipeline_unverified
    // detail, asserted at the API/report layer by
    // test_no_fabricated_confirmation_when_persistence_never_recovers)
    // must still be requestable -- a customer must not be blocked from
    // seeing exactly what happened just because the scan was not a
    // clean "completed".
    useScanMock.mockReturnValue({
      data: baseScan({ status: "completed_with_errors" }),
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.getByRole("button", { name: /request report/i })).toBeInTheDocument();
    expect(screen.queryByText(/can be requested once this scan completes/i)).not.toBeInTheDocument();
  });

  it("does not yet offer the report-request panel for a scan still running", () => {
    useScanMock.mockReturnValue({
      data: baseScan({ status: "running" }),
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.queryByRole("button", { name: /request report/i })).not.toBeInTheDocument();
    expect(screen.getByText(/can be requested once this scan completes/i)).toBeInTheDocument();
  });
});
