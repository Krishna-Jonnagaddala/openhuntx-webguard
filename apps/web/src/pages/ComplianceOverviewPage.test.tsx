import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ComplianceOverviewPage } from "./ComplianceOverviewPage";

const useModuleEntitlementsMock = vi.fn();
const useComplianceFrameworksMock = vi.fn();

vi.mock("../hooks/queries", () => ({
  useModuleEntitlements: () => useModuleEntitlementsMock(),
  useComplianceFrameworks: (enabled: boolean) => useComplianceFrameworksMock(enabled),
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <ComplianceOverviewPage />
    </MemoryRouter>,
  );
}

describe("ComplianceOverviewPage deployment-availability vs. organization-entitlement separation", () => {
  it("shows the deployment-restricted message for a legacy organization with zero entitlement rows", () => {
    useModuleEntitlementsMock.mockReturnValue({
      data: { entitlements: [], deployment_availability: { webguard: true, soc: false, compliance: false } },
      isLoading: false,
    });
    useComplianceFrameworksMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.getByText(/Compliance is not part of this release/i)).toBeInTheDocument();
    expect(useComplianceFrameworksMock).toHaveBeenCalledWith(false);
  });

  it("while entitlements are still loading, does not claim availability and does not fetch frameworks", () => {
    useModuleEntitlementsMock.mockReturnValue({ data: undefined, isLoading: true });
    useComplianceFrameworksMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.queryByText(/Compliance is not part of this release/i)).not.toBeInTheDocument();
    expect(useComplianceFrameworksMock).toHaveBeenCalledWith(false);
  });

  it("fetches and shows frameworks once deployment-available, regardless of this organization's own entitlement rows", () => {
    useModuleEntitlementsMock.mockReturnValue({
      data: { entitlements: [], deployment_availability: { webguard: true, soc: true, compliance: true } },
      isLoading: false,
    });
    useComplianceFrameworksMock.mockReturnValue({
      data: { frameworks: [] },
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.queryByText(/Compliance is not part of this release/i)).not.toBeInTheDocument();
    expect(useComplianceFrameworksMock).toHaveBeenCalledWith(true);
  });
});
