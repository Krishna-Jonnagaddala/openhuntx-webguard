import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ComplianceAssertionsPage } from "./ComplianceAssertionsPage";

const useModuleEntitlementsMock = vi.fn();
const useComplianceAssertionsMock = vi.fn();

vi.mock("../hooks/queries", () => ({
  useModuleEntitlements: () => useModuleEntitlementsMock(),
  useComplianceAssertions: (enabled: boolean) => useComplianceAssertionsMock(enabled),
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <ComplianceAssertionsPage />
    </MemoryRouter>,
  );
}

describe("ComplianceAssertionsPage deployment-availability vs. organization-entitlement separation", () => {
  it("shows the deployment-restricted message for a legacy organization with zero entitlement rows", () => {
    useModuleEntitlementsMock.mockReturnValue({
      data: { entitlements: [], deployment_availability: { webguard: true, soc: false, compliance: false } },
      isLoading: false,
    });
    useComplianceAssertionsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.getByText(/Compliance is not part of this release/i)).toBeInTheDocument();
    expect(useComplianceAssertionsMock).toHaveBeenCalledWith(false);
  });

  it("while entitlements are still loading, does not claim availability and does not fetch assertions", () => {
    useModuleEntitlementsMock.mockReturnValue({ data: undefined, isLoading: true });
    useComplianceAssertionsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.queryByText(/Compliance is not part of this release/i)).not.toBeInTheDocument();
    expect(useComplianceAssertionsMock).toHaveBeenCalledWith(false);
  });

  it("fetches assertions once deployment-available, regardless of this organization's own entitlement rows", () => {
    useModuleEntitlementsMock.mockReturnValue({
      data: { entitlements: [], deployment_availability: { webguard: true, soc: true, compliance: true } },
      isLoading: false,
    });
    useComplianceAssertionsMock.mockReturnValue({
      data: { assertions: [] },
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.queryByText(/Compliance is not part of this release/i)).not.toBeInTheDocument();
    expect(useComplianceAssertionsMock).toHaveBeenCalledWith(true);
  });
});
