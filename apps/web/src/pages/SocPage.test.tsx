import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { SocPage } from "./SocPage";

const useModuleEntitlementsMock = vi.fn();
const useSocConnectorsMock = vi.fn();
const useAuthMock = vi.fn();

vi.mock("../lib/auth", () => ({ useAuth: () => useAuthMock() }));

vi.mock("../hooks/queries", () => ({
  useModuleEntitlements: () => useModuleEntitlementsMock(),
  useSocConnectors: (enabled: boolean) => useSocConnectorsMock(enabled),
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <SocPage />
    </MemoryRouter>,
  );
}

describe("SocPage deployment-availability vs. organization-entitlement separation", () => {
  it("shows the deployment-restricted message for a legacy organization with zero entitlement rows", () => {
    // The real bug: deployment_availability must be read independently
    // of whether this organization has an entitlement row at all. A
    // legacy organization has none (see service.py's own
    // list_module_entitlements docstring); this must not be read as
    // "available".
    useAuthMock.mockReturnValue({ session: { role: "owner" } });
    useModuleEntitlementsMock.mockReturnValue({
      data: { entitlements: [], deployment_availability: { webguard: true, soc: false, compliance: false } },
      isLoading: false,
    });
    useSocConnectorsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.getByText(/SOC is not part of this release/i)).toBeInTheDocument();
    expect(screen.queryByText(/SOC is not enabled for your organization yet/i)).not.toBeInTheDocument();
    // Never fetch the connector catalog for a deployment-restricted module.
    expect(useSocConnectorsMock).toHaveBeenCalledWith(false);
  });

  it("shows the deployment-restricted message even when this organization's own entitlement is enabled", () => {
    useAuthMock.mockReturnValue({ session: { role: "owner" } });
    useModuleEntitlementsMock.mockReturnValue({
      data: {
        entitlements: [
          { module: "soc", status: "enabled", updated_at: "2026-01-01T00:00:00Z", enabled_at: "2026-01-01T00:00:00Z" },
        ],
        deployment_availability: { webguard: true, soc: false, compliance: false },
      },
      isLoading: false,
    });
    useSocConnectorsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.getByText(/SOC is not part of this release/i)).toBeInTheDocument();
  });

  it("while entitlements are still loading, does not show availability and does not fetch connectors", () => {
    useAuthMock.mockReturnValue({ session: { role: "owner" } });
    useModuleEntitlementsMock.mockReturnValue({ data: undefined, isLoading: true });
    useSocConnectorsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.queryByText(/SOC is not part of this release/i)).not.toBeInTheDocument();
    expect(useSocConnectorsMock).toHaveBeenCalledWith(false);
  });

  it("once deployment-available, shows an owner a link to enable a disabled organization entitlement", () => {
    useAuthMock.mockReturnValue({ session: { role: "owner" } });
    useModuleEntitlementsMock.mockReturnValue({
      data: {
        entitlements: [
          { module: "soc", status: "disabled", updated_at: "2026-01-01T00:00:00Z", enabled_at: null },
        ],
        deployment_availability: { webguard: true, soc: true, compliance: true },
      },
      isLoading: false,
    });
    useSocConnectorsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.getByText(/enable it from Settings/i)).toBeInTheDocument();
  });

  it("once deployment-available, a non-owner is told to contact an owner instead of being shown a settings link", () => {
    useAuthMock.mockReturnValue({ session: { role: "viewer" } });
    useModuleEntitlementsMock.mockReturnValue({
      data: {
        entitlements: [
          { module: "soc", status: "disabled", updated_at: "2026-01-01T00:00:00Z", enabled_at: null },
        ],
        deployment_availability: { webguard: true, soc: true, compliance: true },
      },
      isLoading: false,
    });
    useSocConnectorsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
    renderPage();
    expect(screen.getByText(/contact an organization owner/i)).toBeInTheDocument();
    expect(screen.queryByText(/enable it from Settings/i)).not.toBeInTheDocument();
  });
});
