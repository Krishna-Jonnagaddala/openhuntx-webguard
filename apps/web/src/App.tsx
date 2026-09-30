import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { PublicLayout } from "./components/layout/PublicLayout";
import { LoadingState } from "./components/ui/primitives";
import { AcceptInvitationPage } from "./pages/AcceptInvitationPage";
import { ApiKeysPage } from "./pages/ApiKeysPage";
import { AssetDetailPage } from "./pages/AssetDetailPage";
import { AssetsPage } from "./pages/AssetsPage";
import { AuditLogPage } from "./pages/AuditLogPage";
import { ComplianceAssertionsPage } from "./pages/ComplianceAssertionsPage";
import { ComplianceOverviewPage } from "./pages/ComplianceOverviewPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ForgotPasswordPage } from "./pages/ForgotPasswordPage";
import { LoginPage } from "./pages/LoginPage";
import { CompliancePage as CompliancePublicPage } from "./pages/public/CompliancePage";
import { PlatformHomePage } from "./pages/public/PlatformHomePage";
import { SocProductPage } from "./pages/public/SocProductPage";
import { WebGuardProductPage } from "./pages/public/WebGuardProductPage";
import { RegisterPage } from "./pages/RegisterPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ResetPasswordPage } from "./pages/ResetPasswordPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { ScansPage } from "./pages/ScansPage";
import { SchedulesPage } from "./pages/SchedulesPage";
import { SettingsPage } from "./pages/SettingsPage";
import { SocPage } from "./pages/SocPage";
import { TeamPage } from "./pages/TeamPage";
import { VerifyEmailPage } from "./pages/VerifyEmailPage";
import { useAuth } from "./lib/auth";

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  if (status === "checking") return <LoadingState label="Checking your session…" />;
  if (status === "signed-out") return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      {/* Public marketing site -- unauthenticated, explains the
          platform and its three modules (docs/product/OPENHUNTX_BRAND_MARK.md
          §6 named this as the surface its "primary lockup" glow
          treatment was always meant for). */}
      <Route element={<PublicLayout />}>
        <Route index element={<PlatformHomePage />} />
        <Route path="webguard" element={<WebGuardProductPage />} />
        <Route path="soc" element={<SocProductPage />} />
        <Route path="compliance" element={<CompliancePublicPage />} />
      </Route>

      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/accept-invitation" element={<AcceptInvitationPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />

      {/* Authenticated application -- one shared shell, three module
          areas (WebGuard/SOC/Compliance) plus a utility area
          (team/api-keys/audit-log/settings) kept visually separate
          from the module switcher inside AppShell itself. */}
      <Route
        path="/app"
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="webguard" replace />} />

        <Route path="webguard" element={<DashboardPage />} />
        <Route path="webguard/assets" element={<AssetsPage />} />
        <Route path="webguard/assets/:targetId" element={<AssetDetailPage />} />
        <Route path="webguard/scans" element={<ScansPage />} />
        <Route path="webguard/scans/:scanId" element={<ScanDetailPage />} />
        <Route path="webguard/findings" element={<FindingsPage />} />
        <Route path="webguard/findings/:findingId" element={<FindingDetailPage />} />
        <Route path="webguard/reports" element={<ReportsPage />} />
        <Route path="webguard/schedules" element={<SchedulesPage />} />

        <Route path="soc" element={<SocPage />} />

        <Route path="compliance" element={<ComplianceOverviewPage />} />
        <Route path="compliance/assertions" element={<ComplianceAssertionsPage />} />

        <Route path="team" element={<TeamPage />} />
        <Route path="api-keys" element={<ApiKeysPage />} />
        <Route path="audit-log" element={<AuditLogPage />} />
        <Route path="settings" element={<SettingsPage />} />

        <Route path="*" element={<Navigate to="/app/webguard" replace />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
