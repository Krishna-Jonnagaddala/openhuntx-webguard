import { Link } from "react-router-dom";
import { Card, ErrorState, LoadingState, PageHeader, SeverityBadge, StatusBadge } from "../components/ui/primitives";
import { useDashboardSummary } from "../hooks/queries";
import { ApiError } from "../lib/api";

function StatCard({ label, value }: { label: string; value: number | string }) {
  return (
    <Card className="p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-tertiary)]">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-[var(--color-text-primary)]">{value}</p>
    </Card>
  );
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];

export function DashboardPage() {
  const { data, isLoading, error } = useDashboardSummary();

  if (isLoading) return <LoadingState label="Loading dashboard…" />;
  if (error) return <ErrorState message={error instanceof ApiError ? error.message : "Unable to load the dashboard."} />;
  if (!data) return null;

  return (
    <div>
      <PageHeader title="Dashboard" description="A tenant-scoped snapshot of your assets, scans, and findings." />

      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <StatCard label="Total assets" value={data.total_assets} />
        <StatCard label="Verified assets" value={data.verified_assets} />
        <StatCard label="Active scans" value={data.active_scans} />
        <StatCard label="Completed scans" value={data.completed_scans} />
        <StatCard label="Failed scans" value={data.failed_scans} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Findings by severity</h2>
          {Object.keys(data.findings_by_severity).length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">No findings recorded yet.</p>
          ) : (
            <ul className="space-y-2">
              {SEVERITY_ORDER.filter((sev) => data.findings_by_severity[sev]).map((severity) => (
                <li key={severity} className="flex items-center justify-between text-sm">
                  <SeverityBadge severity={severity} />
                  <span className="font-medium text-[var(--color-text-primary)]">
                    {data.findings_by_severity[severity]}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Findings by status</h2>
          {Object.keys(data.findings_by_status).length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">No findings recorded yet.</p>
          ) : (
            <ul className="space-y-2">
              {Object.entries(data.findings_by_status).map(([status, count]) => (
                <li key={status} className="flex items-center justify-between text-sm">
                  <StatusBadge status={status} />
                  <span className="font-medium text-[var(--color-text-primary)]">{count}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Recent scans</h2>
          {data.recent_scans.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">No scans yet.</p>
          ) : (
            <ul className="space-y-2">
              {data.recent_scans.map((scan) => (
                <li key={scan.scan_id} className="flex items-center justify-between text-sm">
                  <Link to={`/app/webguard/scans/${scan.scan_id}`} className="truncate text-[var(--color-text-primary)] hover:text-[var(--color-accent)]">
                    {scan.target}
                  </Link>
                  <StatusBadge status={scan.status} />
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Recent high/critical findings</h2>
          {data.recent_high_or_critical_findings.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">None recorded.</p>
          ) : (
            <ul className="space-y-2">
              {data.recent_high_or_critical_findings.map((finding) => (
                <li key={finding.finding_id} className="flex items-center justify-between gap-2 text-sm">
                  <Link
                    to={`/app/webguard/findings/${finding.finding_id}`}
                    className="truncate text-[var(--color-text-primary)] hover:text-[var(--color-accent)]"
                  >
                    {finding.title}
                  </Link>
                  <SeverityBadge severity={finding.severity} />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
