import { Link, useParams } from "react-router-dom";
import { Button, Card, ErrorState, LoadingState, PageHeader, StatusBadge } from "../components/ui/primitives";
import { useCreateReport, useFindings, useReports, useScan } from "../hooks/queries";
import { ApiError } from "../lib/api";

function RequestReportPanel({ scanId }: { scanId: string }) {
  const { data: reports } = useReports();
  const create = useCreateReport();
  const existing = reports?.reports.find((report) => report.scan_id === scanId);

  if (existing) {
    return (
      <p className="text-sm text-[var(--color-text-secondary)]">
        A report has been requested for this scan (
        <StatusBadge status={existing.state} />
        ). <Link to="/reports" className="text-[var(--color-accent)] hover:underline">View reports →</Link>
      </p>
    );
  }

  return (
    <div>
      <Button variant="secondary" onClick={() => create.mutate(scanId)} disabled={create.isPending}>
        {create.isPending ? "Requesting…" : "Request report"}
      </Button>
      {create.isError ? (
        <p role="alert" className="mt-2 text-sm text-[var(--color-danger)]">
          {create.error instanceof ApiError ? create.error.message : "Unable to request a report."}
        </p>
      ) : null}
    </div>
  );
}

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: scan, isLoading, error } = useScan(scanId);
  const { data: findings } = useFindings(scanId ? { scan_id: scanId } : undefined);

  if (isLoading) return <LoadingState label="Loading scan…" />;
  if (error) return <ErrorState message={error instanceof ApiError ? error.message : "Unable to load this scan."} />;
  if (!scan) return null;

  return (
    <div>
      <PageHeader title={scan.target} description={`Scan ${scan.scan_id}`} actions={<StatusBadge status={scan.status} />} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Details</h2>
          <dl className="space-y-1.5 text-sm">
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Profile</dt>
              <dd className="capitalize text-[var(--color-text-primary)]">{scan.mode.replace("_", " ")}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Scanner version</dt>
              <dd className="text-[var(--color-text-primary)]">{scan.scanner_version}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Started</dt>
              <dd className="text-[var(--color-text-primary)]">
                {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Completed</dt>
              <dd className="text-[var(--color-text-primary)]">
                {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—"}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Requested checks</dt>
              <dd className="text-[var(--color-text-primary)]">
                {scan.requested_checks.length > 0 ? scan.requested_checks.join(", ") : "passive only"}
              </dd>
            </div>
          </dl>
        </Card>
        <Card className="p-4">
          <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Report</h2>
          {scan.status === "completed" ? (
            <RequestReportPanel scanId={scan.scan_id} />
          ) : (
            <p className="text-sm text-[var(--color-text-secondary)]">A report can be requested once this scan completes.</p>
          )}
        </Card>
        <Card className="p-4 lg:col-span-2">
          <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Findings ({scan.finding_count})</h2>
          {!findings || findings.findings.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">No findings from this scan.</p>
          ) : (
            <ul className="space-y-2">
              {findings.findings.map((finding) => (
                <li key={finding.finding_id}>
                  <Link to={`/findings/${finding.finding_id}`} className="text-sm text-[var(--color-text-primary)] hover:text-[var(--color-accent)]">
                    {finding.title}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
