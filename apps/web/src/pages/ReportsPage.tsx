import { Button, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge, Table, Td, Th } from "../components/ui/primitives";
import { useReports } from "../hooks/queries";
import { API_BASE_URL, ApiError, reportsApi } from "../lib/api";
import { loadSession } from "../lib/auth-storage";

async function downloadReport(reportId: string) {
  const session = loadSession();
  const response = await fetch(`${API_BASE_URL}${reportsApi.downloadUrl(reportId)}`, {
    headers: session ? { Authorization: `Bearer ${session.token}` } : {},
  });
  if (!response.ok) {
    window.alert("Unable to download this report.");
    return;
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `report-${reportId}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function ReportsPage() {
  const { data, isLoading, error } = useReports();

  return (
    <div>
      <PageHeader title="Reports" description="Registered report artifacts for your completed scans." />
      {isLoading ? <LoadingState label="Loading reports…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load reports."} /> : null}
      {data && data.reports.length === 0 ? (
        <EmptyState
          title="No reports yet"
          description="Request a report from a completed scan's detail page to see it here."
        />
      ) : null}
      {data && data.reports.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Scan</Th>
              <Th>Format</Th>
              <Th>State</Th>
              <Th>Created</Th>
              <Th>
                <span className="sr-only">Download</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {data.reports.map((report) => (
              <tr key={report.report_id} className="hover:bg-[var(--color-surface-hover)]">
                <Td className="font-mono text-xs text-[var(--color-text-secondary)]">{report.scan_id}</Td>
                <Td className="uppercase text-[var(--color-text-secondary)]">{report.format}</Td>
                <Td>
                  <StatusBadge status={report.state} />
                </Td>
                <Td className="text-[var(--color-text-secondary)]">{new Date(report.created_at).toLocaleString()}</Td>
                <Td>
                  <Button variant="secondary" onClick={() => downloadReport(report.report_id)}>
                    Download
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
    </div>
  );
}
