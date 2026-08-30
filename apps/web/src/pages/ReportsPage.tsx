import { Button, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge, Table, Td, Th } from "../components/ui/primitives";
import { useReports } from "../hooks/queries";
import { API_BASE_URL, ApiError, reportsApi } from "../lib/api";

async function downloadReport(reportId: string) {
  // Session-cookie auth (Slice 16): the browser attaches the HttpOnly
  // session cookie automatically -- there is no token in JS-reachable
  // storage to attach a header from. A GET never needs the CSRF header
  // either (see api.ts's request()).
  const response = await fetch(`${API_BASE_URL}${reportsApi.downloadUrl(reportId)}`, {
    credentials: "include",
  });
  if (!response.ok) {
    // The backend's own error message is already sanitized -- it
    // never contains a vendor's raw response text (e.g. an S3
    // AccessDenied detail or a Postmark error code) -- so it is safe
    // to surface directly. Falls back to a generic message if the
    // body isn't the expected JSON error envelope.
    let message = "We couldn't download this report. Please try again.";
    try {
      const body = await response.json();
      if (typeof body?.error?.message === "string") message = body.error.message;
    } catch {
      // not JSON -- keep the generic message
    }
    window.alert(message);
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
