import { useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge, Table, Td, Th } from "../components/ui/primitives";
import { useScans } from "../hooks/queries";
import { ApiError } from "../lib/api";

const STATUS_OPTIONS = ["queued", "running", "completed", "completed_with_errors", "failed", "cancelled"];

function duration(started: string | null, completed: string | null): string {
  if (!started) return "-";
  const end = completed ? new Date(completed).getTime() : Date.now();
  const seconds = Math.max(0, Math.round((end - new Date(started).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

export function ScansPage() {
  const [status, setStatus] = useState<string>("");
  const { data, isLoading, error } = useScans(status ? { status } : undefined);

  return (
    <div>
      <PageHeader title="Scans" description="Every scan execution across your organization's assets." />
      <div className="mb-4">
        <label htmlFor="scan-status-filter" className="mr-2 text-sm text-[var(--color-text-secondary)]">
          Status
        </label>
        <select
          id="scan-status-filter"
          value={status}
          onChange={(event) => setStatus(event.target.value)}
          className="rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2 py-1.5 text-sm text-[var(--color-text-primary)]"
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map((option) => (
            <option key={option} value={option}>
              {option.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </div>

      {isLoading ? <LoadingState label="Loading scans…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load scans."} /> : null}
      {data && data.scans.length === 0 ? (
        <EmptyState title="No scans yet" description="Start a scan from an asset's detail page to see it here." />
      ) : null}
      {data && data.scans.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Target</Th>
              <Th>Profile</Th>
              <Th>Status</Th>
              <Th>Findings</Th>
              <Th>Started</Th>
              <Th>Duration</Th>
            </tr>
          </thead>
          <tbody>
            {data.scans.map((scan) => (
              <tr key={scan.scan_id} className="hover:bg-[var(--color-surface-hover)]">
                <Td>
                  <Link to={`/scans/${scan.scan_id}`} className="text-[var(--color-text-primary)] hover:text-[var(--color-accent)]">
                    {scan.target}
                  </Link>
                </Td>
                <Td className="text-[var(--color-text-secondary)] capitalize">{scan.mode.replace("_", " ")}</Td>
                <Td>
                  <StatusBadge status={scan.status} />
                </Td>
                <Td className="text-[var(--color-text-secondary)]">{scan.finding_count}</Td>
                <Td className="text-[var(--color-text-secondary)]">
                  {scan.started_at ? new Date(scan.started_at).toLocaleString() : "-"}
                </Td>
                <Td className="text-[var(--color-text-secondary)]">{duration(scan.started_at, scan.completed_at)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
    </div>
  );
}
