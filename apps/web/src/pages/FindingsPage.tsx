import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { EmptyState, ErrorState, LoadingState, PageHeader, SeverityBadge, StatusBadge, Table, Td, Th } from "../components/ui/primitives";
import { useFindings } from "../hooks/queries";
import { ApiError } from "../lib/api";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const STATUSES = ["open", "confirmed", "false_positive", "accepted_risk", "resolved", "reopened"];

export function FindingsPage() {
  const [searchParams] = useSearchParams();
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [cwe, setCwe] = useState("");
  const asset = searchParams.get("asset") ?? "";

  const { data, isLoading, error } = useFindings({
    severity: severity || undefined,
    status: status || undefined,
    cwe_id: cwe || undefined,
    asset: asset || undefined,
  });

  return (
    <div>
      <PageHeader title="Findings" description={asset ? `Filtered to ${asset}` : "Every finding detected across your organization."} />

      <div className="mb-4 flex flex-wrap gap-3">
        <select
          aria-label="Filter by severity"
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          className="rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2 py-1.5 text-sm text-[var(--color-text-primary)]"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by status"
          value={status}
          onChange={(event) => setStatus(event.target.value)}
          className="rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2 py-1.5 text-sm text-[var(--color-text-primary)]"
        >
          <option value="">All statuses</option>
          {STATUSES.map((option) => (
            <option key={option} value={option}>
              {option.replace(/_/g, " ")}
            </option>
          ))}
        </select>
        <input
          aria-label="Filter by CWE"
          value={cwe}
          onChange={(event) => setCwe(event.target.value)}
          placeholder="CWE-79"
          className="w-32 rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2 py-1.5 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)]"
        />
      </div>

      {isLoading ? <LoadingState label="Loading findings…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load findings."} /> : null}
      {data && data.findings.length === 0 ? (
        <EmptyState title="No findings match these filters" description="Findings will appear here once a scan detects them." />
      ) : null}
      {data && data.findings.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Severity</Th>
              <Th>Title</Th>
              <Th>Asset</Th>
              <Th>Endpoint</Th>
              <Th>CWE</Th>
              <Th>Status</Th>
              <Th>Last seen</Th>
            </tr>
          </thead>
          <tbody>
            {data.findings.map((finding) => (
              <tr key={finding.finding_id} className="hover:bg-[var(--color-surface-hover)]">
                <Td>
                  <SeverityBadge severity={finding.severity} />
                </Td>
                <Td>
                  <Link to={`/findings/${finding.finding_id}`} className="text-[var(--color-text-primary)] hover:text-[var(--color-accent)]">
                    {finding.title}
                  </Link>
                </Td>
                <Td className="max-w-48 truncate text-[var(--color-text-secondary)]">{finding.asset}</Td>
                <Td className="text-[var(--color-text-secondary)]">{finding.endpoint}</Td>
                <Td className="text-[var(--color-text-secondary)]">{finding.cwe_id ?? "—"}</Td>
                <Td>
                  <StatusBadge status={finding.status} />
                </Td>
                <Td className="text-[var(--color-text-secondary)]">{new Date(finding.last_seen_at).toLocaleDateString()}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
    </div>
  );
}
