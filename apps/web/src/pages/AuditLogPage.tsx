import { useState } from "react";
import { EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge, Table, Td, Th } from "../components/ui/primitives";
import { useAuditLog } from "../hooks/queries";
import { ApiError } from "../lib/api";

export function AuditLogPage() {
  const [outcome, setOutcome] = useState("");
  const { data, isLoading, error } = useAuditLog(outcome ? { outcome } : undefined);

  return (
    <div>
      <PageHeader title="Audit Log" description="Security-relevant actions taken across your organization." />
      <div className="mb-4">
        <label htmlFor="audit-outcome" className="mr-2 text-sm text-[var(--color-text-secondary)]">
          Outcome
        </label>
        <select
          id="audit-outcome"
          value={outcome}
          onChange={(event) => setOutcome(event.target.value)}
          className="rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2 py-1.5 text-sm text-[var(--color-text-primary)]"
        >
          <option value="">All outcomes</option>
          <option value="succeeded">Succeeded</option>
          <option value="failed">Failed</option>
          <option value="denied">Denied</option>
        </select>
      </div>

      {isLoading ? <LoadingState label="Loading audit log…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load the audit log."} /> : null}
      {data && data.events.length === 0 ? <EmptyState title="No matching events" /> : null}
      {data && data.events.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Timestamp</Th>
              <Th>Action</Th>
              <Th>Resource</Th>
              <Th>Outcome</Th>
            </tr>
          </thead>
          <tbody>
            {data.events.map((event) => (
              <tr key={event.event_id} className="hover:bg-[var(--color-surface-hover)]">
                <Td className="text-[var(--color-text-secondary)]">{new Date(event.occurred_at).toLocaleString()}</Td>
                <Td>{event.action}</Td>
                <Td className="text-[var(--color-text-secondary)]">
                  {event.resource_type}:{event.resource_id.slice(0, 8)}
                </Td>
                <Td>
                  <StatusBadge status={event.outcome} />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
    </div>
  );
}
