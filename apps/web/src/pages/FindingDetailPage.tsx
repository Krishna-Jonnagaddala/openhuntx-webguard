import { useState } from "react";
import { useParams } from "react-router-dom";
import { Button, Card, ErrorState, LoadingState, PageHeader, SeverityBadge, StatusBadge } from "../components/ui/primitives";
import { useFinding, useFindingEvents, useUpdateFindingStatus } from "../hooks/queries";
import { ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";

const LIFECYCLE_ACTIONS: { status: string; label: string }[] = [
  { status: "confirmed", label: "Confirm" },
  { status: "false_positive", label: "False Positive" },
  { status: "accepted_risk", label: "Accept Risk" },
  { status: "resolved", label: "Resolve" },
];

function canManageFindings(role: string | undefined): boolean {
  return role === "owner" || role === "administrator" || role === "analyst";
}

export function FindingDetailPage() {
  const { findingId } = useParams<{ findingId: string }>();
  const { session } = useAuth();
  const { data: finding, isLoading, error } = useFinding(findingId);
  const { data: history } = useFindingEvents(findingId);
  const updateStatus = useUpdateFindingStatus();
  const [reason, setReason] = useState("");
  const [pendingAction, setPendingAction] = useState<string | null>(null);

  if (isLoading) return <LoadingState label="Loading finding…" />;
  if (error) return <ErrorState message={error instanceof ApiError ? error.message : "Unable to load this finding."} />;
  if (!finding || !findingId) return null;

  const allowed = canManageFindings(session?.role);

  async function handleAction(status: string) {
    if (!findingId) return;
    try {
      await updateStatus.mutateAsync({ id: findingId, status, reason: reason.trim() || undefined });
      setPendingAction(null);
      setReason("");
    } catch {
      // surfaced via updateStatus.error
    }
  }

  return (
    <div>
      <PageHeader
        title={finding.title}
        description={`${finding.check_id} · ${finding.asset}${finding.endpoint}`}
        actions={
          <>
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="p-4 lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Details</h2>
          <dl className="grid grid-cols-2 gap-y-2 text-sm">
            <dt className="text-[var(--color-text-secondary)]">Confidence</dt>
            <dd className="text-[var(--color-text-primary)] capitalize">{finding.confidence}</dd>
            <dt className="text-[var(--color-text-secondary)]">CWE</dt>
            <dd className="text-[var(--color-text-primary)]">{finding.cwe_id ?? "-"}</dd>
            <dt className="text-[var(--color-text-secondary)]">OWASP</dt>
            <dd className="text-[var(--color-text-primary)]">{finding.owasp_category ?? "-"}</dd>
            <dt className="text-[var(--color-text-secondary)]">Method</dt>
            <dd className="text-[var(--color-text-primary)]">{finding.http_method}</dd>
            <dt className="text-[var(--color-text-secondary)]">Parameter</dt>
            <dd className="text-[var(--color-text-primary)]">{finding.parameter ?? "-"}</dd>
            <dt className="text-[var(--color-text-secondary)]">First seen</dt>
            <dd className="text-[var(--color-text-primary)]">{new Date(finding.first_seen_at).toLocaleString()}</dd>
            <dt className="text-[var(--color-text-secondary)]">Last seen</dt>
            <dd className="text-[var(--color-text-primary)]">{new Date(finding.last_seen_at).toLocaleString()}</dd>
          </dl>

          {finding.evidence ? (
            <div className="mt-4">
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
                Evidence
              </h3>
              <p className="rounded bg-[var(--color-surface-raised)] p-3 font-mono text-xs text-[var(--color-text-primary)]">
                {finding.evidence}
              </p>
            </div>
          ) : null}

          {finding.remediation ? (
            <div className="mt-4">
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
                Remediation
              </h3>
              <p className="text-sm text-[var(--color-text-secondary)]">{finding.remediation}</p>
            </div>
          ) : null}

          {finding.references.length > 0 ? (
            <div className="mt-4">
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
                References
              </h3>
              <ul className="list-inside list-disc text-sm text-[var(--color-accent)]">
                {finding.references.map((ref) => (
                  <li key={ref} className="truncate">
                    <a href={ref} target="_blank" rel="noreferrer noopener" className="hover:underline">
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </Card>

        <div className="space-y-4">
          <Card className="p-4">
            <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Lifecycle</h2>
            {!allowed ? (
              <p className="text-sm text-[var(--color-text-secondary)]">
                Your role ({session?.role}) can view but not change finding status.
              </p>
            ) : (
              <div className="space-y-2">
                {LIFECYCLE_ACTIONS.map((action) => (
                  <div key={action.status}>
                    {pendingAction === action.status ? (
                      <div className="rounded-md border border-[var(--color-border)] p-2">
                        <label htmlFor={`reason-${action.status}`} className="mb-1 block text-xs text-[var(--color-text-secondary)]">
                          Reason (optional)
                        </label>
                        <textarea
                          id={`reason-${action.status}`}
                          value={reason}
                          onChange={(event) => setReason(event.target.value)}
                          rows={2}
                          className="mb-2 w-full rounded border border-[var(--color-border-strong)] bg-[var(--color-canvas)] p-1.5 text-xs text-[var(--color-text-primary)]"
                        />
                        <div className="flex gap-2">
                          <Button
                            variant="primary"
                            className="text-xs"
                            onClick={() => handleAction(action.status)}
                            disabled={updateStatus.isPending}
                          >
                            Submit
                          </Button>
                          <Button variant="ghost" className="text-xs" onClick={() => setPendingAction(null)}>
                            Cancel
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <Button
                        variant="secondary"
                        className="w-full justify-start"
                        onClick={() => setPendingAction(action.status)}
                        disabled={finding.status === action.status}
                      >
                        {action.label}
                      </Button>
                    )}
                  </div>
                ))}
                {updateStatus.isError ? (
                  <p role="alert" className="text-sm text-[var(--color-danger)]">
                    {updateStatus.error instanceof ApiError ? updateStatus.error.message : "Unable to update this finding."}
                  </p>
                ) : null}
              </div>
            )}
          </Card>

          <Card className="p-4">
            <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">History</h2>
            {!history || history.events.length === 0 ? (
              <p className="text-sm text-[var(--color-text-secondary)]">No status changes recorded.</p>
            ) : (
              <ol className="space-y-3">
                {history.events.map((event) => (
                  <li key={event.event_id} className="text-sm">
                    <p className="text-[var(--color-text-primary)]">
                      <span className="capitalize">{event.previous_status}</span> →{" "}
                      <span className="capitalize">{event.new_status}</span>
                    </p>
                    <p className="text-xs text-[var(--color-text-tertiary)]">
                      {new Date(event.created_at).toLocaleString()} · {event.changed_by ? "by a team member" : "scanner re-detection"}
                    </p>
                    {event.reason ? <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">{event.reason}</p> : null}
                  </li>
                ))}
              </ol>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
