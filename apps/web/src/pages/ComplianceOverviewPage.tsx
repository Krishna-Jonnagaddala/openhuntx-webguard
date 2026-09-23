import { Link } from "react-router-dom";
import { Card, ErrorState, InDevelopmentNotice, LoadingState, PageHeader, StatusBadge } from "../components/ui/primitives";
import { useComplianceFrameworks, useModuleEntitlements } from "../hooks/queries";
import { ApiError } from "../lib/api";

const STATUS_LABEL: Record<string, string> = {
  placeholder: "Reference only",
  current: "Current",
  proposed: "Proposed",
  future_readiness: "Future readiness",
  superseded: "Superseded",
};

export function ComplianceOverviewPage() {
  const { data: entitlements, isLoading: entitlementsLoading } = useModuleEntitlements();
  const complianceEntitlement = entitlements?.entitlements.find((entitlement) => entitlement.module === "compliance");
  // Never fetch the framework catalog until we know whether this
  // deployment offers Compliance at all: available=false must never
  // reach the server, since the route itself now rejects it there too.
  const available = entitlements ? (complianceEntitlement?.available ?? true) : false;
  const { data, isLoading, error } = useComplianceFrameworks(available);

  return (
    <div>
      <PageHeader
        title="Frameworks"
        description="Frameworks your organization can track, and how many controls this platform has loaded under each one."
      />
      {!entitlementsLoading && !available ? (
        <div className="mb-4">
          <InDevelopmentNotice>
            Compliance is not part of this release. It is a separate module still in development; this deployment
            only offers WebGuard today.
          </InDevelopmentNotice>
        </div>
      ) : null}
      {available && isLoading ? <LoadingState label="Loading frameworks…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load frameworks."} /> : null}
      {data ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {data.frameworks.map((framework) => (
            <Card key={framework.framework_id} className="p-5">
              <div className="flex items-start justify-between gap-2">
                <p className="font-medium text-[var(--color-text-primary)]">{framework.name}</p>
                <span className="shrink-0 rounded bg-[var(--color-surface-raised)] px-2 py-0.5 text-xs font-medium text-[var(--color-text-secondary)]">
                  {STATUS_LABEL[framework.status] ?? framework.status}
                </span>
              </div>
              <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{framework.version}</p>
              <p className="mt-3 text-sm text-[var(--color-text-secondary)]">
                {framework.control_count === 0
                  ? "No controls loaded yet."
                  : `${framework.control_count} control${framework.control_count === 1 ? "" : "s"} loaded.`}
              </p>
              <a
                href={framework.source_reference}
                target="_blank"
                rel="noreferrer"
                className="mt-3 inline-block text-sm text-[var(--color-accent)] hover:underline"
              >
                Authoritative source ↗
              </a>
            </Card>
          ))}
        </div>
      ) : null}
      {available ? (
        <div className="mt-8 flex items-center gap-3 border-t border-[var(--color-border)] pt-6">
          <StatusBadge status="pending" />
          <p className="text-sm text-[var(--color-text-secondary)]">
            Looking for something you can actually run today?{" "}
            <Link to="/app/compliance/assertions" className="text-[var(--color-accent)] hover:underline">
              See the technical assertion catalog →
            </Link>
          </p>
        </div>
      ) : null}
    </div>
  );
}
