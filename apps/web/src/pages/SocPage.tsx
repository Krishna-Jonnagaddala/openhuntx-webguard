import { Link } from "react-router-dom";
import {
  Card,
  ErrorState,
  InDevelopmentNotice,
  LoadingState,
  PageHeader,
} from "../components/ui/primitives";
import { useModuleEntitlements, useSocConnectors } from "../hooks/queries";
import { ApiError } from "../lib/api";
import type { SocConnector } from "../lib/api";
import { useAuth } from "../lib/auth";

const LIVE_STATE_LABEL: Record<SocConnector["live_validation_state"], string> = {
  not_started: "Not started",
  contract_designed: "Contract designed",
  fixture_tested: "Fixture tested",
  blocked_on_credentials: "Blocked on credentials",
  live_validated: "Live validated",
};

function ConnectorCard({ connector }: { connector: SocConnector }) {
  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium text-[var(--color-text-primary)]">{connector.display_name}</p>
          <p className="text-sm text-[var(--color-text-secondary)]">
            {connector.vendor} · {connector.api_family}
          </p>
        </div>
        <span className="shrink-0 rounded bg-[var(--color-warning-bg)] px-2 py-0.5 text-xs font-medium text-[var(--color-warning)]">
          {LIVE_STATE_LABEL[connector.live_validation_state]}
        </span>
      </div>
      <p className="mt-3 text-sm text-[var(--color-text-secondary)]">{connector.licensing_dependency}</p>
      <div className="mt-4">
        <p className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-tertiary)]">
          Required permissions ({connector.permissions.length})
        </p>
        <ul className="mt-2 space-y-1.5">
          {connector.permissions.map((permission) => (
            <li key={permission.name} className="text-sm">
              <code className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 font-mono text-xs text-[var(--color-text-primary)]">
                {permission.name}
              </code>{" "}
              <span className="text-[var(--color-text-secondary)]">{permission.purpose}</span>
            </li>
          ))}
        </ul>
      </div>
      {connector.known_limitations.length > 0 ? (
        <div className="mt-4 border-t border-[var(--color-border)] pt-3">
          <p className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-tertiary)]">
            Known limitations
          </p>
          <ul className="mt-2 list-disc space-y-1 pl-4 text-sm text-[var(--color-text-secondary)]">
            {connector.known_limitations.map((limitation) => (
              <li key={limitation}>{limitation}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  );
}

export function SocPage() {
  const { data: entitlements, isLoading: entitlementsLoading } = useModuleEntitlements();
  const { session } = useAuth();
  const socEntitlement = entitlements?.entitlements.find((entitlement) => entitlement.module === "soc");
  // Never fetch the connector catalog until we know whether this
  // deployment offers SOC at all: available=false must never reach
  // the server, since the route itself now rejects it there too.
  const available = entitlements ? (socEntitlement?.available ?? true) : false;
  const { data, isLoading, error } = useSocConnectors(available);

  return (
    <div>
      <PageHeader
        title="SOC"
        description="Connector contracts for the Microsoft security products this module is built against."
      />
      {!entitlementsLoading && !available ? (
        <div className="mb-4">
          <InDevelopmentNotice>
            SOC is not part of this release. It is a separate module still in development; this deployment only
            offers WebGuard today.
          </InDevelopmentNotice>
        </div>
      ) : socEntitlement && socEntitlement.status === "disabled" ? (
        <div className="mb-4">
          <InDevelopmentNotice>
            {session?.role === "owner" ? (
              <>
                SOC is not enabled for your organization yet. You can still review every connector's reviewed
                contract below; <Link to="/app/settings" className="underline">enable it from Settings</Link>.
              </>
            ) : (
              <>
                SOC is not enabled for your organization yet. You can still review every connector's reviewed
                contract below; contact an organization owner to request access once a live connection is available.
              </>
            )}
          </InDevelopmentNotice>
        </div>
      ) : (
        <div className="mb-4">
          <InDevelopmentNotice>
            No connector below has a live HTTP client yet. Every manifest is designed and permission-verified
            against the vendor's own documentation, ahead of a real tenant connection.
          </InDevelopmentNotice>
        </div>
      )}
      {available && isLoading ? <LoadingState label="Loading connectors…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load connectors."} /> : null}
      {data ? (
        <div className="grid gap-4 lg:grid-cols-2">
          {data.connectors.map((connector) => (
            <ConnectorCard key={connector.connector_id} connector={connector} />
          ))}
        </div>
      ) : null}
    </div>
  );
}
