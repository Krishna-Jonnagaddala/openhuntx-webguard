import { Link } from "react-router-dom";
import { ProductLockup } from "../../components/brand/Brand";
import { Button, Card, InDevelopmentNotice } from "../../components/ui/primitives";

const CONNECTORS = [
  {
    name: "Microsoft Entra ID",
    detail: "Privileged role assignments, Conditional Access policy mode, user and sign-in activity.",
  },
  {
    name: "Microsoft Defender XDR",
    detail: "Incident and alert streams, advanced hunting, and Secure Score, via the unified Graph security API.",
  },
  {
    name: "Microsoft Sentinel",
    detail: "Incidents, analytics rules, and data connector health, for a standalone Sentinel workspace.",
  },
];

export function SocProductPage() {
  return (
    <>
      <section className="border-b border-[var(--color-border)]">
        <div className="mx-auto max-w-4xl px-6 py-20 text-center">
          <ProductLockup product="SOC" className="mx-auto justify-center text-2xl" />
          <p className="mx-auto mt-6 max-w-2xl text-lg text-[var(--color-text-secondary)]">
            A security-operations view of your Microsoft security stack: identity, endpoint, and workspace telemetry
            in one place, under the same organization and access model as the rest of OpenHuntX.
          </p>
          <div className="mx-auto mt-8 max-w-xl">
            <InDevelopmentNotice>
              SOC is in active development. Connector contracts below are designed and verified against Microsoft's
              own current API documentation; none is connected to a live tenant yet.
            </InDevelopmentNotice>
          </div>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link to="/register">
              <Button variant="primary" className="px-5 py-2.5 text-base">
                Create a free account
              </Button>
            </Link>
            <Link to="/login">
              <Button variant="secondary" className="px-5 py-2.5 text-base">
                Sign in
              </Button>
            </Link>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-6 py-20">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
          Connectors designed so far
        </h2>
        <p className="mt-2 max-w-2xl text-[var(--color-text-secondary)]">
          Each connector below specifies its exact required permissions, its API surface, and its own operational
          limits, reviewed against Microsoft's documentation before a single line of client code is written.
        </p>
        <div className="mt-8 space-y-4">
          {CONNECTORS.map((connector) => (
            <Card key={connector.name} className="flex flex-col gap-1 p-5 sm:flex-row sm:items-baseline sm:gap-6">
              <p className="w-56 shrink-0 font-medium text-[var(--color-text-primary)]">{connector.name}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">{connector.detail}</p>
            </Card>
          ))}
        </div>
      </section>

      <section className="border-t border-[var(--color-border)] bg-[var(--color-surface)]">
        <div className="mx-auto max-w-4xl px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Sign in to see each connector's exact permission set, endpoints, and current status in your own
            organization.
          </p>
          <div className="mt-5">
            <Link to="/login">
              <Button variant="secondary">Sign in</Button>
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
