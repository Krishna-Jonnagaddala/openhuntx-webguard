import { Link } from "react-router-dom";
import { ProductLockup, WEBGUARD_TAGLINE } from "../../components/brand/Brand";
import { Button, Card } from "../../components/ui/primitives";

const STEPS = [
  {
    title: "Verify a target",
    body: "Prove ownership of a web asset with a DNS TXT record or a well-known HTTP file before anything else can happen against it.",
  },
  {
    title: "Issue a scan permit",
    body: "A signed, time-bounded permit states exactly which checks and HTTP methods are authorized for that target. Nothing runs outside it.",
  },
  {
    title: "Run an authorized scan",
    body: "Execution stays inside the permit's own limits the whole way through, with a signed Safety Receipt recording what was actually enforced.",
  },
  {
    title: "Review findings and coverage",
    body: "Findings land with severity and status tracking. The Coverage Truth Map shows exactly what was checked and what wasn't, honestly, not as a fabricated percentage.",
  },
  {
    title: "Export a report",
    body: "Pull a native report once a scan completes, with real integrity verification behind the download.",
  },
];

export function WebGuardProductPage() {
  return (
    <>
      <section className="border-b border-[var(--color-border)]">
        <div className="mx-auto max-w-4xl px-6 py-20 text-center">
          <ProductLockup product="WebGuard" className="mx-auto justify-center text-2xl" />
          <p className="mt-4 font-display text-xs tracking-[0.2em] text-[var(--color-text-tertiary)]">
            {WEBGUARD_TAGLINE}
          </p>
          <p className="mx-auto mt-6 max-w-2xl text-lg text-[var(--color-text-secondary)]">
            WebGuard runs authorized vulnerability scans against web assets you've verified, inside a scope you
            define, and gives you an honest record of what was actually checked.
          </p>
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
          How a scan happens
        </h2>
        <ol className="mt-8 space-y-0">
          {STEPS.map((step, index) => (
            <li key={step.title} className="flex gap-5 border-l-2 border-[var(--color-border)] py-5 pl-6 first:pt-0 last:border-transparent">
              <span
                aria-hidden="true"
                className="-ml-[calc(1.75rem+1px)] flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-[var(--color-border-strong)] bg-[var(--color-surface-raised)] font-display text-xs text-[var(--color-text-secondary)]"
              >
                {index + 1}
              </span>
              <div>
                <p className="font-medium text-[var(--color-text-primary)]">{step.title}</p>
                <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{step.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="border-t border-[var(--color-border)] bg-[var(--color-surface)]">
        <div className="mx-auto max-w-5xl px-6 py-20">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
            What's available in your account today
          </h2>
          <div className="mt-6 grid gap-5 sm:grid-cols-2">
            <Card className="p-5">
              <p className="font-medium text-[var(--color-text-primary)]">Passive and active checks</p>
              <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Passive, analyzer-style checks run under an ordinary permit. Active, more intrusive checks require an
                organization owner to issue a permit that explicitly authorizes them.
              </p>
            </Card>
            <Card className="p-5">
              <p className="font-medium text-[var(--color-text-primary)]">Scheduling</p>
              <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Recurring scans run against a materialized, permit-backed schedule, not a bare cron entry with no
                authorization behind it.
              </p>
            </Card>
            <Card className="p-5">
              <p className="font-medium text-[var(--color-text-primary)]">Team roles</p>
              <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Owner, administrator, analyst, and viewer roles, each with a distinct permission set enforced on
                every request, not just hidden in the interface.
              </p>
            </Card>
            <Card className="p-5">
              <p className="font-medium text-[var(--color-text-primary)]">Coverage Truth Map</p>
              <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Recorded coverage states are completed, blocked, or unreachable, with an honest denominator. An
                unchecked path stays unchecked; it never becomes a fabricated pass.
              </p>
            </Card>
          </div>
        </div>
      </section>
    </>
  );
}
