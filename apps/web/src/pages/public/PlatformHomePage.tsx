import { Link } from "react-router-dom";
import { OpenHuntXMark, OpenHuntXWordmark } from "../../components/brand/Brand";
import { Button, Card } from "../../components/ui/primitives";

const MODULES = [
  {
    to: "/webguard",
    name: "WebGuard",
    tag: "Available now",
    description:
      "Cryptographically scoped scan permits, safety-bounded execution, and a running findings and coverage record for the web assets you've verified ownership of.",
  },
  {
    to: "/soc",
    name: "SOC",
    tag: "In development",
    description:
      "A security-operations view built on connector contracts for Microsoft Entra ID, Defender XDR, and Sentinel, designed and reviewed ahead of a live connection.",
  },
  {
    to: "/compliance",
    name: "Compliance",
    tag: "In development",
    description:
      "Framework tracking and technical assertions checked against real evidence, starting with one fully evaluated control and a named catalog of what comes next.",
  },
];

export function PlatformHomePage() {
  return (
    <>
      <section className="relative overflow-hidden border-b border-[var(--color-border)]">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 80% 60% at 50% -10%, rgba(229,27,42,0.12), transparent 60%)",
          }}
        />
        <div className="relative mx-auto max-w-4xl px-6 py-24 text-center sm:py-32">
          <div className="mb-8 flex justify-center">
            <OpenHuntXMark className="h-16 w-16" />
          </div>
          <h1 className="flex flex-wrap items-baseline justify-center gap-x-3 text-4xl sm:text-5xl">
            <OpenHuntXWordmark glow className="text-[1em]" />
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-balance text-lg text-[var(--color-text-secondary)]">
            One platform for proving your security posture: authorized web vulnerability discovery today, security
            operations and compliance evidence as they come online.
          </p>
          <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
            <Link to="/register">
              <Button variant="primary" className="px-5 py-2.5 text-base">
                Create a free account
              </Button>
            </Link>
            <Link to="/webguard">
              <Button variant="secondary" className="px-5 py-2.5 text-base">
                See what WebGuard does
              </Button>
            </Link>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-6 py-20">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
          Three modules, one platform
        </h2>
        <p className="mt-2 max-w-2xl text-[var(--color-text-secondary)]">
          A single organization, a single sign-on, and one shared identity and access model underneath every module
          below. Each one has its own dedicated area once you're signed in.
        </p>
        <div className="mt-8 grid gap-5 lg:grid-cols-3">
          {MODULES.map((module) => (
            <Card key={module.to} className="flex flex-col p-6">
              <div className="flex items-center justify-between gap-3">
                <span className="font-display text-lg tracking-wide text-[var(--color-text-primary)]">
                  {module.name}
                </span>
                <span
                  className={`shrink-0 rounded px-2 py-0.5 text-xs font-medium ${
                    module.tag === "Available now"
                      ? "bg-[var(--color-success-bg)] text-[var(--color-success)]"
                      : "bg-[var(--color-warning-bg)] text-[var(--color-warning)]"
                  }`}
                >
                  {module.tag}
                </span>
              </div>
              <p className="mt-3 flex-1 text-sm text-[var(--color-text-secondary)]">{module.description}</p>
              <Link
                to={module.to}
                className="mt-5 text-sm font-medium text-[var(--color-accent)] hover:text-[var(--color-accent-hover)]"
              >
                Learn more about {module.name} →
              </Link>
            </Card>
          ))}
        </div>
      </section>

      <section className="border-t border-[var(--color-border)] bg-[var(--color-surface)]">
        <div className="mx-auto max-w-6xl px-6 py-20">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
            What's real today
          </h2>
          <dl className="mt-6 grid gap-x-8 gap-y-6 sm:grid-cols-3">
            <div>
              <dt className="font-medium text-[var(--color-text-primary)]">WebGuard</dt>
              <dd className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Target verification, permit-scoped scanning, findings, the Coverage Truth Map, and downloadable
                reports run end to end today.
              </dd>
            </div>
            <div>
              <dt className="font-medium text-[var(--color-text-primary)]">SOC</dt>
              <dd className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Connector contracts for three Microsoft security products are designed and permission-verified. No
                live tenant connection exists yet.
              </dd>
            </div>
            <div>
              <dt className="font-medium text-[var(--color-text-primary)]">Compliance</dt>
              <dd className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Five named frameworks are tracked as references, with no control content loaded yet. One technical
                assertion has real, evidence-based evaluation logic; four more are cataloged and awaiting it.
              </dd>
            </div>
          </dl>
        </div>
      </section>

      <section className="mx-auto max-w-4xl px-6 py-20 text-center">
        <h2 className="text-2xl font-semibold text-[var(--color-text-primary)]">Start with WebGuard</h2>
        <p className="mx-auto mt-3 max-w-xl text-[var(--color-text-secondary)]">
          Verify a target you own, issue a scoped scan permit, and see a real finding come through the pipeline.
        </p>
        <div className="mt-7">
          <Link to="/register">
            <Button variant="primary" className="px-5 py-2.5 text-base">
              Create a free account
            </Button>
          </Link>
        </div>
      </section>
    </>
  );
}
