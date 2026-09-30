import { Link } from "react-router-dom";
import { ProductLockup } from "../../components/brand/Brand";
import { Button, Card, InDevelopmentNotice } from "../../components/ui/primitives";

const FRAMEWORKS = ["SOC 2", "ISO/IEC 27001", "HIPAA Security Rule", "EU GDPR", "UK GDPR"];

export function CompliancePage() {
  return (
    <>
      <section className="border-b border-[var(--color-border)]">
        <div className="mx-auto max-w-4xl px-6 py-20 text-center">
          <ProductLockup product="Compliance" className="mx-auto justify-center text-2xl" />
          <p className="mx-auto mt-6 max-w-2xl text-lg text-[var(--color-text-secondary)]">
            Track the frameworks you care about and check specific, evidence-based technical assertions against
            them, with every result labeled by exactly where its evidence came from.
          </p>
          <div className="mx-auto mt-8 max-w-xl">
            <InDevelopmentNotice>
              Compliance is in active development. Frameworks below are named references with no legally-reviewed
              control content loaded yet; one technical assertion has real evaluation logic today.
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
          Frameworks tracked today
        </h2>
        <div className="mt-6 flex flex-wrap gap-2.5">
          {FRAMEWORKS.map((name) => (
            <span
              key={name}
              className="rounded-full border border-[var(--color-border-strong)] px-3.5 py-1.5 text-sm text-[var(--color-text-secondary)]"
            >
              {name}
            </span>
          ))}
        </div>
        <p className="mt-4 max-w-2xl text-sm text-[var(--color-text-secondary)]">
          Each is named and cited to its own authoritative source. None carries real control content yet: loading
          it is a deliberate, later step gated on legal review, not something this page or product implies is
          already done.
        </p>
      </section>

      <section className="border-t border-[var(--color-border)] bg-[var(--color-surface)]">
        <div className="mx-auto max-w-5xl px-6 py-20">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
            How a technical assertion works
          </h2>
          <div className="mt-8 grid gap-5 sm:grid-cols-2">
            <Card className="p-5">
              <p className="font-medium text-[var(--color-text-primary)]">Collection, then evaluation</p>
              <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Collecting evidence and evaluating it are two separate, timestamped steps. A collection can fail
                outright; a successful one is evaluated into a real, distinct outcome.
              </p>
            </Card>
            <Card className="p-5">
              <p className="font-medium text-[var(--color-text-primary)]">Evidence provenance, always labeled</p>
              <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Every result names whether its evidence was a checked-in fixture or manually supplied. Nothing is
                ever presented as a live vendor read unless it actually is one.
              </p>
            </Card>
            <Card className="p-5">
              <p className="font-medium text-[var(--color-text-primary)]">Satisfied, violated, or indeterminate</p>
              <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                An assertion with incomplete evidence is reported as indeterminate, a distinct outcome from either a
                pass or a fail, never silently folded into one or the other.
              </p>
            </Card>
            <Card className="p-5">
              <p className="font-medium text-[var(--color-text-primary)]">One assertion evaluated today</p>
              <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
                Conditional Access policy mode is fully implemented: satisfied only if at least one policy is
                actually enforced, not merely configured in report-only mode.
              </p>
            </Card>
          </div>
        </div>
      </section>
    </>
  );
}
