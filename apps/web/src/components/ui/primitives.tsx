import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from "react";

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] ${className ?? ""}`}
    >
      {children}
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">{title}</h1>
        {description ? <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{description}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost";
}

export function Button({ variant = "secondary", className, ...props }: ButtonProps) {
  const base =
    "inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  const styles: Record<string, string> = {
    primary: "bg-[var(--color-accent)] text-[var(--color-text-on-accent)] hover:bg-[var(--color-accent-hover)]",
    secondary:
      "border border-[var(--color-border-strong)] bg-[var(--color-surface-raised)] text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)]",
    danger: "border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger-bg)]",
    ghost: "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)]",
  };
  return <button className={`${base} ${styles[variant]} ${className ?? ""}`} {...props} />;
}

export function EmptyState({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-[var(--color-border)] px-6 py-16 text-center">
      <p className="text-sm font-medium text-[var(--color-text-primary)]">{title}</p>
      {description ? <p className="max-w-sm text-sm text-[var(--color-text-secondary)]">{description}</p> : null}
      {action}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 px-1 py-8 text-sm text-[var(--color-text-secondary)]">
      <span
        aria-hidden="true"
        className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-[var(--color-border-strong)] border-t-[var(--color-accent)]"
      />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div role="alert" className="rounded-lg border border-[var(--color-danger)]/40 bg-[var(--color-danger-bg)] px-4 py-3 text-sm text-[var(--color-text-primary)]">
      {message}
    </div>
  );
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "text-[var(--color-sev-critical)] bg-[var(--color-sev-critical-bg)]",
  high: "text-[var(--color-sev-high)] bg-[var(--color-sev-high-bg)]",
  medium: "text-[var(--color-sev-medium)] bg-[var(--color-sev-medium-bg)]",
  low: "text-[var(--color-sev-low)] bg-[var(--color-sev-low-bg)]",
  informational: "text-[var(--color-sev-info)] bg-[var(--color-sev-info-bg)]",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.informational;
  return (
    <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium capitalize ${style}`}>{severity}</span>
  );
}

const STATUS_TONE: Record<string, "success" | "warning" | "danger" | "info" | "neutral"> = {
  verified: "success",
  active: "success",
  completed: "success",
  succeeded: "success",
  resolved: "success",
  confirmed: "warning",
  pending: "info",
  running: "info",
  queued: "neutral",
  expiring_soon: "warning",
  paused: "warning",
  false_positive: "neutral",
  accepted_risk: "neutral",
  failed: "danger",
  denied: "danger",
  expired: "danger",
  cancelled: "neutral",
  completed_with_errors: "warning",
  open: "info",
  reopened: "danger",
  enabled: "success",
  disabled: "neutral",
  trial: "warning",
};

const TONE_STYLES: Record<string, string> = {
  success: "text-[var(--color-success)] bg-[var(--color-success-bg)]",
  warning: "text-[var(--color-warning)] bg-[var(--color-warning-bg)]",
  danger: "text-[var(--color-danger)] bg-[var(--color-danger-bg)]",
  info: "text-[var(--color-info)] bg-[var(--color-info-bg)]",
  neutral: "text-[var(--color-text-secondary)] bg-[var(--color-surface-raised)]",
};

export function StatusBadge({ status }: { status: string }) {
  const tone = STATUS_TONE[status] ?? "neutral";
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium capitalize ${TONE_STYLES[tone]}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-[var(--color-border)]">
      <table className="w-full min-w-max border-collapse text-sm">{children}</table>
    </div>
  );
}

export function Th({ children }: { children: ReactNode }) {
  return (
    <th scope="col" className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--color-text-tertiary)]">
      {children}
    </th>
  );
}

export function Td({ children, className }: { children: ReactNode; className?: string }) {
  return <td className={`border-b border-[var(--color-border)] px-4 py-3 text-[var(--color-text-primary)] ${className ?? ""}`}>{children}</td>;
}

export function VisuallyHidden({ children }: { children: ReactNode }) {
  return <span className="sr-only">{children}</span>;
}

export interface TabItem {
  id: string;
  label: string;
  count?: number;
}

/** Roving-tab-index tab list (WAI-ARIA "manual activation" pattern:
 * arrow keys move focus, the panel only changes on Enter/Space or a
 * click, so a keyboard user can arrow past tabs without triggering a
 * fetch for each one). The caller owns which panel renders. */
export function Tabs({
  items,
  value,
  onChange,
  className,
}: {
  items: TabItem[];
  value: string;
  onChange: (id: string) => void;
  className?: string;
}) {
  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const index = items.findIndex((item) => item.id === value);
    if (index === -1) return;
    if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      event.preventDefault();
      const delta = event.key === "ArrowRight" ? 1 : -1;
      const next = items[(index + delta + items.length) % items.length];
      onChange(next.id);
    } else if (event.key === "Home") {
      event.preventDefault();
      onChange(items[0].id);
    } else if (event.key === "End") {
      event.preventDefault();
      onChange(items[items.length - 1].id);
    }
  }

  return (
    <div
      role="tablist"
      aria-orientation="horizontal"
      onKeyDown={handleKeyDown}
      className={`flex items-center gap-1 overflow-x-auto border-b border-[var(--color-border)] ${className ?? ""}`}
    >
      {items.map((item) => {
        const active = item.id === value;
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(item.id)}
            className={`relative shrink-0 whitespace-nowrap px-3 py-2.5 text-sm font-medium transition-colors ${
              active
                ? "text-[var(--color-text-primary)]"
                : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {item.label}
            {item.count !== undefined ? (
              <span className="ml-1.5 text-xs text-[var(--color-text-tertiary)]">{item.count}</span>
            ) : null}
            {active ? (
              <span className="absolute inset-x-0 -bottom-px h-0.5 rounded-full bg-[var(--color-accent)]" />
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

/** A focused, labelled modal. Traps Escape-to-close and restores focus
 * to the element that opened it; does not implement a full focus
 * trap (tabbing out to the browser chrome is possible), a deliberate
 * scope line for this app's own dialogs, which are short forms/
 * confirmations, not multi-step wizards. */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
}) {
  const titleId = useId();
  const descriptionId = useId();
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    previouslyFocused.current = document.activeElement as HTMLElement | null;
    function handleKeyDown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previouslyFocused.current?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        aria-hidden="true"
        className="absolute inset-0 bg-[var(--color-canvas)]/80 backdrop-blur-sm"
        onClick={onClose}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        className="relative w-full max-w-lg rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface-raised)] p-5 shadow-2xl"
      >
        <h2 id={titleId} className="text-base font-semibold text-[var(--color-text-primary)]">
          {title}
        </h2>
        {description ? (
          <p id={descriptionId} className="mt-1 text-sm text-[var(--color-text-secondary)]">
            {description}
          </p>
        ) : null}
        <div className="mt-4">{children}</div>
      </div>
    </div>
  );
}

export function IconButton({
  label,
  children,
  ...props
}: { label: string; children: ReactNode } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className="rounded-md p-2 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)] disabled:opacity-50"
      {...props}
    >
      {children}
    </button>
  );
}

export function Breadcrumb({ items }: { items: { label: string; to?: string }[] }) {
  return (
    <nav aria-label="Breadcrumb" className="mb-3 flex items-center gap-1.5 text-sm text-[var(--color-text-tertiary)]">
      {items.map((item, index) => (
        <span key={index} className="flex items-center gap-1.5">
          {index > 0 ? <span aria-hidden="true">/</span> : null}
          {item.to ? (
            <a href={item.to} className="hover:text-[var(--color-text-secondary)]">
              {item.label}
            </a>
          ) : (
            <span className={index === items.length - 1 ? "text-[var(--color-text-secondary)]" : ""}>
              {item.label}
            </span>
          )}
        </span>
      ))}
    </nav>
  );
}

/** A dashboard-style number callout. Keeps text alongside the number
 * (never color alone) so the figure is legible without relying on
 * the accent hue. */
export function StatCard({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "neutral" | "accent" | "success" | "warning" | "danger";
}) {
  const toneClass: Record<string, string> = {
    neutral: "text-[var(--color-text-primary)]",
    accent: "text-[var(--color-accent)]",
    success: "text-[var(--color-success)]",
    warning: "text-[var(--color-warning)]",
    danger: "text-[var(--color-danger)]",
  };
  return (
    <Card className="p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-tertiary)]">{label}</p>
      <p className={`mt-1.5 font-display text-2xl ${toneClass[tone]}`}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{hint}</p> : null}
    </Card>
  );
}

/** An amber, icon-plus-text notice for a capability that exists in
 * this codebase but is not yet reachable the way the surrounding UI
 * might suggest (no live connector, no evaluation logic yet, etc).
 * Distinct from EmptyState (which describes "nothing here yet" for a
 * capability that fully works) and from a permission-denied state
 * (which is an authorization outcome, not a development state). */
export function InDevelopmentNotice({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-2.5 rounded-lg border border-[var(--color-warning)]/30 bg-[var(--color-warning-bg)] px-4 py-3 text-sm text-[var(--color-text-primary)]">
      <svg viewBox="0 0 20 20" className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-warning)]" fill="none" aria-hidden="true">
        <path d="M10 3.5 2.5 16h15L10 3.5Z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
        <path d="M10 8v3.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
        <circle cx="10" cy="13.6" r="0.9" fill="currentColor" />
      </svg>
      <div>{children}</div>
    </div>
  );
}
