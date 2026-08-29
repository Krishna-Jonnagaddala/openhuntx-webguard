import type { ReactNode } from "react";

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
