/**
 * Brand asset seam (Slice 15 requirement 30). Every place in the app
 * that needs the OpenHuntX wordmark, the OpenHuntX mark, or the
 * WebGuard product lockup imports from here -- never a hard-coded
 * inline SVG scattered across pages. When the final OpenHuntX identity
 * is ready, only this file changes; nothing that renders a logo
 * anywhere in the app needs to.
 */

export function OpenHuntXMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true" fill="none">
      <rect x="2" y="2" width="28" height="28" rx="6" stroke="currentColor" strokeWidth="2" />
      <path d="M11 21 L16 10 L21 21" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function OpenHuntXWordmark({ className }: { className?: string }) {
  return (
    <span className={className} style={{ fontWeight: 600, letterSpacing: "0.02em" }}>
      OpenHunt<span style={{ color: "var(--color-accent)" }}>X</span>
    </span>
  );
}

export function WebGuardLockup({ className }: { className?: string }) {
  return (
    <div className={`flex items-center gap-2 ${className ?? ""}`}>
      <OpenHuntXMark className="h-6 w-6 text-[var(--color-accent)]" />
      <span className="flex items-baseline gap-1.5">
        <OpenHuntXWordmark className="text-sm text-[var(--color-text-primary)]" />
        <span className="text-sm font-medium text-[var(--color-text-secondary)]">WebGuard</span>
      </span>
    </div>
  );
}
