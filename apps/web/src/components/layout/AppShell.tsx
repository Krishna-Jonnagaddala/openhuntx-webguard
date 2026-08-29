import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { WebGuardLockup } from "../brand/Brand";
import { useAuth } from "../../lib/auth";

const PRIMARY_NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/assets", label: "Assets" },
  { to: "/scans", label: "Scans" },
  { to: "/findings", label: "Findings" },
  { to: "/reports", label: "Reports" },
  { to: "/schedules", label: "Schedules" },
];

const SECONDARY_NAV = [
  { to: "/team", label: "Team" },
  { to: "/api-keys", label: "API Keys" },
  { to: "/audit-log", label: "Audit Logs" },
  { to: "/settings", label: "Settings" },
];

function NavItem({ to, label, end }: { to: string; label: string; end?: boolean }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `block rounded-md px-3 py-2 text-sm font-medium transition-colors ${
          isActive
            ? "bg-[var(--color-accent-soft-bg)] text-[var(--color-accent)]"
            : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)]"
        }`
      }
    >
      {label}
    </NavLink>
  );
}

export function AppShell() {
  const { session, signOut } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    function handlePointerDown(event: PointerEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setMenuOpen(false);
    }
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [menuOpen]);

  return (
    <div className="flex min-h-screen flex-col bg-[var(--color-canvas)]">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-[var(--color-accent)] focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-[var(--color-text-on-accent)]"
      >
        Skip to main content
      </a>
      <header className="flex h-14 shrink-0 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4">
        <div className="flex items-center gap-3">
          <button
            type="button"
            className="rounded-md p-2 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] md:hidden"
            aria-label={mobileNavOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={mobileNavOpen}
            onClick={() => setMobileNavOpen((open) => !open)}
          >
            <svg viewBox="0 0 20 20" className="h-5 w-5" fill="none" aria-hidden="true">
              <path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
          <WebGuardLockup />
        </div>
        <div className="flex items-center gap-4">
          {session ? (
            <span className="hidden text-sm text-[var(--color-text-secondary)] sm:inline">
              {session.organizationName}
            </span>
          ) : null}
          <button
            aria-label="Notifications (no unread notifications)"
            className="rounded-md p-2 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
            type="button"
            disabled
            title="Notifications are not yet implemented"
          >
            <svg viewBox="0 0 20 20" className="h-5 w-5" fill="none" aria-hidden="true">
              <path
                d="M10 3a4 4 0 0 0-4 4v2.2c0 .5-.15 1-.44 1.4L4.5 12.5a1 1 0 0 0 .8 1.6h9.4a1 1 0 0 0 .8-1.6l-1.06-1.9a2.4 2.4 0 0 1-.44-1.4V7a4 4 0 0 0-4-4Z"
                stroke="currentColor"
                strokeWidth="1.3"
              />
              <path d="M8.2 16a1.8 1.8 0 0 0 3.6 0" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
            </svg>
          </button>
          <div className="relative" ref={menuRef}>
            <button
              type="button"
              className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)]"
              onClick={() => setMenuOpen((open) => !open)}
              aria-haspopup="menu"
              aria-expanded={menuOpen}
            >
              <span
                aria-hidden="true"
                className="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--color-accent-muted)] text-xs font-semibold text-[var(--color-accent)]"
              >
                {session?.principalName?.[0]?.toUpperCase() ?? "?"}
              </span>
              <span className="hidden sm:inline">{session?.principalName}</span>
            </button>
            {menuOpen ? (
              <div
                role="menu"
                className="absolute right-0 z-10 mt-1 w-48 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] py-1 shadow-lg"
              >
                <div className="border-b border-[var(--color-border)] px-3 py-2 text-xs text-[var(--color-text-tertiary)]">
                  Signed in as <span className="capitalize">{session?.role}</span>
                </div>
                <NavLink
                  to="/settings"
                  role="menuitem"
                  className="block px-3 py-2 text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)]"
                  onClick={() => setMenuOpen(false)}
                >
                  Settings
                </NavLink>
                <button
                  type="button"
                  role="menuitem"
                  className="block w-full px-3 py-2 text-left text-sm text-[var(--color-danger)] hover:bg-[var(--color-surface-hover)]"
                  onClick={signOut}
                >
                  Sign out
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </header>
      <div className="flex flex-1">
        <nav
          aria-label="Primary"
          className={`w-56 shrink-0 border-r border-[var(--color-border)] bg-[var(--color-surface)] p-3 ${
            mobileNavOpen ? "block" : "hidden"
          } md:block`}
        >
          <div className="space-y-1">
            {PRIMARY_NAV.map((item) => (
              <NavItem key={item.to} {...item} />
            ))}
          </div>
          <div className="my-3 border-t border-[var(--color-border)]" />
          <div className="space-y-1">
            {SECONDARY_NAV.map((item) => (
              <NavItem key={item.to} {...item} />
            ))}
          </div>
        </nav>
        <main id="main-content" className="min-w-0 flex-1 overflow-x-hidden p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
