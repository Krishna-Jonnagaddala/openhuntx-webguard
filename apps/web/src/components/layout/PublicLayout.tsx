import { useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { OpenHuntXLockup } from "../brand/Brand";
import { Button } from "../ui/primitives";

const MODULE_NAV = [
  { to: "/webguard", label: "WebGuard" },
  { to: "/soc", label: "SOC" },
  { to: "/compliance", label: "Compliance" },
];

function ModuleNavLink({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `rounded-md px-3 py-2 text-sm font-medium transition-colors ${
          isActive
            ? "text-[var(--color-text-primary)]"
            : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
        }`
      }
    >
      {label}
    </NavLink>
  );
}

export function PublicLayout() {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="flex min-h-screen flex-col bg-[var(--color-canvas)]">
      <header className="border-b border-[var(--color-border)]">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
          <Link to="/" aria-label="OpenHuntX home" className="shrink-0">
            <OpenHuntXLockup />
          </Link>
          <nav aria-label="Platform" className="hidden items-center gap-1 md:flex">
            {MODULE_NAV.map((item) => (
              <ModuleNavLink key={item.to} {...item} />
            ))}
          </nav>
          <div className="hidden items-center gap-3 md:flex">
            <Link to="/login" className="text-sm font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]">
              Sign in
            </Link>
            <Link to="/register">
              <Button variant="primary">Create an account</Button>
            </Link>
          </div>
          <button
            type="button"
            className="rounded-md p-2 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] md:hidden"
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((open) => !open)}
          >
            <svg viewBox="0 0 20 20" className="h-5 w-5" fill="none" aria-hidden="true">
              <path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </div>
        {menuOpen ? (
          <div className="border-t border-[var(--color-border)] px-4 py-3 md:hidden">
            <nav aria-label="Platform" className="flex flex-col gap-1">
              {MODULE_NAV.map((item) => (
                <ModuleNavLink key={item.to} {...item} />
              ))}
            </nav>
            <div className="mt-3 flex flex-col gap-2 border-t border-[var(--color-border)] pt-3">
              <Link to="/login" className="text-sm font-medium text-[var(--color-text-secondary)]">
                Sign in
              </Link>
              <Link to="/register">
                <Button variant="primary" className="w-full">
                  Create an account
                </Button>
              </Link>
            </div>
          </div>
        ) : null}
      </header>
      <main className="flex-1">
        <Outlet />
      </main>
      <footer className="border-t border-[var(--color-border)]">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-8 text-sm text-[var(--color-text-tertiary)] sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <div className="flex items-center gap-2">
            <OpenHuntXLockup className="opacity-80" />
          </div>
          <nav aria-label="Footer" className="flex flex-wrap gap-x-5 gap-y-2">
            {MODULE_NAV.map((item) => (
              <Link key={item.to} to={item.to} className="hover:text-[var(--color-text-secondary)]">
                {item.label}
              </Link>
            ))}
            <Link to="/login" className="hover:text-[var(--color-text-secondary)]">
              Sign in
            </Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
