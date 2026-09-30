import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { OpenHuntXLockup, ProductLockup, type PlatformProductName } from "../brand/Brand";
import { useAuth } from "../../lib/auth";
import { useModuleEntitlements } from "../../hooks/queries";
import type { ModuleEntitlementStatus, PlatformModuleId } from "../../lib/api";

interface ModuleDefinition {
  id: PlatformModuleId;
  to: string;
  label: PlatformProductName;
  nav: { to: string; label: string; end?: boolean }[];
}

const MODULES: ModuleDefinition[] = [
  {
    id: "webguard",
    to: "/app/webguard",
    label: "WebGuard",
    nav: [
      { to: "/app/webguard", label: "Overview", end: true },
      { to: "/app/webguard/assets", label: "Assets" },
      { to: "/app/webguard/scans", label: "Scans" },
      { to: "/app/webguard/findings", label: "Findings" },
      { to: "/app/webguard/reports", label: "Reports" },
      { to: "/app/webguard/schedules", label: "Schedules" },
    ],
  },
  {
    id: "soc",
    to: "/app/soc",
    label: "SOC",
    nav: [{ to: "/app/soc", label: "Connectors", end: true }],
  },
  {
    id: "compliance",
    to: "/app/compliance",
    label: "Compliance",
    nav: [
      { to: "/app/compliance", label: "Frameworks", end: true },
      { to: "/app/compliance/assertions", label: "Assertions" },
    ],
  },
];

const UTILITY_NAV = [
  { to: "/app/team", label: "Team" },
  { to: "/app/api-keys", label: "API Keys" },
  { to: "/app/audit-log", label: "Audit Logs" },
  { to: "/app/settings", label: "Settings" },
];

function activeModuleFromPath(pathname: string): ModuleDefinition {
  const segment = pathname.split("/")[2];
  return MODULES.find((module) => module.id === segment) ?? MODULES[0];
}

function entitlementStatusFor(
  moduleId: PlatformModuleId,
  entitlements: { module: PlatformModuleId; status: ModuleEntitlementStatus }[] | undefined,
): ModuleEntitlementStatus | "unknown" {
  if (moduleId === "webguard") return "enabled";
  const found = entitlements?.find((entitlement) => entitlement.module === moduleId);
  return found?.status ?? "unknown";
}

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

function ModuleSwitcherItem({
  module,
  active,
  status,
}: {
  module: ModuleDefinition;
  active: boolean;
  status: ModuleEntitlementStatus | "unknown";
}) {
  const locked = status === "disabled" || status === "unknown";
  return (
    <Link
      to={module.to}
      aria-current={active ? "page" : undefined}
      className={`relative flex items-center gap-1.5 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
        active
          ? "text-[var(--color-text-primary)]"
          : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
      }`}
    >
      <span className="font-display tracking-wide">{module.label}</span>
      {locked ? (
        <svg viewBox="0 0 16 16" className="h-3 w-3 text-[var(--color-text-tertiary)]" fill="none" aria-hidden="true">
          <rect x="3.5" y="7" width="9" height="6.5" rx="1.2" stroke="currentColor" strokeWidth="1.2" />
          <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        </svg>
      ) : null}
      {active ? <span className="absolute inset-x-2 -bottom-[13px] h-0.5 rounded-full bg-[var(--color-accent)]" /> : null}
    </Link>
  );
}

export function AppShell() {
  const { session, signOut } = useAuth();
  const location = useLocation();
  const activeModule = activeModuleFromPath(location.pathname);
  const { data: entitlementData } = useModuleEntitlements();
  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setMobileNavOpen(false);
  }, [location.pathname]);

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
      <header className="shrink-0 border-b border-[var(--color-border)] bg-[var(--color-surface)]">
        <div className="flex h-14 items-center justify-between px-4">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="rounded-md p-2 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] lg:hidden"
              aria-label={mobileNavOpen ? "Close navigation menu" : "Open navigation menu"}
              aria-expanded={mobileNavOpen}
              onClick={() => setMobileNavOpen((open) => !open)}
            >
              <svg viewBox="0 0 20 20" className="h-5 w-5" fill="none" aria-hidden="true">
                <path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
            </button>
            <Link to="/app" aria-label="OpenHuntX home">
              <OpenHuntXLockup />
            </Link>
            <span aria-hidden="true" className="hidden h-5 w-px bg-[var(--color-border)] md:block" />
            <nav aria-label="Modules" className="hidden items-center gap-1 md:flex">
              {MODULES.map((module) => (
                <ModuleSwitcherItem
                  key={module.id}
                  module={module}
                  active={module.id === activeModule.id}
                  status={entitlementStatusFor(module.id, entitlementData?.entitlements)}
                />
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3">
            {session ? (
              <span className="hidden max-w-[10rem] truncate text-sm text-[var(--color-text-secondary)] sm:inline">
                {session.organization_name}
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
                  {session?.principal_name?.[0]?.toUpperCase() ?? "?"}
                </span>
                <span className="hidden sm:inline">{session?.principal_name}</span>
              </button>
              {menuOpen ? (
                <div
                  role="menu"
                  className="absolute right-0 z-10 mt-1 w-52 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] py-1 shadow-lg"
                >
                  <div className="border-b border-[var(--color-border)] px-3 py-2 text-xs text-[var(--color-text-tertiary)]">
                    Signed in as <span className="capitalize">{session?.role}</span>
                  </div>
                  {UTILITY_NAV.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      role="menuitem"
                      className="block px-3 py-2 text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)]"
                      onClick={() => setMenuOpen(false)}
                    >
                      {item.label}
                    </NavLink>
                  ))}
                  <button
                    type="button"
                    role="menuitem"
                    className="block w-full border-t border-[var(--color-border)] px-3 py-2 text-left text-sm text-[var(--color-danger)] hover:bg-[var(--color-surface-hover)]"
                    onClick={signOut}
                  >
                    Sign out
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      </header>
      <div className="flex flex-1">
        <nav
          aria-label="Primary"
          className={`w-60 shrink-0 border-r border-[var(--color-border)] bg-[var(--color-surface)] p-3 ${
            mobileNavOpen ? "fixed inset-y-0 left-0 top-14 z-20 block overflow-y-auto" : "hidden"
          } lg:sticky lg:top-0 lg:block lg:h-[calc(100vh-3.5rem)]`}
        >
          <div className="mb-4 space-y-1 lg:hidden">
            <p className="px-3 text-xs font-medium uppercase tracking-wide text-[var(--color-text-tertiary)]">
              Modules
            </p>
            {MODULES.map((module) => (
              <NavItem key={module.id} to={module.to} label={module.label} end />
            ))}
          </div>
          <div className="mb-1 px-3">
            <ProductLockup product={activeModule.label} className="text-sm opacity-90" />
          </div>
          <div className="space-y-1">
            {activeModule.nav.map((item) => (
              <NavItem key={item.to} {...item} />
            ))}
          </div>
          <div className="my-3 border-t border-[var(--color-border)] lg:hidden" />
          <div className="space-y-1 lg:hidden">
            {UTILITY_NAV.map((item) => (
              <NavItem key={item.to} {...item} />
            ))}
          </div>
        </nav>
        {mobileNavOpen ? (
          <div
            aria-hidden="true"
            className="fixed inset-0 top-14 z-10 bg-black/50 lg:hidden"
            onClick={() => setMobileNavOpen(false)}
          />
        ) : null}
        <main id="main-content" className="min-w-0 flex-1 overflow-x-hidden p-4 sm:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
