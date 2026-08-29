# WebGuard Web App Design System (Slice 15)

## 1. Direction

Dark-first, carbon/graphite surfaces, off-white type, controlled OpenHuntX
red accents. A clean, technically sophisticated enterprise SaaS surface —
not a security "gaming" UI. Explicitly avoided: neon glow, glassmorphism,
cyberpunk decoration, matrix-style backgrounds, terminal/hacker-movie
graphics. Every color, radius, and font in the app comes from the token set
below (`apps/web/src/index.css`, Tailwind v4's `@theme` block) — no
one-off hex values in component code.

## 2. Color tokens

| Token | Value | Use |
|---|---|---|
| `--color-canvas` | `#0b0d10` | Page background |
| `--color-surface` | `#111418` | Card/panel background |
| `--color-surface-raised` | `#171b20` | Table headers, inputs, nested surfaces |
| `--color-surface-hover` | `#1d2228` | Row/menu hover state |
| `--color-border` | `#262b32` | Default border |
| `--color-border-strong` | `#363c45` | Input/interactive border |
| `--color-text-primary` | `#e9e7e2` | Body text, headings (off-white, never pure white) |
| `--color-text-secondary` | `#a3a9b2` | Supporting text, table cells |
| `--color-text-tertiary` | `#6b727c` | Placeholders, table headers, timestamps |
| `--color-text-on-accent` | `#fbf4f2` | Text on the accent color |
| `--color-accent` / `--color-accent-hover` | `#d64a3c` / `#c23f32` | Primary actions, focus ring, brand mark |
| `--color-accent-muted` / `--color-accent-soft-bg` | `#4a2620` / `#251512` | Text selection, low-emphasis accent fills |

Semantic status (each with a `-bg` pair for badge fills):
`--color-success`, `--color-warning`, `--color-danger` (same value as
accent — a deliberate, single "red" in the palette), `--color-info`.

Severity scale (each with a `-bg` pair): `--color-sev-critical`,
`--color-sev-high`, `--color-sev-medium`, `--color-sev-low`,
`--color-sev-info`.

## 3. Type and shape

- Sans: `"Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif`
- Mono (evidence, tokens, IDs): `"JetBrains Mono", ui-monospace, SFMono-Regular, "Menlo", monospace`
- Radii: `--radius-sm` (0.25rem), `--radius-md` (0.375rem, most controls), `--radius-lg` (0.5rem, cards)
- Base color scheme is `dark` (`html { color-scheme: dark }`); there is no
  light theme this release.

## 4. Component inventory (`src/components/ui/primitives.tsx`)

Every page composes from this fixed set — no page defines its own card,
button, or badge styling:

- `Card` — bordered surface container.
- `PageHeader` — title, optional description, optional right-aligned actions.
- `Button` — variants `primary` / `secondary` / `danger` / `ghost`; disabled
  state dims to 50% opacity and blocks pointer events.
- `EmptyState` — title, optional description, optional action.
- `LoadingState` — `role="status"`, spinner + label.
- `ErrorState` — `role="alert"`, renders the API's own error message.
- `SeverityBadge` / `StatusBadge` — map a severity or status string to a
  token-driven color; both fail safe (unmapped values fall back to a
  neutral tone rather than an undefined class).
- `Table` / `Th` / `Td` — horizontally scrollable on overflow, never the
  page body.
- `VisuallyHidden` — screen-reader-only text (`sr-only`).

## 5. Brand seam (`src/components/brand/Brand.tsx`)

`OpenHuntXMark`, `OpenHuntXWordmark`, and `WebGuardLockup` are the *only*
place any page imports a logo from. The current mark is a simple, literal
placeholder (not the older shield-heavy logo) so that final branding can be
swapped centrally later without touching page code — per the brief's own
explicit instruction not to hard-code the old logo.

## 6. Layout conventions

- Desktop is the primary target: dense tables, multi-column card grids
  (`lg:grid-cols-2`/`lg:grid-cols-3`), a persistent sidebar.
- Tablet: the grid collapses to fewer columns; the sidebar remains but
  narrows; tables remain horizontally scrollable rather than reflowing
  into cards (density is preserved over reflow, per the brief's own
  "don't compromise desktop density for mobile-first tables").
- Mobile: the sidebar becomes a toggleable overlay (`AppShell`'s mobile nav
  button); this is basic viewing support, not a mobile-optimized redesign.

## 7. Accessibility conventions used throughout

- Every icon-only control has an `aria-label` (notification bell, mobile
  nav toggle).
- Loading and error regions use `role="status"` / `role="alert"` so screen
  readers announce state changes without a page reload.
- Focus is always visible: `:focus-visible { outline: 2px solid
  var(--color-accent) }` is a global rule, never suppressed per-component.
- Forms use real `<label htmlFor>` associations, not placeholder-as-label.
- Menus (`AppShell`'s user menu) use `role="menu"`/`aria-expanded` and close
  on outside click and `Escape`.
