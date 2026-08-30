# WebGuard Web App Design System (Slice 15)

## 1. Direction

Dark-first, carbon/graphite surfaces, off-white type, controlled OpenHuntX
red accents. A clean, technically sophisticated enterprise SaaS surface —
not a security "gaming" UI. Explicitly avoided in every *functional* UI
element (buttons, badges, borders, inputs): neon glow, glassmorphism,
cyberpunk decoration, matrix-style backgrounds, terminal/hacker-movie
graphics. Every color, radius, and font in the app comes from the token set
below (`apps/web/src/index.css`, Tailwind v4's `@theme` block) — no
one-off hex values in component code, with exactly one deliberate, scoped
exception: the brand mark itself (`src/components/brand/Brand.tsx`) uses
the OpenHuntX brand's own gradient/drop-shadow treatment on the wordmark
and shield emblem — a logo, not a UI control, and the one place this
document's "no decoration" rule does not apply. See
`docs/product/OPENHUNTX_BRAND_MARK.md`.

## 2. Color tokens

**Recolored to the OpenHuntX brand mark** (`docs/product/OPENHUNTX_BRAND_MARK.md`) — the token *names* and their *roles* below are unchanged from Slice 15; only the hex values moved, to the brand's own carbon-black/corporate-red palette.

| Token | Value | Use |
|---|---|---|
| `--color-canvas` | `#07090c` | Page background |
| `--color-surface` | `#0d1117` | Card/panel background |
| `--color-surface-raised` | `#131820` | Table headers, inputs, nested surfaces |
| `--color-surface-hover` | `#1b222b` | Row/menu hover state |
| `--color-border` | `rgba(245,247,250,0.08)` | Default border |
| `--color-border-strong` | `rgba(245,247,250,0.16)` | Input/interactive border |
| `--color-text-primary` | `#f5f7fa` | Body text, headings (off-white, never pure white) |
| `--color-text-secondary` | `#7a8593` | Supporting text, table cells |
| `--color-text-tertiary` | `#4e5a67` | Placeholders, table headers, timestamps |
| `--color-text-on-accent` | `#ffffff` | Text on the accent color |
| `--color-accent` / `--color-accent-hover` | `#e51b2a` / `#ff2638` | Primary actions, focus ring, brand mark (Corporate Red / Signal Red) |
| `--color-accent-muted` / `--color-accent-soft-bg` | `#7e0a12` / `#2a1512` | Text selection, low-emphasis accent fills |

Semantic status (each with a `-bg` pair for badge fills):
`--color-success`, `--color-warning`, `--color-danger` (same value as
accent — a deliberate, single "red" in the palette), `--color-info`.
Success/warning/info keep their pre-existing conventional hues — the
brand mark defines no green/amber/blue, so there is nothing to recolor
there; only `--color-danger` and the severity-critical tier share the
brand's red, exactly as before.

Severity scale (each with a `-bg` pair): `--color-sev-critical`,
`--color-sev-high`, `--color-sev-medium`, `--color-sev-low`,
`--color-sev-info`.

## 3. Type and shape

- Sans (body): `"Archivo", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif` — self-hosted (`apps/web/public/fonts/`), a variable font (weights 100–900)
- Mono (evidence, tokens, IDs, and the brand's own label/UI-chrome style): `"IBM Plex Mono", ui-monospace, SFMono-Regular, "Menlo", monospace` — self-hosted, weights 400/500
- Display (`--font-display` / `font-display` utility — brand wordmark and lockup text only, never body copy): `"Aldrich", var(--font-sans)` — self-hosted, weight 400
- Radii: `--radius-sm` (0.25rem), `--radius-md` (0.375rem, most controls), `--radius-lg` (0.5rem, cards)
- Base color scheme is `dark` (`html { color-scheme: dark }`); there is no
  light theme this release.

All three font families are self-hosted as static `.woff2` files rather
than loaded from Google Fonts at runtime — this app has no external
font-host dependency, and its CSP (once a serving layer sets one; see
`docs/production/PUBLIC_EDGE_SECURITY.md` §7) never needs a
`fonts.googleapis.com`/`fonts.gstatic.com` allowance.

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
place any page imports a logo from — no page hard-codes an inline SVG or
wordmark of its own. This seam is what let the final OpenHuntX identity
(`docs/product/OPENHUNTX_BRAND_MARK.md`) get implemented by editing this
one file: every consuming page (`AppShell`, `LoginPage`, `RegisterPage`,
`ForgotPasswordPage`, `VerifyEmailPage`, `ResetPasswordPage`,
`AcceptInvitationPage`) updated automatically, with no page-level change
required. `OpenHuntXMark` renders the brand's circular radar/shield emblem
(gradient IDs derived from React's `useId()` so multiple instances on one
page never collide); `OpenHuntXWordmark` renders "OpenHunt" in a chrome
gradient and an oversized "X" in the brand's red gradient via
`background-clip: text` on real text (not an image), preserving
accessibility/selectability.

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
