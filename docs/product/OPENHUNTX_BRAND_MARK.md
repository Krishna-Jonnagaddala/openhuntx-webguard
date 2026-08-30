# OpenHuntX Brand Mark

## Status

**Implemented in `apps/web`.** The wordmark, shield emblem, favicon, color theme, and typography below are real, built, and verified (`npm run build`/`lint`/`test` all pass; visually verified in a browser against the login, registration, and in-product app-bar contexts). This document records the identity system itself — the source design and the decisions made translating it into the app's existing token-based design system (`docs/product/WEB_APP_DESIGN_SYSTEM.md`) — not a proposal.

Source: an OpenHuntX brand-mark design provided directly by the user (Claude Design canvas export), covering the wordmark, shield emblem, color palette, and typography across ten reference panels (primary lockup, wordmark on dark/light, flat/mono reproduction, standalone emblem, favicon at three sizes, corporate/product lockups, in-product app bar, clear space, and the color chip sheet).

## 1. Wordmark

"OpenHunt" in a chrome/steel gradient, followed by an oversized "X" in the brand's red gradient — the "X" is the visual anchor (rendered noticeably larger than the rest of the wordmark, not just bolded), evoking both the company name's own initial and a targeting/marked-for-scan mark, appropriate for a vulnerability-discovery product.

- Chrome gradient (dark backgrounds): `linear-gradient(180deg, #FFFFFF 0%, #D3D9E0 34%, #6D757F 50%, #E4E9EE 62%, #8C949E 82%, #C6CCD3 100%)`
- Red gradient (the "X"): `linear-gradient(170deg, #FF7A80 0%, #E51B2A 30%, #7E0A12 52%, #FF3B48 68%, #A8101B 100%)`
- Rendered as real text via CSS `background-clip: text` (`OpenHuntXWordmark` in `src/components/brand/Brand.tsx`), not an image — preserves selectability, screen-reader text, and SEO.

## 2. Shield / radar emblem (`OpenHuntXMark`)

A circular badge: an outer chrome ring, faint red radar-sweep rings and crosshair guides, four red compass-point triangles at N/S/E/W, and a hexagonal shield split down the middle (red gradient on the left, dark on the right) with a bright-red targeting reticle at the center. Used standalone as the favicon and paired with the wordmark in the in-app header/lockup.

Implementation notes:
- One canonical SVG (viewBox `0 0 100 100`), reused at every size from 16px (favicon) to the header mark — vector, so it scales cleanly; no separate simplified version was built for small sizes, matching the source design's own approach (it reuses the identical detailed paths down to 24px).
- `OpenHuntXMark`'s gradient/clip-path `id`s are derived from React's `useId()` so multiple instances on one page (e.g. a page that shows the mark twice) never collide in the DOM — a real bug the source design's own static HTML doesn't have to worry about but a component library does.

## 3. Color

| Role | Value | Name |
|---|---|---|
| Base background | `#07090C` | Carbon Black |
| Card/surface | `#0D1117` → `#131820` | (gradient) |
| Corporate Red (flat, functional UI) | `#E51B2A` | Corporate Red |
| Signal Red (hover/active/link state) | `#FF2638` | Signal Red |
| Wordmark "X" gradient | see §1 | Red Monolith |
| Wordmark "OpenHunt" gradient | see §1 | Chrome |
| Muted/label text | `#7A8593` | — |

**Flat vs. glow, a deliberate split**: the source design includes a dramatic "primary lockup" treatment with drop-shadow glows (`filter: drop-shadow(0 0 26px rgba(229,27,42,0.45))`) intended for hero/marketing placement, and a separate "flat reproduction" panel explicitly for small sizes and one-color print. `apps/web`'s functional UI (buttons, links, nav highlights, focus rings) uses the **flat** Corporate Red/Signal Red exactly — no glow, no gradient — consistent with `docs/product/WEB_APP_DESIGN_SYSTEM.md`'s existing "no neon glow" philosophy for controls. The gradient/glow treatment is used **only** on the wordmark and shield emblem themselves (a logo, not a control), matching the source design's own distinction between its "primary lockup" panel and its "flat reproduction" panel — this app never had a marketing/hero surface to put the full dramatic treatment on, so the flat variant is what actually ships everywhere the mark appears (header, login, favicon).

Every other design token (`--color-canvas`, `--color-surface`, text colors, etc.) was recolored to match; see `docs/product/WEB_APP_DESIGN_SYSTEM.md` §2 for the full, current table. Semantic status colors (success/warning/info) are unchanged — the brand mark defines no green/amber/blue.

## 4. Typography

| Role | Family | Weight(s) | Where |
|---|---|---|---|
| Display (wordmark/lockup only) | Aldrich | 400 | `OpenHuntXWordmark`, the "WebGuard" product-name label next to it |
| Body | Archivo | 100–900 (variable) | Everything else — replaces the previously-specified but never-actually-loaded "Inter" |
| Monospace | IBM Plex Mono | 400, 500 | Evidence/token/ID display, audit logs — replaces the previously-specified but never-actually-loaded "JetBrains Mono" |

All three are **self-hosted** as static `.woff2` files in `apps/web/public/fonts/` (latin subset only — this is an English-only enterprise console) rather than loaded from Google Fonts at runtime, so the app has no external font-host dependency and its future CSP (`docs/production/PUBLIC_EDGE_SECURITY.md` §7) needs no `fonts.googleapis.com`/`fonts.gstatic.com` allowance. Aldrich is exposed as its own `--font-display` token (`font-display` Tailwind utility) precisely so it is never accidentally used for body copy — a geometric display face reads poorly at paragraph sizes.

**Correction of a pre-existing gap**: the design system doc had specified "Inter"/"JetBrains Mono" since Slice 15, but no font-loading mechanism (no `@font-face`, no Google Fonts `<link>`) ever existed anywhere in the repository — the app was silently falling back to system fonts the entire time. This slice's font work is the first time any of the app's specified typefaces have actually been delivered to the browser.

## 5. Favicon and app icon

`apps/web/public/favicon.svg` is the shield emblem at its own viewBox, referenced from `index.html`'s existing `<link rel="icon" type="image/svg+xml">` — no change needed to that link, only to what it points at. The source design's separate 88px/44px/24px "app icon" panel is the same vector reused at different render sizes (§2) — no separate PNG/ICO raster set was generated, since every consumer here (browser tab, this SPA) supports SVG favicons.

## 6. What was not implemented

Named honestly rather than silently skipped:

- **No marketing/hero surface exists** to place the source design's full "primary lockup" (104px/186px wordmark with heavy glow) on — this app is the in-product console, not a marketing site. If a marketing page is ever built, the primary-lockup treatment described in §3 is what it should use.
- **No print/one-color reproduction assets** (the source design's "flat reproduction" panel shows mono-white/mono-black variants for single-color print) were generated as separate files — the flat color values are documented above (§3) for anyone who needs them, but no dedicated one-color SVG export exists.
- **No raster (PNG/ICO) favicon fallback** was generated — every target this app currently runs in supports SVG favicons; a raster fallback would only matter for a platform that does not (some older social-share unfurl bots), which is out of scope until one is actually needed.
- **No OG/social preview image** was generated from this identity.
