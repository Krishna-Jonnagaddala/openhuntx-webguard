/**
 * Brand asset seam (Slice 15 requirement 30). Every place in the app
 * that needs the OpenHuntX wordmark, the OpenHuntX mark, or the
 * WebGuard product lockup imports from here -- never a hard-coded
 * inline SVG scattered across pages. When the final OpenHuntX identity
 * is ready, only this file changes; nothing that renders a logo
 * anywhere in the app needs to.
 *
 * Implements docs/product/OPENHUNTX_BRAND_MARK.md: a circular
 * radar/shield emblem (OpenHuntXMark) and an "OpenHunt" + oversized
 * red "X" wordmark (OpenHuntXWordmark), both using the brand's own
 * gradients. Gradient IDs are derived from React's useId() so multiple
 * instances of either component can render on one page (e.g. the app
 * bar and a page body) without colliding <defs> ids.
 */

import { useId } from "react";

export function OpenHuntXMark({ className }: { className?: string }) {
  const uid = useId();
  const steel = `ohx-steel-${uid}`;
  const red = `ohx-red-${uid}`;
  const radar = `ohx-radar-${uid}`;
  const clip = `ohx-clip-${uid}`;
  return (
    <svg viewBox="0 0 100 100" className={className} aria-hidden="true">
      <defs>
        <linearGradient id={steel} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#EDF1F5" />
          <stop offset="26%" stopColor="#9AA3AD" />
          <stop offset="50%" stopColor="#3A4149" />
          <stop offset="62%" stopColor="#C3CAD2" />
          <stop offset="100%" stopColor="#5A626B" />
        </linearGradient>
        <linearGradient id={red} x1="0.1" y1="0" x2="0.9" y2="1">
          <stop offset="0%" stopColor="#FF8087" />
          <stop offset="28%" stopColor="#E51B2A" />
          <stop offset="58%" stopColor="#82090F" />
          <stop offset="100%" stopColor="#C4131F" />
        </linearGradient>
        <radialGradient id={radar} cx="0.5" cy="0.42" r="0.7">
          <stop offset="0%" stopColor="#1B222B" />
          <stop offset="100%" stopColor="#080A0E" />
        </radialGradient>
        <clipPath id={clip}>
          <path d="M50,23 L76,32 V55 C76,68 63,73 50,77 C37,73 24,68 24,55 V32 Z" />
        </clipPath>
      </defs>

      <circle cx="50" cy="50" r="43" fill="#0C0F14" stroke={`url(#${steel})`} strokeWidth="3.4" />
      <circle cx="50" cy="50" r="37.5" fill="none" stroke="#E51B2A" strokeWidth="0.9" opacity="0.55" />
      <circle cx="50" cy="50" r="35" fill={`url(#${radar})`} stroke={`url(#${steel})`} strokeWidth="1.4" />

      <g stroke="#E51B2A" strokeWidth="0.5" opacity="0.35">
        <circle cx="50" cy="50" r="27" fill="none" />
        <circle cx="50" cy="50" r="18" fill="none" />
        <circle cx="50" cy="50" r="9" fill="none" />
        <line x1="15" y1="50" x2="85" y2="50" />
        <line x1="50" y1="15" x2="50" y2="85" />
      </g>

      <g fill={`url(#${red})`} stroke={`url(#${steel})`} strokeWidth="0.8">
        <polygon points="50,1 56,19 50,14 44,19" />
        <polygon points="99,50 81,56 86,50 81,44" />
        <polygon points="50,99 44,81 50,86 56,81" />
        <polygon points="1,50 19,44 14,50 19,56" />
      </g>

      <path d="M50,23 L76,32 V55 C76,68 63,73 50,77 C37,73 24,68 24,55 V32 Z" fill={`url(#${steel})`} />
      <g clipPath={`url(#${clip})`}>
        <rect x="24" y="21" width="26" height="58" fill={`url(#${red})`} />
        <rect x="50" y="21" width="26" height="58" fill="#0E131A" />
        <g stroke="#E51B2A" strokeWidth="0.5" opacity="0.4" fill="none">
          <circle cx="50" cy="50" r="20" />
          <circle cx="50" cy="50" r="13" />
        </g>
        <circle cx="62" cy="39" r="1.3" fill="#FF6A72" />
        <circle cx="60" cy="63" r="1.1" fill="#FF6A72" />
      </g>
      <path
        d="M50,23 L76,32 V55 C76,68 63,73 50,77 C37,73 24,68 24,55 V32 Z"
        fill="none"
        stroke={`url(#${steel})`}
        strokeWidth="2.6"
      />

      <g stroke="#FF2638" strokeWidth="1" fill="none">
        <circle cx="50" cy="50" r="4.6" />
        <line x1="41" y1="50" x2="46" y2="50" />
        <line x1="54" y1="50" x2="59" y2="50" />
        <line x1="50" y1="41" x2="50" y2="46" />
        <line x1="50" y1="54" x2="50" y2="59" />
      </g>
    </svg>
  );
}

/**
 * `glow` applies docs/product/OPENHUNTX_BRAND_MARK.md §3's "primary
 * lockup" drop-shadow treatment (`filter: drop-shadow(0 0
 * 26px rgba(229,27,42,0.45))`), documented there as reserved for a
 * marketing/hero surface this app didn't have yet -- the public site
 * added alongside the three-module platform expansion is that
 * surface. Every in-product usage (header, login) keeps the flat,
 * glow-free default.
 */
export function OpenHuntXWordmark({ className, glow = false }: { className?: string; glow?: boolean }) {
  return (
    <span
      className={className}
      style={{
        fontFamily: "var(--font-display)",
        lineHeight: 0.9,
        filter: glow ? "drop-shadow(0 0 26px rgba(229,27,42,0.45))" : undefined,
      }}
    >
      <span
        style={{
          background:
            "linear-gradient(180deg,#FFFFFF 0%,#D3D9E0 34%,#6D757F 50%,#E4E9EE 62%,#8C949E 82%,#C6CCD3 100%)",
          WebkitBackgroundClip: "text",
          backgroundClip: "text",
          WebkitTextFillColor: "transparent",
        }}
      >
        OpenHunt
      </span>
      <span
        style={{
          marginLeft: "-0.02em",
          background: "linear-gradient(170deg,#FF7A80 0%,#E51B2A 30%,#7E0A12 52%,#FF3B48 68%,#A8101B 100%)",
          WebkitBackgroundClip: "text",
          backgroundClip: "text",
          WebkitTextFillColor: "transparent",
        }}
      >
        X
      </span>
    </span>
  );
}

/** The platform-level lockup: mark + wordmark alone, no product name.
 * Used as the home link and everywhere OpenHuntX is referred to as
 * the parent platform rather than one specific module. */
export function OpenHuntXLockup({ className, glow = false }: { className?: string; glow?: boolean }) {
  return (
    <div className={`flex items-center gap-2 ${className ?? ""}`}>
      <OpenHuntXMark className="h-6 w-6 shrink-0" />
      <OpenHuntXWordmark className="text-base" glow={glow} />
    </div>
  );
}

export type PlatformProductName = "WebGuard" | "SOC" | "Compliance";

/** Mark + wordmark + one product name -- the shape
 * docs/product/OPENHUNTX_BRAND_MARK.md's own in-product app-bar panel
 * shows. SOC and Compliance are plain navigation/product names here,
 * never a fabricated lockup of their own (per the platform brief:
 * "do not invent official logo lockups for them"). */
export function ProductLockup({ product, className }: { product: PlatformProductName; className?: string }) {
  return (
    <div className={`flex items-center gap-2 ${className ?? ""}`}>
      <OpenHuntXMark className="h-6 w-6 shrink-0" />
      <span className="flex items-baseline gap-1.5">
        <OpenHuntXWordmark className="text-base" />
        <span className="font-display text-sm tracking-wide text-[var(--color-text-secondary)]">{product}</span>
      </span>
    </div>
  );
}

/** @deprecated use `<ProductLockup product="WebGuard" />` -- kept so
 * no existing import site breaks while the platform shell migrates. */
export function WebGuardLockup({ className }: { className?: string }) {
  return <ProductLockup product="WebGuard" className={className} />;
}

/** The WebGuard product descriptor from the original brand mark
 * lockup. Scoped to WebGuard alone -- never applied to the platform
 * home or to SOC/Compliance, which have no equivalent descriptor of
 * their own yet. */
export const WEBGUARD_TAGLINE = "WEB VULNERABILITY DISCOVERY & SECURITY ASSURANCE";
