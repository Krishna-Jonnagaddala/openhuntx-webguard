/**
 * Token storage (Slice 15 requirement 24 security review).
 *
 * WebGuard's API is Bearer-token only -- there is no browser session
 * layer, no server-set cookie, and therefore no way for this SPA to
 * hold its credential outside JavaScript-reachable storage without a
 * backend-for-frontend layer this slice does not build (see
 * docs/audit/customer-platform-phase1.md's authentication-status
 * section). Given that constraint, `sessionStorage` is used instead of
 * `localStorage` deliberately: it is cleared when the tab closes, is
 * never sent to a different origin, and does not persist across
 * browser restarts the way `localStorage` would -- meaningfully
 * smaller exposure window for the same token, at the cost of the user
 * having to sign in again per browser session. This is an interim
 * choice, not a final one; a real session-cookie + CSRF-token model is
 * named as the correct fix in the design doc and deferred to a
 * dedicated identity slice.
 */

const STORAGE_KEY = "webguard.session.v1";

export interface StoredSession {
  token: string;
  organizationId: string;
  organizationName: string;
  principalId: string;
  principalName: string;
  role: string;
}

export function loadSession(): StoredSession | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StoredSession;
  } catch {
    return null;
  }
}

export function saveSession(session: StoredSession): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  sessionStorage.removeItem(STORAGE_KEY);
}
