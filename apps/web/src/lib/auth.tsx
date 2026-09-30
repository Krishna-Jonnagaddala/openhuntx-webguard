import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { ApiError, UNAUTHORIZED_EVENT, authApi, type SessionResponse } from "./api";

interface AuthContextValue {
  session: SessionResponse | null;
  status: "checking" | "signed-out" | "signed-in";
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (params: {
    organizationName: string;
    displayName: string;
    email: string;
    password: string;
  }) => Promise<void>;
  acceptInvitation: (token: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  signOutAll: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

/**
 * Slice 16 security review note: session state here is derived
 * entirely from `GET /v1/auth/session`, an HttpOnly cookie the
 * browser attaches automatically -- this file never reads, writes, or
 * stores the session credential itself in `localStorage`,
 * `sessionStorage`, or `IndexedDB` (replacing Slice 15's interim
 * `sessionStorage`-held bearer token). The only thing this SPA reads
 * directly is the separate, deliberately non-HttpOnly CSRF cookie
 * (see api.ts's `readCsrfCookie`), which is not a credential on its
 * own -- it authenticates nothing without the HttpOnly session cookie
 * also being present.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [status, setStatus] = useState<AuthContextValue["status"]>("checking");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const current = await authApi.session();
      setSession(current);
      setStatus("signed-in");
    } catch {
      setSession(null);
      setStatus("signed-out");
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    function handleUnauthorized() {
      setSession((previous) => {
        // A 401 on the very first session check (nobody has ever
        // logged in yet this visit) is expected, not a surprise --
        // only a 401 that revokes an *already-established* session
        // deserves the "you were signed out" message.
        if (previous !== null) {
          setError("Your session has expired or was signed out elsewhere. Please sign in again.");
        }
        return null;
      });
      setStatus("signed-out");
    }
    window.addEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
  }, []);

  async function login(email: string, password: string) {
    setError(null);
    try {
      const current = await authApi.login({ email, password });
      setSession(current);
      setStatus("signed-in");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to reach WebGuard.");
      throw err;
    }
  }

  async function register(params: {
    organizationName: string;
    displayName: string;
    email: string;
    password: string;
  }) {
    setError(null);
    try {
      const current = await authApi.register({
        organization_name: params.organizationName,
        display_name: params.displayName,
        email: params.email,
        password: params.password,
      });
      setSession(current);
      setStatus("signed-in");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to reach WebGuard.");
      throw err;
    }
  }

  async function acceptInvitation(token: string, password: string) {
    setError(null);
    try {
      const current = await authApi.acceptInvitation({ token, password });
      setSession(current);
      setStatus("signed-in");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to reach WebGuard.");
      throw err;
    }
  }

  async function signOut() {
    try {
      await authApi.logout();
    } catch {
      // best-effort: the local session view is cleared regardless, so
      // a network hiccup on logout never leaves the UI stuck signed in
    }
    setSession(null);
    setStatus("signed-out");
  }

  async function signOutAll() {
    try {
      await authApi.logoutAll();
    } finally {
      setSession(null);
      setStatus("signed-out");
    }
  }

  return (
    <AuthContext.Provider
      value={{ session, status, error, login, register, acceptInvitation, signOut, signOutAll, refresh }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within an AuthProvider");
  return context;
}
