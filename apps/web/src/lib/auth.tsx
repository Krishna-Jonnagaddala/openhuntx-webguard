import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { ApiError, UNAUTHORIZED_EVENT, meApi } from "./api";
import { clearSession, loadSession, saveSession, type StoredSession } from "./auth-storage";

interface AuthContextValue {
  session: StoredSession | null;
  status: "checking" | "signed-out" | "signed-in";
  error: string | null;
  signIn: (token: string) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<StoredSession | null>(null);
  const [status, setStatus] = useState<AuthContextValue["status"]>("checking");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const existing = loadSession();
    if (!existing) {
      setStatus("signed-out");
      return;
    }
    setSession(existing);
    setStatus("signed-in");
  }, []);

  useEffect(() => {
    function handleUnauthorized() {
      clearSession();
      setSession(null);
      setStatus("signed-out");
      setError("Your session has expired or your token is no longer valid. Please sign in again.");
    }
    window.addEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
  }, []);

  async function signIn(token: string) {
    setError(null);
    // Validate the token exactly once, against the real API, before
    // storing anything -- never trust client-side token shape alone.
    const previous = loadSession();
    saveSession({ token, organizationId: "", organizationName: "", principalId: "", principalName: "", role: "" });
    try {
      const me = await meApi.get();
      const next: StoredSession = {
        token,
        organizationId: me.organization_id,
        organizationName: me.organization_name,
        principalId: me.principal_id,
        principalName: me.principal_name,
        role: me.role,
      };
      saveSession(next);
      setSession(next);
      setStatus("signed-in");
    } catch (err) {
      if (previous) saveSession(previous);
      else clearSession();
      const message =
        err instanceof ApiError ? "That token was rejected: " + err.message : "Unable to reach WebGuard.";
      setError(message);
      throw err;
    }
  }

  function signOut() {
    clearSession();
    setSession(null);
    setStatus("signed-out");
  }

  return (
    <AuthContext.Provider value={{ session, status, error, signIn, signOut }}>{children}</AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within an AuthProvider");
  return context;
}
