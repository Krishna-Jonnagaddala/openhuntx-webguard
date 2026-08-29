import { useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { WebGuardLockup } from "../components/brand/Brand";
import { Button } from "../components/ui/primitives";
import { useAuth } from "../lib/auth";

export function LoginPage() {
  const { session, status, error, signIn } = useAuth();
  const [token, setToken] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  if (status === "signed-in" && session) {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setLocalError(null);
    if (!token.trim()) {
      setLocalError("Enter an API token to continue.");
      return;
    }
    setSubmitting(true);
    try {
      await signIn(token.trim());
    } catch {
      // handled via useAuth().error
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--color-canvas)] px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex justify-center">
          <WebGuardLockup />
        </div>
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
          <h1 className="mb-1 text-lg font-semibold text-[var(--color-text-primary)]">Sign in</h1>
          <p className="mb-5 text-sm text-[var(--color-text-secondary)]">
            WebGuard authenticates with an API token issued by your organization owner or administrator (see{" "}
            <span className="font-mono text-xs">API Keys</span> once signed in). There is no separate
            username/password this release — paste the token you were given below.
          </p>
          <form onSubmit={handleSubmit} noValidate>
            <label htmlFor="api-token" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
              API token
            </label>
            <input
              id="api-token"
              name="api-token"
              type="password"
              autoComplete="off"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              placeholder="wgt_..."
              className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)]"
              aria-describedby={localError || error ? "login-error" : undefined}
              aria-invalid={Boolean(localError || error)}
            />
            {localError || error ? (
              <p id="login-error" role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
                {localError ?? error}
              </p>
            ) : null}
            <Button type="submit" variant="primary" className="w-full" disabled={submitting}>
              {submitting ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </div>
      </div>
    </div>
  );
}
