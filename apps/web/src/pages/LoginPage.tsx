import { useState, type FormEvent } from "react";
import { Link, Navigate } from "react-router-dom";
import { WebGuardLockup } from "../components/brand/Brand";
import { Button } from "../components/ui/primitives";
import { useAuth } from "../lib/auth";

export function LoginPage() {
  const { session, status, error, login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  if (status === "signed-in" && session) {
    return <Navigate to="/app" replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setLocalError(null);
    if (!email.trim() || !password) {
      setLocalError("Enter your email and password to continue.");
      return;
    }
    setSubmitting(true);
    try {
      await login(email.trim(), password);
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
            Sign in with your WebGuard account email and password.
          </p>
          <form onSubmit={handleSubmit} noValidate>
            <label htmlFor="login-email" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
              Email
            </label>
            <input
              id="login-email"
              name="email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@company.com"
              className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)]"
            />
            <div className="mb-1.5 flex items-center justify-between">
              <label htmlFor="login-password" className="block text-sm font-medium text-[var(--color-text-primary)]">
                Password
              </label>
              <Link to="/forgot-password" className="text-xs text-[var(--color-accent)] hover:underline">
                Forgot password?
              </Link>
            </div>
            <input
              id="login-password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)]"
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
          <p className="mt-4 text-center text-sm text-[var(--color-text-secondary)]">
            New to WebGuard?{" "}
            <Link to="/register" className="text-[var(--color-accent)] hover:underline">
              Create an account
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
