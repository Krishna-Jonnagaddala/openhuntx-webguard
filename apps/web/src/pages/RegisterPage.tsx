import { useState, type FormEvent } from "react";
import { Link, Navigate } from "react-router-dom";
import { WebGuardLockup } from "../components/brand/Brand";
import { Button } from "../components/ui/primitives";
import { useAuth } from "../lib/auth";

export function RegisterPage() {
  const { session, status, error, register } = useAuth();
  const [organizationName, setOrganizationName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  if (status === "signed-in" && session) {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setLocalError(null);
    if (password.length < 12) {
      setLocalError("Password must be at least 12 characters.");
      return;
    }
    setSubmitting(true);
    try {
      await register({
        organizationName: organizationName.trim(),
        displayName: displayName.trim(),
        email: email.trim(),
        password,
      });
    } catch {
      // handled via useAuth().error
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--color-canvas)] px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex justify-center">
          <WebGuardLockup />
        </div>
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
          <h1 className="mb-1 text-lg font-semibold text-[var(--color-text-primary)]">Create your organization</h1>
          <p className="mb-5 text-sm text-[var(--color-text-secondary)]">
            This creates a new WebGuard organization with you as its owner. Already have access to an
            organization? Ask an owner or administrator to invite you instead.
          </p>
          <form onSubmit={handleSubmit} noValidate>
            <label htmlFor="reg-org" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
              Organization name
            </label>
            <input
              id="reg-org"
              required
              value={organizationName}
              onChange={(event) => setOrganizationName(event.target.value)}
              className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)]"
            />
            <label htmlFor="reg-name" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
              Your name
            </label>
            <input
              id="reg-name"
              required
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)]"
            />
            <label htmlFor="reg-email" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
              Email
            </label>
            <input
              id="reg-email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)]"
            />
            <label htmlFor="reg-password" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
              Password
            </label>
            <input
              id="reg-password"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mb-1 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)]"
              aria-describedby={localError || error ? "register-error" : "register-password-hint"}
            />
            <p id="register-password-hint" className="mb-3 text-xs text-[var(--color-text-tertiary)]">
              At least 12 characters. Length matters more than complexity.
            </p>
            {localError || error ? (
              <p id="register-error" role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
                {localError ?? error}
              </p>
            ) : null}
            <Button type="submit" variant="primary" className="w-full" disabled={submitting}>
              {submitting ? "Creating your organization…" : "Create organization"}
            </Button>
          </form>
          <p className="mt-4 text-center text-sm text-[var(--color-text-secondary)]">
            Already have an account?{" "}
            <Link to="/login" className="text-[var(--color-accent)] hover:underline">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
