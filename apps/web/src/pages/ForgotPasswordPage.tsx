import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { WebGuardLockup } from "../components/brand/Brand";
import { Button } from "../components/ui/primitives";
import { ApiError, authApi } from "../lib/api";

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      // Requirement 11: the response is identical whether or not this
      // email matches a real account -- shown verbatim, not
      // reinterpreted, so the UI cannot leak a distinction the API
      // itself deliberately does not make.
      const result = await authApi.requestPasswordReset(email.trim());
      setMessage(result.message);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to reach WebGuard.");
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
          <h1 className="mb-1 text-lg font-semibold text-[var(--color-text-primary)]">Reset your password</h1>
          <p className="mb-5 text-sm text-[var(--color-text-secondary)]">
            Enter your account email and we'll send a password reset link if an account exists.
          </p>
          {message ? (
            <p role="status" className="text-sm text-[var(--color-text-primary)]">
              {message}
            </p>
          ) : (
            <form onSubmit={handleSubmit} noValidate>
              <label htmlFor="forgot-email" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
                Email
              </label>
              <input
                id="forgot-email"
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)]"
              />
              {error ? (
                <p role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
                  {error}
                </p>
              ) : null}
              <Button type="submit" variant="primary" className="w-full" disabled={submitting}>
                {submitting ? "Sending…" : "Send reset link"}
              </Button>
            </form>
          )}
          <p className="mt-4 text-center text-sm text-[var(--color-text-secondary)]">
            <Link to="/login" className="text-[var(--color-accent)] hover:underline">
              Back to sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
