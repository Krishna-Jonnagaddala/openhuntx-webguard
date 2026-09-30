import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { WebGuardLockup } from "../components/brand/Brand";
import { Button } from "../components/ui/primitives";
import { ApiError, authApi } from "../lib/api";

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const [newPassword, setNewPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (newPassword.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    setSubmitting(true);
    try {
      const result = await authApi.confirmPasswordReset({ token, new_password: newPassword });
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
          <h1 className="mb-1 text-lg font-semibold text-[var(--color-text-primary)]">Choose a new password</h1>
          {!token ? (
            <p role="alert" className="text-sm text-[var(--color-danger)]">
              This link is missing its reset token. Request a new password reset link.
            </p>
          ) : message ? (
            <div>
              <p role="status" className="mb-3 text-sm text-[var(--color-text-primary)]">
                {message}
              </p>
              <Link to="/login" className="text-sm text-[var(--color-accent)] hover:underline">
                Go to sign in
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} noValidate>
              <label htmlFor="reset-password" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
                New password
              </label>
              <input
                id="reset-password"
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)]"
              />
              {error ? (
                <p role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
                  {error}
                </p>
              ) : null}
              <Button type="submit" variant="primary" className="w-full" disabled={submitting}>
                {submitting ? "Resetting…" : "Reset password"}
              </Button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
