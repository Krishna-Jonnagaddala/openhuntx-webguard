import { useState, type FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { WebGuardLockup } from "../components/brand/Brand";
import { Button } from "../components/ui/primitives";
import { useAuth } from "../lib/auth";

export function AcceptInvitationPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const { session, status, error, acceptInvitation } = useAuth();
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  if (status === "signed-in" && session) {
    return <Navigate to="/app" replace />;
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
      await acceptInvitation(token, password);
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
          <h1 className="mb-1 text-lg font-semibold text-[var(--color-text-primary)]">Accept your invitation</h1>
          {!token ? (
            <p role="alert" className="text-sm text-[var(--color-danger)]">
              This link is missing its invitation token. Ask whoever invited you to resend it.
            </p>
          ) : (
            <>
              <p className="mb-5 text-sm text-[var(--color-text-secondary)]">
                Choose a password to activate your account and sign in.
              </p>
              <form onSubmit={handleSubmit} noValidate>
                <label
                  htmlFor="accept-password"
                  className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]"
                >
                  Password
                </label>
                <input
                  id="accept-password"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={12}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="mb-3 w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)]"
                />
                {localError || error ? (
                  <p role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
                    {localError ?? error}
                  </p>
                ) : null}
                <Button type="submit" variant="primary" className="w-full" disabled={submitting}>
                  {submitting ? "Activating…" : "Activate account"}
                </Button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
