import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { WebGuardLockup } from "../components/brand/Brand";
import { ApiError, authApi } from "../lib/api";

export function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const [status, setStatus] = useState<"checking" | "done" | "error">("checking");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setMessage("This link is missing its verification token.");
      return;
    }
    let cancelled = false;
    authApi
      .confirmEmailVerification(token)
      .then((result) => {
        if (cancelled) return;
        setStatus("done");
        setMessage(result.message);
      })
      .catch((err) => {
        if (cancelled) return;
        setStatus("error");
        setMessage(err instanceof ApiError ? err.message : "Unable to reach WebGuard.");
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--color-canvas)] px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex justify-center">
          <WebGuardLockup />
        </div>
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
          <h1 className="mb-3 text-lg font-semibold text-[var(--color-text-primary)]">Email verification</h1>
          {status === "checking" ? (
            <p role="status" className="text-sm text-[var(--color-text-secondary)]">
              Verifying your email address…
            </p>
          ) : status === "done" ? (
            <p role="status" className="text-sm text-[var(--color-text-primary)]">
              {message}
            </p>
          ) : (
            <p role="alert" className="text-sm text-[var(--color-danger)]">
              {message}
            </p>
          )}
          <Link to="/" className="mt-4 inline-block text-sm text-[var(--color-accent)] hover:underline">
            Go to WebGuard
          </Link>
        </div>
      </div>
    </div>
  );
}
