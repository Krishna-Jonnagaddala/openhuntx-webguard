import { useState, type FormEvent } from "react";
import { Button, Card, ErrorState, LoadingState, PageHeader, StatusBadge } from "../components/ui/primitives";
import { useChangePassword, useRequestEmailVerification, useSettings, useSignOutAllSessions } from "../hooks/queries";
import { ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";

function ChangePasswordCard() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [success, setSuccess] = useState(false);
  const changePassword = useChangePassword();

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSuccess(false);
    if (newPassword.length < 12) return;
    try {
      await changePassword.mutateAsync({ current_password: currentPassword, new_password: newPassword });
      setCurrentPassword("");
      setNewPassword("");
      setSuccess(true);
    } catch {
      // surfaced below
    }
  }

  return (
    <Card className="p-4">
      <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Change password</h2>
      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label htmlFor="current-password" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
            Current password
          </label>
          <input
            id="current-password"
            type="password"
            autoComplete="current-password"
            required
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
            className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
          />
        </div>
        <div>
          <label htmlFor="new-password" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
            New password
          </label>
          <input
            id="new-password"
            type="password"
            autoComplete="new-password"
            required
            minLength={12}
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
          />
          <p className="mt-1 text-xs text-[var(--color-text-tertiary)]">At least 12 characters.</p>
        </div>
        {changePassword.isError ? (
          <p role="alert" className="text-sm text-[var(--color-danger)]">
            {changePassword.error instanceof ApiError ? changePassword.error.message : "Unable to change your password."}
          </p>
        ) : null}
        {success ? (
          <p role="status" className="text-sm text-[var(--color-success)]">
            Password changed. Your other sessions have been signed out.
          </p>
        ) : null}
        <Button type="submit" variant="primary" disabled={changePassword.isPending}>
          {changePassword.isPending ? "Changing…" : "Change password"}
        </Button>
      </form>
    </Card>
  );
}

function SessionsCard() {
  const [done, setDone] = useState(false);
  const signOutAll = useSignOutAllSessions();
  const { refresh } = useAuth();

  async function handleSignOutAll() {
    try {
      await signOutAll.mutateAsync();
      setDone(true);
      await refresh();
    } catch {
      // surfaced below
    }
  }

  return (
    <Card className="p-4">
      <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Sessions</h2>
      <p className="mb-3 text-sm text-[var(--color-text-secondary)]">
        Sign out of WebGuard everywhere, on every device that currently has an active session for your account.
      </p>
      {signOutAll.isError ? (
        <p role="alert" className="mb-2 text-sm text-[var(--color-danger)]">
          {signOutAll.error instanceof ApiError ? signOutAll.error.message : "Unable to sign out all sessions."}
        </p>
      ) : null}
      {done ? (
        <p role="status" className="mb-2 text-sm text-[var(--color-text-secondary)]">
          You have been signed out everywhere, including this device.
        </p>
      ) : (
        <Button variant="danger" onClick={handleSignOutAll} disabled={signOutAll.isPending}>
          {signOutAll.isPending ? "Signing out everywhere…" : "Sign out everywhere"}
        </Button>
      )}
    </Card>
  );
}

function EmailVerificationCard({ email, verifiedAt }: { email: string | null; verifiedAt: string | null }) {
  const [sent, setSent] = useState(false);
  const requestVerification = useRequestEmailVerification();

  if (!email) return null;

  return (
    <Card className="p-4">
      <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Email verification</h2>
      <p className="mb-2 text-sm text-[var(--color-text-secondary)]">
        {email} — <StatusBadge status={verifiedAt ? "verified" : "pending"} />
      </p>
      {!verifiedAt ? (
        <>
          {sent ? (
            <p role="status" className="text-sm text-[var(--color-text-secondary)]">
              Verification email sent. Check your inbox for the link.
            </p>
          ) : (
            <Button
              variant="secondary"
              disabled={requestVerification.isPending}
              onClick={async () => {
                try {
                  await requestVerification.mutateAsync();
                  setSent(true);
                } catch {
                  // surfaced via requestVerification.error below
                }
              }}
            >
              {requestVerification.isPending ? "Sending…" : "Resend verification email"}
            </Button>
          )}
          {requestVerification.isError ? (
            <p role="alert" className="mt-2 text-sm text-[var(--color-danger)]">
              {requestVerification.error instanceof ApiError
                ? requestVerification.error.message
                : "Unable to send a verification email."}
            </p>
          ) : null}
        </>
      ) : null}
    </Card>
  );
}

export function SettingsPage() {
  const { data, isLoading, error } = useSettings();

  if (isLoading) return <LoadingState label="Loading settings…" />;
  if (error) return <ErrorState message={error instanceof ApiError ? error.message : "Unable to load settings."} />;
  if (!data) return null;

  return (
    <div>
      <PageHeader
        title="Settings"
        description="Only genuine, currently-backed settings are shown. There is no notification-preference or scan-default configuration screen this release — see the API contract doc."
      />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Organization</h2>
          <dl className="space-y-1.5 text-sm">
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Name</dt>
              <dd className="text-[var(--color-text-primary)]">{data.organization.name}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Status</dt>
              <dd className="capitalize text-[var(--color-text-primary)]">{data.organization.status}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Created</dt>
              <dd className="text-[var(--color-text-primary)]">{new Date(data.organization.created_at).toLocaleDateString()}</dd>
            </div>
          </dl>
        </Card>
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Your account</h2>
          <dl className="space-y-1.5 text-sm">
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Name</dt>
              <dd className="text-[var(--color-text-primary)]">{data.account.display_name}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[var(--color-text-secondary)]">Role</dt>
              <dd className="capitalize text-[var(--color-text-primary)]">{data.account.role}</dd>
            </div>
          </dl>
        </Card>
        <EmailVerificationCard email={data.account.email} verifiedAt={data.account.email_verified_at} />
        <ChangePasswordCard />
        <SessionsCard />
      </div>
    </div>
  );
}
