import { Card, ErrorState, LoadingState, PageHeader } from "../components/ui/primitives";
import { useSettings } from "../hooks/queries";
import { ApiError } from "../lib/api";

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
      </div>
    </div>
  );
}
