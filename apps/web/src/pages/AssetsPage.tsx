import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  Table,
  Td,
  Th,
} from "../components/ui/primitives";
import { useAssets, useCreateAsset } from "../hooks/queries";
import { ApiError } from "../lib/api";

function AddAssetForm({ onClose }: { onClose: () => void }) {
  const [url, setUrl] = useState("");
  const [label, setLabel] = useState("");
  const create = useCreateAsset();

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    try {
      await create.mutateAsync({ url: url.trim(), label: label.trim() || undefined });
      onClose();
    } catch {
      // surfaced via create.error below
    }
  }

  return (
    <Card className="mb-4 p-4">
      <form onSubmit={handleSubmit}>
        <div className="mb-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label htmlFor="asset-url" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
              URL
            </label>
            <input
              id="asset-url"
              required
              type="url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://app.example.com/"
              className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
            />
          </div>
          <div>
            <label htmlFor="asset-label" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
              Label (optional)
            </label>
            <input
              id="asset-label"
              type="text"
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              placeholder="Production marketing site"
              className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
            />
          </div>
        </div>
        {create.error ? (
          <p role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
            {create.error instanceof ApiError ? create.error.message : "Unable to add this asset."}
          </p>
        ) : null}
        <div className="flex gap-2">
          <Button type="submit" variant="primary" disabled={create.isPending}>
            {create.isPending ? "Adding…" : "Add asset"}
          </Button>
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </form>
    </Card>
  );
}

function VerificationIndicator({ status }: { status: string | undefined }) {
  const label = status ?? "unverified";
  const tone: Record<string, string> = {
    verified: "text-[var(--color-success)]",
    pending: "text-[var(--color-info)]",
    failed: "text-[var(--color-danger)]",
    expired: "text-[var(--color-danger)]",
    unverified: "text-[var(--color-text-tertiary)]",
  };
  return <span className={`text-xs font-medium capitalize ${tone[label]}`}>{label}</span>;
}

export function AssetsPage() {
  const { data, isLoading, error } = useAssets();
  const [showForm, setShowForm] = useState(false);

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Targets your organization has registered for authorized scanning."
        actions={
          !showForm ? (
            <Button variant="primary" onClick={() => setShowForm(true)}>
              Add asset
            </Button>
          ) : undefined
        }
      />
      {showForm ? <AddAssetForm onClose={() => setShowForm(false)} /> : null}

      {isLoading ? <LoadingState label="Loading assets…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load assets."} /> : null}
      {data && data.assets.length === 0 ? (
        <EmptyState
          title="No assets yet"
          description="Add your first asset URL above. You'll need to verify ownership and have an authorization on file before scanning it."
        />
      ) : null}
      {data && data.assets.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>URL</Th>
              <Th>Label</Th>
              <Th>Verification</Th>
              <Th>Added</Th>
            </tr>
          </thead>
          <tbody>
            {data.assets.map((asset) => (
              <tr key={asset.target_id} className="hover:bg-[var(--color-surface-hover)]">
                <Td>
                  <Link to={`/app/webguard/assets/${asset.target_id}`} className="text-[var(--color-text-primary)] hover:text-[var(--color-accent)]">
                    {asset.url}
                  </Link>
                </Td>
                <Td className="text-[var(--color-text-secondary)]">{asset.label ?? "-"}</Td>
                <Td>
                  <VerificationIndicator status={asset.verification?.status} />
                </Td>
                <Td className="text-[var(--color-text-secondary)]">{new Date(asset.created_at).toLocaleDateString()}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
    </div>
  );
}
