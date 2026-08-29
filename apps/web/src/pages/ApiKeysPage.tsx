import { useState, type FormEvent } from "react";
import { Button, Card, EmptyState, ErrorState, LoadingState, PageHeader, Table, Td, Th } from "../components/ui/primitives";
import { useApiKeys, useCreateApiKey, useRevokeApiKey } from "../hooks/queries";
import { ApiError } from "../lib/api";

export function ApiKeysPage() {
  const { data, isLoading, error } = useApiKeys();
  const create = useCreateApiKey();
  const revoke = useRevokeApiKey();
  const [label, setLabel] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    try {
      const key = await create.mutateAsync({ label: label.trim() });
      if (key.token) setIssuedToken(key.token);
      setShowForm(false);
      setLabel("");
    } catch {
      // surfaced below
    }
  }

  return (
    <div>
      <PageHeader
        title="API Keys"
        description="Personal access tokens you use to authenticate with the WebGuard API."
        actions={
          !showForm ? (
            <Button variant="primary" onClick={() => setShowForm(true)}>
              Create key
            </Button>
          ) : undefined
        }
      />

      {issuedToken ? (
        <Card className="mb-4 border-[var(--color-accent)]/50 p-4">
          <p className="mb-2 text-sm font-medium text-[var(--color-text-primary)]">
            Your new token is shown once. Copy it now — WebGuard cannot show it to you again.
          </p>
          <div className="mb-2 flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded bg-[var(--color-surface-raised)] px-2 py-1.5 text-xs text-[var(--color-text-primary)]">
              {issuedToken}
            </code>
            <Button
              variant="secondary"
              onClick={async () => {
                await navigator.clipboard.writeText(issuedToken);
                setCopied(true);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <Button variant="ghost" onClick={() => { setIssuedToken(null); setCopied(false); }}>
            I've saved this token, dismiss
          </Button>
        </Card>
      ) : null}

      {showForm ? (
        <Card className="mb-4 p-4">
          <form onSubmit={handleSubmit}>
            <label htmlFor="api-key-label" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
              Label
            </label>
            <input
              id="api-key-label"
              required
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              placeholder="CI pipeline"
              className="mb-3 w-full max-w-sm rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
            />
            {create.isError ? (
              <p role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
                {create.error instanceof ApiError ? create.error.message : "Unable to create this key."}
              </p>
            ) : null}
            <div className="flex gap-2">
              <Button type="submit" variant="primary" disabled={create.isPending}>
                {create.isPending ? "Creating…" : "Create key"}
              </Button>
              <Button type="button" variant="ghost" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      ) : null}

      {isLoading ? <LoadingState label="Loading API keys…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load API keys."} /> : null}
      {data && data.api_keys.length === 0 ? <EmptyState title="No API keys yet" /> : null}
      {data && data.api_keys.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Label</Th>
              <Th>Created</Th>
              <Th>Last used</Th>
              <Th>Status</Th>
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {data.api_keys.map((key) => (
              <tr key={key.token_id} className="hover:bg-[var(--color-surface-hover)]">
                <Td>{key.label}</Td>
                <Td className="text-[var(--color-text-secondary)]">{new Date(key.created_at).toLocaleDateString()}</Td>
                <Td className="text-[var(--color-text-secondary)]">
                  {key.last_used_at ? new Date(key.last_used_at).toLocaleString() : "never"}
                </Td>
                <Td className="text-[var(--color-text-secondary)]">{key.revoked_at ? "Revoked" : "Active"}</Td>
                <Td>
                  {!key.revoked_at ? (
                    <Button variant="danger" onClick={() => revoke.mutate(key.token_id)} disabled={revoke.isPending}>
                      Revoke
                    </Button>
                  ) : null}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
    </div>
  );
}
