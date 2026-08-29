import { useState, type FormEvent } from "react";
import { Button, Card, ErrorState, LoadingState, PageHeader, Table, Td, Th } from "../components/ui/primitives";
import { useInviteMember, useRemoveMember, useTeam, useUpdateMemberRole } from "../hooks/queries";
import { ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";

const ROLES = ["owner", "administrator", "analyst", "viewer"];

function InviteForm({ onClose, onIssued }: { onClose: () => void; onIssued: (token: string) => void }) {
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState("viewer");
  const invite = useInviteMember();

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    try {
      const member = await invite.mutateAsync({ display_name: displayName.trim(), role });
      if (member.initial_token) onIssued(member.initial_token);
      onClose();
    } catch {
      // surfaced below
    }
  }

  return (
    <Card className="mb-4 p-4">
      <form onSubmit={handleSubmit}>
        <div className="mb-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label htmlFor="invite-name" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
              Name
            </label>
            <input
              id="invite-name"
              required
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
            />
          </div>
          <div>
            <label htmlFor="invite-role" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
              Role
            </label>
            <select
              id="invite-role"
              value={role}
              onChange={(event) => setRole(event.target.value)}
              className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)] capitalize"
            >
              {ROLES.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>
        </div>
        {invite.isError ? (
          <p role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
            {invite.error instanceof ApiError ? invite.error.message : "Unable to invite this member."}
          </p>
        ) : null}
        <div className="flex gap-2">
          <Button type="submit" variant="primary" disabled={invite.isPending}>
            {invite.isPending ? "Inviting…" : "Send invitation"}
          </Button>
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </form>
    </Card>
  );
}

export function TeamPage() {
  const { session } = useAuth();
  const { data, isLoading, error } = useTeam();
  const updateRole = useUpdateMemberRole();
  const removeMember = useRemoveMember();
  const [showInvite, setShowInvite] = useState(false);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const canManage = session?.role === "owner" || session?.role === "administrator";

  return (
    <div>
      <PageHeader
        title="Team"
        description="Members of your organization and their roles."
        actions={
          canManage && !showInvite ? (
            <Button variant="primary" onClick={() => setShowInvite(true)}>
              Invite member
            </Button>
          ) : undefined
        }
      />

      {issuedToken ? (
        <Card className="mb-4 border-[var(--color-accent)]/50 p-4">
          <p className="mb-2 text-sm font-medium text-[var(--color-text-primary)]">
            Invitation created. This token is shown once — copy it now and relay it to your new team member securely.
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

      {showInvite ? <InviteForm onClose={() => setShowInvite(false)} onIssued={setIssuedToken} /> : null}

      {isLoading ? <LoadingState label="Loading team…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load the team."} /> : null}
      {data ? (
        <Table>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Role</Th>
              <Th>Status</Th>
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {data.members.map((member) => {
              const isSelf = member.principal_id === session?.principalId;
              return (
                <tr key={member.principal_id} className="hover:bg-[var(--color-surface-hover)]">
                  <Td>
                    {member.display_name}
                    {isSelf ? <span className="ml-1 text-xs text-[var(--color-text-tertiary)]">(you)</span> : null}
                  </Td>
                  <Td>
                    {canManage && !isSelf ? (
                      <select
                        aria-label={`Role for ${member.display_name}`}
                        value={member.role}
                        onChange={(event) => updateRole.mutate({ id: member.principal_id, role: event.target.value })}
                        className="rounded border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-2 py-1 text-xs capitalize text-[var(--color-text-primary)]"
                      >
                        {ROLES.map((role) => (
                          <option key={role} value={role}>
                            {role}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <span className="capitalize text-[var(--color-text-secondary)]">{member.role}</span>
                    )}
                  </Td>
                  <Td className="text-[var(--color-text-secondary)]">{member.active ? "Active" : "Removed"}</Td>
                  <Td>
                    {canManage && !isSelf && member.active ? (
                      <Button variant="danger" onClick={() => removeMember.mutate(member.principal_id)}>
                        Remove
                      </Button>
                    ) : null}
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      ) : null}
    </div>
  );
}
