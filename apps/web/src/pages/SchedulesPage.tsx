import { useState, type FormEvent } from "react";
import { Button, Card, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge, Table, Td, Th } from "../components/ui/primitives";
import { useAssets, useCreateSchedule, useSchedules, useToggleSchedule } from "../hooks/queries";
import { ApiError } from "../lib/api";

function CreateScheduleForm({ onClose }: { onClose: () => void }) {
  const { data: assets } = useAssets();
  const create = useCreateSchedule();
  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState("");
  const [mode, setMode] = useState<"single_page" | "crawl">("single_page");
  const [intervalHours, setIntervalHours] = useState(24);

  const eligible = (assets?.assets ?? []).filter(
    (asset) => asset.verification?.status === "verified" && asset.authorization?.state !== "expired" && asset.authorization,
  );

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const asset = eligible.find((item) => item.target_id === targetId);
    if (!asset?.authorization) return;
    try {
      await create.mutateAsync({
        name: name.trim(),
        target: asset.url,
        authorizationId: asset.authorization.authorization_id,
        mode,
        intervalSeconds: intervalHours * 3600,
      });
      onClose();
    } catch {
      // surfaced via create.error
    }
  }

  return (
    <Card className="mb-4 p-4">
      {eligible.length === 0 ? (
        <p className="text-sm text-[var(--color-text-secondary)]">
          No verified, authorized assets are available yet. Verify an asset and confirm its authorization before
          scheduling a recurring scan.
        </p>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="mb-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="schedule-name" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
                Name
              </label>
              <input
                id="schedule-name"
                required
                value={name}
                onChange={(event) => setName(event.target.value)}
                className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
              />
            </div>
            <div>
              <label htmlFor="schedule-target" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
                Asset
              </label>
              <select
                id="schedule-target"
                required
                value={targetId}
                onChange={(event) => setTargetId(event.target.value)}
                className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
              >
                <option value="">Select an asset…</option>
                {eligible.map((asset) => (
                  <option key={asset.target_id} value={asset.target_id}>
                    {asset.label ?? asset.url}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="schedule-mode" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
                Profile
              </label>
              <select
                id="schedule-mode"
                value={mode}
                onChange={(event) => setMode(event.target.value as "single_page" | "crawl")}
                className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
              >
                <option value="single_page">Single page</option>
                <option value="crawl">Crawl</option>
              </select>
            </div>
            <div>
              <label htmlFor="schedule-interval" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
                Repeat every (hours)
              </label>
              <input
                id="schedule-interval"
                type="number"
                min={1}
                max={720}
                value={intervalHours}
                onChange={(event) => setIntervalHours(Number(event.target.value))}
                className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
              />
            </div>
          </div>
          {create.isError ? (
            <p role="alert" className="mb-3 text-sm text-[var(--color-danger)]">
              {create.error instanceof ApiError ? create.error.message : "Unable to create this schedule."}
            </p>
          ) : null}
          <div className="flex gap-2">
            <Button type="submit" variant="primary" disabled={create.isPending}>
              {create.isPending ? "Creating…" : "Create schedule"}
            </Button>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
          </div>
        </form>
      )}
    </Card>
  );
}

export function SchedulesPage() {
  const { data, isLoading, error } = useSchedules();
  const toggle = useToggleSchedule();
  const [showForm, setShowForm] = useState(false);

  return (
    <div>
      <PageHeader
        title="Schedules"
        description="Recurring scans on your verified, authorized assets."
        actions={
          !showForm ? (
            <Button variant="primary" onClick={() => setShowForm(true)}>
              Create schedule
            </Button>
          ) : undefined
        }
      />
      {showForm ? <CreateScheduleForm onClose={() => setShowForm(false)} /> : null}
      {isLoading ? <LoadingState label="Loading schedules…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load schedules."} /> : null}
      {data && data.schedules.length === 0 ? (
        <EmptyState title="No schedules yet" description="Create a recurring schedule from a verified, authorized asset." />
      ) : null}
      {data && data.schedules.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Target</Th>
              <Th>State</Th>
              <Th>Next run</Th>
              <Th>Last run</Th>
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {data.schedules.map((schedule) => (
              <tr key={schedule.schedule_id} className="hover:bg-[var(--color-surface-hover)]">
                <Td>{schedule.name}</Td>
                <Td className="max-w-48 truncate text-[var(--color-text-secondary)]">{schedule.target}</Td>
                <Td>
                  <StatusBadge status={schedule.state} />
                </Td>
                <Td className="text-[var(--color-text-secondary)]">
                  {schedule.next_run_at ? new Date(schedule.next_run_at).toLocaleString() : "—"}
                </Td>
                <Td className="text-[var(--color-text-secondary)]">
                  {schedule.last_enqueued_at ? new Date(schedule.last_enqueued_at).toLocaleString() : "never"}
                </Td>
                <Td>
                  <Button
                    variant="secondary"
                    onClick={() =>
                      toggle.mutate({ id: schedule.schedule_id, action: schedule.state === "active" ? "pause" : "resume" })
                    }
                    disabled={toggle.isPending}
                  >
                    {schedule.state === "active" ? "Disable" : "Enable"}
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
    </div>
  );
}
