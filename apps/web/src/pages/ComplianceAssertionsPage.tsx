import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Button,
  Card,
  Dialog,
  EmptyState,
  ErrorState,
  InDevelopmentNotice,
  LoadingState,
  PageHeader,
  Table,
  Td,
  Th,
} from "../components/ui/primitives";
import {
  useAssertionCollections,
  useCollectAssertion,
  useComplianceAssertions,
  useModuleEntitlements,
} from "../hooks/queries";
import { ApiError } from "../lib/api";
import type { AssertionCollection, AssertionOutcome, TechnicalAssertion } from "../lib/api";

const OUTCOME_LABEL: Record<AssertionOutcome, { label: string; className: string }> = {
  satisfied: { label: "Satisfied", className: "text-[var(--color-success)] bg-[var(--color-success-bg)]" },
  violated: { label: "Violated", className: "text-[var(--color-danger)] bg-[var(--color-danger-bg)]" },
  indeterminate: { label: "Indeterminate", className: "text-[var(--color-warning)] bg-[var(--color-warning-bg)]" },
  not_tested: { label: "Not tested", className: "text-[var(--color-text-secondary)] bg-[var(--color-surface-raised)]" },
};

// No freshness budget is defined by the backend yet (Coverage Truth
// Map's own coverage_records has the same gap). 24 hours is a
// client-side-only display heuristic, not a product commitment --
// changing it changes nothing about what was actually collected.
const STALE_AFTER_MS = 24 * 60 * 60 * 1000;

function isStale(collectedAt: string): boolean {
  return Date.now() - new Date(collectedAt).getTime() > STALE_AFTER_MS;
}

function CollectionRow({ collection }: { collection: AssertionCollection }) {
  const failed = collection.collection_status === "failed";
  return (
    <tr>
      <Td>
        {failed ? (
          <span className="inline-flex rounded bg-[var(--color-danger-bg)] px-2 py-0.5 text-xs font-medium text-[var(--color-danger)]">
            Collection failed
          </span>
        ) : collection.outcome ? (
          <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${OUTCOME_LABEL[collection.outcome].className}`}>
            {OUTCOME_LABEL[collection.outcome].label}
          </span>
        ) : null}
      </Td>
      <Td className="text-[var(--color-text-secondary)]">
        {failed ? collection.collection_error : collection.outcome_detail}
      </Td>
      <Td>
        <span className="text-xs font-medium capitalize text-[var(--color-text-secondary)]">
          {collection.evidence_source}
        </span>
        <span className="ml-1.5 text-xs text-[var(--color-text-tertiary)]">{collection.evidence_provenance}</span>
      </Td>
      <Td className="whitespace-nowrap text-[var(--color-text-secondary)]">
        {new Date(collection.collected_at).toLocaleString()}
        {isStale(collection.collected_at) ? (
          <span className="ml-1.5 text-xs text-[var(--color-text-tertiary)]">(stale)</span>
        ) : (
          <span className="ml-1.5 text-xs text-[var(--color-success)]">(fresh)</span>
        )}
      </Td>
    </tr>
  );
}

function RunCollectionDialog({
  assertion,
  fixtureNames,
  open,
  onClose,
}: {
  assertion: TechnicalAssertion;
  fixtureNames: string[];
  open: boolean;
  onClose: () => void;
}) {
  const [source, setSource] = useState<"fixture" | "manual">("fixture");
  const [fixtureName, setFixtureName] = useState(fixtureNames[0] ?? "");
  const [manualEvidence, setManualEvidence] = useState("[]");
  const [parseError, setParseError] = useState<string | null>(null);
  const collect = useCollectAssertion(assertion.assertion_id);

  async function handleSubmit() {
    setParseError(null);
    if (source === "fixture") {
      await collect.mutateAsync({ evidence_source: "fixture", fixture_name: fixtureName });
      onClose();
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(manualEvidence);
    } catch {
      setParseError("Manual evidence must be valid JSON, matching a real connector response's own shape.");
      return;
    }
    if (!Array.isArray(parsed)) {
      setParseError("Manual evidence must be a JSON array.");
      return;
    }
    await collect.mutateAsync({ evidence_source: "manual", manual_evidence: parsed });
    onClose();
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Run a collection: ${assertion.title}`}
      description="Nothing here contacts a live Microsoft tenant. Choose a checked-in fixture, or supply evidence shaped the way a real connector response eventually will be."
    >
      <div className="space-y-4">
        <div role="radiogroup" aria-label="Evidence source" className="flex gap-2">
          <Button
            type="button"
            variant={source === "fixture" ? "primary" : "secondary"}
            onClick={() => setSource("fixture")}
          >
            Fixture
          </Button>
          <Button
            type="button"
            variant={source === "manual" ? "primary" : "secondary"}
            onClick={() => setSource("manual")}
          >
            Manual evidence
          </Button>
        </div>
        {source === "fixture" ? (
          <div>
            <label htmlFor="fixture-name" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
              Fixture set
            </label>
            <select
              id="fixture-name"
              value={fixtureName}
              onChange={(event) => setFixtureName(event.target.value)}
              className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 text-sm text-[var(--color-text-primary)]"
            >
              {fixtureNames.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </div>
        ) : (
          <div>
            <label htmlFor="manual-evidence" className="mb-1 block text-sm font-medium text-[var(--color-text-primary)]">
              Evidence (JSON array)
            </label>
            <textarea
              id="manual-evidence"
              rows={6}
              value={manualEvidence}
              onChange={(event) => setManualEvidence(event.target.value)}
              className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-canvas)] px-3 py-2 font-mono text-xs text-[var(--color-text-primary)]"
            />
          </div>
        )}
        {parseError ? <p className="text-sm text-[var(--color-danger)]">{parseError}</p> : null}
        {collect.error ? (
          <p className="text-sm text-[var(--color-danger)]">
            {collect.error instanceof ApiError ? collect.error.message : "Unable to run this collection."}
          </p>
        ) : null}
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleSubmit} disabled={collect.isPending}>
            {collect.isPending ? "Running…" : "Run collection"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function AssertionDetail({
  assertion,
  fixtureNames,
  canCollect,
}: {
  assertion: TechnicalAssertion;
  fixtureNames: string[];
  canCollect: boolean;
}) {
  const { data, isLoading, error } = useAssertionCollections(assertion.assertion_id);
  const [dialogOpen, setDialogOpen] = useState(false);

  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">{assertion.title}</h2>
          <p className="mt-1 max-w-2xl text-sm text-[var(--color-text-secondary)]">{assertion.objective}</p>
        </div>
        {assertion.evaluatable && canCollect ? (
          <Button variant="primary" onClick={() => setDialogOpen(true)}>
            Run collection
          </Button>
        ) : null}
      </div>
      {!assertion.evaluatable ? (
        <div className="mt-4">
          <InDevelopmentNotice>
            This assertion has no evaluation logic in this version of the codebase yet. Its catalog entry (source
            connector, required permissions) is real; collecting against it is not yet possible.
          </InDevelopmentNotice>
        </div>
      ) : null}
      {assertion.evaluatable && !canCollect ? (
        <div className="mt-4">
          <InDevelopmentNotice>
            Compliance is not enabled for your organization, so running a new collection is disabled. Any history
            below is still visible.
          </InDevelopmentNotice>
        </div>
      ) : null}
      <div className="mt-5 flex flex-wrap gap-x-6 gap-y-1 text-xs text-[var(--color-text-tertiary)]">
        <span>
          Source connector: <span className="font-mono">{assertion.source_connector_id}</span>
        </span>
        <span>Required permissions: {assertion.required_permissions.join(", ")}</span>
      </div>
      <h3 className="mt-6 text-sm font-semibold text-[var(--color-text-primary)]">Collection history</h3>
      {isLoading ? <LoadingState label="Loading collection history…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load history."} /> : null}
      {data && data.collections.length === 0 ? (
        <EmptyState
          title="Never attempted"
          description="No one has run a collection against this assertion yet for your organization."
        />
      ) : null}
      {data && data.collections.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Outcome</Th>
              <Th>Detail</Th>
              <Th>Evidence</Th>
              <Th>Collected</Th>
            </tr>
          </thead>
          <tbody>
            {data.collections.map((collection) => (
              <CollectionRow key={collection.collection_id} collection={collection} />
            ))}
          </tbody>
        </Table>
      ) : null}
      <RunCollectionDialog
        assertion={assertion}
        fixtureNames={fixtureNames}
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
      />
    </div>
  );
}

export function ComplianceAssertionsPage() {
  const { data, isLoading, error } = useComplianceAssertions();
  const { data: entitlements } = useModuleEntitlements();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get("assertion");
  const canCollect = entitlements?.entitlements.some(
    (entitlement) => entitlement.module === "compliance" && (entitlement.status === "enabled" || entitlement.status === "trial"),
  );

  const selected = data?.assertions.find((assertion) => assertion.assertion_id === selectedId) ?? data?.assertions[0];

  return (
    <div>
      <PageHeader
        title="Technical assertions"
        description="What this platform knows how to check, and your organization's own collection history against each one."
      />
      {isLoading ? <LoadingState label="Loading assertions…" /> : null}
      {error ? <ErrorState message={error instanceof ApiError ? error.message : "Unable to load assertions."} /> : null}
      {data ? (
        <div className="grid gap-5 lg:grid-cols-[18rem_1fr]">
          <div className="space-y-1">
            {data.assertions.map((assertion) => (
              <button
                key={assertion.assertion_id}
                type="button"
                onClick={() => setSearchParams({ assertion: assertion.assertion_id })}
                className={`block w-full rounded-md px-3 py-2.5 text-left text-sm transition-colors ${
                  selected?.assertion_id === assertion.assertion_id
                    ? "bg-[var(--color-accent-soft-bg)] text-[var(--color-accent)]"
                    : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)]"
                }`}
              >
                <span className="block font-medium">{assertion.title}</span>
                <span className="mt-0.5 block text-xs text-[var(--color-text-tertiary)]">
                  {assertion.evaluatable ? "Evaluation available" : "Catalog only"}
                </span>
              </button>
            ))}
          </div>
          <Card className="p-5">
            {selected ? (
              <AssertionDetail assertion={selected} fixtureNames={data.fixture_evidence_sets} canCollect={!!canCollect} />
            ) : null}
          </Card>
        </div>
      ) : null}
    </div>
  );
}
