import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Button,
  Card,
  ErrorState,
  LoadingState,
  PageHeader,
  StatusBadge,
} from "../components/ui/primitives";
import {
  useAsset,
  useCheckVerification,
  useIssuePermitAndSubmitJob,
  useStartVerification,
} from "../hooks/queries";
import { ApiError } from "../lib/api";

function VerificationPanel({ targetId }: { targetId: string }) {
  const { data: asset } = useAsset(targetId);
  const start = useStartVerification();
  const check = useCheckVerification();
  const verification = asset?.verification;

  if (!verification) {
    return (
      <Card className="p-4">
        <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Ownership verification</h2>
        <p className="mb-3 text-sm text-[var(--color-text-secondary)]">
          Prove control of this asset before requesting an authorization. WebGuard performs the check itself.
          The app never marks an asset verified on your behalf.
        </p>
        <Button variant="primary" onClick={() => start.mutate(targetId)} disabled={start.isPending}>
          {start.isPending ? "Starting…" : "Start verification"}
        </Button>
      </Card>
    );
  }

  return (
    <Card className="p-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--color-text-primary)]">Ownership verification</h2>
        <StatusBadge status={verification.status} />
      </div>
      {verification.status === "pending" && verification.instructions ? (
        <div className="text-sm text-[var(--color-text-secondary)]">
          <p className="mb-2">
            Publish this file at your asset's origin, then request a check:
          </p>
          <p className="mb-1 font-mono text-xs text-[var(--color-text-primary)]">
            {new URL(verification.instructions.path, asset.url).toString()}
          </p>
          <p className="mb-3 rounded bg-[var(--color-surface-raised)] px-2 py-1.5 font-mono text-xs text-[var(--color-text-primary)]">
            {verification.instructions.expected_content}
          </p>
          <Button variant="primary" onClick={() => check.mutate(targetId)} disabled={check.isPending}>
            {check.isPending ? "Checking…" : "Check now"}
          </Button>
          {check.isError ? (
            <p role="alert" className="mt-2 text-sm text-[var(--color-danger)]">
              {check.error instanceof ApiError ? check.error.message : "Unable to check verification."}
            </p>
          ) : null}
        </div>
      ) : (
        <div>
          <p className="mb-3 text-sm text-[var(--color-text-secondary)]">
            {verification.status === "verified"
              ? "Ownership has been verified."
              : "The last check did not succeed. You can start a new verification attempt."}
          </p>
          {verification.status !== "verified" ? (
            <Button variant="secondary" onClick={() => start.mutate(targetId)} disabled={start.isPending}>
              Start a new verification
            </Button>
          ) : null}
        </div>
      )}
    </Card>
  );
}

function StartScanPanel({ targetId }: { targetId: string }) {
  const { data: asset } = useAsset(targetId);
  const navigate = useNavigate();
  const [mode, setMode] = useState<"single_page" | "crawl">("single_page");
  const submit = useIssuePermitAndSubmitJob();

  if (!asset) return null;
  const authorized = asset.authorization && asset.authorization.state !== "expired";
  const verified = asset.verification?.status === "verified";

  async function handleStart() {
    const authorization = asset?.authorization;
    if (!asset || !authorization) return;
    try {
      const job = await submit.mutateAsync({
        target: asset.url,
        authorizationId: authorization.authorization_id,
        mode,
      });
      navigate(`/scans?justSubmitted=${job.job_id}`);
    } catch {
      // surfaced below
    }
  }

  return (
    <Card className="p-4">
      <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Start a scan</h2>
      {!verified ? (
        <p className="text-sm text-[var(--color-text-secondary)]">Verify ownership of this asset before scanning it.</p>
      ) : !authorized ? (
        <p className="text-sm text-[var(--color-text-secondary)]">
          No active authorization currently covers this exact URL. An owner or administrator must assign one
          before a scan can be issued. The app cannot construct or bypass this requirement.
        </p>
      ) : (
        <div>
          <fieldset className="mb-3">
            <legend className="mb-1.5 text-sm font-medium text-[var(--color-text-primary)]">Scan profile</legend>
            <div className="flex gap-4 text-sm text-[var(--color-text-secondary)]">
              <label className="flex items-center gap-1.5">
                <input
                  type="radio"
                  name="scan-mode"
                  checked={mode === "single_page"}
                  onChange={() => setMode("single_page")}
                />
                Single page (passive checks on one page)
              </label>
              <label className="flex items-center gap-1.5">
                <input type="radio" name="scan-mode" checked={mode === "crawl"} onChange={() => setMode("crawl")} />
                Crawl (passive checks across same-origin pages)
              </label>
            </div>
          </fieldset>
          <p className="mb-3 text-xs text-[var(--color-text-tertiary)]">
            This issues a passive-only TrustScan permit bound to your current authorization and submits a job,
            under the same authorization boundary the API enforces for every scan, regardless of how it was requested.
          </p>
          <Button variant="primary" onClick={handleStart} disabled={submit.isPending}>
            {submit.isPending ? "Starting scan…" : "Start scan"}
          </Button>
          {submit.isError ? (
            <p role="alert" className="mt-2 text-sm text-[var(--color-danger)]">
              {submit.error instanceof ApiError ? submit.error.message : "Unable to start the scan."}
            </p>
          ) : null}
        </div>
      )}
    </Card>
  );
}

export function AssetDetailPage() {
  const { targetId } = useParams<{ targetId: string }>();
  const { data: asset, isLoading, error } = useAsset(targetId);

  if (isLoading) return <LoadingState label="Loading asset…" />;
  if (error) return <ErrorState message={error instanceof ApiError ? error.message : "Unable to load this asset."} />;
  if (!asset) return null;

  return (
    <div>
      <PageHeader title={asset.label ?? asset.url} description={asset.url} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <VerificationPanel targetId={asset.target_id} />
        <Card className="p-4">
          <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Authorization</h2>
          {asset.authorization ? (
            <div className="text-sm text-[var(--color-text-secondary)]">
              <p className="mb-1">
                Status: <StatusBadge status={asset.authorization.state} />
              </p>
              <p>Expires {new Date(asset.authorization.expires_at).toLocaleString()}</p>
            </div>
          ) : (
            <p className="text-sm text-[var(--color-text-secondary)]">No authorization currently assigned to this URL.</p>
          )}
        </Card>
        <StartScanPanel targetId={asset.target_id} />
        <Card className="p-4">
          <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Findings summary</h2>
          {!asset.finding_counts || Object.keys(asset.finding_counts).length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">No findings recorded for this asset.</p>
          ) : (
            <ul className="space-y-1 text-sm text-[var(--color-text-secondary)]">
              {Object.entries(asset.finding_counts).map(([severity, count]) => (
                <li key={severity} className="flex justify-between capitalize">
                  <span>{severity}</span>
                  <span className="font-medium text-[var(--color-text-primary)]">{count}</span>
                </li>
              ))}
            </ul>
          )}
          <Link to={`/findings?asset=${encodeURIComponent(asset.url)}`} className="mt-3 inline-block text-sm text-[var(--color-accent)] hover:underline">
            View findings for this asset →
          </Link>
        </Card>
      </div>
    </div>
  );
}
