import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Button,
  Card,
  ErrorState,
  LoadingState,
  PageHeader,
  StatusBadge,
  Table,
  Td,
  Th,
} from "../components/ui/primitives";
import {
  useAsset,
  useAssetCoverage,
  useCheckVerification,
  useIssuePermitAndSubmitJob,
  useStartVerification,
} from "../hooks/queries";
import { ApiError } from "../lib/api";

function CopyableValue({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mb-3 flex items-center gap-2">
      <code className="flex-1 overflow-x-auto rounded bg-[var(--color-surface-raised)] px-2 py-1.5 font-mono text-xs text-[var(--color-text-primary)]">
        {value}
      </code>
      <Button
        variant="secondary"
        onClick={async () => {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 2000);
        }}
      >
        {copied ? "Copied" : `Copy ${label}`}
      </Button>
    </div>
  );
}

function WellKnownHelp() {
  return (
    <details className="mb-3 rounded border border-[var(--color-border)] p-2.5 text-sm text-[var(--color-text-secondary)]">
      <summary className="cursor-pointer select-none font-medium text-[var(--color-text-primary)]">
        How do I publish this file?
      </summary>
      <div className="mt-2 space-y-2">
        <p>
          Create a folder named <code className="font-mono text-xs">.well-known</code> at the root of your site
          (not inside a subfolder), and put a plain text file named{" "}
          <code className="font-mono text-xs">webguard-verification.txt</code> inside it, containing only the
          code above.
        </p>
        <ul className="list-disc space-y-1 pl-5">
          <li>
            <strong>Netlify, Vercel, GitHub Pages, Cloudflare Pages:</strong> add the file to your site's
            source (e.g. the <code className="font-mono text-xs">public/</code> folder) at path{" "}
            <code className="font-mono text-xs">.well-known/webguard-verification.txt</code>, then deploy.
          </li>
          <li>
            <strong>WordPress:</strong> use your host's file manager or an FTP client to add the file directly
            under the site's root directory (the same level as <code className="font-mono text-xs">wp-config.php</code>).
          </li>
          <li>
            <strong>A server you manage (Nginx, Apache, etc.):</strong> place the file in your site's document
            root, e.g. <code className="font-mono text-xs">/var/www/html/.well-known/webguard-verification.txt</code>.
          </li>
        </ul>
        <p className="rounded bg-[var(--color-surface-raised)] px-2 py-1.5">
          <strong>Important:</strong> the file must load directly, with no redirect. WebGuard does not follow
          redirects when checking. If your site forces <code className="font-mono text-xs">https://</code> or
          adds/drops <code className="font-mono text-xs">www.</code>, publish the file at the exact address
          shown above, not one that redirects to it.
        </p>
        <p>
          Some no-code website builders (Wix, Squarespace, Framer, Figma Sites, and others) don't let you
          publish an arbitrary file at all. If you can't find a way to do this, use DNS verification instead:
          it only needs access to your domain's DNS settings, not your site's files.
        </p>
      </div>
    </details>
  );
}

function DnsTxtHelp() {
  return (
    <details className="mb-3 rounded border border-[var(--color-border)] p-2.5 text-sm text-[var(--color-text-secondary)]">
      <summary className="cursor-pointer select-none font-medium text-[var(--color-text-primary)]">
        How do I add a DNS TXT record?
      </summary>
      <div className="mt-2 space-y-2">
        <p>
          Sign in to whichever service manages DNS for your domain (your domain registrar, or a separate DNS
          provider like Cloudflare) and find its DNS records page. Add a new record: type{" "}
          <code className="font-mono text-xs">TXT</code>, host/name is the record name shown above, value is
          the code above. Leave TTL at its default.
        </p>
        <p>
          Where "host" or "name" goes depends on the provider: some want the full record name shown above,
          others want just the part before your domain (e.g. just{" "}
          <code className="font-mono text-xs">_webguard-verification</code>, since they add your domain
          automatically). If the record doesn't verify at first, check whether your provider expects the
          short form instead of the full name.
        </p>
        <p className="rounded bg-[var(--color-surface-raised)] px-2 py-1.5">
          <strong>DNS changes take time to spread.</strong> This can take anywhere from a few minutes to a few
          hours depending on your provider. If "Check now" doesn't succeed right away, wait a bit and try
          again before assuming something is wrong.
        </p>
      </div>
    </details>
  );
}

function checkFailureMessage(detail: string, isDnsTxt: boolean): string {
  if (detail === "dns-record-not-found") {
    return "The DNS record wasn't found yet. This is normal right after adding it: changes can take anywhere from a few minutes to a few hours to spread. No need to generate a new value, just try again shortly.";
  }
  if (detail === "token-mismatch") {
    return isDnsTxt
      ? "A record was found at that name, but its value doesn't match. Double-check you copied the value exactly, with no extra spaces."
      : "The file was found, but its contents don't match. Double-check you copied the code exactly, with no extra spaces or lines.";
  }
  if (detail === "dns-lookup-timed-out" || detail.startsWith("dns-lookup-failed.")) {
    return "The DNS lookup didn't complete in time. This can happen right after adding a record; try again in a few minutes.";
  }
  if (detail.startsWith("unexpected-status.") || detail.startsWith("fetch-failed.") || detail.startsWith("target-validation-failed.")) {
    return "The file couldn't be loaded at that address yet. Double-check it's published and loads directly, with no login and no redirect.";
  }
  return "That check didn't succeed yet. This is often just a timing issue: try again in a few minutes.";
}

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
          The app never marks an asset verified on your behalf. Choose whichever is easier for how your site
          is hosted.
        </p>
        <div className="flex gap-2">
          <Button
            variant="primary"
            onClick={() => start.mutate({ id: targetId, method: "well_known_http" })}
            disabled={start.isPending}
          >
            {start.isPending ? "Starting…" : "Verify via file"}
          </Button>
          <Button
            variant="secondary"
            onClick={() => start.mutate({ id: targetId, method: "dns_txt" })}
            disabled={start.isPending}
          >
            {start.isPending ? "Starting…" : "Verify via DNS"}
          </Button>
        </div>
      </Card>
    );
  }

  const isDnsTxt = verification.method === "dns_txt";

  return (
    <Card className="p-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--color-text-primary)]">Ownership verification</h2>
        <StatusBadge status={verification.status} />
      </div>
      {verification.status === "pending" && verification.instructions ? (
        <div className="text-sm text-[var(--color-text-secondary)]">
          {isDnsTxt && "record_prefix" in verification.instructions ? (
            <>
              <p className="mb-2">
                Add a DNS TXT record with this name and this value, then request a check. This expires 24
                hours after verification was started.
              </p>
              <CopyableValue
                value={`${verification.instructions.record_prefix}.${new URL(asset.url).hostname}`}
                label="record name"
              />
              <CopyableValue value={verification.instructions.expected_content} label="value" />
              <DnsTxtHelp />
            </>
          ) : "path" in verification.instructions ? (
            <>
              <p className="mb-2">
                Publish a file containing this code at the exact address below, then request a check. This
                expires 24 hours after verification was started.
              </p>
              <CopyableValue
                value={new URL(verification.instructions.path, asset.url).toString()}
                label="address"
              />
              <CopyableValue value={verification.instructions.expected_content} label="code" />
              <WellKnownHelp />
            </>
          ) : null}
          {check.data?.last_check_detail ? (
            <p className="mb-3 rounded bg-[var(--color-surface-raised)] px-2 py-1.5 text-sm text-[var(--color-text-secondary)]">
              {checkFailureMessage(check.data.last_check_detail, isDnsTxt)}
            </p>
          ) : null}
          <div className="flex items-center gap-2">
            <Button variant="primary" onClick={() => check.mutate(targetId)} disabled={check.isPending}>
              {check.isPending ? "Checking…" : "Check now"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                check.reset();
                start.mutate({ id: targetId, method: verification.method });
              }}
              disabled={start.isPending}
            >
              {start.isPending ? "Starting…" : "Start over"}
            </Button>
          </div>
          {check.isError ? (
            <p role="alert" className="mt-2 text-sm text-[var(--color-danger)]">
              {check.error instanceof ApiError ? check.error.message : "Unable to check verification."}
            </p>
          ) : null}
          <Button
            variant="ghost"
            className="mt-2"
            onClick={() => {
              check.reset();
              start.mutate({ id: targetId, method: isDnsTxt ? "well_known_http" : "dns_txt" });
            }}
            disabled={start.isPending}
          >
            Or verify via {isDnsTxt ? "file" : "DNS"} instead
          </Button>
        </div>
      ) : (
        <div>
          <p className="mb-3 text-sm text-[var(--color-text-secondary)]">
            {verification.status === "verified"
              ? "Ownership has been verified."
              : "The verification code expired before a successful check. Start a new verification for a fresh code."}
          </p>
          {verification.status !== "verified" ? (
            <div className="flex gap-2">
              <Button
                variant="secondary"
                onClick={() => start.mutate({ id: targetId, method: "well_known_http" })}
                disabled={start.isPending}
              >
                Start over via file
              </Button>
              <Button
                variant="secondary"
                onClick={() => start.mutate({ id: targetId, method: "dns_txt" })}
                disabled={start.isPending}
              >
                Start over via DNS
              </Button>
            </div>
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
      navigate(`/app/webguard/scans?justSubmitted=${job.job_id}`);
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

function CoveragePanel({ targetId }: { targetId: string }) {
  const [cursorStack, setCursorStack] = useState<(string | undefined)[]>([undefined]);
  const cursor = cursorStack[cursorStack.length - 1];
  const { data, isLoading, error } = useAssetCoverage(targetId, cursor);

  const counts = data?.status_counts;
  const totalRecorded = counts ? counts.completed + counts.blocked + counts.unreachable : 0;

  return (
    <Card className="p-4 lg:col-span-2">
      <h2 className="mb-2 text-sm font-semibold text-[var(--color-text-primary)]">Coverage</h2>
      <p className="mb-3 text-xs text-[var(--color-text-tertiary)]">
        Which URL/method/check combinations have actually been assessed, and what happened. Counts below are
        what this asset has recorded so far, not a claim that everything possible was checked.
      </p>
      {isLoading ? (
        <p className="text-sm text-[var(--color-text-secondary)]">Loading coverage…</p>
      ) : error ? (
        <p role="alert" className="text-sm text-[var(--color-danger)]">
          {error instanceof ApiError ? error.message : "Unable to load coverage for this asset."}
        </p>
      ) : !data || totalRecorded === 0 ? (
        <p className="text-sm text-[var(--color-text-secondary)]">
          No coverage recorded for this asset yet. This means no scan has completed against it while coverage
          tracking was active, not that it has been assessed and found clean.
        </p>
      ) : (
        <div>
          <ul className="mb-3 flex flex-wrap gap-4 text-sm text-[var(--color-text-secondary)]">
            <li>
              <span className="font-medium text-[var(--color-text-primary)]">{totalRecorded}</span> recorded
            </li>
            <li>
              <span className="font-medium text-[var(--color-text-primary)]">{counts!.completed}</span> completed
            </li>
            <li>
              <span className="font-medium text-[var(--color-text-primary)]">{counts!.blocked}</span> blocked
            </li>
            <li>
              <span className="font-medium text-[var(--color-text-primary)]">{counts!.unreachable}</span> unreachable
            </li>
          </ul>
          <Table>
            <thead>
              <tr>
                <Th>Path</Th>
                <Th>Method</Th>
                <Th>Check</Th>
                <Th>Identity</Th>
                <Th>Status</Th>
                <Th>Last observed</Th>
              </tr>
            </thead>
            <tbody>
              {data.coverage.map((row) => (
                <tr key={`${row.path}|${row.http_method}|${row.identity_label}|${row.check_id}`}>
                  <Td className="font-mono text-xs">{row.path}</Td>
                  <Td>{row.http_method}</Td>
                  <Td>{row.check_id}</Td>
                  <Td>{row.identity_label}</Td>
                  <Td>
                    <StatusBadge status={row.status} />
                  </Td>
                  <Td>{new Date(row.last_observed_at).toLocaleString()}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <div className="mt-3 flex items-center justify-between">
            <Button
              variant="secondary"
              disabled={cursorStack.length <= 1}
              onClick={() => setCursorStack((stack) => stack.slice(0, -1))}
            >
              Previous
            </Button>
            <Button
              variant="secondary"
              disabled={!data.page.next_cursor}
              onClick={() => setCursorStack((stack) => [...stack, data.page.next_cursor ?? undefined])}
            >
              Next
            </Button>
          </div>
          <p className="mt-3 text-xs text-[var(--color-text-tertiary)]">
            Identity tracked today: <span className="font-medium">unauthenticated</span> only — authenticated-scan
            coverage is not yet attributed to a specific identity. Not yet tracked at all:{" "}
            {data.not_populated_states.join(", ")}.
          </p>
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
          <Link to={`/app/webguard/findings?asset=${encodeURIComponent(asset.url)}`} className="mt-3 inline-block text-sm text-[var(--color-accent)] hover:underline">
            View findings for this asset →
          </Link>
        </Card>
        <CoveragePanel targetId={asset.target_id} />
      </div>
    </div>
  );
}
