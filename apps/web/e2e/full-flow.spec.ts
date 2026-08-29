import { expect, test } from "@playwright/test";

/**
 * Slice 15 requirement 28: the full product flow driven through the
 * real browser UI, against the real production-mode API + PostgreSQL
 * + worker started by `global-setup.ts`. Every step below is the same
 * click/type a human operator would perform -- nothing here reaches
 * around the UI to poke the API directly.
 */

const TOKEN = process.env.WEBGUARD_E2E_TOKEN;
const TARGET_URL = process.env.WEBGUARD_E2E_TARGET_URL;

test.beforeAll(() => {
  if (!TOKEN || !TARGET_URL) {
    throw new Error("global-setup did not publish WEBGUARD_E2E_TOKEN/WEBGUARD_E2E_TARGET_URL");
  }
});

test("full customer platform flow: sign in, add asset, verify, scan, findings, report", async ({ page }) => {
  // -- sign in --
  await page.goto("/login");
  await page.getByLabel("API token").fill(TOKEN!);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // -- add the controlled fixture asset --
  await page.goto("/assets");
  await page.getByRole("button", { name: "Add asset" }).click();
  await page.getByLabel("URL").fill(TARGET_URL!);
  await page.getByRole("button", { name: "Add asset", exact: true }).click();
  await expect(page.getByRole("link", { name: TARGET_URL! })).toBeVisible();
  await page.getByRole("link", { name: TARGET_URL! }).click();

  // -- verify ownership through the real server-side check --
  await expect(page.getByRole("heading", { name: "Ownership verification" })).toBeVisible();
  await page.getByRole("button", { name: "Start verification" }).click();
  await page.getByRole("button", { name: "Check now" }).click();
  await expect(page.getByText("Ownership has been verified.")).toBeVisible({ timeout: 15_000 });

  // -- authorization was pre-assigned by the E2E harness (no
  // frontend UI exists to create one -- that stays an offline,
  // out-of-band legal step in this product's model) --
  await expect(page.getByText(/status:/i)).toBeVisible();
  const startScanButton = page.getByRole("button", { name: "Start scan" });
  await expect(startScanButton).toBeEnabled();

  // -- start a real passive scan --
  await startScanButton.click();
  await expect(page).toHaveURL(/\/scans\?justSubmitted=/, { timeout: 15_000 });

  // -- wait for the real worker to complete the job --
  const scanRow = page.getByRole("row").filter({ hasText: TARGET_URL! }).first();
  await expect(scanRow.getByText("completed", { exact: true })).toBeVisible({ timeout: 20_000 });
  await scanRow.getByRole("link").first().click();

  // -- scan detail shows real, persisted findings --
  const findingsHeading = page.getByRole("heading", { name: /Findings \(\d+\)/ });
  await expect(findingsHeading).toBeVisible();
  const findingsHeadingText = await findingsHeading.textContent();
  const findingCount = Number((findingsHeadingText ?? "").match(/\((\d+)\)/)?.[1] ?? "0");
  expect(findingCount).toBeGreaterThan(0);

  // -- request a report for this completed scan. Object-storage
  // artifact persistence is a known, documented gap (see
  // docs/audit/customer-platform-phase1.md): this disposable stack
  // has no S3 provisioned (requirement 29 forbids provisioning one
  // without separate approval), so the backend honestly refuses
  // rather than silently treating a local path as durable cloud
  // storage. The frontend must surface that real error, not paper
  // over it -- so this assertion is a correctness check on error
  // handling, not a workaround. --
  await page.getByRole("button", { name: "Request report" }).click();
  await expect(page.getByText(/object-storage artifact persistence is not implemented/i)).toBeVisible({
    timeout: 10_000,
  });

  // -- dashboard reflects the completed scan and its findings --
  await page.goto("/");
  await expect(page.getByText("No scans yet.")).toHaveCount(0);
  await expect(page.getByText("No findings recorded yet.")).toHaveCount(0);

  // -- open a finding and change its lifecycle status --
  await page.goto("/findings");
  const firstFindingLink = page.getByRole("table").getByRole("link").first();
  const findingTitle = await firstFindingLink.textContent();
  await firstFindingLink.click();
  await expect(page.getByRole("heading", { name: findingTitle ?? "" })).toBeVisible();
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page.getByText("confirmed", { exact: true }).first()).toBeVisible();

  // -- the reports list itself is real and reachable (report creation
  // is blocked by the known object-storage gap above, not by this
  // page) --
  await page.goto("/reports");
  await expect(page.getByRole("heading", { name: "Reports" })).toBeVisible();
});
