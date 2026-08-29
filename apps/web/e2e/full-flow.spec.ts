import { expect, test } from "@playwright/test";

/**
 * Slice 15 requirement 28 (rewritten for Slice 16 requirement 24): the
 * full product flow driven through the real browser UI, against the
 * real production-mode API + PostgreSQL + worker started by
 * `global-setup.ts`. Every step below is the same click/type a human
 * operator would perform -- nothing here reaches around the UI to
 * poke the API directly.
 *
 * The account itself is bootstrapped out-of-band by the harness (a
 * real password credential + a verified email, set up the same way
 * an admin-provisioned account would be) rather than registered
 * on-screen, since registration is already covered by its own
 * dedicated backend/unit coverage -- but sign-in, session
 * establishment, and sign-out below all go through the real login
 * form and real HttpOnly session cookie. The old "paste your API
 * token into the login screen" mechanism this spec used through
 * Slice 15 no longer exists in the product at all.
 */

const TOKEN = process.env.WEBGUARD_E2E_TOKEN;
const OWNER_EMAIL = process.env.WEBGUARD_E2E_OWNER_EMAIL;
const OWNER_PASSWORD = process.env.WEBGUARD_E2E_OWNER_PASSWORD;
const TARGET_URL = process.env.WEBGUARD_E2E_TARGET_URL;

test.beforeAll(() => {
  if (!TOKEN || !OWNER_EMAIL || !OWNER_PASSWORD || !TARGET_URL) {
    throw new Error(
      "global-setup did not publish WEBGUARD_E2E_TOKEN/WEBGUARD_E2E_OWNER_EMAIL/" +
        "WEBGUARD_E2E_OWNER_PASSWORD/WEBGUARD_E2E_TARGET_URL",
    );
  }
});

test("full customer platform flow: sign in, add asset, verify, scan, findings, report, sign out", async ({
  page,
}) => {
  // -- sign in with a real email/password account, establishing a
  // real server-side browser session (HttpOnly cookie) -- not a
  // pasted bearer token --
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER_EMAIL!);
  await page.getByLabel("Password").fill(OWNER_PASSWORD!);
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

  // -- sign out through the real UI: this revokes the session
  // server-side (not just a client-side state clear), so the browser
  // session cookie stops authenticating anything afterward --
  await page.getByRole("button", { name: "Dev Owner", exact: true }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login/);

  // -- a protected page is inaccessible after logout: the SPA's
  // route guard redirects back to /login rather than rendering
  // authenticated content from stale client state --
  await page.goto("/assets");
  await expect(page).toHaveURL(/\/login/);
});
