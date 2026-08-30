import { expect, test } from "@playwright/test";
import { extractToken, waitForMail } from "./mail-sink";

/**
 * Slice 17 requirement 16: register -> verification email emitted by
 * the real (fake-Postmark-backed) ProductionMailProvider code path ->
 * verification token opened -> account becomes verified. Entirely
 * through the real UI and the real backend identity flow; the only
 * thing substituted anywhere in this path is the Postmark network
 * boundary (see `webguard_production_harness.py`'s `FakePostmarkTransport`).
 */

test("registration: verification email is real, opening its link verifies the account", async ({ page }) => {
  const unique = Date.now();
  const email = `e2e-register-${unique}@webguard-e2e.invalid`;

  await page.goto("/register");
  await page.getByLabel("Organization name").fill(`E2E Register Org ${unique}`);
  await page.getByLabel("Your name").fill("Register E2E");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("a genuinely long e2e password 123");
  await page.getByRole("button", { name: "Create organization" }).click();

  // Registration auto-establishes a session (Slice 16) -- lands on
  // the dashboard signed in, but not yet email-verified.
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  const message = await waitForMail(email, "email_verification");
  expect(message.subject).toContain("Verify your WebGuard email address");
  // Requirement 3: never a password/session/API-token secret in the
  // mail body -- only the verification link itself.
  expect(message.body).not.toContain("a genuinely long e2e password 123");
  const token = extractToken(message.body);

  await page.goto(`/verify-email?token=${token}`);
  await expect(page.getByRole("status")).toHaveText("Email address verified.");

  // The account's own settings page now reflects the verified state.
  await page.goto("/settings");
  await expect(page.getByText("verified", { exact: true })).toBeVisible();
});
