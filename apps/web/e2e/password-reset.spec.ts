import { expect, test } from "@playwright/test";
import { extractToken, waitForMail } from "./mail-sink";

/**
 * Slice 17 requirement 17: forgot password -> email sent (real, via
 * the fake-Postmark-backed ProductionMailProvider code path) -> reset
 * link -> password replaced -> previous sessions revoked -> new login
 * succeeds. Entirely through the real UI/backend.
 */

test("password reset: real email, reset revokes the old session, new password signs in", async ({ page }) => {
  const unique = Date.now();
  const email = `e2e-reset-${unique}@webguard-e2e.invalid`;
  const originalPassword = "the original e2e password 123";
  const newPassword = "the replaced e2e password 456";

  // -- register, establishing a real session (session A) --
  await page.goto("/register");
  await page.getByLabel("Organization name").fill(`E2E Reset Org ${unique}`);
  await page.getByLabel("Your name").fill("Reset E2E");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(originalPassword);
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // -- forgot password, while session A's cookie is still present --
  await page.goto("/forgot-password");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(page.getByRole("status")).toContainText("password reset link has been sent");

  const message = await waitForMail(email, "password_reset");
  expect(message.subject).toContain("Reset your WebGuard password");
  expect(message.body).not.toContain(originalPassword);
  const token = extractToken(message.body);

  // -- open the reset link and set a new password --
  await page.goto(`/reset-password?token=${token}`);
  await page.getByLabel("New password").fill(newPassword);
  await page.getByRole("button", { name: "Reset password" }).click();
  await expect(page.getByRole("status")).toContainText("Password has been reset");

  // -- session A must now be revoked: a fresh load of a protected
  // page redirects to /login, not the dashboard --
  await page.goto("/app");
  await expect(page).toHaveURL(/\/login/);

  // -- the OLD password no longer works --
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(originalPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toBeVisible();

  // -- the NEW password signs in successfully --
  await page.getByLabel("Password").fill(newPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
});
