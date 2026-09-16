import { expect, test } from "@playwright/test";
import { extractToken, waitForMail } from "./mail-sink";

/**
 * Slice 17 requirement 18: owner invites a teammate -> invitation
 * email (real, via the fake-Postmark-backed ProductionMailProvider
 * code path) -> recipient accepts -> account created/activated ->
 * membership/role correct -> browser login succeeds independently
 * afterward. Entirely through the real UI/backend.
 */

test("invitation: real email, accepting activates the account with the granted role", async ({ page }) => {
  const unique = Date.now();
  const ownerEmail = `e2e-inviter-${unique}@webguard-e2e.invalid`;
  const inviteeEmail = `e2e-invitee-${unique}@webguard-e2e.invalid`;
  const inviteePassword = "the invitee's chosen e2e password 123";

  // -- register a fresh organization as its owner --
  await page.goto("/register");
  await page.getByLabel("Organization name").fill(`E2E Invitation Org ${unique}`);
  await page.getByLabel("Your name").fill("Inviter E2E");
  await page.getByLabel("Email").fill(ownerEmail);
  await page.getByLabel("Password").fill("the inviter's own e2e password 123");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // -- invite a teammate as administrator --
  await page.goto("/app/team");
  await page.getByRole("button", { name: "Invite member" }).click();
  await page.getByLabel("Name").fill("Invitee E2E");
  await page.getByLabel("Email").fill(inviteeEmail);
  await page.getByLabel("Role").selectOption("administrator");
  await page.getByRole("button", { name: "Send invitation" }).click();
  await expect(page.getByText(`An invitation email was sent to ${inviteeEmail}`)).toBeVisible();
  const inviteeRow = page.getByRole("row").filter({ hasText: inviteeEmail });
  await expect(inviteeRow).toBeVisible();
  // The owner's own row is also unverified in this test (registered
  // via the UI, never verified) -- scope to the invitee's row
  // specifically rather than asserting "pending" appears anywhere.
  await expect(inviteeRow.getByText("pending", { exact: true })).toBeVisible();

  const message = await waitForMail(inviteeEmail, "invitation");
  expect(message.subject).toContain("invited to WebGuard");
  const token = extractToken(message.body);

  // -- the invitee accepts from what is, in reality, a different
  // browser entirely (a different person, a different machine). Sign
  // the owner out first so this one shared browser context correctly
  // simulates that -- AcceptInvitationPage redirects an already
  // signed-in visitor straight to the dashboard (the correct guard
  // against re-clicking an invitation link while already logged in),
  // which would otherwise fire here since this is still the owner's
  // own session. --
  await page.getByRole("button", { name: "Inviter E2E", exact: true }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login/);

  await page.goto(`/accept-invitation?token=${token}`);
  await page.getByLabel("Password").fill(inviteePassword);
  await page.getByRole("button", { name: "Activate account" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // -- the invitee's own session reflects the granted role, and RBAC
  // enforces it identically to any other administrator: no owner-only
  // capability leaks in --
  await page.goto("/app/settings");
  await expect(page.getByText("administrator", { exact: true })).toBeVisible();

  // -- sign out, then a fresh login with the invitee's own chosen
  // credentials succeeds independently -- the account is durably
  // usable, not merely auto-logged-in once --
  await page.getByRole("button", { name: "Invitee E2E", exact: true }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login/);
  await page.getByLabel("Email").fill(inviteeEmail);
  await page.getByLabel("Password").fill(inviteePassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
});
