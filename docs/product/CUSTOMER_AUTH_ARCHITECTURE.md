# Customer Authentication Architecture (Slice 16)

## 1. What this is

Slice 15 built the customer platform's frontend-facing API surface and a
first SPA on top of it, but its "login" was a paste-your-API-token screen —
an honest interim adaptation of the fact that the API had no browser
session layer at all, not a real authentication product. Slice 16 replaces
that with a real one: email/password accounts, server-side browser
sessions, CSRF protection, password reset, email verification, and an
invitation flow that actually sends mail (to a logged/test sink — see §7)
instead of handing back a raw API token.

This document describes the product-level model: the account, the
session, and how they relate to the organization/RBAC model that has
existed since Slice 2. For the session/cookie/CSRF *security* design and
threat model, see `docs/security/BROWSER_SESSION_SECURITY.md`. For the
concrete implementation record (what shipped, what broke, what remains a
gap), see `docs/audit/customer-platform-phase2-identity-sessions.md`.

## 2. Two authenticators, one authorization model

```
Bearer token  ──┐
                ├──► AuthContext (organization_id, principal_id, role, ...) ──► RBAC (ApiPermission)
Session cookie ─┘
```

`ApiTokenAuthenticator` (Bearer header, unchanged since Slice 12) and the
new `BrowserSessionAuthenticator` (HttpOnly cookie) are the only two ways
to reach the API. Both resolve into the exact same `AuthContext` dataclass
that every service method and every RBAC check
(`ApiPermission`/`_ROLE_PERMISSIONS`) already used before this slice
existed. There is no separate "browser permission model" and there never
will be one, by construction — a new capability added to RBAC in a future
slice is automatically enforced identically for both authenticators,
because there is only one code path past this point.

`AuthContext` gained one new field this slice, `auth_method`
(`"api_token"` | `"browser_session"`), used in exactly two places: the
CSRF gate (§0d of the API contract; browser sessions must prove a CSRF
token, Bearer tokens never do) and audit-log differentiation. Nothing in
RBAC ever reads it.

## 3. Account model

The existing `Principal` record (organization membership + role +
active/created_at, since the very first slice) gained three fields:
`email`, `email_verified_at`, `last_login_at`. No second, parallel "user"
table was introduced — a customer-facing account **is** a principal, the
same entity a CLI-bootstrapped or API-token principal already was. This
was a deliberate rejection of the more common pattern (a `users` table
separate from an `organization_members`/principal table) because this
product has no principal that exists independent of an organization
membership in the first place — every principal has belonged to exactly
one organization since Slice 2, so a second identity table would only
duplicate `organization_id`/`role`/`active` and require keeping two tables
in sync on every future change.

Password credentials, identity tokens (verification/reset/invitation),
and browser sessions each get their own table (`password_credentials`,
`identity_tokens`, `browser_sessions` — see the security doc §4-5 for
why), all foreign-keyed to `principal_id`. A principal with no password
credential yet (an invited-but-not-yet-accepted member) simply has no row
in `password_credentials` — not a null-password sentinel value.

## 4. Registration and invitation

Two ways a principal gets an account, matching requirement 9's own
framing ("if no public self-registration, support invitation instead"):
this product supports **both**.

- **`POST /v1/auth/register`** — creates a *new* organization and its
  first principal as `owner`, in one call, with a password and an
  email-verification token, then establishes a session immediately
  (auto-login). There is deliberately no "join an existing organization
  by matching email domain" flow — that would let anyone with an
  `@acme.com` address self-admit into Acme's organization with no
  approval step, which is a real, well-known SaaS vulnerability class,
  not a hypothetical one.
- **`POST /v1/team/invitations`** (owner/administrator only) — creates a
  principal in the *caller's* organization with no password yet, and
  sends an invitation email. `POST /v1/auth/invitations/accept` consumes
  the mailed token, sets the password, and — since clicking a link
  delivered to a specific mailbox is itself proof of controlling that
  mailbox — marks the email verified in the same step, then establishes a
  session (auto-login).

This is a **revision** of Slice 15's own invitation behavior, not an
inconsistency: Slice 15 issued a raw API bearer token directly from the
invite call, explicitly justified at the time by "no email infrastructure
exists yet." Slice 16 builds that infrastructure (the mail-provider
abstraction, §7), so the workaround it was justifying is gone, and the
invitation flow now looks like every other mailed-invitation product.

## 5. Password and session lifecycle, at a glance

| Event | What happens to sessions |
|---|---|
| Login | A new session is created. Any cookie the client presented on the login request itself is ignored — the server always mints a fresh, unguessable session ID (session-fixation defense, security doc §6). |
| Password change (in-session) | Every *other* session for the principal is revoked; the session used to make the change survives. |
| Password reset (via emailed token) | **Every** session for the principal is revoked, including the one that requested the reset, if any — this is a "you no longer trust anything that was signed in before" boundary, not just a targeted fix. |
| Role change or removal (by an admin) | Every session belonging to the *target* principal is revoked — they must re-authenticate to pick up the new role or the fact that they were removed. |
| Explicit logout | The current session is revoked. |
| Explicit "sign out everywhere" | Every session for the principal is revoked, including the current one. |
| Idle timeout (30 min) / absolute timeout (12 h) | The session simply stops being usable; nothing needs to "happen" — `is_usable(now)` fails closed. |

There is no literal "rotate this session's ID in place" operation,
because there is never a caller-observable reason to keep the *same*
session identifier alive across one of these boundaries — targeted
revocation (issue a new session, invalidate the old one or every other
one) achieves the same security property (an attacker who captured an old
session token loses it) with a simpler model than in-place rotation would
need.

## 6. Organization context: one per principal, unchanged

Slice 16 does **not** add multi-organization membership. A principal
still belongs to exactly one organization, exactly as every prior slice
already assumed. Requirement 14 ("if a principal can belong to multiple
organizations, org switching must be server-authorized...") is satisfied
vacuously but verifiably: there is no client-suppliable
`organization_id` anywhere in this API (there never was), so there is
nothing to spoof, no switch endpoint exists to abuse, and
`docs/audit/customer-platform-phase2-identity-sessions.md` records a
dedicated regression test proving `context.organization_id` — resolved
once, server-side, from the authenticated session or token — is the only
thing any route ever reads.

This was a deliberate scope decision, not an oversight: building a
half-finished multi-org switcher (e.g., a `POST /v1/auth/organization`
endpoint with no invitation-to-a-second-org flow behind it, no UI for
managing multiple memberships, no tests for the switch boundary itself)
would add real attack surface — an org-switch endpoint is exactly the
kind of thing that gets the organization-confusion class of bug wrong —
for a capability nothing else in the product yet needs. If a future slice
adds real multi-org membership, this is the document to update.

## 7. Mail provider: an interface, not a promise of delivery

`MailProvider` (a small Protocol in `apps/api/src/webguard_api/mail.py`)
has exactly two implementations this slice: `LoggingMailProvider`
(writes to the application log — the production default today, since no
transactional email vendor is provisioned) and `InMemoryMailProvider`
(test/dev only, with an optional JSON-lines sink file so an
out-of-process test runner — the Playwright E2E, if it ever needs to read
a mailed token — can observe a message without a new HTTP endpoint).
Real delivery (Postmark or similar) is explicitly deferred to a future
infrastructure slice, per requirement 26's own instruction not to
provision production email without separate approval. Nothing in the
identity-token or invitation model needs to change when that happens —
only a third `MailProvider` implementation needs to be written and wired
into `production_startup.py` in place of `LoggingMailProvider`.

## 8. What is deliberately not here

- No MFA is implemented. The session model carries an `assurance_level`
  field (currently always `"password"`) specifically so a future TOTP/
  WebAuthn/recovery-codes slice can add a `"mfa"` level without replacing
  the session model itself — see the security doc §7.
- No account-level "sessions" management UI beyond "sign out everywhere"
  — a per-device session list with individual revocation is a plausible
  future addition (`list_sessions_for_principal` already exists at the
  repository layer) but has no route or UI this slice.
- No SSO/OAuth. Password-only, by design, matching the brief's own scope.
