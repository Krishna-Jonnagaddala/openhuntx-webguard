# Browser Session Security (Slice 16)

This document is the threat model and design rationale for the browser
session/CSRF/cookie layer added this slice. For the product-level account
model, see `docs/product/CUSTOMER_AUTH_ARCHITECTURE.md`. For the
implementation record and test counts, see
`docs/audit/customer-platform-phase2-identity-sessions.md`.

## 1. Design goal: one authorization model, two authenticators

The single most important security property of this design is that a
browser session and an API bearer token produce an **identical**
`AuthContext`, so RBAC (`ApiPermission`/`_ROLE_PERMISSIONS`) is checked
exactly once, in exactly one place, regardless of how the caller
authenticated. The alternative, a parallel "web session permission
model", is a well-known source of privilege-escalation bugs (the two
models drift apart over time, and an attacker finds the gap). This
codebase structurally cannot have that class of bug, because there is
only one `AuthContext` and only one place that reads it for authorization
decisions. `AuthContext.auth_method` exists only for CSRF gating and
audit differentiation; RBAC never inspects it.

## 2. Passwords: Argon2id, not a custom scheme

`apps/api/src/webguard_api/passwords.py` uses `argon2-cffi`
(`argon2.PasswordHasher`) with explicit parameters pinned in code rather
than left at library defaults: `time_cost=3, memory_cost=65536` (64 MiB),
`parallelism=4, hash_len=32, salt_len=16`, RFC 9106 §4's "second
recommended option," chosen so a future upstream default change cannot
silently weaken (or strengthen, breaking capacity planning) this system's
actual parameters without a deliberate code change. `needs_rehash()`
supports incrementally upgrading a principal's stored hash the next time
they successfully authenticate, without a bulk migration.

Password policy is **length-only** (minimum 12 characters, maximum 256;
the upper bound exists only to bound Argon2's own input-processing cost,
not as a security control). No composition rules (uppercase/digit/symbol
requirements), per NIST SP 800-63B's own current guidance that
composition rules push users toward predictable patterns and provide
little real defense against a modern password-cracking attacker; length
and a real KDF are what actually matter.

Passwords, and the current or new value on a change/reset, are never
logged, never included in an audit-event payload, and never returned in
any response. This is verified explicitly by
`test_no_json_response_ever_contains_the_raw_session_or_csrf_secret` and
the audit-event schema itself (`SecurityAuditEvent` has no
password-shaped field to accidentally populate).

## 3. Sessions: bearer secret + separate CSRF token, both hashed at rest

A browser session is issued as `wgs_{session_id}_{secret}` (mirroring the
existing `wgt_{token_id}_{secret}` API-token format, reusing the same
scrypt-based `_hash_secret`/`_verify_secret` implementation: there is
exactly one reviewed secret-hashing implementation in this codebase, used
for both). Only `secret_hash` is persisted; the raw secret exists only in
the `Set-Cookie` response and the browser's own cookie store afterward. A
separate CSRF token is generated alongside the session, likewise stored
only as a hash (`csrf_hash`), and is delivered via a **second**, non-
`HttpOnly` cookie: the browser can read it (so JavaScript can copy it
into a header), but it authenticates nothing by itself; it only ever
matters paired with the `HttpOnly` session cookie a real cross-origin
attacker cannot read or forge.

Neither hash is ever exposed on `BrowserSessionRecord`, the same
pattern `ApiTokenMetadata` already used for API tokens (it never carries
its own `secret_hash` either). CSRF verification happens *inside*
`authenticate_session()` itself (both the in-memory and PostgreSQL
implementations), because that is the one place the caller-supplied
header and the stored hash are naturally both in scope already. The
alternative (exposing the hash to a separate comparison step) would leak
a sensitive value out of the repository for no benefit.

### Session record fields

`session_id`, `principal_id`, `organization_id`, `assurance_level`,
`issued_at`, `idle_expires_at`, `absolute_expires_at`, `last_used_at`,
`revoked_at`, plus `user_agent`/`ip_address` as security metadata. Idle
timeout defaults to 30 minutes and is extended ("touched") on every
authenticated use, but capped by the 12-hour absolute timeout
(`min(now + idle_ttl, absolute_expires_at)`): a session can never outlive
its absolute expiry no matter how continuously it is used.
`is_usable(now)` fails closed on either expiry or a non-null `revoked_at`;
there is no other path to "this session still works."

## 4. CSRF: an explicit double-submit-cookie pattern, verified server-side

`SameSite=Lax` is applied to the session cookie as defense-in-depth, but
is **not** the sole CSRF defense (requirement 7 explicitly calls this
out, and `SameSite` support/enforcement has historically varied enough
across browsers and request types (e.g. top-level navigations, some
non-GET simple requests in older or misconfigured clients) that relying
on it alone is not a defensible position for a security-sensitive API).

The actual mechanism: two cookies are set on session creation,
`wg_session` (`HttpOnly`, the bearer secret) and `wg_csrf` (readable, an
independent random token). Every state-changing request
(`POST`/`PATCH`/`DELETE`) authenticated via the session cookie must also
carry `X-CSRF-Token` matching the stored `csrf_hash`, or the request is
rejected with **403** `csrf_token_invalid`, deliberately distinct from
**401** (not authenticated at all), since a request with a valid session
but a missing/wrong CSRF token *is* authenticated, just forbidden from
this specific mutation. `GET` requests never require it (mutation-free
requests are not a CSRF target by definition).

An API-token client (`Authorization: Bearer ...`) is exempt from this
check entirely, by construction: `_authenticate(require_csrf=True)` in
`http_api.py` only routes into the session-cookie branch when a session
cookie is actually present on the request. A CLI/automation client that
happens to also carry a stray cookie is unaffected: the Bearer branch
never inspects `require_csrf` at all.

**Why this defeats a cross-origin attacker concretely**: a malicious page
cannot read `wg_csrf`'s value across origins (the Same-Origin Policy
blocks that), so it cannot construct a correct `X-CSRF-Token` header. A
plain cross-origin `<form>` POST (no JavaScript, no custom headers
possible at all) can never attach `X-CSRF-Token` in the first place and
is rejected with 403. A cross-origin `fetch`/`XHR` attempt that tries to
attach a *guessed* header value triggers a CORS preflight (a custom
header makes the request "non-simple"), which fails for any origin not
in the explicit `allowed_origins` list (§5), so the browser never even
dispatches the real request. Both paths are covered by dedicated tests
(`test_customer_auth.py`'s CSRF section, plus `CorsCrossOriginPolicyTests`
for the preflight path).

## 5. CORS: explicit allowlist, credentials only ever paired with a real origin

`allowed_origins` (`http_api.py`'s `build_handler`/`create_server`) is an
explicit, operator-configured set, never a wildcard. `Access-Control-
Allow-Credentials: true` (added this slice, required for
`fetch(..., {credentials: "include"})` to work at all) is only ever sent
alongside a *reflected, allowlisted* `Access-Control-Allow-Origin` value,
never `*`: pairing a credentialed CORS response with a wildcard origin
would let any origin on the internet read authenticated responses, which
is exactly the vulnerability class this design avoids by construction (a
non-allowlisted origin's preflight and actual-request responses both omit
the CORS headers entirely, see `CorsCrossOriginPolicyTests` in
`test_customer_auth.py`, which asserts both the positive case, a listed
origin getting `Access-Control-Allow-Origin` + `Access-Control-Allow-
Credentials: true`, and the negative case, an unlisted origin getting
neither header at all, so the policy is proven to discriminate rather
than merely deny or merely allow everything).

## 6. Session fixation

An attacker who can get a victim's browser to carry an attacker-chosen
`wg_session` cookie value into the login page cannot make that value
become the victim's real, authenticated session: `login()`,
`register()`, and `accept_invitation()` always call
`sessions.create_session(...)`, which mints a brand-new
`session_id`/secret pair unconditionally. Nothing in the login code path
reads any pre-existing cookie the client presented. Verified by
`test_login_never_honours_a_client_supplied_session_cookie`, which sends a
login request carrying an attacker-chosen `wg_session` value and asserts
the resulting session cookie is neither that value nor derived from it.

## 7. What this design defers

- **MFA is not implemented**, but the session model does not need to
  change to add it: `BrowserSessionRecord.assurance_level` (currently
  always `"password"`) is the seam a future TOTP/WebAuthn/recovery-code
  slice would raise to `"mfa"` after a successful second factor, without
  touching the session-lifecycle mechanics (issuance, rotation, expiry,
  revocation) described above at all.
- **Rate limiting is PostgreSQL-backed, not Redis**, and is documented as
  a deliberate choice, not an oversight: `PostgresAuthRateLimiter` counts
  attempts in a trailing window via delete-old-rows + count + insert
  against a dedicated `auth_rate_limit_events` table. This is an accepted
  best-effort race under concurrent bursts from the same bucket key
  (two simultaneous requests can both observe a count just under the
  threshold and both proceed) rather than serializing every attempt via a
  Postgres advisory lock, which would itself become a denial-of-service
  vector on this exact endpoint (an attacker deliberately holding many
  concurrent login attempts open would serialize *every* login attempt
  system-wide, not just their own). If a future slice needs
  Redis-precision (single-digit-attempt) rate limiting under real
  concurrent load, that is the point to introduce it as a new,
  purpose-built consumer, not to retrofit it into this table.
- **No per-device session management UI**: `list_sessions_for_principal`
  exists at the repository layer; only "sign out everywhere" is exposed
  as an endpoint/UI action this slice.
