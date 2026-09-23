# Public Edge Security (Slice 18)

## Status

**Reviewed, unapplied IaC plus real, tested application-layer controls. Not deployed.** No Cloudflare account exists, no zone has been created, no DNS name below has been verified to resolve, and no load balancer or reverse-proxy sidecar has been provisioned (requirement 24). Everything in this document is either (a) `infra/terraform/cloudflare.tf`, validated (`terraform fmt -check` / `init -backend=false` / `validate`, all clean) but never applied, or (b) real application code in `apps/api/src/webguard_api/http_api.py` and `apps/web/`, exercised by real tests against a real running server: each claim below says which.

## 1. Public domain model (requirement 5)

Three hostnames, one root domain (`infra/terraform/variables.tf`'s `root_domain`, default `openhuntx.com`, operator-overridable): `app.` (WebGuard SPA), `api.` (WebGuard API), `callback.` (SSRF callback receiver, see `docs/production/CALLBACK_SERVICE_DEPLOYMENT.md` for why it is a distinct origin, not a path). Every hostname, origin, and credential is environment-driven (`variables.tf`'s `origin_web_hostname`/`origin_api_hostname`/`origin_callback_hostname`, all required with no default): nothing assumes these names actually exist in DNS today, per requirement 5's own instruction.

## 2. Reverse proxy / ingress path (requirement 6)

```
Internet -> Cloudflare (TLS, WAF, rate limiting) -> Load balancer -> [host-local TLS-terminating reverse-proxy sidecar] -> WebGuard API process (127.0.0.1:8765)
```

The bracketed hop is not optional, and is not new to this slice: `ProductionServiceConfig.__post_init__` (`production_config.py`, pre-dating Slice 12) hard-rejects any non-loopback `host`/`port` combination with `production_config_non_loopback_binding_rejected`. The API process itself will never bind to a public interface, in this slice or any prior one. A load balancer therefore cannot forward directly to the API process; each host running the API needs its own local reverse proxy (nginx/Caddy/Envoy or equivalent) terminating the LB's connection and forwarding to `127.0.0.1:8765`. This is stated explicitly here because it is a real constraint on how requirement 6's path must be implemented, not a detail this slice introduces: no origin compute is provisioned by this repository's Terraform (consistent with every prior slice's "no compute" scope), so the sidecar's actual configuration is deployment-specific and out of this document's scope; what this document fixes is that Cloudflare and the load balancer are the only public-facing hops, and the origin is never directly reachable (§4).

The callback receiver (`callback.openhuntx.com`) and the API (`api.openhuntx.com`) are deliberately separate origins in the DNS layer (`cloudflare.tf`), not a shared one, see `docs/production/CALLBACK_SERVICE_DEPLOYMENT.md` §3-4.

## 3. TLS (requirement 7)

`infra/terraform/cloudflare.tf`'s zone settings: `ssl = "strict"` (Cloudflare refuses to connect to the origin over plaintext or with an invalid/self-signed certificate: origin must present a valid or Cloudflare Origin CA certificate), `min_tls_version = "1.2"`, `tls_1_3 = "on"`, `always_use_https = "on"` and `automatic_https_rewrites = "on"` (HTTP→HTTPS redirect, satisfying requirement 7 without a hand-written redirect rule). Certificate automation/rotation for the edge half is Cloudflare's own universal-SSL/Cloudflare-managed-certificate feature, requiring no Terraform resource; the origin-side certificate (required by `ssl = "strict"`) is provisioned separately from whatever compute eventually exists, not built here, matching this repository's "no compute" scope.

**Origin traffic protection** is `ssl = "strict"` (above) combined with authenticated origin pulls (§4): Cloudflare both requires a valid origin certificate and presents its own client certificate, so a plaintext or unauthenticated connection to the origin is rejected from either direction.

## 4. Cloudflare security policy and origin protection (requirements 8-9)

All in `cloudflare.tf`, reviewed against the *current* (v5.24.0) Cloudflare Terraform provider schema: verified via the provider's own published documentation and cross-checked against a real-world, actively-maintained configuration using the identical managed-ruleset IDs, not guessed:

- **WAF**: `cloudflare_ruleset` (`phase = "http_request_firewall_managed"`) executes Cloudflare's own Managed Ruleset and OWASP Core Ruleset: chosen over hand-written signatures specifically so this slice does not risk writing a rule that blocks legitimate WebGuard traffic (requirement 8's own warning); Cloudflare tunes these rulesets' false-positive rate directly.
- **Request-size bound**: a custom `cloudflare_ruleset` (`phase = "http_request_firewall_custom"`) blocks any request body over 131072 bytes (128 KiB): the *exact* figure `webguard_api.config.MAXIMUM_API_REQUEST_BYTES` already hard-caps at the application layer (§5), so the edge can never reject something the application would accept, or vice versa.
- **Rate limiting**: a `cloudflare_ruleset` (`phase = "http_ratelimit"`) with three per-IP rules (login, asset-verification, report requests): each deliberately looser than the corresponding application-level limiter (`InMemoryAuthRateLimiter`/`FixedWindowRateLimiter`), so the application, which has real per-account state, remains the actual authority on abuse; the edge rule's job is blunting a volumetric flood before it reaches the origin at all (§5 elaborates the complementary-not-contradictory relationship).
- **Origin protection**: `cloudflare_authenticated_origin_pulls_settings` (`enabled = true`). Cloudflare presents a Cloudflare-signed client certificate on every connection to the origin; the origin is expected to require and verify it. Chosen over relying on Cloudflare's published IP ranges alone, which `PUBLIC_EDGE_SECURITY.md` (this document) still recommends as a *complementary* second layer at the load-balancer/security-group level (an IP allow-list needs no origin-side TLS reconfiguration and fails safe even before authenticated-pulls is correctly wired), but a certificate check does not depend on the requester's network origin at all, which is why it is the primary control here, not the only one.

No aggressive Cloudflare feature (e.g., Bot Fight Mode, `security_level = "high"`/`"under_attack"`, JS challenges) is enabled by default: `cloudflare_security_level` defaults to Cloudflare's own recommended `"medium"`, operator-overridable, specifically to avoid requirement 8's named failure mode of breaking real WebGuard API/browser workflows (a JSON API and a bearer-token CLI are exactly the kind of traffic an aggressive bot-challenge would incorrectly block).

## 5. API request limits (requirement 10)

Reviewed for contradiction between edge and application, not just existence at each layer:

| Bound | Application | Edge (Cloudflare) |
|---|---|---|
| Request body/headers | `MAXIMUM_API_REQUEST_BYTES` = 128 KiB, enforced in `http_api.py` (`maximum_request_bytes`, validated 1024–131072 in `config.py`) | Custom ruleset blocking `http.request.body.size gt 131072`, the identical figure (§4) |
| Login rate | `InMemoryAuthRateLimiter` (per-account, real lockout semantics) | `cloudflare_edge_rate_limit_login_requests_per_minute` (default 60/min per IP), coarser, complementary outer bound |
| Asset-verification rate | Application-level `FixedWindowRateLimiter` on the relevant routes | `cloudflare_edge_rate_limit_asset_verification_requests_per_minute` (default 30/min per IP) |
| Report-request rate | Application-level `FixedWindowRateLimiter` | `cloudflare_edge_rate_limit_report_requests_per_minute` (default 60/min per IP) |

Every edge limit is a *looser* outer bound than its application counterpart by design: the edge exists to blunt a volumetric flood cheaply before it reaches the origin, never to be the actual decision-maker on a specific account's abuse, which requires state the edge does not have. This also closes a real, previously-named gap: `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`'s "Web/API (public-facing)" section named `FixedWindowRateLimiter`'s in-process, per-instance nature as a limitation once horizontally scaled: Cloudflare's edge rules are evaluated centrally, across every origin instance, giving a real cross-instance-shared bound the application layer alone cannot provide (the application layer's per-instance limit remains unchanged and still matters for the finer-grained, per-account decision).

## 6. Trusted-proxy handling (requirement 13)

`http_api.py`'s `_resolve_client_ip()` (used for every rate-limit bucket key and every audit `ip_address` field, not just some call sites): `CF-Connecting-IP`/`X-Forwarded-For` are honored **only** when the direct TCP peer is itself inside a configured `trusted_proxy_networks` CIDR set (`create_server`'s new parameter, wired from `WEBGUARD_TRUSTED_PROXY_CIDRS` in `cli.py`'s `_serve_command`). Empty by default: every pre-Slice-18 deployment's behavior is byte-for-byte unchanged. `CF-Connecting-IP` takes priority over `X-Forwarded-For` (no comma-chain ambiguity); the `X-Forwarded-For` fallback uses only the leftmost entry, and only after the immediate peer is already confirmed trusted (a single-trusted-edge model, not recursive multi-hop validation). A request from any untrusted peer has both headers ignored entirely and falls back to the real peer address. This is what makes it safe: an attacker connecting directly cannot claim to be a different IP merely by setting a header, since their own connection's peer address is never inside the trusted set.

**Proven by `tests/unit/test_trusted_proxy.py` (5 tests, real HTTP against a real running server)**: headers are ignored and share one rate-limit bucket when no trust is configured; `CF-Connecting-IP` is honored and gives each claimed IP its own bucket once the peer is trusted; the `X-Forwarded-For` leftmost-entry fallback works; `CF-Connecting-IP` takes priority over `X-Forwarded-For` when both are present; a malformed header falls back to the real (rate-limited) peer rather than crashing or being silently accepted.

## 7. Browser security headers, validated against the real built frontend (requirement 11)

`apps/web` was built for real this slice (`npm run build`, Vite 8/rolldown) and its output inspected directly: `dist/index.html` has **no inline script or style**, every asset is external and same-origin (`/assets/index-*.js`, `/assets/index-*.css`), and the only external network dependency the bundle makes at runtime is to `VITE_API_BASE_URL` (a build-time-inlined constant, `src/lib/api.ts`): no CDN, no font host, no analytics. This means the SPA's own CSP can be genuinely strict:

```
default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' https://api.openhuntx.com;
img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

No hosting/reverse-proxy config for the built SPA exists in this repository (no `_headers` file, no nginx config, no CSP `<meta>` tag), stated as a real, named gap rather than assumed away: requirement 6's own "Internet → Cloudflare → load balancer/ingress → Web App" model means whatever serves these static files (the load balancer/ingress in front of `app.openhuntx.com`, per §2) is what must actually emit the header above; this document specifies what that header must be, evidenced against the real build, but does not implement the serving layer itself, matching this repository's consistent "no compute provisioned" scope.

The **API's own** security headers were verified against a real running server (not code review alone), configured exactly as production would be (`secure_cookies=True`, `hsts_enabled=True`, a real `allowed_origins` set, a real trusted-proxy CIDR):

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()
Strict-Transport-Security: max-age=63072000; includeSubDomains
```

`default-src 'none'` is correct, not weakened, for a JSON/bytes-only API that never serves HTML, a script, or a style from any origin including itself: CSP was not loosened to make anything work, satisfying requirement 11's explicit warning. CORS was verified the same way: a request from the configured `https://app.openhuntx.com` origin receives `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials: true`/`Vary: Origin` and a correct preflight response (`Access-Control-Allow-Methods`/`-Headers`/`Max-Age`); a request from an untrusted origin (`https://evil.example`) receives **no** `Access-Control-Allow-*` header at all: never an echoed wildcard, never a silent grant.

## 8. Cookie security behind a proxy (requirement 12)

Verified by three new tests (`tests/unit/test_customer_auth.py::SecureCookieAttributesTests`): the first tests in this codebase to exercise `secure_cookies=True` at all; every pre-existing cookie test uses the dev-mode `secure_cookies=False` default. Against a real running server:

- `wg_session` (the session cookie): `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`: all four present.
- `wg_csrf` (the double-submit CSRF cookie): `Secure`, `SameSite=Lax`, `Path=/`, and **not** `HttpOnly`: deliberately, since the double-submit pattern requires the page's own script to read it; this asymmetry is what the test explicitly checks, not merely the presence of `Secure` everywhere.
- Logout clears both cookies (`Max-Age=0`) while still marking them `Secure`.

No `Domain` attribute is ever set (host-only cookies), a deliberate, reviewed choice, not an oversight: `app.openhuntx.com` and `api.openhuntx.com` are different origins, and the session cookie is only ever sent to the origin that set it (`api.openhuntx.com`), so there is no legitimate reason to broaden it to `.openhuntx.com` and every other subdomain.

**Proxy-HTTPS-awareness**: `secure_cookies` is a static, operator-set deployment flag (`WEBGUARD_SECURE_COOKIES`), **never** derived from a per-request header like `X-Forwarded-Proto`. This is a deliberate, reviewed design, not a gap: `X-Forwarded-Proto` is exactly the kind of forwarding header requirement 12 warns against "blindly trusting"; deriving cookie security from it would let an attacker who can reach the origin bypass the trusted-proxy check entirely by simply omitting or forging that header on a request the API cannot distinguish from a legitimate proxied one. An operator explicitly declaring "my public entry point is always HTTPS" is the correct trust model here, and it was already how this code worked before Slice 18: this slice's contribution is proving it holds under `secure_cookies=True` for the first time (above), not changing the mechanism.

## 9. Secrets (requirement 19)

Every credential introduced or touched by this slice's public-edge/signing work flows through the same channels already established:

| Secret | Channel |
|---|---|
| `WEBGUARD_SIGNING_SERVICE_BEARER_TOKEN` | Environment variable, sourced from the existing `SecretProvider`/Secrets Manager path in a real deployment (`docs/production/TRUSTSCAN_SIGNING_SERVICE.md` §6) |
| CloudHSM PKCS#11 PIN | Same, never a Terraform variable, never in `infra/terraform/` source |
| Cloudflare API token (for `terraform apply`, never performed this slice) | `CLOUDFLARE_API_TOKEN` environment variable read by the Terraform provider itself (`versions.tf`), no `api_token` attribute is ever set in Terraform source |
| Postmark server token, DB credentials | Unchanged from Slice 17/12: already through `SecretProvider`/RDS-managed-password respectively |

No secret of any kind appears in `infra/terraform/` source or this repository's Git history (verified: `python scripts/scan-secrets.py`, part of the standard security gates, passed with these files included).

## 2026-09-23 addendum: the host-local sidecar, named but left unconfigured above, now has a real config

Section 2 above names the gap directly: "the sidecar's actual configuration is deployment-specific and out of this document's scope." `infra/nginx/api-sidecar.conf` fills it in for the WebGuard API's own origin (`api.openhuntx.com`): TLS termination on 443, an HTTP-to-HTTPS redirect on 80, a `proxy_pass` to `127.0.0.1:8765` forwarding `CF-Connecting-IP`/`X-Forwarded-For`/`X-Forwarded-Proto`, a `client_max_body_size` of 128k matching both `DEFAULT_API_MAXIMUM_REQUEST_BYTES` and the edge's own request-size rule, and dedicated `/healthz`/`/ready` locations with `access_log off`. It is not syntax-validated against a real nginx binary (none was available while writing it); review with `nginx -t` before use, and treat it as a reviewed starting point, not a drop-in-and-forget file.

The API process itself must be started with these values once this sidecar is in front of it, so the trust model in sections 6-8 above actually holds rather than merely being documented:

- `WEBGUARD_TRUSTED_PROXY_CIDRS=127.0.0.1/32` (plus `::1/128` if the sidecar and API both bind dual-stack loopback): this is always `127.0.0.1/32`, regardless of how many hops (Cloudflare, load balancer) precede this sidecar, since `create_server` rejects any non-loopback bind, so the API's only possible direct TCP peer is this same-host nginx process. Cloudflare's own edge IP ranges never belong in this variable; they are a load-balancer/security-group concern, a layer this sidecar sits behind, not in front of.
- `WEBGUARD_SECURE_COOKIES=true` and `WEBGUARD_HSTS_ENABLED=true`: both assume every request reaching the API already arrived over HTTPS, which this sidecar's own port-80-redirect now actually guarantees rather than merely assuming.
- `WEBGUARD_WEB_ALLOWED_ORIGINS=https://app.openhuntx.com`: unchanged from section 1's domain model, restated here since leaving it unset silently breaks every credentialed cross-origin request from the SPA with no server-side error to point at.

Left out of this addendum's scope, stated plainly rather than silently assumed solved: the identical sidecar pattern is needed a second time for `callback.openhuntx.com` (`docs/production/CALLBACK_SERVICE_DEPLOYMENT.md`'s own standalone process, its own host/port environment variables, not the combined `serve` process this config fronts). Building that second config file was not done here; the pattern in `api-sidecar.conf` transfers directly (same TLS/redirect/proxy_pass shape, a different upstream port), but the callback receiver's own port is environment-configured, not fixed, so a generic template would need that operator input to be more than a copy with the port number changed.
