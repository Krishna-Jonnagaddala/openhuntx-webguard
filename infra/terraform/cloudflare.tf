# Public edge (Slice 18 requirements 5-9). Prepares the Cloudflare-side
# half of "Internet -> Cloudflare -> load balancer/ingress -> WebGuard
# API/Web App" (requirement 6) for openhuntx.com's three public
# hostnames. Scope discipline matches every other file in this
# directory (see README.md): reviewed, syntactically-complete IaC that
# has never been applied -- no Cloudflare account has been created, no
# zone has been onboarded, and no DNS name in here has been verified to
# actually exist (requirement 5's own instruction). An operator who has
# actually registered openhuntx.com and created a Cloudflare account
# supplies real values for every variable in the "Public edge
# (Cloudflare)" section of variables.tf before ever running `terraform
# plan` against this file.
#
# This configuration provisions no compute (see README.md) -- the three
# origin_*_hostname variables are deliberately left as required inputs
# rather than resources created here, exactly like
# application_security_group_id in networking.tf already does for the
# AWS side. requirement 15 (callback-service isolation) is reflected
# directly in the DNS layer here: callback.<root_domain> proxies to its
# own, distinct origin (origin_callback_hostname), never to the same
# origin as api.<root_domain> -- so the callback receiver can be
# deployed, scaled, and rate-limited (see callback_server.py's own
# Slice 18 rate-limiting work) entirely independently of the main API.

resource "cloudflare_zone" "openhuntx" {
  account = {
    id = var.cloudflare_account_id
  }
  name = var.root_domain
}

# --- DNS (requirement 5) ---
#
# All three records are proxied (orange-clouded) -- Cloudflare, not the
# origin, is what the public Internet actually connects to. This is
# also the mechanism requirement 6's "backend services must not be
# unnecessarily exposed directly to the public Internet" and
# requirement 9's origin-protection model both depend on: an unproxied
# (grey-clouded) record would hand out the real origin address in plain
# DNS, making every edge control below (WAF, rate limiting, TLS
# enforcement) trivially bypassable by anyone who just connects to the
# origin directly instead.

resource "cloudflare_dns_record" "app" {
  zone_id = cloudflare_zone.openhuntx.id
  name    = "app.${var.root_domain}"
  type    = "CNAME"
  content = var.origin_web_hostname
  ttl     = 1 # automatic -- required alongside proxied = true
  proxied = true
  comment = "WebGuard SPA (WebGuard Web App) -- Slice 18 public edge"
}

resource "cloudflare_dns_record" "api" {
  zone_id = cloudflare_zone.openhuntx.id
  name    = "api.${var.root_domain}"
  type    = "CNAME"
  content = var.origin_api_hostname
  ttl     = 1
  proxied = true
  comment = "WebGuard API -- Slice 18 public edge"
}

resource "cloudflare_dns_record" "callback" {
  zone_id = cloudflare_zone.openhuntx.id
  name    = "callback.${var.root_domain}"
  type    = "CNAME"
  content = var.origin_callback_hostname
  ttl     = 1
  proxied = true
  comment = "TrustScan SSRF callback receiver -- deliberately its own origin (requirement 15); see callback_server.py"
}

# --- TLS (requirement 7) ---
#
# ssl = "strict" requires the origin to present a valid, Cloudflare-
# trusted (or Cloudflare Origin CA) certificate -- Cloudflare refuses to
# connect to an origin over plaintext or with a self-signed/expired
# certificate under this mode, which is what makes it the correct
# choice paired with authenticated_origin_pulls below (both halves of
# "protect origin traffic appropriately"). min_tls_version = "1.2"
# rejects any client (or Cloudflare-to-origin, for the corresponding
# origin-side setting an operator configures on the origin's own TLS
# stack) negotiation below TLS 1.2, directly satisfying "enforce TLS
# 1.2+". always_use_https + automatic_https_rewrites give the
# HTTP->HTTPS redirect requirement 7 asks for without needing a
# redirect rule of its own.

resource "cloudflare_zone_setting" "ssl" {
  zone_id    = cloudflare_zone.openhuntx.id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "min_tls_version" {
  zone_id    = cloudflare_zone.openhuntx.id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "tls_1_3" {
  zone_id    = cloudflare_zone.openhuntx.id
  setting_id = "tls_1_3"
  value      = "on"
}

resource "cloudflare_zone_setting" "always_use_https" {
  zone_id    = cloudflare_zone.openhuntx.id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "automatic_https_rewrites" {
  zone_id    = cloudflare_zone.openhuntx.id
  setting_id = "automatic_https_rewrites"
  value      = "on"
}

# Deliberately NOT setting the "security_header" (HSTS) zone setting
# here. The origin application already sends its own Strict-Transport-
# Security header (see production_security_headers.py / requirement 11)
# -- that is the single source of truth for HSTS policy (max-age,
# includeSubDomains, preload). Having Cloudflare inject a second,
# independently-configured HSTS header risks the exact "do not weaken
# CSP [or other security headers] to make the app work" failure mode
# requirement 11 warns against, just for a different header: two
# HSTS policies from two layers can silently diverge. TLS transport
# enforcement (the settings above) and browser-facing security headers
# (the application) are kept as two clearly separated concerns.

# --- Cloudflare security policy: WAF (requirement 8) ---
#
# Executes Cloudflare's own managed rulesets rather than hand-writing
# WAF signatures -- both IDs are Cloudflare's stable, publicly
# documented managed-ruleset identifiers (the same for every Cloudflare
# account), not account-specific secrets. `expression = "true"` means
# "evaluate against every request on this zone"; the managed rulesets
# make their own request-by-request decisions (Cloudflare tunes their
# false-positive rate directly), so this deliberately does not add a
# second, hand-rolled block condition on top that could reject
# legitimate WebGuard API traffic (requirement 8's "do not enable
# aggressive rules that break WebGuard workflows").

resource "cloudflare_ruleset" "firewall_managed" {
  zone_id     = cloudflare_zone.openhuntx.id
  name        = "WebGuard managed WAF rules"
  description = "Executes Cloudflare's managed WAF rulesets in front of the WebGuard API and Web App."
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules = [
    {
      ref         = "execute_cloudflare_managed"
      description = "Execute Cloudflare Managed Ruleset"
      expression  = "true"
      action      = "execute"
      enabled     = true

      action_parameters = {
        id = var.cloudflare_managed_ruleset_id
      }
    },
    {
      ref         = "execute_owasp_core"
      description = "Execute Cloudflare OWASP Core Ruleset"
      expression  = "true"
      action      = "execute"
      enabled     = true

      action_parameters = {
        id = var.cloudflare_owasp_ruleset_id
      }
    },
  ]
}

# --- Cloudflare security policy: request-size bound (requirement 10) ---
#
# The application itself already hard-caps every request body at
# MAXIMUM_API_REQUEST_BYTES (128 KiB -- see config.py) regardless of
# what any edge control does; this rule is a complementary, not a
# competing, outer bound: it rejects an oversized request at the edge,
# before it ever consumes a connection against the origin, using the
# *exact same* 128 KiB figure so the edge can never reject something
# the application would have accepted, or vice versa. Kept as a
# byte-precise custom rule rather than the coarser, megabyte-granularity
# `max_upload` zone setting (whose minimum on most plans is far larger
# than this API's entire request-size ceiling and would not meaningfully
# bound anything here) -- WebGuard's public API is JSON-only with no
# browser-facing large-file upload endpoint (reports are written
# directly to object storage by the worker, never uploaded through this
# API -- see docs/production/ARTIFACT_STORAGE.md).

resource "cloudflare_ruleset" "firewall_custom" {
  zone_id     = cloudflare_zone.openhuntx.id
  name        = "WebGuard request-size bound"
  description = "Blocks any request body larger than the API's own hard cap, before it reaches the origin."
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "block_oversized_request_body"
      description = "Reject request bodies over 128 KiB -- matches webguard_api.config.MAXIMUM_API_REQUEST_BYTES exactly"
      expression  = "http.request.body.size gt 131072"
      action      = "block"
      enabled     = true
    },
  ]
}

# --- Cloudflare security policy: rate limiting (requirement 10) ---
#
# Every rule below is a coarse, IP-keyed *edge* bound in front of an
# endpoint that already has its own, more precise application-level
# limiter (auth_rate_limit.py's InMemoryAuthRateLimiter for login;
# FixedWindowRateLimiter-backed checks for the others) -- deliberately
# set looser than the corresponding application limit everywhere, so
# the application (which has real per-account/per-token state, not just
# a per-IP counter) always remains the actual authority on whether a
# given request is abusive. The edge rule's only job is blunting a
# volumetric flood before it ever reaches the origin, never replacing
# the application's own decision (requirement 10: "edge and application
# limits should complement, not contradict").

resource "cloudflare_ruleset" "rate_limiting" {
  zone_id     = cloudflare_zone.openhuntx.id
  name        = "WebGuard edge rate limits"
  description = "Coarse per-IP outer bounds for the login, asset-verification, and report endpoints."
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "login_rate_limit"
      description = "Outer bound for POST /v1/auth/login, in front of the application's own auth rate limiter"
      expression  = "(http.request.uri.path eq \"/v1/auth/login\")"
      action      = "block"
      enabled     = true

      ratelimit = {
        characteristics     = ["ip.src"]
        period              = 60
        requests_per_period = var.cloudflare_edge_rate_limit_login_requests_per_minute
        mitigation_timeout  = 60
      }
    },
    {
      ref         = "asset_verification_rate_limit"
      description = "Outer bound for the asset-ownership verification endpoints"
      expression  = "(starts_with(http.request.uri.path, \"/v1/assets/\") and ends_with(http.request.uri.path, \"/verification\")) or (starts_with(http.request.uri.path, \"/v1/assets/\") and ends_with(http.request.uri.path, \"/verification/check\"))"
      action      = "block"
      enabled     = true

      ratelimit = {
        characteristics     = ["ip.src"]
        period              = 60
        requests_per_period = var.cloudflare_edge_rate_limit_asset_verification_requests_per_minute
        mitigation_timeout  = 60
      }
    },
    {
      ref         = "report_request_rate_limit"
      description = "Outer bound for report listing/detail/download requests"
      expression  = "starts_with(http.request.uri.path, \"/v1/reports\")"
      action      = "block"
      enabled     = true

      ratelimit = {
        characteristics     = ["ip.src"]
        period              = 60
        requests_per_period = var.cloudflare_edge_rate_limit_report_requests_per_minute
        mitigation_timeout  = 60
      }
    },
  ]
}

# --- Origin protection (requirement 9) ---
#
# Authenticated Origin Pulls: once enabled, Cloudflare presents a
# Cloudflare-signed client certificate on every connection it makes to
# the origin, and the origin is expected to require and verify it
# (out-of-band origin-side TLS configuration -- see
# docs/production/PUBLIC_EDGE_SECURITY.md for the chosen model and the
# origin-side half of this that Terraform cannot express). This is the
# concrete mechanism behind "prevent bypassing Cloudflare to hit origin
# directly where practical": even if the real origin hostname/IP leaks,
# a direct connection cannot present Cloudflare's client certificate and
# the origin rejects it. Chosen over Cloudflare-IP-range allow-listing
# alone (allow-listing is documented as a *complementary* second layer
# in PUBLIC_EDGE_SECURITY.md, not a replacement) because an IP allow-
# list must be kept in sync with Cloudflare's published IP ranges
# indefinitely, while a certificate check does not depend on the
# requester's network origin at all.

resource "cloudflare_authenticated_origin_pulls_settings" "openhuntx" {
  zone_id = cloudflare_zone.openhuntx.id
  enabled = true
}
