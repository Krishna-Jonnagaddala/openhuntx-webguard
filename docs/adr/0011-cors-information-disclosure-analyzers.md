# ADR 0011: Passive CORS and Information-Disclosure Analysers

- Status: Accepted
- Date: 2026-08-03

## Context

OpenHuntX WebGuard already performs one bounded, scope-approved GET request
and analyses security headers and `Set-Cookie` metadata. The same response can
support additional passive checks without increasing request volume or adding
active payloads.

Two useful groups are:

1. CORS response configuration;
2. response headers that reveal server, framework, generator, proxy, or
   deployment information.

CORS analysis requires careful wording. A single ordinary request does not
contain an attacker-controlled `Origin` header and therefore cannot prove that
a server reflects arbitrary origins. A passive scanner must not label a
specific allowed origin as vulnerable merely because credentials are enabled.

Disclosure headers can contain internal hostnames, deployment identifiers, or
other environment-specific values. Findings should identify the header and
risk without copying raw values into reports.

## Decision

### CORS analyser

Add `cors_analyzer.py` with five check families:

- origin syntax;
- wildcard origin;
- null origin;
- credentialed-CORS consistency;
- dynamic-origin indication.

The analyser reports:

- multiple `Access-Control-Allow-Origin` fields;
- comma-separated or malformed allowed-origin values;
- wildcard origin exposure;
- wildcard origin combined with credentials;
- literal `null` origin;
- literal `null` origin combined with credentials;
- invalid `Access-Control-Allow-Credentials` values;
- credentials configuration without an allowed origin;
- a medium-confidence dynamic-origin signal when a specific non-target origin
  appears with `Vary: Origin`.

The dynamic-origin signal is informational. It explicitly states that passive
inspection cannot prove arbitrary origin reflection. No active Origin probes
are sent in this milestone.

Specific external origin values are not retained in finding evidence.

### Information-disclosure analyser

Add `disclosure_analyzer.py` with six check families:

- `Server`;
- `X-Powered-By`;
- ASP.NET version headers;
- generator headers;
- `Via`;
- curated framework and deployment headers.

A generic `Server: webserver` or equivalent non-informative value does not
produce a finding. Product-identifying values produce informational findings,
while version-like server values produce low-severity findings.

All raw disclosure-header values are discarded. Evidence records only:

- the header name;
- whether a version-like token was observed;
- that the raw value was intentionally not retained.

### Orchestration

The existing passive scan executes both analysers after the safe request,
security-header analyser, and cookie analyser. Controlled analyser failures:

- produce a validated failed `ScanResult`;
- are recorded at the `analysis` stage;
- are never retried;
- preserve the successful request-attempt audit trail.

The scan continues to use one GET request and does not follow redirects.

### Coverage

The passive check catalogue grows from 13 to 24 check families:

- 5 security-header checks;
- 8 cookie checks;
- 5 CORS checks;
- 6 information-disclosure checks.

For the HTTP Juice Shop laboratory target, HSTS remains the only skipped
check, producing 23 executed checks out of 24 and 95.83 percent coverage.

## Consequences

### Positive

- More findings are produced from the existing bounded response.
- No additional network traffic is introduced.
- Wildcard, null-origin, and malformed CORS policies are identified.
- Dynamic CORS handling is surfaced without falsely claiming confirmed origin
  reflection.
- Common technology and framework disclosure headers are normalized.
- Raw origin, framework, proxy, and internal-routing values are excluded from
  reports.
- Analysis failures remain deterministic and non-retryable.

### Negative

- Arbitrary Origin reflection cannot be confirmed passively.
- A wildcard CORS policy may be intentional for public non-sensitive content.
- Header-based technology identification may be inaccurate or intentionally
  deceptive.
- The curated framework-header list will require maintenance.
- Removing all disclosure headers is not always possible when standards or
  intermediary requirements apply.

## Future work

A later authorised active-CORS milestone may send bounded, non-credentialed
Origin variants to confirm reflection and allowlist bypasses. That work must
have explicit scope controls, request budgets, audit records, and separate
finding confidence from this passive signal.
