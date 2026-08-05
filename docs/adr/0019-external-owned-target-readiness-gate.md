# ADR 0019: External Owned-Target Readiness Gate

- Status: Accepted
- Date: 2026-08-05
- Decision owners: OpenHuntX WebGuard engineering

## Context

WebGuard has reached the point where its passive scanner can safely analyse deliberately vulnerable laboratory targets and is preparing for a first controlled assessment of an externally hosted website owned by the operator. Laboratory allowlisting alone is not sufficient for public targets. An external run needs an explicit authorization record, conservative production limits, exact operator acknowledgement, public-scope validation, and durable evidence of the policy approved before traffic begins.

This milestone must not introduce active testing. WebGuard continues to avoid form submission, JavaScript execution, active payload injection, redirect following, brute force, and directory enumeration.

## Decision

### Strict versioned authorization document

External commercial scans require a canonical JSON `owned_target_authorization` document using schema version `1.0`. The document records:

- a canonical UUID;
- the organization and named approver;
- one canonical HTTPS target;
- canonical explicitly owned hostnames;
- an issuance and expiry window no longer than 366 days;
- a bounded passive-only purpose;
- maximum request, response, retry, crawl, delay, and execution settings.

The loader rejects duplicate keys, unknown or missing fields, non-canonical values, malformed timestamps, oversized documents, symbolic links, and non-regular files. Canonical JSON provides a stable SHA-256 authorization fingerprint.

### Exact operator confirmation

Every external scan requires both `--authorization-file` and `--confirm-authorization`. The confirmation value must exactly match the authorization UUID. A valid file without exact confirmation does not permit execution.

### HTTPS and exact target binding

The authorization and validated scan target must be the same canonical HTTPS URL. IP-literal targets, credentials, query strings, fragments, unsupported ports, and non-canonical target forms are rejected by the authorization contract or existing target validator.

The target validator resolves the hostname before the owned-target gate runs. The readiness gate defensively rechecks every resolved address and requires all addresses to be globally routable public IPs. Empty, private, loopback, link-local, reserved, multicast, unspecified, invalid, or mixed public/private results stop execution.

Existing safe HTTP controls continue to pin the connection to an approved resolved address and reject redirects. A redirect response is treated as a stop condition rather than silently expanding scope.

### Conservative external defaults and authorization caps

External crawl defaults are:

- 10 pages;
- depth 1;
- 50 links per page;
- 1 second minimum delay;
- 60 seconds maximum execution time;
- 15 total request attempts;
- 1 attempt per request;
- 10 second request timeout;
- 1 MiB response body limit;
- 64 KiB response header limit;
- 100 response headers.

The authorization may lower those limits. CLI overrides may never exceed the authorization and may never reduce the required delay. Laboratory defaults remain unchanged.

### Readiness-only mode

`--preflight-only` validates the authorization, exact confirmation, canonical target, current validity window, public DNS results, and effective execution policy. It prints the resulting scope, limits, stop conditions, and authorization fingerprint.

Readiness-only mode may perform DNS resolution as part of target validation. It sends no HTTP request and writes no report, authorization audit, or checkpoint file. Output-related options are rejected in this mode.

### Pre-execution audit sidecar

For an actual external run, WebGuard writes a strict versioned `owned_target_preflight_audit` sidecar before the scanner sends HTTP traffic. The audit records:

- the scan ID;
- authorization UUID and SHA-256 fingerprint;
- organization and approver;
- exact canonical target;
- canonical public resolved addresses;
- UTC creation time;
- exact effective fetch, retry, and crawl policy;
- fixed controlled stop conditions.

The audit contains no authorization secrets, response bodies, cookie values, arbitrary response headers, or certificate material. Audit and authorization writers use private `0600` files, same-directory temporary files, filesystem sync, atomic replacement for explicit overwrite, and atomic no-clobber publication for new files. Symbolic-link destinations are rejected.

### Fixed stop conditions

The recorded stop conditions are:

- scope or DNS validation failure;
- redirect response;
- TLS certificate verification failure;
- request-attempt budget;
- execution-time budget;
- root-request failure;
- operator interrupt.

These conditions are implemented through the existing target validator, safe HTTP client, bounded crawler, TLS verification, cancellation token, and termination taxonomy. The audit record documents the controls in force; it does not create a second execution engine.

### Laboratory separation and resume

Owned-target authorization options are invalid with `--lab`. Laboratory scans still require an explicit lab host allowlist.

A resumed external crawl must pass a fresh authorization and preflight. Checkpoint integrity alone never authorizes an external target, and remaining budgets are not reset by resume.

## Consequences

### Positive

- No external HTTP request begins without a validated authorization and exact acknowledgement.
- Scope, approval, effective limits, resolved addresses, and scan ID are preserved in a deterministic audit record.
- Public scans use safer defaults than laboratory scans.
- Readiness can be reviewed before HTTP traffic begins.
- Existing safe HTTP, TLS, retry, crawler, checkpoint, and report controls remain authoritative.

### Trade-offs

- Operators must manage an additional authorization file and audit sidecar.
- Exact URL binding means a canonical-host change or separate `www` hostname requires a separately reviewed authorization target.
- Redirects are not followed, so a redirecting entry URL may produce a controlled failure and require a new canonical target.
- DNS resolution still occurs during readiness-only validation.

## Security boundary and limitations

A locally generated authorization document is an operator-controlled process and audit control. It is not a cryptographic statement from the target owner and does not independently establish legal authority. It must not be presented as proof of ownership.

A production multi-tenant service must add authenticated customer identity, server-side authorization issuance, DNS or HTTP asset ownership verification, role-based approval, tenant isolation, central audit retention, revocation, and policy enforcement outside the customer-controlled CLI environment.

This decision authorizes only passive owned-target scanning within the recorded scope and limits. It does not authorize destructive, exploitative, credential-based, or third-party assessment activity.
