# ADR 0001: Target Scope and Network Validation

## Status

Accepted

## Context

OpenHuntX WebGuard sends automated requests to customer-supplied targets.

Without strict validation, the platform could be abused to:

- Access localhost or internal services;
- Reach cloud metadata endpoints;
- Scan private networks;
- Follow redirects into prohibited networks;
- Exploit DNS rebinding;
- Test systems outside the authorised scope.

## Decision

WebGuard will maintain two separate validation modes.

### Commercial mode

Commercial targets must:

- Use HTTP or HTTPS;
- Contain no embedded username or password;
- Resolve exclusively to globally routable public IP addresses;
- Contain no query string or fragment during asset registration;
- Pass domain ownership verification before scanning;
- Be revalidated immediately before connection; and
- Have every redirect destination independently validated.

If DNS returns both public and prohibited addresses, the entire target is rejected.

### Laboratory mode

Laboratory mode may access private or loopback addresses only when:

- Laboratory mode is enabled internally;
- The hostname is explicitly allowlisted;
- The destination is part of an approved test environment; and
- The mode cannot be enabled through an ordinary customer request.

### Connection-time enforcement

Initial URL validation is not sufficient.

Future scanner network clients must:

- Connect only to the validated IP address;
- Preserve the approved HTTP Host header and TLS server name;
- Re-resolve and compare DNS where appropriate;
- Reject unapproved DNS changes;
- Disable automatic redirect following;
- Validate each redirect before following it;
- Apply request, response-size and timeout limits; and
- Record the final connected address in the audit trail.

## Consequences

This policy intentionally prevents the public SaaS scanner from assessing
private customer applications.

Private-network scanning will require a separately deployed customer-controlled
scanner agent rather than weakening the public scanner's network restrictions.

Some legitimate targets may be rejected when DNS configuration is ambiguous.
This is an accepted safety trade-off.
