# ADR 0010: Passive Secure Cookie Analysis

- Status: Accepted
- Date: 2026-08-03

## Context

OpenHuntX WebGuard already performs one bounded, scope-validated HTTP GET
request and analyses security response headers without following redirects or
sending active payloads.

`Set-Cookie` response headers carry additional passive security information.
A scanner can assess cookie attributes from the response that it has already
received, but cookie values may contain session identifiers, authentication
tokens, anti-CSRF material, personal information, or other secrets. Copying
those values into findings, logs, exceptions, test output, or reports would
create an unnecessary disclosure risk.

Cookie purpose is also not always observable from one response. For example,
some application cookies intentionally require JavaScript access, while
session cookies generally should not. Findings therefore need conservative
severity and remediation wording where application intent is unknown.

## Decision

Add a dedicated `cookie_analyzer` module that analyses every `Set-Cookie`
header already present in a bounded `SafeHttpResponse`.

The analyser sends no additional requests and performs no active testing.

### Metadata handling

The analyser:

- processes multiple `Set-Cookie` fields independently;
- extracts a bounded syntactically valid cookie name;
- discards the cookie value immediately during parsing;
- stores the cookie name only as finding identity metadata;
- never puts a cookie value in a finding, evidence summary, exception,
  terminal output, or scan report;
- identifies malformed headers only by their one-based response-header
  occurrence number;
- deduplicates findings by normalized fingerprint.

Cookie names are retained because they are required to distinguish repeated
findings for different cookies. Names are restricted to the HTTP token
character set and a maximum of 128 characters.

### Checks

The passive cookie analyser evaluates:

1. missing `Secure`;
2. missing `HttpOnly`;
3. missing, invalid, or repeated `SameSite`;
4. `SameSite=None` without `Secure`;
5. a `Domain` attribute that broadens host-only scope;
6. an invalid or non-matching `Domain`;
7. a missing, invalid, or unnecessarily broad `Path`;
8. cookies observed in an unencrypted HTTP response;
9. case-insensitive `__Secure-` prefix requirements;
10. case-insensitive `__Host-` prefix requirements;
11. malformed cookie syntax that cannot be safely identified.

Prefix recognition is case-insensitive under the current cookie storage
model. The `__Secure-` prefix requires a secure origin and the `Secure`
attribute. The `__Host-` prefix additionally requires no `Domain`
attribute and `Path=/`.

The analyser does not attempt public-suffix classification. A valid `Domain`
attribute is reported as a low-severity scope-broadening observation without
claiming that the domain is a public suffix. A non-matching or ambiguous
domain is reported separately.

Missing `HttpOnly`, `SameSite`, and explicit `Path` are low-severity
hardening findings because one passive response cannot determine every
cookie's business purpose.

### Orchestration and coverage

The existing `run_passive_header_scan` entry point is retained for backward
compatibility. It now runs both the security-header analyser and the cookie
analyser against the same response.

The existing scan type value `passive-http-headers` is also retained until
the planned multi-analyser orchestration milestone introduces a broader
versioned scan profile.

Coverage becomes the union of:

- five existing security-header checks; and
- eight cookie-check families.

On HTTPS, all thirteen check families execute. On HTTP, HSTS remains skipped,
so twelve of thirteen check families execute and coverage is 92.31 percent.

A response with no `Set-Cookie` fields still counts the cookie checks as
executed and produces no cookie findings.

Controlled cookie-analysis failures use the existing analysis-stage error
path and are never retried.

## Standards basis

The implementation follows the current HTTP State Management Mechanism work
for cookie syntax, attributes, domain/path processing, and reserved prefixes.
Security recommendations are aligned with OWASP cookie guidance and ASVS
cookie requirements.

## Consequences

### Positive

- WebGuard gains useful passive cookie findings without another request.
- Secret cookie values do not enter normalized reports.
- Multiple cookies and repeated response fields are handled deterministically.
- Reserved prefix violations are reported explicitly.
- Cookie checks participate in scan coverage and report validation.
- Existing CLI and public scan entry points remain compatible.

### Negative

- One response cannot determine whether every cookie truly requires
  `HttpOnly`, cross-site delivery, host sharing, or site-wide path scope.
- Cookie names remain visible in findings and reports.
- No public-suffix-list dependency is introduced, so the analyser does not
  label a domain as a public suffix.
- The legacy scan function and scan-type names are temporarily narrower than
  the checks they execute.
- Cookie values cannot be used for entropy or token-format analysis because
  they are intentionally discarded.
