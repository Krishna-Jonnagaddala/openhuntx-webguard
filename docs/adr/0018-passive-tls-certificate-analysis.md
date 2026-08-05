# ADR 0018: Passive TLS and Certificate Security Analysis

- Status: Accepted
- Date: 2026-08-05
- Milestone: 1.22
- Product: OpenHuntX WebGuard

## Context

WebGuard already performs a verified HTTPS request through a socket pinned to
an address approved by target validation. The passive analyser pipeline then
inspects the bounded HTTP response without issuing additional requests.

TLS and certificate assessment must preserve those properties. A separate
certificate probe could create a second network action, use a different DNS
answer, bypass the pinned address, or weaken certificate verification to
inspect an invalid endpoint. It would also complicate request accounting and
crawl execution budgets.

The scanner therefore needs bounded TLS metadata from the same verified
connection that produced the HTTP response.

## Decision

WebGuard captures a small `TlsConnectionInfo` value while the existing HTTPS
connection is open. The value is attached only to the in-memory
`SafeHttpResponse` passed to passive analysers.

The safe client continues to:

- connect directly to an address approved during target validation;
- send SNI and the HTTP Host header for the validated hostname;
- use `ssl.create_default_context()`;
- require certificate-chain verification;
- require hostname verification;
- reject redirects and preserve all existing response limits;
- count the operation as the existing HTTP request, not a second TLS probe.

The captured metadata is limited to:

- negotiated TLS protocol;
- negotiated cipher name and secret-bit count;
- validated server hostname;
- certificate not-before and not-after timestamps;
- SHA-256 fingerprint of the leaf certificate;
- bounded DNS/IP subject alternative names;
- certificate and hostname verification flags;
- verified-chain length when the Python runtime exposes it.

Certificate bodies and chain certificates are not retained.

## Registered checks

The TLS analyser owns seven check families:

1. `web.tls.certificate.expiry`
2. `web.tls.certificate.hostname`
3. `web.tls.certificate.lifetime`
4. `web.tls.certificate.validity`
5. `web.tls.chain`
6. `web.tls.cipher`
7. `web.tls.protocol`

The analyser can report:

- expired or not-yet-valid certificates;
- certificates approaching expiry;
- certificate lifetimes above the applicable public TLS schedule;
- disabled hostname validation;
- unverified or empty chain projections;
- deprecated or unrecognised protocol versions;
- weak, legacy, or insufficient-strength ciphers.

## Certificate lifetime schedule

For public TLS certificates, the analyser applies the CA/Browser Forum
schedule according to the certificate not-before timestamp:

- before 2026-03-15: 398 days;
- from 2026-03-15: 200 days;
- from 2027-03-15: 100 days;
- from 2029-03-15: 47 days.

This is a passive policy observation. It does not assert that a private PKI
certificate is publicly trusted, and the resulting finding is low severity.

Reference:

- https://cabforum.org/working-groups/server/baseline-requirements/requirements/

## HTTPS-only applicability

For an HTTP target, all TLS check families are explicitly recorded as skipped.
They are never executed against synthetic or absent TLS metadata.

For an HTTPS target, missing or inconsistent TLS metadata becomes a controlled
`analysis.tls` error. The TLS-owned checks are then accounted as skipped while
findings from other analysers are preserved.

## Invalid certificates

WebGuard does not disable verification to retrieve metadata from an invalid
certificate. Certificate verification and handshake failures remain
request-stage failures such as:

- `tls_certificate_invalid`;
- `tls_handshake_failed`;
- `tls_context_insecure`;
- `tls_metadata_unavailable`.

This fails closed and avoids presenting an unverified connection as a normal
successful scan.

## Chain metadata compatibility

`SSLSocket.get_verified_chain()` is not available on every supported Python
runtime. When unavailable, chain length is `None`. A successful default-context
handshake still records certificate verification as true, and the analyser
does not create a false positive solely because the optional chain-length API
is unavailable.

## Data minimisation

TLS metadata remains in memory only for the duration of response analysis.
Scan reports and crawl checkpoints do not serialize:

- the leaf certificate fingerprint;
- subject alternative names;
- negotiated cipher metadata;
- certificate bodies;
- certificate chains;
- response bodies.

A finding includes only the minimum evidence required to explain the detected
condition, such as an expiry time, protocol name, or cipher name.

## Consequences

### Positive

- TLS analysis uses the exact verified connection already authorised and
  counted by WebGuard.
- No additional request, DNS lookup, redirect, or certificate probe is needed.
- Certificate and hostname verification remain mandatory.
- TLS findings participate in existing analyser isolation, page ownership,
  deterministic reporting, and crawl coverage.
- HTTP targets have explicit and auditable HTTPS-only skips.

### Trade-offs

- An endpoint with an invalid certificate is represented as a request failure,
  not as a normal response plus a vulnerability finding.
- Full chain certificates and signature algorithms are not available without
  adding a dedicated X.509 parsing dependency.
- Chain length can be unavailable on older Python runtimes.
- HTTP-target coverage percentage decreases because HTTPS-only checks are
  planned but skipped under the current executed-check coverage definition.

## Rejected alternatives

### Open a second TLS connection

Rejected because it duplicates network activity, can consume a different DNS
or routing result, and complicates budgets and audit records.

### Disable certificate verification for inspection

Rejected because it weakens the safe client and permits untrusted metadata to
be treated as a successful connection.

### Persist certificates in reports

Rejected because certificate bodies and complete chains are unnecessary for
current findings and increase report size and retention risk.

### Add an external TLS library now

Deferred. The standard library provides sufficient verified connection facts
for the first passive TLS milestone. Signature algorithms, key sizes, OCSP,
CT, and protocol-configuration enumeration can be considered in a later,
separately authorised milestone.

## Verification requirements

The milestone is accepted when tests demonstrate that:

- safe HTTPS responses capture bounded TLS metadata;
- HTTP responses carry no TLS metadata;
- insecure TLS contexts and malformed metadata fail closed;
- the analyser covers validity, expiry, lifetime, hostname, chain, protocol,
  and cipher conditions;
- TLS checks are skipped on HTTP targets;
- successful HTTPS scans execute all TLS check families;
- crawl pages analyse the existing response without refetching;
- certificate bodies and TLS connection metadata are absent from reports;
- existing single-page, crawl, checkpoint, and request safety tests continue
  to pass.
