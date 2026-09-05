# OpenHuntX WebGuard Authorisation Model

## 1. Principle

WebGuard follows one core rule:

> No valid permission chain, no scanner network execution.

The permission chain is layered. No single object should be interpreted as complete legal or technical authority by itself.

## 2. What WebGuard authorisation does and does not mean

WebGuard records and enforces technical permission boundaries. It does not independently determine whether an organisation has legal ownership of a system or whether a person is legally entitled to authorise testing.

Public reachability is not permission. A DNS record, an HTTP response, or knowledge of a target URL is not sufficient authority to scan.

A TrustScan permit is a cryptographic technical authorisation record. It narrows an already accepted owned-target authorisation; it does not replace contracts, customer verification, delegated-authority evidence, or applicable law.

## 3. Permission chain

```text
External legal / organisational permission
                |
                v
Owned-target authorisation document
                |
                v
Organisation assignment in WebGuard
                |
                v
TrustScan Scan Permit
                |
                v
Job / schedule binding
                |
                v
Execution-time revalidation
                |
                v
Request-boundary runtime enforcement
                |
                v
Signed Safety Receipt
```

Each layer narrows or verifies the previous layer.

## 4. Laboratory authorisation

Laboratory mode is separate from external owned-target mode.

A lab scan requires:

- explicit `--lab` use;
- an explicit host allowlist; and
- an intentionally authorised laboratory target.

The repository's integration environment uses OWASP Juice Shop on loopback. Commercial target policy must still reject local/private targets outside explicit lab mode.

Lab mode must not be used as a bypass for scanning a real target that would otherwise fail commercial authorisation policy.

## 5. Owned-target authorisation document

The current owned-target authorisation contract is schema `1.0` and records bounded approval for a passive external assessment.

Important fields include:

- canonical `authorization_id`;
- organisation name;
- `authorized_by` identity text;
- canonical target URL;
- canonical allowed hosts;
- issue and expiry timestamps;
- assessment purpose;
- `passive_only=true`; and
- bounded execution limits.

The authorisation fingerprint is the SHA-256 digest of its canonical JSON representation.

### Current contract invariants

- The canonical target hostname must be in `allowed_hosts`.
- The authorisation validity window must be positive and cannot exceed 366 days.
- External owned-target authorisation must explicitly remain passive-only.
- Execution policy may be equal to or stricter than the authorisation limits, never broader.

The authorisation file itself is not a legal title document and is not proof of ownership.

## 6. Owned-target preflight

Before external network execution, preflight requires:

1. a validated owned-target authorisation;
2. exact operator confirmation matching the `authorization_id`;
3. a timezone-aware current time within the authorisation window;
4. HTTPS;
5. exact equality between the validated canonical target and the authorised target;
6. target-host membership in the authorisation allowlist;
7. DNS resolution exclusively to public addresses; and
8. execution settings that do not exceed authorisation limits.

The preflight creates an audit record containing the authorisation fingerprint, resolved public addresses, effective execution policy, and stop conditions.

## 7. Organisation assignment

The local service adds a separate tenancy boundary: an authorisation must be assigned to the authenticated organisation before that organisation may use it.

This prevents possession or knowledge of an authorisation ID from granting cross-tenant authority.

The API service reloads the server-side authorisation and checks the organisation assignment. Client-provided target text or identifiers are not treated as authoritative on their own.

## 8. TrustScan Scan Permit v1

A TrustScan permit is issued only after the underlying organisation and authorisation checks succeed.

The permit contains immutable signed claims for:

- permit ID;
- organisation ID;
- authorisation ID;
- authorisation SHA-256 fingerprint;
- canonical target;
- issuing principal;
- issue time;
- not-before and expiry times;
- permitted scan modes;
- allowed HTTP methods;
- maximum request attempts;
- maximum requests per second;
- maximum concurrency; and
- prohibited operations.

Permit v1 requires maximum concurrency of `1` and limits the permit validity window to no more than 90 days.

Claims are signed using Ed25519. The permit fingerprint is a SHA-256 digest over canonical signed claims.

## 9. Permit state

A persisted permit has immutable signed claims plus mutable revocation metadata.

At a given time the permit is one of:

- `pending`: before `not_before`;
- `active`: within its validity window and not revoked;
- `expired`: at or after `expires_at`; or
- `revoked`: explicitly revoked.

Only an active permit can authorise execution.

## 10. Permit scope validation

Permit validation verifies:

- Ed25519 signature;
- active signing key ID;
- revocation state;
- organisation binding;
- authorisation ID binding;
- authorisation fingerprint binding;
- target binding; and
- scan-mode permission.

If the underlying authorisation changes after permit issuance, the fingerprint mismatch invalidates the permit for execution.

## 11. RBAC and permit operations

Current role behaviour is intentionally narrower for less-privileged users:

| Role | Permit issue | Permit read | Permit revoke | Job submit/read/cancel | Schedule create/read/update | Audit read |
| --- | --- | --- | --- | --- | --- | --- |
| Owner | Yes | Yes | Yes | Yes | Yes | Yes |
| Administrator | Yes | Yes | Yes | Yes | Yes | Yes |
| Analyst | No | Yes | No | Yes | Yes | No |
| Viewer | No | Yes | No | Read only | Read only | No |

The exact permission map is code-defined in `apps/api/src/webguard_api/auth.py` and must remain covered by tests.

## 12. Job binding

Job creation requires:

- authenticated tenant context;
- permission to submit;
- a server-assigned owned-target authorisation;
- exact target match;
- a valid TrustScan permit;
- exact permit scope for the requested mode; and
- an idempotency key.

The queued job persists the authorisation fingerprint and permit fingerprint that were accepted at submission time.

A queued job is not permission to execute indefinitely. Permission is checked again when the worker executes it.

## 13. Schedule binding

Recurring schedules are similarly bound to an authorisation and TrustScan permit.

Schedule creation must start within the permit validity window. When a schedule becomes due, WebGuard revalidates permission before atomically materialising a job. Invalid permission blocks the schedule rather than silently running with stale authority.

## 14. Worker execution-time revalidation

Immediately before scanner execution, the worker verifies that:

- the queued job is in the correct lease state;
- the server-side authorisation still exists and matches the stored fingerprint;
- the TrustScan permit still exists;
- the permit is still correctly signed;
- the permit is still active;
- organisation, target, authorisation, and scan mode still match; and
- the job remains bound to the expected permit fingerprint.

Legacy or unbound jobs fail closed before network activity.

## 15. Request-boundary enforcement

TrustScan permission is not checked only once at job start. The runtime safety engine enforces permit constraints before every outbound scanner request.

Before a request is allowed, the engine checks:

- runtime circuit state;
- same-origin scope;
- allowed HTTP method;
- remaining request-attempt budget;
- maximum concurrency;
- current permit and authorisation state; and
- rate timing.

Permission is revalidated again after any enforced throttle sleep because authority may change while the worker waits.

Revocation or expiry during a crawl therefore prevents the next request from being sent.

## 16. Network-scope enforcement

External owned-target scans require public-address resolution. WebGuard rejects private, loopback, link-local, multicast, reserved, unspecified, and other non-global target addresses in the commercial external path.

The safe HTTP client also blocks redirects and connects only through validated destination state. This reduces target substitution and SSRF-style scope escape.

## 17. Safety Receipt

At terminal execution WebGuard can produce a signed TrustScan Safety Receipt containing the permit binding and observed enforcement counters, including:

- attempted, permitted, and blocked requests;
- `429` and `5xx` responses;
- request errors;
- throttling;
- circuit-breaker activations;
- scope violations;
- permit revalidations;
- peak concurrency; and
- termination reason.

The receipt is evidence about WebGuard's enforcement behaviour. It is not a guarantee of zero target impact and is not a legal opinion about permission.

## 18. Revocation expectations

Revocation is prospective. A revoked API token prevents future authenticated API use. A revoked TrustScan permit blocks subsequent execution checks and subsequent outbound requests once the runtime revalidation observes the revoked state.

Previously produced artefacts and historical audit events remain historical records and should not be rewritten to imply the permit was never valid.

## 19. Production evolution

A hosted production release must strengthen the external-authority layer with centrally controlled asset registration and verifiable customer/delegated authority. The current local authorisation document remains an engineering control, not the final customer-verification workflow.

Planned production controls include stronger identity assurance, formal target verification, managed signing-key custody, isolated scanner runners, and auditable customer acceptance of testing terms.
