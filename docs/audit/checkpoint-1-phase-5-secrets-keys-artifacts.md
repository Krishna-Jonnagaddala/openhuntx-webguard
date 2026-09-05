# Audit Checkpoint 1, Phase 5: Secrets, Keys & Artifact Security

## Status

Technical audit completed.

Phase 5 assessed WebGuard's handling of credentials, long-lived service
signing material, checkpoint keys, filesystem trust boundaries, generated
artifacts, authentication-secret disclosure, and repository secret-scanning
controls.

Ten product findings were confirmed during this phase:

- **P5-001 (Medium): Long-lived service signing secrets were directly coupled to the SQLite database.**
- **P5-002 (Low): Default external service-secret paths could collide between databases in the same directory.**
- **P5-003 (Medium): The immediate service-secret directory trust boundary was insufficiently validated.**
- **P5-004 (Low): Service-secret pathname identity was not bound across validation and open.**
- **P5-005 (Medium): Checkpoint HMAC key pathname identity could change between validation and read.**
- **P5-006 (Low): Checkpoint document pathname identity could change between validation and read.**
- **P5-007 (Low): Checkpoint no-overwrite writes were not atomically no-clobber.**
- **P5-008 (Medium): Checkpoint HMAC key directory trust and ownership were insufficiently enforced.**
- **P5-009 (Low): Repository secret scanning did not inspect reachable Git history.**
- **P5-010 (Medium): Service-secret parent directories owned by unrelated UIDs were trusted.**

All confirmed findings were remediated and regression-tested before Phase 5
technical closure.

No Critical or High severity findings were identified during Phase 5.

Additional investigations found no evidence of:

- raw API bearer-token persistence;
- bearer-token disclosure through object repr, authentication errors, or HTTP error responses;
- secrets in current generated scan/report/artifact output;
- secrets in the current reachable Git history;
- checkpoint forgery from a writable checkpoint-document directory when the trusted HMAC key remained protected.

---

## Audit Scope

Phase 5 focused on components responsible for storing, loading, using and
transporting security-sensitive material.

Primary areas reviewed:

- API bearer-token generation and storage;
- service pagination HMAC keys;
- TrustScan Ed25519 private signing material;
- database migration of long-lived service secrets;
- external service-secret file permissions;
- service-secret directory trust boundaries;
- filesystem symlink and pathname-replacement races;
- crawl-checkpoint HMAC key handling;
- crawl-checkpoint document loading and writing;
- generated scan/report/artifact files;
- authentication error disclosure;
- secret-scanning security gates;
- reachable Git history;
- shallow CI checkout behaviour.

The audit used direct database inspection, database-copy attacks, filesystem
replacement races, permission and ownership mutation, symlink/FIFO probes,
late-destination creation races, synthetic credential canaries, isolated Git
history probes, shallow-clone probes, and authorised Juice Shop integration.

---

## Phase 5A: Long-Lived Service Signing Secrets

### Finding P5-001

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Long-lived service signing secrets were directly coupled to the SQLite database

### Initial behaviour

The SQLite service database contained long-lived secret material used for:

- pagination cursor HMAC signing;
- TrustScan Ed25519 private signing.

A copy of the database therefore also copied these service trust roots.

The pagination-key equivalence was demonstrated by successfully forging a
same-tenant cursor using only the copied database.

Tenant scoping still rejected cross-tenant use.

### Security impact

A database-only compromise or backup disclosure unnecessarily included
long-lived service signing authority.

The database therefore represented a broader trust boundary than required.

### Remediation

The service-secret schema was migrated from database schema version 6 to 7.

Long-lived service secrets are now stored in an external canonical JSON
document rather than in SQLite.

Migration:

- validates or creates the external secret file before changing the database;
- preserves existing key material;
- removes the legacy `service_secrets` table;
- verifies the migrated state;
- fails closed on inconsistent or corrupt external secret material.

Database inspection confirmed that the raw signing material is absent after
migration.

### Result

P5-001 is recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 5B: External Service-Secret Filesystem Boundary

### Finding P5-002

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Default external service-secret paths could collide between databases

### Initial behaviour

Multiple databases in the same directory could derive the same default
service-secret filename.

This caused unrelated database instances to share a service-secret sidecar
and produced worker/lease failures.

### Remediation

Default service-secret files are now database-specific:

`<database-name>.service-secrets.json`

---

### Finding P5-003

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Immediate service-secret directory trust boundary was insufficiently validated

### Initial behaviour

A service-secret file could reside under an immediate parent directory that
was writable by group or other users, or represented by an unsafe symlinked
directory boundary.

A protected file mode alone does not prevent pathname replacement by an actor
who controls its directory entry.

### Remediation

The immediate service-secret parent is now validated before creation and
reopening.

Unsafe symlink, non-directory, group-writable and world-writable parent
boundaries are rejected.

---

### Finding P5-004

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Service-secret pathname identity was not bound across validation and open

### Initial behaviour

The secret file was validated through pathname metadata before opening, but
the opened file descriptor was not proven to reference the same filesystem
object.

A pathname replacement race therefore existed between validation and use.

### Remediation

The implementation now opens the service-secret file using no-follow
semantics where supported, validates the opened descriptor, and compares its
device and inode identity with the previously inspected pathname.

The device/inode comparison is defense-in-depth rather than the sole
filesystem trust boundary.

Linux portability testing demonstrated that an unlink/recreate sequence can
immediately reuse the same device and inode. The service-secret security
boundary therefore also requires the immediate parent directory to be
protected from control by unrelated users.

---

### Finding P5-010

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Service-secret parent directories owned by unrelated UIDs were trusted

### Initial behaviour

A service-secret parent directory could be non-writable by group and other
users while still being owned by an unrelated UID.

Such a directory passed the original service-secret parent validation.

### Security impact

The owner of a directory controls its directory entries even when other users
cannot write to that directory.

An unrelated directory owner could therefore rename, remove, or replace the
service-secret pathname despite the secret file itself being owner-only.

### Remediation

On POSIX systems, the immediate service-secret parent directory must now be
owned by either:

- the current effective service UID; or
- root.

Group-writable and world-writable parent directories remain rejected.

Regression tests verify both rejection of an unrelated owner and acceptance
of a legitimate protected directory.

### Result

P5-002, P5-003, P5-004 and P5-010 are recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 5C: Crawl Checkpoint Filesystem Security

### Finding P5-005

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Checkpoint HMAC key pathname identity could change during read

### Initial behaviour

The checkpoint HMAC key loader validated the pathname and then reopened it
through a separate pathname operation.

An attacker able to mutate that filesystem location could replace the key
between validation and read.

### Security impact

Checkpoint verification depends on the HMAC key as its trust root.

Substituting that key could alter the authenticity boundary for checkpoint
state.

### Remediation

Checkpoint key loading now:

- opens by file descriptor;
- uses `O_NOFOLLOW` where available;
- validates the opened file with `fstat`;
- binds opened device/inode identity to the prior pathname validation;
- performs bounded descriptor reads;
- returns controlled errors when the opened filesystem object differs from
  the previously validated object.

Device/inode identity checking is defense-in-depth. The trusted
checkpoint-key parent-directory ownership and permission boundary documented
in P5-008 prevents an unrelated local user from controlling the key pathname
namespace.

---

### Finding P5-006

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Checkpoint document pathname identity could change during read

### Initial behaviour

Checkpoint documents had the same pathname validation/read separation.

Because valid checkpoints remain HMAC authenticated, arbitrary state forgery
was not demonstrated, but replacement could produce denial, replay, or
substitution of another valid signed document.

### Remediation

Checkpoint document loading now uses descriptor-bound identity validation and
controlled bounded reads.

Device/inode comparison detects replacement when filesystem identity changes,
but is not treated as the sole authenticity control. Checkpoint documents
remain HMAC authenticated, so control of the checkpoint-document pathname
alone does not provide the signing authority required to forge arbitrary
checkpoint state.

---

### Finding P5-007

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Checkpoint no-overwrite writes were not atomically no-clobber

### Initial behaviour

`overwrite=False` checked whether the destination existed before later using
a replacement operation.

A destination created after the existence check could therefore be
overwritten.

### Remediation

No-overwrite writes now publish the completed temporary file through an
atomic same-filesystem hard-link operation.

A late destination produces the controlled `checkpoint_exists` outcome and
the temporary file is removed.

---

### Finding P5-008

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Checkpoint HMAC key directory trust and ownership were insufficiently enforced

### Initial behaviour

A `0600` checkpoint HMAC key inside a group/world-writable parent directory
was accepted.

Further ownership testing demonstrated that a non-writable directory owned
by an unrelated UID could also be accepted.

### Security impact

Protection of the key file itself was insufficient when an untrusted actor
controlled its immediate pathname namespace.

### Remediation

On POSIX systems the immediate checkpoint-key parent now:

- rejects group or world write permissions;
- rejects ownership by unrelated UIDs;
- permits ownership by the current effective UID;
- permits root-owned protected deployment directories.

A writable checkpoint-document directory by itself was separately tested and
could not forge a checkpoint while the trusted HMAC key remained intact.

### Result

Checkpoint hardening regression:

**9/9 tests passed.**

P5-005 through P5-008 are recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## Phase 5D: API Token Non-Disclosure

The API bearer-token lifecycle was reviewed separately from long-lived
service signing secrets.

Verified properties:

- API token secrets are generated using cryptographic randomness;
- only a salted scrypt hash is persisted;
- raw tokens are returned only through the one-time issuance result;
- `IssuedApiToken` excludes the raw token from `repr`;
- authentication errors do not echo the submitted token or secret;
- HTTP authentication failures do not return bearer secrets in response
  bodies or headers;
- public authentication context contains token identifiers rather than raw
  token material;
- pre-authentication rate-limit keys retain only the canonical token UUID or
  client peer address.

Dedicated Phase 5 API-token non-disclosure tests passed.

No additional Phase 5 finding was assigned.

---

## Phase 5E: Repository and Generated-Artifact Secret Scanning

### Finding P5-009

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Repository secret scanning did not inspect reachable Git history

### Initial behaviour

The security scanner enumerated current tracked and unignored files using Git
filesystem enumeration.

An isolated adversarial repository demonstrated:

1. a synthetic WebGuard token was committed;
2. the token was removed in a later commit;
3. the normal current-tree secret scan passed;
4. the secret-bearing historical blob remained reachable.

This proved that removal from the final tree could bypass the existing
repository secret gate.

The real OpenHuntX repository was separately scanned and contained no
matching historical secret.

### CI boundary

The security-gate GitHub Actions checkout also used the default shallow
checkout behaviour.

Adding Git-history scanning alone would therefore have provided false
assurance inside CI.

### Remediation

The scanner now:

- requires a non-shallow repository;
- fails closed when complete history is unavailable;
- enumerates reachable Git objects;
- scans unique reachable text blobs using the same credential rules;
- avoids printing credential contents;
- retains size and binary safeguards.

The GitHub Actions security-gate checkout now uses:

`fetch-depth: 0`

Generated output under:

- `scan-results/`;
- `reports/`;
- `artifacts/`;

is now scanned explicitly even though these locations are excluded from
normal repository tracking.

### Verification

The historical regression now detects the removed synthetic credential.

A shallow clone fails closed.

The real repository passed with:

- **225 repository files scanned;**
- **27 generated artifact files scanned;**
- **464 reachable Git blobs scanned;**
- **0 secret findings.**

### Result

P5-009 is recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

---

## CI Filesystem Portability Follow-Up

The first Linux pull-request CI run exposed three failures in adversarial
pathname-replacement tests across Python 3.11, 3.12, 3.13 and 3.14.

The affected tests simulated replacement using:

`unlink -> recreate -> open`

A Linux container probe demonstrated immediate reuse of the same device and
inode identity in **100/100** iterations. In that environment, even the
observed nanosecond change timestamp remained identical during the probe.

This showed that the original race-injection technique was not portable and
that device/inode identity must not be documented as an absolute guarantee
against every unlink/recreate sequence.

The adversarial tests now prepare a distinct replacement file before the
race and publish it with `os.replace`. This deterministically presents a
different filesystem object to the production loader without depending on
filesystem inode-allocation behaviour.

The same investigation identified P5-010: service-secret directory ownership
was not validated even though equivalent ownership protection already
existed for checkpoint HMAC-key directories.

Post-remediation local verification confirmed:

- all corrected pathname-replacement controls pass;
- unrelated service-secret directory owners are rejected;
- legitimate protected service-secret directories remain accepted.

The follow-up was verified successfully by the pull-request Linux
Python-version matrix across Python 3.11, 3.12, 3.13 and 3.14.

---

## Phase 5 Verification Summary

Dedicated Phase 5 security regression:

**42/42 tests passed.**

Expanded Phase 5 persistence/resource diagnostic with `ResourceWarning`
promoted to an error:

**55/55 tests passed.**

Complete unit suite:

**1074/1074 tests passed.**

Authorised OWASP Juice Shop integration:

**14/14 tests passed.**

Security gates:

- repository/generated/history secret scan: passed;
- static Python security analysis: passed;
- locked dependency advisory audit: passed.

`git diff --check` passed.

---

## Residual Risk

The following residual boundaries remain intentionally documented.

External service-secret files protect against a database-only copy or backup
compromise. They do not protect against compromise of the entire runtime
directory, same-UID process compromise, or privileged operating-system
compromise.

POSIX mode-bit validation does not provide complete visibility into every
possible ACL or platform-specific access-control mechanism.

Historical schema-v6 backups created before migration may retain the old
database-resident signing material. Migration of the active database cannot
scrub independent historical backups.

The CLI provides an explicit service-secret path so operators can place
long-lived secret material on a storage boundary separate from the primary
database.

The complete unit suite may emit SQLite `ResourceWarning` messages in test
paths outside the targeted Phase 5 diagnostic set. The Phase 5-focused
warnings-as-errors diagnostic did not reproduce a leak. Broader connection
lifecycle analysis is therefore carried forward to the reliability and
failure-safety audit rather than classified as a Phase 5 security finding.

---

## Phase 5 Closure Decision

No unresolved confirmed Phase 5 vulnerability remains.

Final finding status:

P5-001 (Medium): REMEDIATED / VERIFIED
P5-002 (Low): REMEDIATED / VERIFIED
P5-003 (Medium): REMEDIATED / VERIFIED
P5-004 (Low): REMEDIATED / VERIFIED
P5-005 (Medium): REMEDIATED / VERIFIED
P5-006 (Low): REMEDIATED / VERIFIED
P5-007 (Low): REMEDIATED / VERIFIED
P5-008 (Medium): REMEDIATED / VERIFIED
P5-009 (Low): REMEDIATED / VERIFIED
P5-010 (Medium): REMEDIATED / VERIFIED

Phase 5 remediation and cross-version CI verification are complete.

The pull-request verification passed on Python 3.11, 3.12, 3.13 and 3.14,
together with the security gates and authorised Juice Shop integration.

No unresolved confirmed Phase 5 vulnerability remains.

Phase 5 is ready for merge and formal closure.
