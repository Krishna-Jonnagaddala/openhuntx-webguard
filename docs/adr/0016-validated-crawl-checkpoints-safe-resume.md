# ADR 0016: Validated Crawl Checkpoints and Safe Resume

- Status: Accepted
- Date: 2026-08-03
- Decision owners: OpenHuntX WebGuard engineering
- Milestone: 1.20

## Context

Milestone 1.19 introduced bounded crawl execution, cooperative cancellation,
request-attempt budgets, and explicit termination reasons. A cancelled or
budget-limited crawl could produce a valid partial report, but continuing the
crawl required starting again from the root.

A resumable crawler introduces additional trust and safety risks:

- a checkpoint may be modified to insert an unauthorised URL;
- a pending queue may be reordered or detached from its attempted parent;
- a checkpoint may belong to another target, policy, or engine version;
- DNS resolution may have changed since the checkpoint was created;
- elapsed time and consumed request attempts may be reset;
- previously analysed pages may be requested again;
- response bodies, cookies, or secret headers could be persisted accidentally;
- direct checkpoint writes may leave truncated files after interruption;
- a symbolic-link destination could redirect writes to an unintended file.

## Decision

WebGuard will use a signed, versioned crawl checkpoint document and will resume
only after strict target, policy, queue, and integrity validation.

### Checkpoint envelope

The checkpoint JSON envelope contains:

- `checkpoint_type: crawl_checkpoint`;
- schema version `1.0`;
- one canonical payload object;
- an integrity object using `hmac-sha256`.

The HMAC is calculated over canonical UTF-8 JSON for the payload. The key is
provided separately and is never stored in the checkpoint.

An unkeyed checksum is not sufficient because an attacker who can alter the
checkpoint could also recalculate the checksum.

### Persisted state

The payload stores only the state required to continue deterministically:

- original scan ID and start time;
- canonical target root;
- validated resolved IP addresses;
- engine name and version;
- crawl, fetch, and retry policy snapshots;
- policy and target SHA-256 fingerprints;
- completed page scan results;
- the ordered breadth-first pending queue;
- the canonical visited-URL projection;
- aggregate skipped-link counters;
- elapsed active execution time;
- consumed request attempts.

The checkpoint does not store:

- response bodies;
- cookie values;
- request or response authentication material;
- arbitrary response headers;
- form data;
- JavaScript state;
- browser storage.

Existing analyser redaction rules continue to apply to findings included in
completed page scan results.

### Resume validation

Before any resumed request, WebGuard must:

1. authenticate the checkpoint using HMAC and constant-time comparison;
2. strictly validate the schema and reject duplicate or unexpected JSON keys;
3. validate completed page results using the crawl report contracts;
4. validate same-origin page ownership;
5. validate breadth-first queue ordering and parent/depth relationships;
6. validate that attempted and pending URLs are disjoint;
7. validate the visited-URL projection;
8. re-run normal target scope validation;
9. require the canonical target and resolved IP addresses to match;
10. require crawl, fetch, and retry policies to match;
11. require the engine name and version to match;
12. require remaining time and request-attempt budgets;
13. reject checkpoints with no pending pages.

A changed DNS result is treated as stale target state and is rejected. This is
intentionally conservative. A new authorised scan may be started after the
operator reviews the change.

### Budget continuation

A resumed crawl does not reset execution controls.

- `elapsed_execution_seconds` reduces the remaining execution-time budget.
- `attempts_used` reduces the remaining request-attempt budget.
- completed pages are preserved and are not fetched again.
- the pending queue continues in its original breadth-first order.

### Checkpoint timing

The crawler emits checkpoint state:

- before the first request;
- after each completed or failed page transition;
- after early termination;
- after final queue handling.

This permits pre-request cancellation to produce a resumable root checkpoint.

### Atomic writes

Checkpoint files are written using a temporary file in the destination
directory, flushed with `fsync`, and installed with `os.replace`.

The implementation:

- uses mode `0600` for temporary checkpoint files;
- rejects symbolic-link checkpoint paths;
- rejects non-regular destinations;
- optionally requires explicit replacement for an existing fresh checkpoint;
- attempts to sync the containing directory after replacement;
- removes abandoned temporary files on failure.

### Key files

The CLI requires `--checkpoint-key-file` with `--checkpoint` or
`--resume-from`.

On POSIX systems the key file must not grant group or other access. Key files
must be regular files, must not be symbolic links, and must contain 32 to 4096
bytes after surrounding whitespace is removed.

A suitable local lab key can be created with:

```bash
umask 077
openssl rand -hex 32 > .webguard-checkpoint.key
chmod 600 .webguard-checkpoint.key
```

Production deployments should source checkpoint keys from a managed secret
store rather than committing them to source control.

### CLI behaviour

New crawl options are:

- `--checkpoint PATH`
- `--resume-from PATH`
- `--checkpoint-key-file PATH`
- `--checkpoint-overwrite`

Checkpoint and resume options require `--crawl`.

When resuming:

- the original scan ID and start time are preserved;
- the resume file is updated atomically unless another checkpoint destination
  is supplied;
- the target is revalidated before the first request;
- stored crawl policy is used when no crawl-limit overrides are supplied;
- supplied policy, fetch, and retry settings must match the signed checkpoint.

The final report and checkpoint path must be different.

## Consequences

### Positive

- interrupted crawls can continue without refetching completed pages;
- unauthorised queue modification is detected;
- target and DNS changes fail closed;
- time and request budgets cannot be reset through resume;
- checkpoint corruption and partial writes are detected or avoided;
- response bodies and cookie values remain transient;
- the original scan identity and audit history are preserved.

### Trade-offs

- operators must protect and supply an HMAC key;
- benign DNS changes cause resume rejection;
- checkpoints are authenticated but not encrypted;
- checkpoint files may contain redacted findings and URL paths and must still
  be handled as security data;
- a completed checkpoint cannot be resumed;
- changing crawl, fetch, retry, or engine settings requires a new scan.

## Alternatives considered

### Unkeyed SHA-256 checksum

Rejected because an attacker who modifies a checkpoint can calculate a new
checksum.

### Resume from partial report only

Rejected because the report does not contain the pending queue, visited state,
elapsed budget, or exact crawler continuation state.

### Re-fetch all visited pages

Rejected because it defeats resume semantics, consumes additional budget, and
may produce inconsistent evidence.

### Persist response bodies

Rejected because it increases sensitive-data retention and is unnecessary for
continuing the crawler.

### Automatically accept changed DNS results

Rejected because it could move a resumed scan onto a different network asset.

## Verification

Milestone tests cover:

- deterministic signed checkpoint round trips;
- wrong-key and modified-payload rejection;
- duplicate state and projection validation;
- private key-file permissions;
- atomic file replacement;
- pre-request checkpoint creation;
- breadth-first pending queue resume;
- request-budget continuation;
- no request after cancellation;
- no response-body retention;
- scan ID and finding preservation;
- changed policy and address rejection;
- CLI option dependency and path conflicts;
- authorised OWASP Juice Shop checkpoint resume.
