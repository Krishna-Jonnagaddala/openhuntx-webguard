# Audit Checkpoint 1 — Phase 6: Network Request Safety & Scanner Runtime Boundaries

## Status

In progress.

Phase 6 assesses `safe_http.py`, the connection-time HTTP safety layer used
by the crawler and analyzers, and the scanner runtime boundaries that
consume it: connection lifecycle, socket failures, TLS handling, redirects,
response-size limits, method restrictions, timeout behaviour, DNS/IP
validation, retry classification, exception taxonomy, cleanup failures,
cancellation, crawler behaviour, checkpoint/resume interaction, and
authorization state during execution.

This checkpoint records the first confirmed finding, produced from an
explicit hypothesis carried over from Phase 5's residual-risk notes about
connection lifecycle. The remainder of the Phase 6 attack surface (DNS/IP
validation and SSRF boundaries, TLS handshake and certificate handling,
redirect and response-limit enforcement, retry/backoff interaction with the
crawler, cancellation, and checkpoint/resume interaction) has not yet been
audited and is carried forward under this same checkpoint.

One finding has been confirmed during this phase:

- **P6-001 — Medium — A connection-cleanup failure in `_perform_request` could silently replace the controlled outcome of an HTTP request, including successful responses and non-retryable policy decisions.**

No Critical or High severity findings have been identified so far.

---

## Audit Scope (this checkpoint)

- `_perform_request` in `workers/scanner/src/webguard_scanner/safe_http.py`,
  specifically the `try/finally: connection.close()` structure wrapping one
  HTTP request/response cycle.
- The interaction between `_perform_request`'s cleanup path,
  `fetch_once`'s per-address exception handling, and
  `error_taxonomy.py`'s retryability classification consumed by the crawler.

## Step B — Attack Surface Mapping (network boundary, partial)

External inputs relevant to this checkpoint:

- The remote server's TCP/TLS behaviour during connection teardown (RST,
  delayed FIN, TLS-level errors during socket close).
- The remote server's response (status, headers, body) that determines
  which controlled outcome `_perform_request` is in the middle of producing
  when cleanup runs.

Trust boundary: the return value / exception of `fetch_once` is the
contract the crawler and every analyzer rely on to make retry, safety, and
reporting decisions. That contract is defined by `error_taxonomy.py`
(`ErrorCategory`, `retryable` per code). Anything that changes which code
reaches the caller changes retry behaviour and audit-trail accuracy without
changing the underlying request outcome.

## Step C — Invariant

**Invariant:** once `_perform_request`'s try block has produced an outcome
(a `SafeHttpResponse` to return, or a `SafeRequestError`/transport exception
to propagate), that outcome must reach `fetch_once` unchanged. Connection
cleanup is best-effort and must not be able to substitute a different
outcome.

- **What must always be true:** the classification of a request outcome
  (success vs. specific controlled failure code) is determined solely by
  what happened during the request/response cycle, not by whether the
  socket happened to close cleanly afterward.
- **When it is checked:** implicitly, by whatever code executes after
  `_perform_request` returns/raises — in particular the crawler's
  `is_retryable_error` lookup and audit-trail recording of `exc.code`.
- **Whether it can change afterward:** prior to remediation, yes — a
  `close()` failure during the `finally` block ran *after* the real
  outcome was already determined, and Python's `finally` semantics let an
  exception raised there discard a pending `return` or replace an
  in-flight exception.
- **Whether it is revalidated at the next trust boundary:** no — the
  crawler consumes `exc.code` directly with no independent check that the
  code reflects the actual request outcome.
- **Fail-open or fail-closed:** effectively fail-open with respect to
  *policy* decisions. `redirect_blocked`, `tls_context_insecure`,
  `response_body_too_large`, and `response_headers_too_many` are all
  `NON_RETRYABLE` in `error_taxonomy.py`; the observed failure mode
  reclassified all of them as `RETRYABLE` network-transient codes
  (`connection_failed` / `connection_interrupted`, depending on the close()
  exception's errno).

## Step D — Adversarial Reproduction

### Finding P6-001

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Connection-cleanup failure in `_perform_request` could silently
replace the controlled outcome of an HTTP request

### Initial behaviour

```python
try:
    ...
    return SafeHttpResponse(...)
finally:
    connection.close()
```

A minimal adversarial harness (a fake `http.client`-shaped connection whose
`close()` raises `OSError(ECONNRESET, ...)`, driven through the real
`fetch_once`/`_perform_request` code path with no other change) was used to
test six scenarios: a controlled policy failure, a successful response, a
timeout, a TLS failure, a redirect rejection, and a response-size
rejection. In every scenario, prior to remediation, the `close()` failure
replaced the real outcome:

| Scenario | Real outcome | Observed outcome after `close()` raises |
|---|---|---|
| Too-many-headers policy failure | `SafeRequestError(response_headers_too_many)` | `SafeRequestError(connection_interrupted)` |
| Successful response | `SafeHttpResponse(status=200, ...)` | `SafeRequestError(connection_interrupted)` — the response was discarded entirely |
| Timeout | `SafeRequestError(connection_timeout)` | `SafeRequestError(connection_interrupted)` |
| TLS context insecure | `SafeRequestError(tls_context_insecure)` | `SafeRequestError(connection_interrupted)` |
| Redirect rejection | `SafeRequestError(redirect_blocked)` | `SafeRequestError(connection_interrupted)` |
| Oversized response | `SafeRequestError(response_body_too_large)` | `SafeRequestError(connection_interrupted)` |

Because `fetch_once` re-raises `SafeRequestError` unchanged but catches
`OSError`/`ssl.SSLError`/`http.client.HTTPException` as a per-address
connection failure, a `close()`-raised `OSError` was caught by the *outer*
handler instead of the original exception (or return) reaching the caller
at all — the original outcome was gone by the time `fetch_once` observed
anything.

### Security impact

- `redirect_blocked`, `tls_context_insecure`, `response_body_too_large`,
  and `response_headers_too_many` are deliberately `NON_RETRYABLE` in
  `error_taxonomy.py` — each represents a security- or safety-relevant
  decision that a request must not be repeated. A `close()` failure could
  reclassify any of them as a `RETRYABLE` network-transient code, which the
  crawler would then retry (up to `RetryPolicy.maximum_attempts`) against
  the same target. `tls_context_insecure` is the most significant of these:
  it is the check that verifies TLS certificate/hostname verification was
  actually enforced on the connection, and it is exactly the kind of
  finding that must halt, not retry.
- A successful response could be discarded outright: the body was already
  fully read and the response fully constructed before cleanup ran, yet
  the caller received an error instead of the real result — losing scan
  data and, if retried by the crawler, causing an avoidable extra request
  against the target.
- More broadly, the finding degraded the controlled error taxonomy this
  audit has been establishing since Phase 3/4: the caller could no longer
  trust that `exc.code` reflected what actually happened during the
  request.

`ConnectionResetError` (`ECONNRESET`) on `close()` is not a purely
theoretical trigger: TLS sockets and TCP sockets with unread buffered data
at close time can surface such errors from the underlying platform during
teardown, so an adversarial or simply unfriendly server can plausibly
induce this condition.

### Reproduction

Reproducer: adversarial `close()`-raising connection driven through
`fetch_once` for all six scenarios above (not committed; used to establish
the vulnerable behaviour before writing the permanent regression test).

### Remediation

```python
finally:
    try:
        connection.close()
    except (OSError, ssl.SSLError, http.client.HTTPException):
        # A cleanup-time failure must never replace the try block's
        # outcome (a returned response or an already-raised error).
        # The socket is being discarded either way.
        pass
```

The cleanup failure is now scoped to exactly the same exception types the
rest of the module already treats as transport-layer failures, so
programming errors (e.g. `AttributeError` from a genuinely broken
connection object) are still not swallowed. The connection is discarded
either way — cleanup best-effort suppression here does not weaken any
existing safety property, since the socket resource is released by the OS
regardless of whether `close()` itself reports success.

### Regression test

`tests/unit/test_phase6_connection_cleanup_isolation.py` — 7 tests, one per
scenario above plus an explicit check that a `redirect_blocked` outcome is
never reclassified as retryable via `is_retryable_error`. All 7 tests were
confirmed to fail against the pre-remediation code (`git stash` verification)
and pass against the remediated code.

### Result

**7/7 tests passed** (post-remediation).

Full unit suite: **1081/1081 tests passed** (1074 pre-existing + 7 new).

Security gates: secret scan, static Python security analysis, and locked
dependency audit all passed post-remediation.

P6-001 is recorded as:

**CONFIRMED -> REMEDIATED -> REGRESSION TESTED**

### Residual risk

This remediation addresses the cleanup-swallowing mechanism generically for
`_perform_request`. It does not, by itself, constitute a full audit of
connection lifecycle, DNS/IP validation, TLS handshake behaviour, redirect
handling, response-size enforcement, retry/backoff interaction, or
cancellation — those remain open Phase 6 scope and are carried forward.

---

## Phase 6 Next Steps

The following areas from the Phase 6 direction remain to be audited under
this checkpoint:

- DNS resolution and IP/address validation (SSRF boundary: private/link-local
  addresses, DNS rebinding between validation and connect).
- TLS handshake and certificate validation edge cases beyond the
  `tls_context_insecure` check already covered incidentally above.
- Redirect handling beyond the single-response rejection path.
- Response-size and header-limit enforcement under adversarial streaming
  behaviour (slow-loris-style incremental delivery, chunked encoding edge
  cases).
- Retry/backoff interaction with the crawler's request budget.
- Cancellation and checkpoint/resume interaction with an in-flight request.
- Authorization revalidation during long-running scanner execution
  (extending the Phase 4 authority-revalidation invariant to the network
  boundary specifically).

Phase 6 is **not yet closed**.
