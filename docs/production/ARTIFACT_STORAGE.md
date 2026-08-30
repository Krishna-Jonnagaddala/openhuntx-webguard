# Artifact (Report) Object Storage (Slice 17)

## 1. What this is

Slice 14 named the artifact-storage interface (`ArtifactStore`) and
built its local-filesystem implementation (`LocalArtifactStore`).
Slice 15 wired it into the report-creation/download API surface but
left `ObjectStorageArtifactStore` an honest stub -- production failed
closed with `object_storage_not_implemented` rather than silently
treating a local path as durable cloud storage. This slice completes
it: a real S3-backed implementation, real encryption, a real retention
policy, and a real end-to-end proof (browser login → scan → report →
download → checksum-verified bytes) replacing that stub everywhere.

## 2. Provider choice and scope

`docs/production/PROVIDER_EVALUATION.md`'s Object storage section
already recommended S3 (single-vendor networking simplicity alongside
RDS/KMS, which this project already uses). This slice implements that
recommendation directly. Scope, per requirement 8: generated reports
(implemented) and report exports (the same artifact -- there is no
separate "export" format distinct from the report itself in this
product yet). Bounded evidence artifacts (the per-job authorization
audit file, the TrustScan safety receipt) remain local-filesystem-only
this slice -- a deliberate, narrow scope decision, not an oversight;
see §6.

## 3. Encryption: SSE-KMS with a dedicated key, not SSE-S3

Evaluated both, per requirement 12:

| | SSE-S3 (AWS-managed key) | SSE-KMS (customer-managed key) |
|---|---|---|
| Per-request audit trail | No -- AWS's own key, no CloudTrail entry naming which principal used it | Yes -- every `Decrypt`/`GenerateDataKey` call is a CloudTrail event |
| Key-level access control | None (implicit, bucket-wide) | IAM policy on the specific key, independent of S3 bucket policy |
| Revocation path | None -- the key cannot be disabled or rotated by the account | Real -- the key can be disabled, its policy tightened, or (with notice) scheduled for deletion |
| Operational cost | None | Per-request KMS API cost (mitigated by `bucket_key_enabled = true`, `storage.tf`) |

**Chosen: SSE-KMS with a dedicated customer-managed key**
(`aws_kms_key.artifact_storage_encryption`, `infra/terraform/storage.tf`),
mirroring the same choice already made for RDS storage encryption
(`postgres.tf`'s own dedicated key, not RDS's default). This is a
security-report product; per-principal audit trail and a real
revocation path for the encryption key outweigh the added KMS request
cost, matching this project's existing risk posture (`docs/THREAT_MODEL.md`).

`ObjectStorageArtifactStore.put()` always passes
`ServerSideEncryption="aws:kms"` and the specific `SSEKMSKeyId` --
never omitted, never defaulted to SSE-S3. The S3 bucket policy
independently denies any `PutObject` that does not specify this exact
key (`storage.tf`'s `DenyWrongKmsKey`/`DenyUnencryptedObjectUploads`
statements) -- defense in depth beyond the application always sending
the right parameters (requirement 10).

## 4. Architecture: mirrors the KMS/Secrets-Manager duck-typing pattern exactly

```
service.py / executor.py (domain logic)
    │  .put(reference, data) / .get_reference(reference) / .checksum(reference)
    ▼
ArtifactStore (Protocol -- LocalArtifactStore | ObjectStorageArtifactStore)
    │
    ▼  (ObjectStorageArtifactStore only)
S3ClientProtocol (Protocol: put_object/get_object/head_object/delete_object)
    │
    ▼
boto3.client("s3")  -- constructed once, at the one call site that needs it (cli.py's `_production_components()`)
```

`ObjectStorageArtifactStore` never imports `boto3` -- it depends on
`S3ClientProtocol`, satisfied structurally by a real
`boto3.client("s3")` or a fake in tests, exactly like
`secret_provider.py`'s `SecretsManagerClientProtocol` and
`signing.py`'s `KmsClientProtocol`. `boto3` remains a lazy import at
the single production call site, not a project dependency --
`requirements-ci.lock` gained nothing for this slice's S3 work (same
as it gained nothing for KMS/Secrets Manager in earlier slices).

## 5. Completing the write path (a real Slice 14 gap, closed here)

Before this slice, `ScanJobExecutor` wrote a completed report directly
to the local filesystem via its own hand-rolled `_write_report`
function -- `ArtifactStore.put()` was never actually called by
anything; only the read side (`service.py`'s `checksum()`/
`get_reference()`) went through the interface. This meant
`ObjectStorageArtifactStore` could never have held real report bytes
even once implemented, because nothing ever wrote to it. `executor.py`
now accepts an injected `artifact_store` (defaulted to
`LocalArtifactStore(self.artifact_directory)` when not given -- every
pre-Slice-17 local/dev/test/lab call site is unaffected, byte-for-byte
identical file permissions/paths) and writes the completed report
through it. Production wiring passes the *same*
`ObjectStorageArtifactStore` instance to both the executor (writes)
and the service (reads), so a report a worker just generated is
immediately, durably readable through the API -- `tests/unit/test_job_executor.py`'s
`test_report_is_written_through_an_injected_artifact_store_not_local_disk`
and the real (fake-S3-backed) production E2E in
`tests/integration/test_production_runtime_completion_e2e.py` both
prove this.

The authorization-audit file and TrustScan safety receipt remain
local-filesystem-only, unchanged -- they are operator/compliance
records, never read back through `ArtifactStore` by anything, and
never customer-downloadable. Migrating them to S3 was evaluated and
explicitly deferred: it would touch `webguard_contracts`'s own
path-based `write_owned_target_audit_file`/`write_owned_target_authorization_file`
helpers (used by more than just this executor, including the E2E
harness), a materially larger and riskier change for artifacts this
slice's own requirement 8 only asks for "where applicable."

## 6. Object naming and tenant isolation (requirements 9-10)

Object keys are exactly the pre-existing, already-server-generated
`report_ref` scheme: `organizations/<org-id>/jobs/<job-id>/report.json`.
This was not changed to the brief's suggested
`organizations/.../scans/.../reports/.../<artifact>` nesting -- the
existing scheme already satisfies every actual security property that
hierarchy exists for (a tenant-scoped prefix, server-generated,
non-guessable UUIDs, never a customer-supplied filename), and changing
it would mean either migrating every already-persisted `report_ref`
value with no security benefit, or running two key schemes side by
side. `_reject_unsafe_reference` (shared with `LocalArtifactStore`)
rejects any reference containing `..` or a leading `/` before either
backend ever issues a request, closing the path-traversal case both
backends share.

**Tenant isolation is enforced at the application layer, exactly like
every other resource in this system** (`get_report_scoped(report_id,
organization_id=...)` -- the same `WHERE organization_id = ?` pattern
Postgres rows use everywhere else, not a per-tenant database user).
S3-side, this slice adds defense in depth (bucket policy denying
insecure/unencrypted writes, no public access by any mechanism) but
deliberately does **not** add per-organization IAM policies or
per-prefix bucket-policy conditions -- evaluated and rejected as
disproportionate infrastructure complexity for this product's current
scale (organizations are created dynamically at runtime; a static
Terraform-managed IAM policy per organization is not a workable model
without a whole separate provisioning pipeline). If cross-tenant
object access were ever attempted by a bug, the object KEY itself
already makes guessing another organization's `job_id` computationally
infeasible (a UUID), and the application check remains the actual
enforcement point regardless.

## 7. Retention (requirement 13)

`infra/terraform/storage.tf`'s `aws_s3_bucket_lifecycle_configuration`:
transition to `STANDARD_IA` after `object_storage_transition_days`
(default 90), expire after `object_storage_retention_days` (default
400), and `abort_incomplete_multipart_upload` after 7 days (covers
"failed/incomplete artifact uploads" explicitly). This is one uniform
policy for every object today -- **there is no per-organization
retention override**, a named, honest gap. The natural extension point
for one, if a future slice needs it, is S3 object tagging at write
time (e.g. `Organization=<org-id>`) paired with a tag-scoped lifecycle
rule -- not implemented this slice, since `ArtifactStore.put(reference,
data)`'s interface deliberately stays narrow (the module's own
docstring: "nothing else") and threading an organization ID into it
just for tagging would widen that interface for a feature nothing
requires yet.

## 8. Secure report download (requirement 11)

**Chosen: authenticated API streaming, not a signed URL.**
`GET /v1/reports/{id}/download` remains the sole customer-facing
retrieval path: it re-authenticates and re-authorizes the caller
(the same `REPORT_READ` RBAC check and tenant-scoped lookup every
other route uses) on every request, then streams the artifact's bytes
directly through the API process -- the customer's browser never sees
a bucket name, an object key, or any S3 URL, signed or otherwise.

A short-lived signed S3 URL was considered and rejected for this
product's shape: it would require a second authorization decision (who
is allowed to *mint* a signed URL) to stay as strict as the first (who
is allowed to *use* it), while adding a real new risk the current
design does not have -- a signed URL, once issued, is a bearer
credential of its own for its validity window, shareable independent
of the session that requested it. Authenticated streaming has a real
cost (report bytes pass through the API process rather than being
served directly by S3/CloudFront), but every report this product
handles today is a small JSON document, not a multi-gigabyte artifact,
so that cost is not a real constraint at this project's scale.
Revisit this decision if artifacts grow large enough for streaming
cost/latency to matter.

## 9. Integrity (requirement 14)

`create_report()` computes and persists a SHA-256 checksum from the
artifact's own bytes at registration time (`self.artifact_store.checksum(...)`,
never a client-supplied value -- unchanged since Slice 14).
`download_report()` (new this slice) re-computes SHA-256 over the
bytes it is about to serve and compares against that persisted value
*before* returning anything -- a mismatch fails closed with
`report_integrity_check_failed` (500), never silently serving
corrupted or truncated bytes. Tested directly
(`tests/unit/test_customer_platform_api.py`'s
`test_report_download_fails_closed_when_bytes_do_not_match_the_persisted_checksum`,
which tampers with the artifact after registration) and exercised for
real end-to-end (`test_production_runtime_completion_e2e.py`'s report
test now downloads the report through real HTTP and asserts the
downloaded bytes' SHA-256 against the checksum the API itself
returned). `ObjectStorageArtifactStore`'s own unit tests
(`tests/unit/test_object_storage_artifact_store.py`) additionally cover
the object-storage-specific failure shapes: missing object
(`artifact_not_found`), access-denied translation without vendor-detail
leakage, and path-traversal rejection before any S3 call is made.

## 10. What this document is not

It does not cover Postmark/email (see
`docs/production/TRANSACTIONAL_EMAIL.md`) or the report *generation*
logic itself (Scanner v1, unchanged and feature-frozen this slice).
