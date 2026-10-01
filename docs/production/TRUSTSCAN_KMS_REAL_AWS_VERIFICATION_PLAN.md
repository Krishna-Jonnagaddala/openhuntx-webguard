# TrustScan KMS signing: real-AWS verification plan

## Status

**A plan only. No AWS account action has been taken to write this document, and none should be taken without the owner action this document ends with.** Every command below is proposed, not run. This closes the specific gap M23 (`docs/production/WEBGUARD_RELEASE_CHECKLIST.md`) names: `KmsSigningProvider` and the dual-algorithm signing contract are complete and tested against a duck-typed fake client, but have never made one real call to AWS KMS.

## What's already verified, and what isn't: three distinct tiers

Getting these three straight matters, because they get conflated easily and this project has been careful elsewhere not to let a mock stand in for reality:

1. **Local cryptographic tests** (already done): `tests/unit/test_p1_7_signature_algorithm_metadata.py` performs a real NIST P-256 ECDSA sign and verify, real `cryptography` library math, no network call at all. This proves the *algorithm* is implemented correctly.
2. **Mocked AWS calls** (already done): the same test file, and `KmsSigningProvider`'s own unit tests, use a fake object satisfying `KmsClientProtocol` (`get_public_key`, `sign`) with a hand-written response shape (`{"PublicKey": b"...", "Signature": b"..."}`). This proves `KmsSigningProvider`'s own code correctly consumes that shape, *if AWS's real API returns it identically*. It does not prove that assumption.
3. **Real AWS evidence** (does not exist yet): a real `boto3.client("kms")` object, a real key, a real network round trip to `kms.eu-west-2.amazonaws.com`, a real response parsed by the unmodified `KmsSigningProvider` class. This is what this plan produces.

Tier 2 is the tier every existing test lives at. The gap this plan closes is specifically getting to tier 3, once, deliberately, and tearing down immediately after.

## Credentials: no persistent access key

`KmsSigningProvider` takes any object satisfying `KmsClientProtocol`: it is never told how that client authenticated. Two ways to run this verification without creating a long-lived IAM user or access key pair, in preference order:

1. **GitHub Actions OIDC federation** (preferred): a one-time IAM role with a trust policy scoped to this repository's OIDC subject (`repo:Krishna-Jonnagaddala/openhuntx-webguard:ref:refs/heads/<verification-branch>`), assumed via `aws-actions/configure-aws-credentials`'s OIDC mode. Credentials are minted for the single workflow run and expire automatically; nothing is stored anywhere, matching this repository's own "no `secrets.*` in workflows" finding from the M17 audit. This is the actual "workload identity" fit the eventual ECS Fargate deployment (`docs/production/PROVIDER_EVALUATION.md`) would use in production too, just federated from CI instead of from a running task.
2. **Owner-run `aws sts assume-role`**: if the owner prefers to run this by hand rather than via a workflow, a scoped IAM role assumed via their own already-authenticated AWS CLI session (MFA-protected, 1-hour session token), never a static access key created for this purpose.

Either way: no `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` pair should be created or stored for this verification.

## Minimal IAM policy

Scoped to one key (by ARN, once created) and the exact five KMS actions this verification needs, nothing account-wide and nothing beyond what `KmsSigningProvider` itself calls plus the lifecycle actions to create and delete the key:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustScanKmsVerificationKeyLifecycle",
      "Effect": "Allow",
      "Action": ["kms:CreateKey", "kms:TagResource", "kms:ScheduleKeyDeletion", "kms:DescribeKey"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {"aws:RequestTag/purpose": "trustscan-kms-verification-2026-09"}
      }
    },
    {
      "Sid": "TrustScanKmsVerificationSignAndRead",
      "Effect": "Allow",
      "Action": ["kms:GetPublicKey", "kms:Sign"],
      "Resource": "arn:aws:kms:eu-west-2:<account-id>:key/<key-id>"
    }
  ]
}
```

`kms:CreateKey` cannot itself be resource-scoped to a not-yet-existing key ARN (a KMS/IAM limitation, not a choice made here), so the tag condition is the actual scoping mechanism: this role can create only a key it immediately tags `purpose=trustscan-kms-verification-2026-09`, and can sign/read only the one specific key ARN produced by that create call, filled in after step 1 below.

## Test sequence

Region `eu-west-2` (London), matching the region PR #71 and `docs/production/PROVIDER_EVALUATION.md` already settled on, so this key's own region matches wherever RDS eventually lands, if it matters for latency later.

1. **Create the key**: `aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --tags TagKey=purpose,TagValue=trustscan-kms-verification-2026-09 --region eu-west-2`. Proves the exact `KeySpec`/`KeyUsage` combination `KmsSigningProvider.algorithm = "ECDSA_SHA_256"` targets is real and creatable, not just assumed from AWS's documentation.
2. **Construct the real provider**: `KmsSigningProvider(boto3.client("kms", region_name="eu-west-2"), key_id=<arn from step 1>)`, completely unmodified from the class already in `signing.py`. Its `__init__` immediately calls `get_public_key` for real. This is the single highest-value step: every existing test's `get_public_key` response is hand-written; this is the first time the *real* response shape is parsed by this exact code.
3. **Sign**: call `.sign(message)` with a real, minimal TrustScan permit's canonical bytes. A real `kms:Sign` request with `SigningAlgorithm="ECDSA_SHA_256"`, `MessageType="RAW"`. Proves AWS accepts the exact request shape this code sends, not a shape assumed to be accepted.
4. **Independent verification** (the part a KMS-only test could accidentally skip): verify the signature from step 3 using a *separate* code path from `KmsSigningProvider` itself, the plain `cryptography` library's `ec.ECDSA(hashes.SHA256())` verify against the public key bytes fetched in step 2, run entirely outside AWS's own SDK. Confirms the signature is a standards-conformant ECDSA-P256-SHA256 signature usable by any verifier, not merely accepted by round-tripping back through the same AWS call that produced it.
5. **Algorithm/key identification**: confirm `provider.key_id` (`sha256:<hex>` of the public key bytes from step 2) is computed identically to how `SigningKeyRegistry.register` would derive it from the same bytes, and confirm it differs from `provider.provider_key_id` (the real ARN) exactly as `signing.py`'s own docstring specifies. This is what stops the real ARN from ever reaching a permit's `signing_key_id` field, where its format would fail the existing `^sha256:[0-9a-f]{64}$` contract validation.
6. **Denied access**: attempt `.sign()` again using a second, deliberately unauthorized principal (or the same key with an explicit `kms:Sign` deny statement attached). Confirm the result is `SigningProviderError("kms_signing_request_failed")`, exactly as the existing exception handling in `signing.py:251-258` specifies, never a silent fallback to a different provider or algorithm.
7. **Unavailable-service behavior**: point the client at an unreachable endpoint (an invalid region or a deliberately wrong endpoint URL) and confirm the identical `SigningProviderError` path fires, rather than an unhandled `botocore` exception escaping past this class's own boundary, or worse, a silent fallback to `LocalDevelopmentSigner`. `production_config.py`'s existing rejection of `key_source=development` in production already prevents that specific fallback structurally; this step confirms the KMS provider itself fails closed on its own, as defense in depth.
8. **Compatibility with existing artifacts**: with this real KMS key now registered as one more `VerificationKey` in a `SigningKeyRegistry` alongside a `LocalDevelopmentSigner` fixture key (exactly the dual-key configuration a real cutover would run during a transition period), confirm a permit signed earlier by the local Ed25519 key still verifies correctly through `TrustScanSigner.verify()`, which resolves by `signing_key_id` per key, not by whichever provider is currently "active". This is the multi-algorithm registry design already proven with two local keys; this step is the first time one of the two is a real KMS-backed key.

## Teardown

Immediately after step 8: `aws kms schedule-key-deletion --key-id <arn> --pending-window-in-days 7` (the minimum AWS allows). The key enters `PendingDeletion` state and cannot be used again; verify with `aws kms describe-key` that its `KeyState` is `PendingDeletion` before considering this verification closed.

## Cost

Every action above (`CreateKey`, `GetPublicKey`, `Sign` x2, `DescribeKey`, `ScheduleKeyDeletion`) is a handful of API calls: KMS asymmetric request pricing is $0.03 per 10,000 requests, so this verification's request cost is a fraction of a cent. The unavoidable cost is the key's own $1/month storage charge, prorated: with the minimum 7-day `PendingDeletion` window, that's roughly $0.23 regardless of how quickly the 8 steps themselves run, charged for the key existing at all, not for how it's used. Total real-AWS cost for this entire verification: under $0.25.

## What this plan does not verify

Real production traffic volume or latency under sustained load; multi-region failover; a real IAM role attached to a real ECS Fargate task (this plan uses a human- or CI-assumed role, since ECS itself is not provisioned — that is a separate decision, tracked under the same "real infrastructure" dependency as M18). This plan proves the code is correct against real AWS KMS; it does not simulate production traffic patterns.

## Owner action needed to run this

Approve: (1) the ~$0.25 spend, (2) creating the one-time GitHub OIDC IAM role (or running the assume-role sequence by hand instead), (3) the exact IAM policy above. Nothing runs until that approval is explicit; this document is the proposal, not the execution.
