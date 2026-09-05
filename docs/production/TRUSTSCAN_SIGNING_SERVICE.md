# TrustScan Signing Service: CloudHSM-Backed Ed25519 (Slice 18)

## Status

**Implemented, not deployed.** Every class, config path, and test named below exists and passes in this repository. No CloudHSM cluster has been provisioned (`infra/terraform/cloudhsm.tf` is reviewed, unapplied IaC), and the PKCS#11 adapter that would actually talk to one has never run against real CloudHSM hardware, or even a real PKCS#11 driver library: no cluster and no software module are available in this environment. Do not read anything in this document as a claim that real CloudHSM signing has been validated; §5 states the honesty boundary precisely.

This document implements the decision `docs/production/TRUSTSCAN_PRODUCTION_SIGNING.md` made in Slice 14: **Option A, AWS CloudHSM-backed Ed25519**. That document is now updated to point here for the implementation; it still owns the *decision rationale* (why CloudHSM over KMS/ECDSA, why not a bare protected-key service) and is not repeated here.

## 1. Why a dedicated service, not direct HSM access from the API/worker

Requirement 2's own instruction: *"do not give every API/worker process direct unrestricted HSM access."* Two production processes (`webguard-api serve`, `webguard-api worker`) already construct a `TrustScanSigner` each: the API to issue permits (`service.py`'s `sign(claims)`), the worker to sign Safety Receipts at scan completion (`executor.py`). Handing each process its own PKCS#11 session and CloudHSM crypto-user credentials would mean two independent production processes, each with a broad HSM session, for a workload that only ever needs three narrow operations: sign, get the active key ID, get a public key.

Instead:

```
WebGuard API / worker  -->  TrustScan Signing Service  -->  CloudHSM
        (bearer HTTP)              (PKCS#11)
```

The signing service (`apps/api/src/webguard_api/signing_service.py`, run via `webguard-api signing-service --key-source cloudhsm`) is the *only* process holding a PKCS#11 session. Its HTTP surface mirrors `signing.py`'s `SigningProvider` protocol exactly, and nothing more:

| Method | Path | Maps to |
|---|---|---|
| `POST` | `/v1/sign` | `SigningProvider.sign(message)` |
| `GET` | `/v1/active-key-id` | `SigningKeyRegistry.active.key_id` |
| `GET` | `/v1/public-key/{id}` | `SigningKeyRegistry.verification_key(id)` |

There is no `/v1/encrypt`, `/v1/decrypt`, `/v1/keys`, `/v1/rotate`, or `/v1/disable` endpoint: `tests/unit/test_cloudhsm_signing.py::SigningServiceHandlerTests` asserts every one of those 404s. Key lifecycle (§4) is a config-and-restart operation on the signing service's own host, deliberately not a remotely-triggerable HTTP mutation: exposing one would need its own strong authorization model this narrow interface is not trying to be.

Authentication is a single shared bearer secret (`WEBGUARD_SIGNING_SERVICE_BEARER_TOKEN`), constant-time compared (`hmac.compare_digest`). This service is never intended to be reachable from the public Internet (see `docs/production/PUBLIC_EDGE_SECURITY.md`'s ingress model): the bearer secret is defense-in-depth, not the sole boundary; real network isolation (a private subnet, and the security group in `cloudhsm.tf` that only accepts CloudHSM client traffic from this service's own security group) is the primary one.

## 2. Preserving the Ed25519 contract exactly

`CloudHsmSigningProvider` (`signing.py`) implements the same `SigningProvider` protocol `LocalDevelopmentSigner`/`KmsSigningProvider` already satisfy: `algorithm = "Ed25519"`, `sign(message) -> bytes`, `public_key_material() -> bytes`, `key_id` derived as `sha256:<hex of SHA-256(public_key_material)>`, identical to every other provider's derivation. Zero change to `SignedTrustScanPermit`, zero dual-algorithm verification period, zero risk of a permit issued under one algorithm being misverified under another: exactly the property that made Option A the recommended v1 path over an ECDSA/KMS migration.

`SigningServiceClient` (`signing.py`) is the API/worker-side counterpart: it also satisfies `SigningProvider`, but delegates every call over `SigningServiceClientProtocol` (a narrow `sign`/`get_active_key_id`/`get_public_key` duck-typed interface) to `SigningServiceHttpClient` (`signing_service.py`), a standard-library-only (`http.client`) transport, matching this codebase's established outbound-HTTP convention (`mail.py`'s `PostmarkHttpClient`).

`ProductionServiceConfig.signing_provider` (`production_config.py`) now accepts exactly `"kms"` or `"cloudhsm_signing_service"`:

- `"kms"` (unchanged since Slice 12): `build_production_components()` constructs `KmsSigningProvider(kms_client, key_id=config.kms_key_id)` directly in the API/worker process.
- `"cloudhsm_signing_service"` (new this slice): `build_production_components()` constructs `SigningServiceHttpClient(base_url=config.signing_service_url, bearer_token=config.signing_service_bearer_token)` and wraps it in `SigningServiceClient`. Requires `WEBGUARD_SIGNING_SERVICE_URL` (absolute `http(s)://`) and `WEBGUARD_SIGNING_SERVICE_BEARER_TOKEN`; `kms_key_id` is present but unvalidated in this branch (there is no KMS key to require).

## 3. Running the signing service

```
webguard-api signing-service --key-source development   # local/dev: LocalDevelopmentSigner, no HSM
webguard-api signing-service --key-source cloudhsm       # production: PKCS#11 against a real cluster
```

`--key-source cloudhsm` calls `build_cloudhsm_signing_provider_from_env()`, which reads:

| Variable | Purpose |
|---|---|
| `WEBGUARD_SIGNING_SERVICE_PKCS11_LIBRARY_PATH` | Path to the CloudHSM PKCS#11 shared library |
| `WEBGUARD_SIGNING_SERVICE_PKCS11_TOKEN_LABEL` | CloudHSM token label |
| `WEBGUARD_SIGNING_SERVICE_PKCS11_PIN` | Crypto User `username:password` PIN, through the existing `SecretProvider` architecture in a real deployment (see §6), never a literal in configuration source |
| `WEBGUARD_SIGNING_SERVICE_PKCS11_PRIVATE_KEY_LABEL` | Label of the Ed25519 private key object on the HSM |
| `WEBGUARD_SIGNING_SERVICE_PKCS11_PUBLIC_KEY_LABEL` | Optional; defaults to the private key's own label |

`python-pkcs11` is imported lazily, inside this one function only, never at package level, mirroring `cli.py`'s own lazy `import boto3` for the identical reason: the hash-locked dependency set (`requirements-ci.lock`) stays minimal regardless of which production signing path an operator chooses. It is not, and must not become, a package-level dependency of `webguard_api`.

## 4. Key lifecycle

Entirely inherited, unchanged, from `SigningKeyRegistry` (`signing.py`, built in Slice 12): this slice adds no new lifecycle machinery, only a new provider the registry can hold:

- **Active/retired/disabled states**: `SigningKeyRegistry` tracks exactly one active provider plus zero or more retired `VerificationKey` records. A retired key still verifies (an in-flight permit signed before rotation is not suddenly unverifiable); a disabled key does neither.
- **Rotation**: provision a new CloudHSM key pair (or a new KMS key), point a fresh `SigningKeyRegistry` construction at it, retire the old key's `VerificationKey` rather than deleting it. This is a restart-time operation on whichever process constructs the registry (the signing service, in the CloudHSM path), not a live HTTP mutation (§1).
- **Emergency disable**: mark a compromised key `disabled` in the registry; no permit signed under it verifies again. Since the signing service is the only process with signing capability in the CloudHSM path, revoking its network access (the security group in `cloudhsm.tf`) or its bearer token is an equally effective, faster circuit-breaker than a registry change requiring a restart.
- **Raw private-key material never leaves CloudHSM.** `CloudHsmSigningProvider.sign()` calls the PKCS#11 adapter's `sign()`, which calls `private_key.sign(...)`: the private key object lives only inside the HSM; the adapter only ever holds a PKCS#11 *handle* to it, never exported key bytes. Nothing in the API, PostgreSQL, Redis, logs, reports, object storage, or application configuration ever contains the private key.

## 5. Honesty boundary: what has and has not been proven

**Proven, by real tests in this repository:**

- `tests/unit/test_cloudhsm_signing.py`: `CloudHsmSigningProvider` round-trips real Ed25519 signatures (via `FakePkcs11Ed25519Key`, which performs genuine Ed25519 cryptography through the `cryptography` library, only the HSM/PKCS#11 *hardware* boundary is faked, not the math), correctly derives `key_id`, translates signing failures, rejects a malformed public key, and round-trips through a real `TrustScanSigner.from_registry(...)`. The signing service's HTTP handler is proven to require auth, reject the wrong token, correctly cross-verify a sign/verify round trip, 404 on an unknown key, and, critically, 404 on every non-sign/read endpoint (§1).
- `tests/integration/test_signing_service_e2e.py`: a full production-component-assembly chain (`webguard_production_harness.run_production_stack(..., signing_mode="cloudhsm_signing_service")`) against **real PostgreSQL**: a permit is issued and signed through a real, running `SigningServiceServer` over real HTTP, a scan job consumes it, the worker verifies the permit and produces a signed Safety Receipt, all through the exact `SigningServiceClient`/`SigningServiceHttpClient` code path production uses.

**Not proven, stated precisely rather than left implicit:**

- The harness above backs `SigningServiceServer` with `LocalDevelopmentSigner`, not `CloudHsmSigningProvider`: it proves the *service boundary and HTTP wiring* end-to-end against a real database, not CloudHSM itself. No test in this repository constructs `build_cloudhsm_signing_provider_from_env()` against anything but nothing (there is no PKCS#11 library or cluster available here to construct it against at all).
- The single riskiest assumption in `build_cloudhsm_signing_provider_from_env()`'s PKCS#11 adapter, how a CloudHSM-reported `EC_POINT` attribute encodes an Ed25519 public key (a bare 32-byte point vs. a DER-wrapped `0x04 0x20 <point>` octet string), is a defensive guess with both branches handled, marked unverified inline in `signing_service.py`, and must be confirmed against a real cluster before any production cutover.
- No CloudHSM cluster has ever been created, initialized, or had a key pair provisioned on it by this project. §"The activation ceremony Terraform cannot express" in `infra/terraform/cloudhsm.tf` names the exact manual steps (CSR signing, crypto-officer/crypto-user setup) that remain entirely undone.

## 6. Secrets

Every credential this service needs (the bearer token and, in the CloudHSM path, the PKCS#11 PIN) is read from environment variables at process startup, sourced in a real deployment through the existing `SecretProvider`/Secrets Manager architecture (`secret_provider.py`), never hardcoded and never logged. No secret appears in `infra/terraform/` source or Git (requirement 19; see `docs/production/PUBLIC_EDGE_SECURITY.md` §"Secrets" for the full inventory across every Slice 18 component).
