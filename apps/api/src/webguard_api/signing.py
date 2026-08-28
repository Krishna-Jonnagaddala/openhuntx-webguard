"""Provider-neutral signing abstraction for TrustScan permits and safety
receipts (Slice 12, requirements 2-3).

Scope discipline: this module intentionally exposes only what TrustScan
signing actually needs -- ``sign(message)``, public verification
material, a key identifier, and algorithm metadata. It is not a general
encryption API (no encrypt/decrypt, no key-wrapping, no arbitrary KMS
operation surface) because TrustScan has never needed one and adding
one "for later" is exactly the kind of speculative surface this
project's own conventions (see ``docs/audit/trustscan-permit-schema-
policy.md``) reject.

Two concrete ``SigningProvider`` implementations exist:

- ``LocalDevelopmentSigner`` -- an in-process Ed25519 key, identical
  cryptography to every prior slice. This remains a fully supported
  local/dev/test backend; it is not being removed or deprecated by the
  existence of a KMS-backed option, mirroring this slice's own explicit
  instruction not to remove SQLite just because PostgreSQL exists.
- ``KmsSigningProvider`` -- signs through an injected, duck-typed
  ``KmsClientProtocol`` (matching the shape of ``boto3``'s KMS client:
  ``sign(...)`` / ``get_public_key(...)``) rather than importing
  ``boto3`` directly. This keeps the project's minimal, hash-locked
  dependency footprint intact (``requirements-ci.lock`` pins exactly
  four packages today, none of them an AWS SDK) -- any real
  ``boto3.client("kms")`` satisfies this protocol structurally, so
  production code can inject one without this package ever depending
  on it, and tests can inject a fake with zero network access.

The AWS KMS Ed25519 gap (read, do not skip): AWS KMS's asymmetric
``KeySpec`` values are RSA_2048/3072/4096 and
ECC_NIST_P256/P384/P521/SECG_P256K1 -- there is no Ed25519/EdDSA
option in KMS as of this writing. ``KmsSigningProvider`` therefore
targets ``ECDSA_SHA_256`` as its own distinct, honestly-labeled
algorithm; it never claims Ed25519 compatibility and is never wired as
TrustScan's active signer in this slice or silently substituted for
``LocalDevelopmentSigner``. Switching TrustScan's production signing
algorithm from Ed25519 to ECDSA_SHA_256 would change what
``SignedTrustScanPermit.signature`` actually verifies against and is a
separate, explicit permit-schema/security decision this slice does not
make. The recommended future path to a genuine Ed25519 HSM-backed key
is AWS CloudHSM (a general-purpose HSM reachable via PKCS#11, which
does support Ed25519), not KMS -- see
``docs/production/INFRASTRUCTURE_REQUIREMENTS.md``.

``SigningKeyRegistry`` is the lifecycle layer (requirement 3): one
active provider used for new signatures, plus a set of
``VerificationKey`` records (including the active key's own public
half) used to verify by key ID. A key's ``status`` is one of
``"active"`` (used for new signing and accepted for verification),
``"retired"`` (no longer used for new signing, but still accepted for
verification so permits/receipts issued before a rotation continue to
verify until they naturally expire), or ``"disabled"`` (rejected for
verification unconditionally -- the emergency-revocation case, e.g. a
suspected key compromise, where even an unexpired signature must no
longer be trusted). Verification is always looked up by the key ID
carried in the signed object itself (``signing_key_id`` /
``verifying_key_id``), never assumed to be the currently active key --
this is what makes rotation possible at all.

No raw private key material is ever placed in this module's own
state beyond what each provider already holds in memory for its own
signing operation (an Ed25519 private key object for
``LocalDevelopmentSigner``, or nothing at all for
``KmsSigningProvider``, whose private key material never leaves AWS
KMS by design). Nothing here writes to a database, log, report,
checkpoint, or environment dump -- callers are responsible for keeping
it that way, as they already are for the pre-Slice-12 signing key.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

KeyStatus = Literal["active", "retired", "disabled"]


class SigningProviderError(RuntimeError):
    """Controlled signing-provider configuration or operation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@runtime_checkable
class SigningProvider(Protocol):
    """The narrow contract TrustScan signing needs from any key
    custody backend. Deliberately excludes decrypt/encrypt/key-wrap --
    TrustScan only ever signs and verifies."""

    key_id: str
    algorithm: str

    def sign(self, message: bytes) -> bytes:
        """Return a raw signature over ``message``."""

    def public_key_material(self) -> bytes:
        """Return the raw, algorithm-specific public verification
        material (not secret) for this provider's key."""


class LocalDevelopmentSigner:
    """Ed25519 signing backed by an in-process private key. The
    supported local/unit/lab backend -- unchanged cryptography from
    every prior slice, not deprecated by ``KmsSigningProvider``
    existing."""

    algorithm = "Ed25519"

    def __init__(self, private_key_bytes: bytes) -> None:
        if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
            raise SigningProviderError(
                "trustscan_signing_key_invalid",
                "TrustScan Ed25519 private key must contain exactly 32 bytes.",
            )
        try:
            self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        except ValueError as exc:
            raise SigningProviderError(
                "trustscan_signing_key_invalid",
                "TrustScan Ed25519 private key is invalid.",
            ) from exc
        self._public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = f"sha256:{hashlib.sha256(self._public_bytes).hexdigest()}"

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def public_key_material(self) -> bytes:
        return self._public_bytes


@runtime_checkable
class KmsClientProtocol(Protocol):
    """Structural shape of the subset of ``boto3``'s KMS client this
    module calls -- satisfied by a real ``boto3.client("kms")`` without
    this package importing ``boto3``, and by a plain fake in tests."""

    def sign(
        self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ) -> dict:
        ...

    def get_public_key(self, *, KeyId: str) -> dict:
        ...


class KmsSigningProvider:
    """Signs through an injected AWS KMS-shaped client. Targets
    ``ECDSA_SHA_256`` -- KMS has no Ed25519 ``KeySpec`` -- and never
    claims Ed25519 compatibility. Not wired as TrustScan's active
    signer this slice; see module docstring."""

    algorithm = "ECDSA_SHA_256"

    def __init__(self, client: KmsClientProtocol, *, key_id: str) -> None:
        self._client = client
        self.key_id = key_id

    def sign(self, message: bytes) -> bytes:
        try:
            response = self._client.sign(
                KeyId=self.key_id,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm=self.algorithm,
            )
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise SigningProviderError(
                "kms_signing_request_failed",
                "The KMS signing request failed.",
            ) from exc
        signature = response.get("Signature")
        if not isinstance(signature, (bytes, bytearray)):
            raise SigningProviderError(
                "kms_signing_response_invalid",
                "The KMS signing response did not contain a usable signature.",
            )
        return bytes(signature)

    def public_key_material(self) -> bytes:
        try:
            response = self._client.get_public_key(KeyId=self.key_id)
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise SigningProviderError(
                "kms_public_key_request_failed",
                "The KMS get-public-key request failed.",
            ) from exc
        public_key = response.get("PublicKey")
        if not isinstance(public_key, (bytes, bytearray)):
            raise SigningProviderError(
                "kms_public_key_response_invalid",
                "The KMS get-public-key response did not contain usable key material.",
            )
        return bytes(public_key)


def _verify_ed25519(public_key_material: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_material).verify(
            signature, message
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def _verify_ecdsa_sha256(
    public_key_material: bytes, message: bytes, signature: bytes
) -> bool:
    try:
        public_key = serialization.load_der_public_key(public_key_material)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


_VERIFIERS = {
    "Ed25519": _verify_ed25519,
    "ECDSA_SHA_256": _verify_ecdsa_sha256,
}


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """Public-only verification record for one signing key. Never
    holds private key material -- safe to log, persist as
    configuration, or hand to an operator, unlike the signer it
    describes."""

    key_id: str
    algorithm: str
    public_key_material: bytes
    status: KeyStatus = "active"

    def verify(self, message: bytes, signature: bytes) -> bool:
        verifier = _VERIFIERS.get(self.algorithm)
        if verifier is None:
            return False
        return verifier(self.public_key_material, message, signature)


class SigningKeyRegistry:
    """Signing-key lifecycle (requirement 3): one active provider used
    for new signatures, plus every key (active, retired, or disabled)
    known for verification. Verification always resolves by the key ID
    carried in the signed object -- never assumed to be the current
    active key -- which is what makes rotation possible: a permit
    signed under a now-retired key keeps verifying until it naturally
    expires, while a disabled key is rejected unconditionally even if
    otherwise still within its old validity window."""

    def __init__(self, active: SigningProvider) -> None:
        self._active = active
        self._verification_keys: dict[str, VerificationKey] = {
            active.key_id: VerificationKey(
                key_id=active.key_id,
                algorithm=active.algorithm,
                public_key_material=active.public_key_material(),
                status="active",
            )
        }

    @property
    def active(self) -> SigningProvider:
        return self._active

    def add_verification_key(self, key: VerificationKey) -> None:
        """Registers an additional key as verifiable -- typically a
        just-retired former active key, kept around only so permits it
        already signed keep verifying until they expire."""

        self._verification_keys[key.key_id] = key

    def set_status(self, key_id: str, status: KeyStatus) -> None:
        existing = self._verification_keys.get(key_id)
        if existing is None:
            raise SigningProviderError(
                "trustscan_signing_key_unknown",
                "No signing key is registered under the requested key ID.",
            )
        self._verification_keys[key_id] = VerificationKey(
            key_id=existing.key_id,
            algorithm=existing.algorithm,
            public_key_material=existing.public_key_material,
            status=status,
        )

    def verify_by_key_id(self, key_id: str, message: bytes, signature: bytes) -> None:
        key = self._verification_keys.get(key_id)
        if key is None:
            raise SigningProviderError(
                "trustscan_signing_key_unknown",
                "No signing key is registered under the requested key ID.",
            )
        if key.status == "disabled":
            raise SigningProviderError(
                "trustscan_signing_key_disabled",
                "This signing key has been disabled and can no longer be trusted.",
            )
        if not key.verify(message, signature):
            raise SigningProviderError(
                "trustscan_signature_invalid",
                "Signature verification failed.",
            )

    def verification_key_documents(self) -> list[dict[str, str]]:
        return [
            {
                "type": "trustscan_verification_key",
                "algorithm": key.algorithm,
                "key_id": key.key_id,
                "status": key.status,
                "encoding": "base64url-raw",
                "public_key": _b64url_encode(key.public_key_material),
            }
            for key in self._verification_keys.values()
        ]


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


__all__ = [
    "KeyStatus",
    "KmsClientProtocol",
    "KmsSigningProvider",
    "LocalDevelopmentSigner",
    "SigningKeyRegistry",
    "SigningProvider",
    "SigningProviderError",
    "VerificationKey",
]
