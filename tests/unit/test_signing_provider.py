"""Tests for the provider-neutral signing abstraction (Slice 12,
requirements 2-3): `LocalDevelopmentSigner`, `KmsSigningProvider`
against a fake duck-typed KMS client (no `boto3` import anywhere in
this codebase), and `SigningKeyRegistry`'s key-ID-based verification,
rotation (retired-but-still-verifiable), and disabled-key rejection.
"""

from __future__ import annotations

import unittest

from webguard_api.signing import (
    KmsSigningProvider,
    LocalDevelopmentSigner,
    SigningKeyRegistry,
    SigningProviderError,
    VerificationKey,
)


class LocalDevelopmentSignerTests(unittest.TestCase):
    def test_sign_and_self_verify_round_trip(self) -> None:
        provider = LocalDevelopmentSigner(bytes(range(32)))
        message = b"trustscan-claims-bytes"
        signature = provider.sign(message)
        registry = SigningKeyRegistry(provider)
        registry.verify_by_key_id(provider.key_id, message, signature)

    def test_algorithm_is_ed25519(self) -> None:
        provider = LocalDevelopmentSigner(bytes(range(32)))
        self.assertEqual(provider.algorithm, "Ed25519")

    def test_rejects_wrong_length_key(self) -> None:
        with self.assertRaises(SigningProviderError) as caught:
            LocalDevelopmentSigner(bytes(range(16)))
        self.assertEqual(caught.exception.code, "trustscan_signing_key_invalid")


class FakeKmsClient:
    """Duck-typed stand-in for `boto3.client("kms")` -- exercises
    `KmsSigningProvider` without any AWS SDK dependency or network
    access. Uses a real Ed25519... no: KMS cannot do Ed25519, so this
    fake simulates ECDSA_SHA_256 opaquely (the exact bytes returned
    are irrelevant to this test; what matters is that
    `KmsSigningProvider` calls the client with the documented
    parameter shape and surfaces its response, or normalizes its
    failure)."""

    def __init__(self, *, fail_sign: bool = False, fail_public_key: bool = False) -> None:
        self.fail_sign = fail_sign
        self.fail_public_key = fail_public_key
        self.sign_calls: list[dict] = []
        self.public_key_calls: list[dict] = []

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        self.sign_calls.append(
            {
                "KeyId": KeyId,
                "Message": Message,
                "MessageType": MessageType,
                "SigningAlgorithm": SigningAlgorithm,
            }
        )
        if self.fail_sign:
            raise RuntimeError("simulated KMS outage")
        return {"Signature": b"\x00" * 72, "KeyId": KeyId, "SigningAlgorithm": SigningAlgorithm}

    def get_public_key(self, *, KeyId):
        self.public_key_calls.append({"KeyId": KeyId})
        if self.fail_public_key:
            raise RuntimeError("simulated KMS outage")
        return {"KeyId": KeyId, "PublicKey": b"\x01" * 91}


class KmsSigningProviderTests(unittest.TestCase):
    def test_targets_ecdsa_sha_256_never_claims_ed25519(self) -> None:
        provider = KmsSigningProvider(FakeKmsClient(), key_id="arn:aws:kms:test-key")
        self.assertEqual(provider.algorithm, "ECDSA_SHA_256")
        self.assertNotEqual(provider.algorithm, "Ed25519")

    def test_sign_calls_client_with_documented_shape(self) -> None:
        client = FakeKmsClient()
        provider = KmsSigningProvider(client, key_id="arn:aws:kms:test-key")
        signature = provider.sign(b"message-bytes")
        self.assertEqual(signature, b"\x00" * 72)
        self.assertEqual(
            client.sign_calls,
            [
                {
                    "KeyId": "arn:aws:kms:test-key",
                    "Message": b"message-bytes",
                    "MessageType": "RAW",
                    "SigningAlgorithm": "ECDSA_SHA_256",
                }
            ],
        )

    def test_public_key_material_calls_client(self) -> None:
        client = FakeKmsClient()
        provider = KmsSigningProvider(client, key_id="arn:aws:kms:test-key")
        material = provider.public_key_material()
        self.assertEqual(material, b"\x01" * 91)
        self.assertEqual(client.public_key_calls, [{"KeyId": "arn:aws:kms:test-key"}])

    def test_sign_failure_is_normalized_not_leaked(self) -> None:
        provider = KmsSigningProvider(
            FakeKmsClient(fail_sign=True), key_id="arn:aws:kms:test-key"
        )
        with self.assertRaises(SigningProviderError) as caught:
            provider.sign(b"message-bytes")
        self.assertEqual(caught.exception.code, "kms_signing_request_failed")

    def test_public_key_failure_is_normalized_not_leaked(self) -> None:
        provider = KmsSigningProvider(
            FakeKmsClient(fail_public_key=True), key_id="arn:aws:kms:test-key"
        )
        with self.assertRaises(SigningProviderError) as caught:
            provider.public_key_material()
        self.assertEqual(caught.exception.code, "kms_public_key_request_failed")

    def test_no_boto3_import_required(self) -> None:
        import sys

        self.assertNotIn("boto3", sys.modules)


class SigningKeyRegistryLifecycleTests(unittest.TestCase):
    """Requirement 3: active key, key ID, verification-by-key-ID,
    rotation, disabled key, retired verification key, deterministic
    verification behavior."""

    def test_unknown_key_id_fails_closed(self) -> None:
        registry = SigningKeyRegistry(LocalDevelopmentSigner(bytes(range(32))))
        with self.assertRaises(SigningProviderError) as caught:
            registry.verify_by_key_id("sha256:not-a-real-key", b"message", b"signature")
        self.assertEqual(caught.exception.code, "trustscan_signing_key_unknown")

    def test_rotation_retired_key_still_verifies_its_own_old_signatures(self) -> None:
        old_provider = LocalDevelopmentSigner(bytes(range(32)))
        message = b"permit-issued-before-rotation"
        old_signature = old_provider.sign(message)

        new_provider = LocalDevelopmentSigner(bytes(range(1, 33)))
        registry = SigningKeyRegistry(new_provider)
        registry.add_verification_key(
            VerificationKey(
                key_id=old_provider.key_id,
                algorithm=old_provider.algorithm,
                public_key_material=old_provider.public_key_material(),
                status="retired",
            )
        )

        # Old permit, signed under the now-retired key, still verifies.
        registry.verify_by_key_id(old_provider.key_id, message, old_signature)

        # New signatures are issued and verified under the new active key.
        new_message = b"permit-issued-after-rotation"
        new_signature = registry.active.sign(new_message)
        registry.verify_by_key_id(registry.active.key_id, new_message, new_signature)
        self.assertNotEqual(registry.active.key_id, old_provider.key_id)

    def test_disabled_key_is_rejected_even_if_signature_is_genuinely_valid(self) -> None:
        provider = LocalDevelopmentSigner(bytes(range(32)))
        message = b"message-signed-before-emergency-revocation"
        signature = provider.sign(message)
        registry = SigningKeyRegistry(provider)

        registry.set_status(provider.key_id, "disabled")

        with self.assertRaises(SigningProviderError) as caught:
            registry.verify_by_key_id(provider.key_id, message, signature)
        self.assertEqual(caught.exception.code, "trustscan_signing_key_disabled")

    def test_tampered_message_fails_verification_deterministically(self) -> None:
        provider = LocalDevelopmentSigner(bytes(range(32)))
        registry = SigningKeyRegistry(provider)
        signature = provider.sign(b"original-message")

        with self.assertRaises(SigningProviderError) as caught:
            registry.verify_by_key_id(provider.key_id, b"tampered-message", signature)
        self.assertEqual(caught.exception.code, "trustscan_signature_invalid")

    def test_set_status_on_unknown_key_fails_closed(self) -> None:
        registry = SigningKeyRegistry(LocalDevelopmentSigner(bytes(range(32))))
        with self.assertRaises(SigningProviderError) as caught:
            registry.set_status("sha256:not-a-real-key", "disabled")
        self.assertEqual(caught.exception.code, "trustscan_signing_key_unknown")

    def test_verification_key_documents_never_contain_private_material(self) -> None:
        provider = LocalDevelopmentSigner(bytes(range(32)))
        registry = SigningKeyRegistry(provider)
        documents = registry.verification_key_documents()
        self.assertEqual(len(documents), 1)
        self.assertNotIn(bytes(range(32)).hex(), str(documents))
        self.assertEqual(documents[0]["status"], "active")


if __name__ == "__main__":
    unittest.main()
