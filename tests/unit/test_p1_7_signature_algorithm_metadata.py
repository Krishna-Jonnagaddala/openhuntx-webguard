"""P1-7 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): proves
``TrustScanSigner.sign()``/``sign_safety_receipt()`` self-report the
signing provider's own actual algorithm rather than the previously
hardcoded ``"Ed25519"`` literal, and that ``SignedTrustScanPermit``/
``SignedTrustScanSafetyReceipt`` accept a second, honestly-labeled
algorithm (``ECDSA_SHA_256``, matching ``KmsSigningProvider``) without
weakening what a signature must cryptographically satisfy to verify.

Uses a duck-typed KMS client performing real ECDSA_SHA_256 signing
in-process via a real NIST P-256 key pair (no real AWS KMS, no boto3
import anywhere in this test or the modules it exercises) -- the same
technique this project already uses for CloudHSM
(``test_cloudhsm_signing.py``) and the KMS provider's own shape tests
(``test_signing_provider.py``'s opaque-byte ``FakeKmsClient``, which
this file does not reuse because those existing tests specifically
assert on that fixture's fixed opaque bytes; a genuine sign/verify
round trip needs a real key pair instead).

``KmsSigningProvider`` is still never wired as TrustScan's active
signer in production (see ``webguard_api.signing``'s own module
docstring); this file proves the contract and signer no longer force
a wrong self-report if that ever changes, not that it has changed.
"""

from __future__ import annotations

import unittest
from datetime import timedelta
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from webguard_api.permits import TrustScanSigner
from webguard_api.signing import KmsSigningProvider, SigningKeyRegistry
from webguard_contracts import (
    ScanJobMode,
    SignedTrustScanPermit,
    SignedTrustScanSafetyReceipt,
    TrustScanPermitClaims,
    TrustScanPermitValidationError,
    TrustScanSafetyReceiptClaims,
    TrustScanSafetyReceiptError,
)

from tests.unit.service_test_support import AUTH_ID, NOW, ORG_ID, OWNER_ID, TARGET, authorization


class RealEcdsaKmsClient:
    """Duck-typed stand-in for ``boto3.client("kms")`` that performs
    genuine ECDSA_SHA_256 signing with an in-process NIST P-256 key,
    returning DER-encoded signatures and a DER SubjectPublicKeyInfo
    public key -- the real shapes AWS KMS's own ``Sign``/
    ``GetPublicKey`` responses use for an ``ECC_NIST_P256`` key, so
    ``webguard_api.signing``'s own ``_verify_ecdsa_sha256`` (which
    calls ``serialization.load_der_public_key``) can verify against it
    for real."""

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        assert SigningAlgorithm == "ECDSA_SHA_256"
        signature = self._private_key.sign(Message, ec.ECDSA(hashes.SHA256()))
        return {"Signature": signature, "KeyId": KeyId, "SigningAlgorithm": SigningAlgorithm}

    def get_public_key(self, *, KeyId):
        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {"KeyId": KeyId, "PublicKey": public_bytes}


def _permit_claims() -> TrustScanPermitClaims:
    auth = authorization()
    return TrustScanPermitClaims(
        permit_id=str(uuid4()),
        organization_id=ORG_ID,
        authorization_id=AUTH_ID,
        authorization_sha256=auth.fingerprint,
        target=TARGET,
        issued_by=OWNER_ID,
        issued_at=NOW,
        not_before=NOW,
        expires_at=NOW + timedelta(days=7),
        permitted_modes=(ScanJobMode.CRAWL, ScanJobMode.SINGLE_PAGE),
        allowed_http_methods=("GET", "HEAD"),
        maximum_request_attempts=15,
        maximum_requests_per_second=1.0,
    )


def _receipt_claims() -> TrustScanSafetyReceiptClaims:
    return TrustScanSafetyReceiptClaims(
        receipt_id=str(uuid4()),
        permit_id=str(uuid4()),
        permit_sha256="a" * 64,
        organization_id=ORG_ID,
        job_id=str(uuid4()),
        scan_id=str(uuid4()),
        target=TARGET,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
        maximum_request_attempts=15,
        maximum_requests_per_second=1.0,
        maximum_concurrency=1,
        requests_attempted=2,
        requests_permitted=2,
        requests_blocked=0,
        responses_429=0,
        responses_5xx=0,
        request_errors=0,
        throttles=1,
        throttle_seconds=1.0,
        circuit_breaker_activations=0,
        scope_violations=0,
        permit_revalidations=3,
        peak_concurrency=1,
        termination_reason="completed",
        safety_policy_respected=True,
    )


class PermitSignatureAlgorithmSelfReportTests(unittest.TestCase):
    def _kms_signer(self) -> TrustScanSigner:
        provider = KmsSigningProvider(RealEcdsaKmsClient(), key_id="arn:aws:kms:test-key")
        registry = SigningKeyRegistry(provider)
        return TrustScanSigner.from_registry(registry)

    def test_ed25519_permit_self_reports_ed25519(self) -> None:
        # Regression: the local-development path (still every real
        # active production signer today) must self-report exactly as
        # it always has -- this fix must not change that.
        signer = TrustScanSigner(bytes(range(32)))
        permit = signer.sign(_permit_claims())
        self.assertEqual(permit.signature_algorithm, "Ed25519")
        signer.verify(permit)

    def test_kms_backed_permit_self_reports_ecdsa_and_verifies(self) -> None:
        signer = self._kms_signer()
        permit = signer.sign(_permit_claims())
        self.assertEqual(permit.signature_algorithm, "ECDSA_SHA_256")
        signer.verify(permit)  # real ECDSA cryptographic verification, must not raise

    def test_kms_backed_permit_tamper_detection_still_works(self) -> None:
        from dataclasses import replace

        from webguard_api import TrustScanPermitError

        signer = self._kms_signer()
        permit = signer.sign(_permit_claims())
        tampered = replace(permit, claims=replace(permit.claims, maximum_request_attempts=1))
        with self.assertRaises(TrustScanPermitError) as caught:
            signer.verify(tampered)
        self.assertEqual(caught.exception.code, "trustscan_permit_signature_invalid")

    def test_unsupported_permit_signature_algorithm_is_still_rejected(self) -> None:
        signer = TrustScanSigner(bytes(range(32)))
        permit = signer.sign(_permit_claims())
        with self.assertRaises(TrustScanPermitValidationError) as caught:
            SignedTrustScanPermit(
                claims=permit.claims,
                signing_key_id=permit.signing_key_id,
                signature=permit.signature,
                signature_algorithm="RSA_PSS_SHA_256",
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_signature_algorithm_invalid")


class SafetyReceiptSignatureAlgorithmSelfReportTests(unittest.TestCase):
    def _kms_signer(self) -> TrustScanSigner:
        provider = KmsSigningProvider(RealEcdsaKmsClient(), key_id="arn:aws:kms:test-key")
        registry = SigningKeyRegistry(provider)
        return TrustScanSigner.from_registry(registry)

    def test_ed25519_receipt_self_reports_ed25519(self) -> None:
        signer = TrustScanSigner(bytes(range(32)))
        receipt = signer.sign_safety_receipt(_receipt_claims())
        self.assertEqual(receipt.signature_algorithm, "Ed25519")
        signer.verify_safety_receipt(receipt)

    def test_kms_backed_receipt_self_reports_ecdsa_and_verifies(self) -> None:
        signer = self._kms_signer()
        receipt = signer.sign_safety_receipt(_receipt_claims())
        self.assertEqual(receipt.signature_algorithm, "ECDSA_SHA_256")
        signer.verify_safety_receipt(receipt)

    def test_kms_backed_receipt_tamper_detection_still_works(self) -> None:
        from dataclasses import replace

        from webguard_api import TrustScanPermitError

        signer = self._kms_signer()
        receipt = signer.sign_safety_receipt(_receipt_claims())
        tampered = replace(receipt, claims=replace(receipt.claims, requests_attempted=99))
        with self.assertRaises(TrustScanPermitError) as caught:
            signer.verify_safety_receipt(tampered)
        self.assertEqual(caught.exception.code, "trustscan_safety_receipt_signature_invalid")

    def test_unsupported_receipt_signature_algorithm_is_still_rejected(self) -> None:
        signer = TrustScanSigner(bytes(range(32)))
        receipt = signer.sign_safety_receipt(_receipt_claims())
        with self.assertRaises(TrustScanSafetyReceiptError) as caught:
            SignedTrustScanSafetyReceipt(
                claims=receipt.claims,
                signing_key_id=receipt.signing_key_id,
                signature=receipt.signature,
                signature_algorithm="RSA_PSS_SHA_256",
            )
        self.assertEqual(caught.exception.code, "trustscan_safety_receipt_signature_algorithm_invalid")


if __name__ == "__main__":
    unittest.main()
