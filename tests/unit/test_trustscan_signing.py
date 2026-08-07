from __future__ import annotations

import base64
import unittest
from dataclasses import replace
from datetime import timedelta

from webguard_api import PersistedTrustScanPermit, TrustScanPermitError, TrustScanSigner, validate_permit_use
from webguard_contracts import ScanJobMode, TrustScanPermitClaims

from tests.unit.service_test_support import AUTH_ID, NOW, ORG_ID, OWNER_ID, TARGET, authorization


class TrustScanSigningTests(unittest.TestCase):
    def claims(self) -> TrustScanPermitClaims:
        auth = authorization()
        return TrustScanPermitClaims(
            permit_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
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

    def test_ed25519_signature_verifies(self) -> None:
        signer = TrustScanSigner(bytes(range(32)))
        permit = signer.sign(self.claims())
        signer.verify(permit)
        self.assertEqual(permit.signature_algorithm, "Ed25519")
        self.assertTrue(signer.key_id.startswith("sha256:"))

    def test_changed_claims_fail_signature_verification(self) -> None:
        signer = TrustScanSigner(bytes(range(32)))
        permit = signer.sign(self.claims())
        changed = replace(
            permit,
            claims=replace(permit.claims, maximum_request_attempts=14),
        )
        with self.assertRaises(TrustScanPermitError) as caught:
            signer.verify(changed)
        self.assertEqual(caught.exception.code, "trustscan_permit_signature_invalid")

    def test_noncanonical_base64url_signature_is_rejected(self) -> None:
        signer = TrustScanSigner(bytes(range(32)))
        permit = signer.sign(self.claims())
        raw = permit.signature.encode("ascii")
        padding = b"=" * ((4 - len(raw) % 4) % 4)
        decoded = base64.urlsafe_b64decode(raw + padding)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        alternate = None
        for character in alphabet:
            if character == permit.signature[-1]:
                continue
            candidate = (permit.signature[:-1] + character).encode("ascii")
            candidate_padding = b"=" * ((4 - len(candidate) % 4) % 4)
            try:
                candidate_decoded = base64.urlsafe_b64decode(candidate + candidate_padding)
            except Exception:
                continue
            if candidate_decoded == decoded:
                alternate = permit.signature[:-1] + character
                break
        self.assertIsNotNone(alternate)
        changed = replace(permit, signature=alternate)
        with self.assertRaises(TrustScanPermitError) as caught:
            signer.verify(changed)
        self.assertEqual(caught.exception.code, "trustscan_permit_signature_non_canonical")

    def test_other_key_is_rejected(self) -> None:
        first = TrustScanSigner(bytes(range(32)))
        second = TrustScanSigner(bytes(range(1, 33)))
        with self.assertRaises(TrustScanPermitError) as caught:
            second.verify(first.sign(self.claims()))
        self.assertEqual(caught.exception.code, "trustscan_permit_signing_key_mismatch")

    def test_revoked_permit_is_rejected_before_execution(self) -> None:
        signer = TrustScanSigner(bytes(range(32)))
        permit = signer.sign(self.claims())
        record = PersistedTrustScanPermit(
            permit=permit,
            revoked_at=NOW,
            revoked_by=OWNER_ID,
        )
        with self.assertRaises(TrustScanPermitError) as caught:
            validate_permit_use(
                record,
                signer=signer,
                organization_id=ORG_ID,
                authorization=authorization(),
                target=TARGET,
                mode=ScanJobMode.CRAWL,
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "trustscan_permit_revoked")

    def test_public_key_document_contains_no_private_seed(self) -> None:
        signer = TrustScanSigner(bytes(range(32)))
        document = signer.verification_key_document()
        self.assertEqual(document["algorithm"], "Ed25519")
        self.assertEqual(document["encoding"], "base64url-raw")
        self.assertNotIn("private_key", document)
        self.assertNotIn(bytes(range(32)).hex(), str(document))


if __name__ == "__main__":
    unittest.main()
