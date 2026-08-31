"""Slice 18 requirements 1-4: CloudHSM-backed Ed25519 TrustScan
signing, the dedicated signing-service HTTP boundary, and the client
the main WebGuard API/worker use to reach it -- against a fake,
duck-typed PKCS#11 key handle performing real Ed25519 cryptography
in-process (no real CloudHSM, no python-pkcs11 import anywhere in this
test or in the modules it exercises). This is explicitly NOT a claim
of real CloudHSM validation -- see
docs/audit/production-platform-phase4-edge-signing.md for the honest
scope of what this proves versus what still requires real CloudHSM
hardware/credentials.
"""

from __future__ import annotations

import http.client
import threading
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from webguard_api.permits import TrustScanSigner
from webguard_api.signing import (
    CloudHsmSigningProvider,
    SigningKeyRegistry,
    SigningProviderError,
    SigningServiceClient,
    VerificationKey,
)
from webguard_api.signing_service import (
    SigningServiceHttpClient,
    SigningServiceServer,
    build_signing_service_handler,
)


class FakePkcs11Ed25519Key:
    """Duck-typed stand-in for a real PKCS#11 Ed25519 key handle
    (e.g. a thin adapter over `python-pkcs11`'s `PrivateKey`/
    `PublicKey` pair against a real CloudHSM cluster) -- performs real
    Ed25519 signing in-process via the `cryptography` library, exactly
    like `LocalDevelopmentSigner` already does, and exactly like
    `FakeKmsClient` performs real ECDSA signing for the KMS path. Only
    the HSM hardware/PKCS#11 driver boundary is faked; the actual
    cryptographic operation is real."""

    def __init__(self, *, fail_sign: bool = False) -> None:
        self._private_key = Ed25519PrivateKey.generate()
        self.fail_sign = fail_sign
        self.sign_calls: list[bytes] = []

    def sign(self, message: bytes) -> bytes:
        self.sign_calls.append(message)
        if self.fail_sign:
            raise RuntimeError("simulated HSM session failure")
        return self._private_key.sign(message)

    def public_key_material(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )


class CloudHsmSigningProviderTests(unittest.TestCase):
    def test_sign_and_self_verify_round_trip(self) -> None:
        key_handle = FakePkcs11Ed25519Key()
        provider = CloudHsmSigningProvider(key_handle)
        message = b"trustscan-claims-bytes"
        signature = provider.sign(message)
        registry = SigningKeyRegistry(provider)
        registry.verify_by_key_id(provider.key_id, message, signature)

    def test_algorithm_is_ed25519_preserving_the_existing_format(self) -> None:
        provider = CloudHsmSigningProvider(FakePkcs11Ed25519Key())
        self.assertEqual(provider.algorithm, "Ed25519")

    def test_key_id_is_sha256_of_public_material_not_a_vendor_identifier(self) -> None:
        import hashlib

        key_handle = FakePkcs11Ed25519Key()
        provider = CloudHsmSigningProvider(key_handle)
        expected = f"sha256:{hashlib.sha256(key_handle.public_key_material()).hexdigest()}"
        self.assertEqual(provider.key_id, expected)

    def test_signing_failure_is_translated_not_leaked(self) -> None:
        provider = CloudHsmSigningProvider(FakePkcs11Ed25519Key(fail_sign=True))
        with self.assertRaises(SigningProviderError) as caught:
            provider.sign(b"anything")
        self.assertEqual(caught.exception.code, "cloudhsm_signing_request_failed")

    def test_invalid_public_key_length_is_rejected(self) -> None:
        class _BadKey:
            def public_key_material(self) -> bytes:
                return b"too-short"

            def sign(self, message: bytes) -> bytes:
                return b""

        with self.assertRaises(SigningProviderError) as caught:
            CloudHsmSigningProvider(_BadKey())
        self.assertEqual(caught.exception.code, "cloudhsm_public_key_invalid")

    def test_trustscan_signer_works_identically_over_a_cloudhsm_backed_registry(self) -> None:
        """The whole point of Option A: zero code-path difference for
        the actual permit-signing/verification logic."""
        from datetime import datetime, timedelta, timezone
        from uuid import uuid4

        from webguard_contracts import ScanJobMode, TrustScanPermitClaims

        provider = CloudHsmSigningProvider(FakePkcs11Ed25519Key())
        registry = SigningKeyRegistry(provider)
        signer = TrustScanSigner.from_registry(registry)
        now = datetime(2026, 8, 6, 18, 0, tzinfo=timezone.utc)
        claims = TrustScanPermitClaims(
            permit_id=str(uuid4()),
            organization_id=str(uuid4()),
            authorization_id=str(uuid4()),
            authorization_sha256="a" * 64,
            target="https://example.com/",
            issued_by=str(uuid4()),
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(days=7),
            permitted_modes=(ScanJobMode.SINGLE_PAGE,),
            allowed_http_methods=("GET", "HEAD"),
            maximum_request_attempts=10,
            maximum_requests_per_second=1.0,
            maximum_concurrency=1,
            active_checks=(),
        )
        permit = signer.sign(claims)
        signer.verify(permit)  # must not raise


class SigningServiceHandlerTests(unittest.TestCase):
    """Slice 18 requirement 2: the signing service's own HTTP surface
    is exactly sign/get_public_key/get_active_key_id -- never a
    general encrypt/decrypt or PKCS#11-passthrough endpoint."""

    def setUp(self) -> None:
        self.key_handle = FakePkcs11Ed25519Key()
        self.provider = CloudHsmSigningProvider(self.key_handle)
        self.registry = SigningKeyRegistry(self.provider)
        self.token = "test-signing-service-bearer-token"  # noqa: S105 - a test fixture value
        handler = build_signing_service_handler(self.registry, bearer_token=self.token)
        from http.server import ThreadingHTTPServer

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, token=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        raw = None
        if body is not None:
            import json

            raw = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        import json as json_module

        payload = response.read()
        connection.close()
        return response.status, (json_module.loads(payload) if payload else None)

    def test_sign_requires_authentication(self) -> None:
        status, payload = self.request("POST", "/v1/sign", {"message": "AA"})
        self.assertEqual(status, 401, payload)

    def test_sign_with_wrong_token_is_rejected(self) -> None:
        status, payload = self.request("POST", "/v1/sign", {"message": "AA"}, token="wrong-token")
        self.assertEqual(status, 401, payload)

    def test_sign_and_get_active_key_id_and_get_public_key(self) -> None:
        import base64

        message = b"trustscan-claims-bytes"
        encoded = base64.urlsafe_b64encode(message).rstrip(b"=").decode()
        status, payload = self.request("POST", "/v1/sign", {"message": encoded}, token=self.token)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["key_id"], self.provider.key_id)

        status, active = self.request("GET", "/v1/active-key-id", token=self.token)
        self.assertEqual(status, 200, active)
        self.assertEqual(active["key_id"], self.provider.key_id)

        status, pubkey = self.request("GET", f"/v1/public-key/{self.provider.key_id}", token=self.token)
        self.assertEqual(status, 200, pubkey)
        self.assertEqual(pubkey["algorithm"], "Ed25519")
        self.assertEqual(pubkey["status"], "active")

        # The signature the service returned must actually verify
        # against the public key it also returned -- a real,
        # end-to-end proof, not just "the HTTP calls succeeded".
        decoded_signature = base64.urlsafe_b64decode(payload["signature"] + "==")
        decoded_public_key = base64.urlsafe_b64decode(pubkey["public_key"] + "==")
        verification_key = VerificationKey(
            key_id=pubkey["key_id"], algorithm=pubkey["algorithm"], public_key_material=decoded_public_key
        )
        self.assertTrue(verification_key.verify(message, decoded_signature))

    def test_unknown_public_key_id_is_404(self) -> None:
        status, payload = self.request("GET", "/v1/public-key/sha256:doesnotexist", token=self.token)
        self.assertEqual(status, 404, payload)

    def test_no_encrypt_or_decrypt_or_key_management_endpoint_exists(self) -> None:
        """Requirement 2's own instruction: no general-purpose
        encryption/decryption API, no key-management surface."""
        for path in ("/v1/encrypt", "/v1/decrypt", "/v1/keys", "/v1/rotate", "/v1/disable"):
            with self.subTest(path=path):
                status, _ = self.request("POST", path, {"data": "AA"}, token=self.token)
                self.assertEqual(status, 404)

    def test_oversized_sign_payload_is_rejected(self) -> None:
        import base64

        huge = base64.urlsafe_b64encode(b"x" * 100_000).decode()
        status, payload = self.request("POST", "/v1/sign", {"message": huge}, token=self.token)
        self.assertEqual(status, 400, payload)

    def test_disabled_active_key_cannot_sign_over_http(self) -> None:
        """A disabled key must stop signing immediately, not just stop
        verifying -- disabling the currently-active key (e.g. mid-
        rotation, or in response to a suspected compromise) previously
        had no effect on this endpoint: ``registry.active.sign()`` was
        called unconditionally, ignoring the key's own status."""

        import base64

        # First prove signing genuinely works before disabling, so the
        # subsequent rejection is provably caused by the status change
        # and not some other pre-existing failure.
        message = base64.urlsafe_b64encode(b"trustscan-claims-bytes").rstrip(b"=").decode()
        status, payload = self.request("POST", "/v1/sign", {"message": message}, token=self.token)
        self.assertEqual(status, 200, payload)

        self.registry.set_status(self.provider.key_id, "disabled")

        status, payload = self.request("POST", "/v1/sign", {"message": message}, token=self.token)
        self.assertEqual(status, 500, payload)
        self.assertEqual(payload["error"]["code"], "trustscan_signing_key_disabled")


class SigningServiceEndToEndTests(unittest.TestCase):
    """The full chain requirement 4 asks for, at the unit-test level:
    permit request -> (a real, if fake-HSM-backed) signing service ->
    signed permit -> verification. A fuller proof against the real
    production component-assembly wiring lives in
    tests/integration/test_production_mode_e2e.py."""

    def test_signing_service_client_round_trip_through_a_real_http_server(self) -> None:
        key_handle = FakePkcs11Ed25519Key()
        provider = CloudHsmSigningProvider(key_handle)
        registry = SigningKeyRegistry(provider)
        token = "e2e-signing-service-token"  # noqa: S105 - a test fixture value
        server = SigningServiceServer(registry, bearer_token=token, host="127.0.0.1", port=0)
        server.start()
        try:
            transport = SigningServiceHttpClient(base_url=server.base_url, bearer_token=token)
            client_provider = SigningServiceClient(transport)
            self.assertEqual(client_provider.key_id, provider.key_id)

            message = b"trustscan-signing-bytes"
            signature = client_provider.sign(message)
            # Verify with the REAL local registry (simulating the
            # worker side, which holds its own SigningKeyRegistry --
            # never the private key, only public verification material).
            verifying_registry = SigningKeyRegistry(provider)
            verifying_registry.verify_by_key_id(client_provider.key_id, message, signature)
        finally:
            server.stop()

    def test_wrong_bearer_token_fails_closed(self) -> None:
        key_handle = FakePkcs11Ed25519Key()
        provider = CloudHsmSigningProvider(key_handle)
        registry = SigningKeyRegistry(provider)
        server = SigningServiceServer(registry, bearer_token="correct-token", host="127.0.0.1", port=0)
        server.start()
        try:
            transport = SigningServiceHttpClient(base_url=server.base_url, bearer_token="wrong-token")
            with self.assertRaises(SigningProviderError) as caught:
                SigningServiceClient(transport)
            self.assertEqual(caught.exception.code, "signing_service_unauthorized")
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
