"""TrustScan permit signing, verification, and runtime policy checks."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from webguard_contracts import (
    OwnedTargetAuthorization,
    ScanJobMode,
    SignedTrustScanPermit,
    SignedTrustScanSafetyReceipt,
    TrustScanPermitClaims,
    TrustScanSafetyReceiptClaims,
)


class TrustScanPermitError(ValueError):
    """Controlled TrustScan permit validation or cryptographic failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode_canonical(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise TrustScanPermitError(
            "trustscan_permit_signature_invalid",
            "TrustScan permit signature is invalid.",
        )
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TrustScanPermitError(
            "trustscan_permit_signature_invalid",
            "TrustScan permit signature is invalid.",
        ) from exc
    padding = b"=" * ((4 - len(raw) % 4) % 4)
    try:
        decoded = base64.b64decode(raw + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise TrustScanPermitError(
            "trustscan_permit_signature_invalid",
            "TrustScan permit signature is invalid.",
        ) from exc
    if _b64url_encode(decoded) != value:
        raise TrustScanPermitError(
            "trustscan_permit_signature_non_canonical",
            "TrustScan permit signature is not canonical Base64URL.",
        )
    return decoded


@dataclass(frozen=True, slots=True)
class PersistedTrustScanPermit:
    """Signed permit plus mutable revocation metadata."""

    permit: SignedTrustScanPermit
    revoked_at: datetime | None = None
    revoked_by: str | None = None

    def state_at(self, now: datetime) -> str:
        current = now.astimezone(timezone.utc)
        if self.revoked_at is not None:
            return "revoked"
        if current < self.permit.claims.not_before:
            return "pending"
        if current >= self.permit.claims.expires_at:
            return "expired"
        return "active"

    def to_public_dict(self, *, now: datetime) -> dict[str, object]:
        return {
            "permit": self.permit.to_dict(),
            "state": self.state_at(now),
            "revoked_at": None
            if self.revoked_at is None
            else self.revoked_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "revoked_by": self.revoked_by,
        }


class TrustScanSigner:
    """Ed25519 signer and verifier for locally issued TrustScan permits."""

    def __init__(self, private_key_bytes: bytes) -> None:
        if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
            raise TrustScanPermitError(
                "trustscan_signing_key_invalid",
                "TrustScan Ed25519 private key must contain exactly 32 bytes.",
            )
        try:
            self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        except ValueError as exc:
            raise TrustScanPermitError(
                "trustscan_signing_key_invalid",
                "TrustScan Ed25519 private key is invalid.",
            ) from exc
        self._public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = f"sha256:{hashlib.sha256(self._public_bytes).hexdigest()}"

    def sign(self, claims: TrustScanPermitClaims) -> SignedTrustScanPermit:
        signature = self._private_key.sign(claims.signing_bytes)
        return SignedTrustScanPermit(
            claims=claims,
            signing_key_id=self.key_id,
            signature=_b64url_encode(signature),
        )

    def verify(self, permit: SignedTrustScanPermit) -> None:
        if permit.signing_key_id != self.key_id:
            raise TrustScanPermitError(
                "trustscan_permit_signing_key_mismatch",
                "TrustScan permit was not signed by the active service key.",
            )
        signature = _b64url_decode_canonical(permit.signature)
        if len(signature) != 64:
            raise TrustScanPermitError(
                "trustscan_permit_signature_invalid",
                "TrustScan permit Ed25519 signature must contain exactly 64 bytes.",
            )
        try:
            self._private_key.public_key().verify(signature, permit.claims.signing_bytes)
        except InvalidSignature as exc:
            raise TrustScanPermitError(
                "trustscan_permit_signature_invalid",
                "TrustScan permit signature verification failed.",
            ) from exc

    def sign_safety_receipt(
        self, claims: TrustScanSafetyReceiptClaims
    ) -> SignedTrustScanSafetyReceipt:
        signature = self._private_key.sign(claims.signing_bytes)
        return SignedTrustScanSafetyReceipt(
            claims=claims,
            signing_key_id=self.key_id,
            signature=_b64url_encode(signature),
        )

    def verify_safety_receipt(
        self, receipt: SignedTrustScanSafetyReceipt
    ) -> None:
        if receipt.signing_key_id != self.key_id:
            raise TrustScanPermitError(
                "trustscan_safety_receipt_signing_key_mismatch",
                "TrustScan safety receipt was not signed by the active service key.",
            )
        signature = _b64url_decode_canonical(receipt.signature)
        if len(signature) != 64:
            raise TrustScanPermitError(
                "trustscan_safety_receipt_signature_invalid",
                "TrustScan safety receipt Ed25519 signature must contain exactly 64 bytes.",
            )
        try:
            self._private_key.public_key().verify(
                signature, receipt.claims.signing_bytes
            )
        except InvalidSignature as exc:
            raise TrustScanPermitError(
                "trustscan_safety_receipt_signature_invalid",
                "TrustScan safety receipt signature verification failed.",
            ) from exc

    def verification_key_document(self) -> dict[str, str]:
        return {
            "type": "trustscan_verification_key",
            "algorithm": "Ed25519",
            "key_id": self.key_id,
            "encoding": "base64url-raw",
            "public_key": _b64url_encode(self._public_bytes),
        }


def validate_permit_scope(
    record: PersistedTrustScanPermit,
    *,
    signer: TrustScanSigner,
    organization_id: str,
    authorization: OwnedTargetAuthorization,
    target: str,
    mode: ScanJobMode,
) -> None:
    """Verify signature, revocation, tenant, authorization, target, and mode binding."""

    signer.verify(record.permit)
    claims = record.permit.claims
    if record.revoked_at is not None:
        raise TrustScanPermitError(
            "trustscan_permit_revoked",
            "TrustScan permit is revoked and cannot authorize scanner execution.",
        )
    if claims.organization_id != organization_id:
        raise TrustScanPermitError(
            "trustscan_permit_organization_mismatch",
            "TrustScan permit does not belong to this organization.",
        )
    if claims.authorization_id != authorization.authorization_id:
        raise TrustScanPermitError(
            "trustscan_permit_authorization_mismatch",
            "TrustScan permit does not reference the current authorization.",
        )
    if claims.authorization_sha256 != authorization.fingerprint:
        raise TrustScanPermitError(
            "trustscan_permit_authorization_changed",
            "Underlying authorization changed after the TrustScan permit was issued.",
        )
    if claims.target != target or authorization.target != target:
        raise TrustScanPermitError(
            "trustscan_permit_target_mismatch",
            "TrustScan permit target does not match the requested target.",
        )
    if mode not in claims.permitted_modes:
        raise TrustScanPermitError(
            "trustscan_permit_mode_not_allowed",
            "Requested scan mode is not allowed by the TrustScan permit.",
        )


def validate_permit_use(
    record: PersistedTrustScanPermit,
    *,
    signer: TrustScanSigner,
    organization_id: str,
    authorization: OwnedTargetAuthorization,
    target: str,
    mode: ScanJobMode,
    now: datetime,
) -> None:
    """Fail closed unless a signed permit authorizes this exact execution now."""

    validate_permit_scope(
        record,
        signer=signer,
        organization_id=organization_id,
        authorization=authorization,
        target=target,
        mode=mode,
    )
    state = record.state_at(now)
    if state != "active":
        raise TrustScanPermitError(
            f"trustscan_permit_{state}",
            f"TrustScan permit is {state} and cannot authorize scanner execution.",
        )


__all__ = [
    "PersistedTrustScanPermit",
    "TrustScanPermitError",
    "TrustScanSigner",
    "validate_permit_scope",
    "validate_permit_use",
]
