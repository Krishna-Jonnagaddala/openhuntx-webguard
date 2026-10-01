"""TrustScan permit signing, verification, and runtime policy checks."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone

from webguard_contracts import (
    OwnedTargetAuthorization,
    ScanJobMode,
    SignedTrustScanPermit,
    SignedTrustScanSafetyReceipt,
    TrustScanPermitClaims,
    TrustScanSafetyReceiptClaims,
)

from .signing import LocalDevelopmentSigner, SigningKeyRegistry, SigningProviderError


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
    """Signer and verifier for locally issued TrustScan permits and
    safety receipts, over a provider-neutral ``SigningKeyRegistry``
    (Slice 12 requirements 2-3).

    The default constructor (``TrustScanSigner(private_key_bytes)``)
    is unchanged from every prior slice -- it builds a
    ``LocalDevelopmentSigner`` from a raw 32-byte Ed25519 key exactly
    as before, so every existing call site across the CLI, service,
    scheduler, and test suite keeps working with zero changes. Use
    ``TrustScanSigner.from_registry`` to back this with a
    ``KmsSigningProvider`` or any other ``SigningProvider`` instead.

    Verification now resolves by the key ID carried in the signed
    object (``permit.signing_key_id`` / ``receipt.signing_key_id``)
    against the registry's known keys, rather than only accepting the
    currently active key -- this is what makes key rotation possible:
    a permit signed under a since-retired key still verifies (until it
    naturally expires), while a disabled key is rejected
    unconditionally. See ``webguard_api.signing`` for the full
    lifecycle model.
    """

    def __init__(self, private_key_bytes: bytes) -> None:
        try:
            provider = LocalDevelopmentSigner(private_key_bytes)
        except SigningProviderError as exc:
            raise TrustScanPermitError(exc.code, exc.message) from exc
        self._registry = SigningKeyRegistry(provider)
        self.key_id = provider.key_id

    @classmethod
    def from_registry(cls, registry: SigningKeyRegistry) -> "TrustScanSigner":
        instance = cls.__new__(cls)
        instance._registry = registry
        instance.key_id = registry.active.key_id
        return instance

    def sign(self, claims: TrustScanPermitClaims) -> SignedTrustScanPermit:
        signature = self._registry.active.sign(claims.signing_bytes)
        return SignedTrustScanPermit(
            claims=claims,
            signing_key_id=self._registry.active.key_id,
            signature=_b64url_encode(signature),
            signature_algorithm=self._registry.active.algorithm,
        )

    def verify(self, permit: SignedTrustScanPermit) -> None:
        signature = _b64url_decode_canonical(permit.signature)
        try:
            self._registry.verify_by_key_id(
                permit.signing_key_id, permit.claims.signing_bytes, signature
            )
        except SigningProviderError as exc:
            code = (
                "trustscan_permit_signing_key_mismatch"
                if exc.code in ("trustscan_signing_key_unknown", "trustscan_signing_key_disabled")
                else "trustscan_permit_signature_invalid"
            )
            message = (
                "TrustScan permit was not signed by a trusted service key."
                if code == "trustscan_permit_signing_key_mismatch"
                else "TrustScan permit signature verification failed."
            )
            raise TrustScanPermitError(code, message) from exc
        self._require_declared_algorithm_matches_key(
            permit.signing_key_id,
            permit.signature_algorithm,
            error_code="trustscan_permit_signature_algorithm_mismatch",
            message="TrustScan permit's declared signature algorithm does not match its signing key's registered algorithm.",
        )

    def sign_safety_receipt(
        self, claims: TrustScanSafetyReceiptClaims
    ) -> SignedTrustScanSafetyReceipt:
        signature = self._registry.active.sign(claims.signing_bytes)
        return SignedTrustScanSafetyReceipt(
            claims=claims,
            signing_key_id=self._registry.active.key_id,
            signature=_b64url_encode(signature),
            signature_algorithm=self._registry.active.algorithm,
        )

    def verify_safety_receipt(
        self, receipt: SignedTrustScanSafetyReceipt
    ) -> None:
        signature = _b64url_decode_canonical(receipt.signature)
        try:
            self._registry.verify_by_key_id(
                receipt.signing_key_id, receipt.claims.signing_bytes, signature
            )
        except SigningProviderError as exc:
            code = (
                "trustscan_safety_receipt_signing_key_mismatch"
                if exc.code in ("trustscan_signing_key_unknown", "trustscan_signing_key_disabled")
                else "trustscan_safety_receipt_signature_invalid"
            )
            message = (
                "TrustScan safety receipt was not signed by a trusted service key."
                if code == "trustscan_safety_receipt_signing_key_mismatch"
                else "TrustScan safety receipt signature verification failed."
            )
            raise TrustScanPermitError(code, message) from exc
        self._require_declared_algorithm_matches_key(
            receipt.signing_key_id,
            receipt.signature_algorithm,
            error_code="trustscan_safety_receipt_signature_algorithm_mismatch",
            message="TrustScan safety receipt's declared signature algorithm does not match its signing key's registered algorithm.",
        )

    def _require_declared_algorithm_matches_key(
        self, key_id: str, declared_algorithm: str, *, error_code: str, message: str
    ) -> None:
        """A permit's/receipt's ``signature_algorithm`` field is
        self-reported by whoever produced the JSON (attacker-
        controlled on anything loaded from external input); the actual
        cryptographic check just above this call always verifies
        against the key's own *registered* algorithm
        (``VerificationKey.algorithm``), never this field, so a
        mismatch here can never let a signature verify under the
        wrong algorithm. What it CAN do, if left unchecked, is carry a
        self-report that lies about which algorithm was actually used:
        caught here, after a genuine cryptographic pass, so this
        never masks a real signature failure with a less specific
        error. Resolving by ``key_id`` cannot miss: this is only
        reached after ``verify_by_key_id`` already resolved that exact
        key successfully."""

        key = self._registry.verification_key(key_id)
        if key is None:
            raise AssertionError("verify_by_key_id just resolved this same key_id")  # unreachable
        if key.algorithm != declared_algorithm:
            raise TrustScanPermitError(error_code, message)

    def verification_key_document(self) -> dict[str, str]:
        for document in self._registry.verification_key_documents():
            if document["key_id"] == self._registry.active.key_id:
                return document
        raise AssertionError("active key missing from its own registry")  # unreachable

    def verification_key_documents(self) -> list[dict[str, str]]:
        return self._registry.verification_key_documents()


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


def active_checks_authorized(
    record: PersistedTrustScanPermit,
    check_ids: tuple[str, ...],
) -> bool:
    """Return whether every requested active-detector ID is authorized by
    this permit's active_checks claim.

    An empty check_ids tuple is trivially authorized (no active checks
    requested). A permit whose own active_checks claim is empty authorizes
    nothing -- this is the fail-closed default for every existing and newly
    issued permit that does not explicitly opt in.
    """

    claims = record.permit.claims
    return all(check_id in claims.active_checks for check_id in check_ids)


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
    "active_checks_authorized",
    "validate_permit_scope",
    "validate_permit_use",
]
