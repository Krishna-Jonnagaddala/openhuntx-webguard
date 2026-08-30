"""Artifact-storage interface (Slice 14 requirement 6).

Report and scan-evidence *bodies* (JSON/HTML report files, safety
receipts, owned-target audit files) have always been local filesystem
artifacts referenced by a relative path (``report_ref``, ``audit_ref``,
``safety_receipt_ref``) -- PostgreSQL persists metadata *about* them
(Slice 13), never the bodies themselves. This module names that
filesystem role as an explicit, narrow interface for the first time, so
a future object-storage backend (Slice 15) is a second implementation
of the same four operations, not a redesign of every caller.

Deliberately narrow, per this slice's own instruction: ``put``,
``get_reference``, ``exists``, ``delete``, ``checksum`` -- nothing else.
This is not a general filesystem abstraction (no directory listing, no
streaming, no arbitrary path operations) because nothing in this
project needs one; adding one "for later" is exactly the kind of
speculative surface this project's own conventions reject (see
``docs/audit/trustscan-permit-schema-policy.md``).

``LocalArtifactStore`` is a real, fully-implemented backend -- the
existing filesystem behavior (`apps/api/src/webguard_api/executor.py`'s
`_prepare_private_directory`/`_write_report`), reusable now that it has
a name.

``ObjectStorageArtifactStore`` (completed in Slice 17 requirement 7) is
a real S3-backed implementation, reached through ``S3ClientProtocol`` --
a structural duck-type of the subset of ``boto3``'s S3 client this
module calls, mirroring ``secret_provider.py``'s
``SecretsManagerClientProtocol`` and ``signing.py``'s
``KmsClientProtocol`` exactly. This module never imports ``boto3``
directly (see ``cli.py``'s ``_production_components()`` for the one
call site that does, and why); a real ``boto3.client("s3")`` satisfies
this protocol structurally, and a plain fake satisfies it in tests.
Every artifact is written with server-side encryption
(``ServerSideEncryption="aws:kms"``, a specific customer-managed key --
see ``docs/production/ARTIFACT_STORAGE.md`` §3 for why SSE-KMS was
chosen over SSE-S3). Production must never treat a local path as
durable cloud storage -- see ``build_production_components``, which
never constructs ``LocalArtifactStore`` for a production deployment.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Protocol


class ArtifactStoreError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ArtifactStore(Protocol):
    def put(self, reference: str, data: bytes) -> str:
        """Write ``data`` at ``reference``, returning its SHA-256 checksum."""
        ...

    def get_reference(self, reference: str) -> bytes:
        """Read back the bytes previously stored at ``reference``."""
        ...

    def exists(self, reference: str) -> bool: ...

    def delete(self, reference: str) -> None:
        """Remove the artifact at ``reference``, per retention policy.
        Deleting a reference that does not exist is not an error --
        the postcondition ("this reference is gone") already holds."""
        ...

    def checksum(self, reference: str) -> str:
        """Return the SHA-256 checksum of the artifact at ``reference``,
        without necessarily reading the whole thing into memory twice."""
        ...


def _reject_unsafe_reference(reference: str) -> None:
    if not reference or reference.startswith("/") or ".." in reference.split("/"):
        raise ArtifactStoreError(
            "artifact_reference_invalid",
            "Artifact reference must be a safe, relative path.",
        )


class LocalArtifactStore:
    """The existing filesystem-artifact behavior, named. Every
    operation is confined to ``root`` (an owner-only, real directory --
    never a symlink) via ``_reject_unsafe_reference`` plus a resolved-
    path containment check, matching the safety posture
    ``executor.py``'s own artifact-writing code has always used."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root).expanduser()

    def _resolve(self, reference: str) -> Path:
        _reject_unsafe_reference(reference)
        resolved = (self._root / reference).resolve()
        if self._root.resolve() not in resolved.parents and resolved != self._root.resolve():
            raise ArtifactStoreError(
                "artifact_reference_invalid", "Artifact reference escapes the artifact root."
            )
        return resolved

    def put(self, reference: str, data: bytes) -> str:
        path = self._resolve(reference)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        except OSError as exc:
            raise ArtifactStoreError("artifact_write_failed", f"Unable to write artifact {reference}.") from exc
        return hashlib.sha256(data).hexdigest()

    def get_reference(self, reference: str) -> bytes:
        path = self._resolve(reference)
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ArtifactStoreError("artifact_not_found", f"Artifact {reference} was not found.")
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactStoreError("artifact_not_found", f"Artifact {reference} was not found.") from exc
        except OSError as exc:
            raise ArtifactStoreError("artifact_read_failed", f"Unable to read artifact {reference}.") from exc

    def exists(self, reference: str) -> bool:
        try:
            path = self._resolve(reference)
        except ArtifactStoreError:
            return False
        return path.exists() and not path.is_symlink()

    def delete(self, reference: str) -> None:
        path = self._resolve(reference)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise ArtifactStoreError("artifact_delete_failed", f"Unable to delete artifact {reference}.") from exc

    def checksum(self, reference: str) -> str:
        return hashlib.sha256(self.get_reference(reference)).hexdigest()


class S3ClientProtocol(Protocol):
    """Structural shape of the subset of ``boto3``'s S3 client this
    module calls -- satisfied by a real ``boto3.client("s3")`` without
    this package importing ``boto3``, and by a plain fake in tests."""

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        ServerSideEncryption: str,
        SSEKMSKeyId: str,
        ContentType: str,
    ) -> dict: ...

    def get_object(self, *, Bucket: str, Key: str) -> dict: ...

    def head_object(self, *, Bucket: str, Key: str) -> dict: ...

    def delete_object(self, *, Bucket: str, Key: str) -> dict: ...


def _s3_error_code(exc: Exception) -> str | None:
    """Extract ``response["Error"]["Code"]`` from a real (or fake)
    ``botocore.exceptions.ClientError``-shaped exception without
    importing ``botocore`` to check ``isinstance`` -- structural, like
    everything else this module accepts from an injected client."""

    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return None
    error = response.get("Error")
    return error.get("Code") if isinstance(error, dict) else None


def _translate_s3_error(exc: Exception, reference: str, *, operation: str) -> ArtifactStoreError:
    """Never propagates the raw vendor exception text -- only a fixed,
    already-reviewed message per failure class (requirement 6's "avoid
    leaking vendor-internal responses directly to users", applied here
    to storage the same way it applies to mail)."""

    code = _s3_error_code(exc)
    if code in ("NoSuchKey", "404", "NotFound"):
        return ArtifactStoreError("artifact_not_found", f"Artifact {reference} was not found.")
    if code in ("AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch"):
        return ArtifactStoreError("artifact_storage_access_denied", "Access to the artifact store was denied.")
    return ArtifactStoreError(f"artifact_{operation}_failed", f"Unable to {operation} artifact {reference}.")


class ObjectStorageArtifactStore:
    """Production object-storage backend (Slice 17 requirement 7):
    AWS S3, reached only through the injected, duck-typed
    ``S3ClientProtocol`` -- this class never imports or depends on
    ``boto3`` directly. Every write is server-side encrypted with a
    specific customer-managed KMS key (SSE-KMS, not the AWS-managed
    SSE-S3 default -- see ``docs/production/ARTIFACT_STORAGE.md`` §3
    for the deliberate choice). ``checksum()`` reads the object back
    and hashes it directly, exactly like ``LocalArtifactStore`` --
    S3's own ``ETag`` is not a reliable SHA-256 substitute (it is an
    MD5 only for a single-part, non-KMS-encrypted upload, and this
    store always uses SSE-KMS).

    Object keys are never accepted from a caller-controlled filename --
    every ``reference`` this store ever receives was already
    constructed server-side (``executor.py``'s
    ``organizations/<org-id>/jobs/<job-id>/report.json`` scheme, never
    a customer-supplied string), and ``_reject_unsafe_reference``
    (shared with ``LocalArtifactStore``) rejects path-traversal/
    absolute-path shapes identically for both backends."""

    def __init__(self, *, bucket: str, client: S3ClientProtocol, kms_key_id: str) -> None:
        self._bucket = bucket
        self._client = client
        self._kms_key_id = kms_key_id

    def put(self, reference: str, data: bytes) -> str:
        _reject_unsafe_reference(reference)
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=reference,
                Body=data,
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=self._kms_key_id,
                ContentType="application/json",
            )
        except Exception as exc:  # noqa: BLE001 - translated into a fixed ArtifactStoreError below
            raise _translate_s3_error(exc, reference, operation="write") from exc
        return hashlib.sha256(data).hexdigest()

    def get_reference(self, reference: str) -> bytes:
        _reject_unsafe_reference(reference)
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=reference)
            return response["Body"].read()
        except Exception as exc:  # noqa: BLE001 - translated into a fixed ArtifactStoreError below
            raise _translate_s3_error(exc, reference, operation="read") from exc

    def exists(self, reference: str) -> bool:
        try:
            _reject_unsafe_reference(reference)
            self._client.head_object(Bucket=self._bucket, Key=reference)
            return True
        except ArtifactStoreError:
            return False
        except Exception as exc:  # noqa: BLE001 - translated below, then narrowed to a bool
            translated = _translate_s3_error(exc, reference, operation="check")
            if translated.code == "artifact_not_found":
                return False
            raise translated from exc

    def delete(self, reference: str) -> None:
        _reject_unsafe_reference(reference)
        try:
            self._client.delete_object(Bucket=self._bucket, Key=reference)
        except Exception as exc:  # noqa: BLE001 - translated below; not-found is not an error (see ArtifactStore.delete)
            translated = _translate_s3_error(exc, reference, operation="delete")
            if translated.code != "artifact_not_found":
                raise translated from exc

    def checksum(self, reference: str) -> str:
        return hashlib.sha256(self.get_reference(reference)).hexdigest()


__all__ = [
    "ArtifactStore",
    "ArtifactStoreError",
    "LocalArtifactStore",
    "ObjectStorageArtifactStore",
    "S3ClientProtocol",
]
