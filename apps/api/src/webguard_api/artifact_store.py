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
a name. ``ObjectStorageArtifactStore`` exists to validate that the
interface is genuinely implementable by something other than a local
path -- every method is fully specified and raises a clear, honest
"not yet implemented" error rather than a stub that silently does
nothing; per this slice's explicit instruction, this does not include a
real S3 SDK integration, since nothing in this slice's scope requires
one to exist yet (no code path in this slice writes to object storage;
`docs/production/INFRASTRUCTURE_REQUIREMENTS.md`'s object-storage
section already tracks that as future work). Production must never
treat a local path as durable cloud storage -- see
``build_production_components``, which never constructs
``LocalArtifactStore`` for a production deployment.
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


class ObjectStorageArtifactStore:
    """Interface validation only (Slice 14 requirement 6) -- proves
    ``ArtifactStore`` is genuinely implementable by a non-filesystem
    backend without committing to a specific provider, SDK dependency,
    or credential model this slice does not need to decide. A real
    implementation (S3, GCS, Azure Blob) is Slice 15 work, once
    ``docs/production/INFRASTRUCTURE_REQUIREMENTS.md``'s object-storage
    requirement is actually being built, not merely anticipated."""

    def __init__(self, *, bucket: str) -> None:
        self._bucket = bucket

    @staticmethod
    def _not_implemented() -> ArtifactStoreError:
        return ArtifactStoreError(
            "object_storage_not_implemented",
            "Object-storage artifact persistence is not implemented yet "
            "(Slice 15). Production deployments must not treat a local "
            "path as durable cloud storage in the meantime.",
        )

    def put(self, reference: str, data: bytes) -> str:
        raise self._not_implemented()

    def get_reference(self, reference: str) -> bytes:
        raise self._not_implemented()

    def exists(self, reference: str) -> bool:
        raise self._not_implemented()

    def delete(self, reference: str) -> None:
        raise self._not_implemented()

    def checksum(self, reference: str) -> str:
        raise self._not_implemented()


__all__ = [
    "ArtifactStore",
    "ArtifactStoreError",
    "LocalArtifactStore",
    "ObjectStorageArtifactStore",
]
