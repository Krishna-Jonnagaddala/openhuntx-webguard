"""Private external storage for long-lived WebGuard service secrets."""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


SERVICE_SECRET_FILENAME = "service-secrets.json"  # noqa: S105
SERVICE_SECRET_DOCUMENT_TYPE = "webguard_service_secrets"  # noqa: S105
SERVICE_SECRET_DOCUMENT_VERSION = 1

CURSOR_SECRET_NAME = "pagination_cursor_hmac"  # noqa: S105
TRUSTSCAN_SECRET_NAME = "trustscan_ed25519_private_key_v1"  # noqa: S105

_MAXIMUM_SECRET_DOCUMENT_BYTES = 4096


def default_service_secret_path(database_path: Path) -> Path:
    """Return the private secret-file path associated with one database."""

    database = Path(database_path).expanduser()
    return database.with_name(
        f"{database.name}.{SERVICE_SECRET_FILENAME}"
    )


class ServiceSecretError(ValueError):
    """Controlled service-secret filesystem or document failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class ServiceSecrets:
    """Validated private service-signing material."""

    cursor_signing_key: bytes
    trustscan_signing_private_key: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.cursor_signing_key, bytes)
            or len(self.cursor_signing_key) != 32
            or not isinstance(self.trustscan_signing_private_key, bytes)
            or len(self.trustscan_signing_private_key) != 32
        ):
            raise ServiceSecretError(
                "service_secret_document_invalid",
                "Service-secret document contains invalid key material.",
            )

    def encoded_values(self) -> dict[str, str]:
        return {
            CURSOR_SECRET_NAME: base64.urlsafe_b64encode(
                self.cursor_signing_key
            ).decode("ascii"),
            TRUSTSCAN_SECRET_NAME: base64.urlsafe_b64encode(
                self.trustscan_signing_private_key
            ).decode("ascii"),
        }


def _decode_key(value: object) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document contains invalid key material.",
        )

    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(
            encoded,
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document contains invalid key material.",
        ) from exc

    if base64.urlsafe_b64encode(decoded).decode("ascii") != value:
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document contains non-canonical key material.",
        )

    if len(decoded) != 32:
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document contains invalid key material.",
        )

    return decoded


def service_secrets_from_encoded(
    cursor_value: object,
    trustscan_value: object,
) -> ServiceSecrets:
    """Validate legacy encoded key values."""

    return ServiceSecrets(
        cursor_signing_key=_decode_key(cursor_value),
        trustscan_signing_private_key=_decode_key(trustscan_value),
    )


def _document_bytes(material: ServiceSecrets) -> bytes:
    values = material.encoded_values()

    document = {
        "type": SERVICE_SECRET_DOCUMENT_TYPE,
        "version": SERVICE_SECRET_DOCUMENT_VERSION,
        CURSOR_SECRET_NAME: values[CURSOR_SECRET_NAME],
        TRUSTSCAN_SECRET_NAME: values[TRUSTSCAN_SECRET_NAME],
    }

    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _load_document(data: bytes) -> ServiceSecrets:
    if not data or len(data) > _MAXIMUM_SECRET_DOCUMENT_BYTES:
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document is empty or exceeds its size limit.",
        )

    try:
        text = data.decode("ascii")
        document = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document is not valid canonical JSON.",
        ) from exc

    required = {
        "type",
        "version",
        CURSOR_SECRET_NAME,
        TRUSTSCAN_SECRET_NAME,
    }

    if not isinstance(document, dict) or set(document) != required:
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document fields are invalid.",
        )

    if (
        document["type"] != SERVICE_SECRET_DOCUMENT_TYPE
        or document["version"] != SERVICE_SECRET_DOCUMENT_VERSION
    ):
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document type or version is unsupported.",
        )

    material = service_secrets_from_encoded(
        document[CURSOR_SECRET_NAME],
        document[TRUSTSCAN_SECRET_NAME],
    )

    if _document_bytes(material) != data:
        raise ServiceSecretError(
            "service_secret_document_invalid",
            "Service-secret document is not canonical.",
        )

    return material


class ServiceSecretFile:
    """Owner-only regular file containing long-lived service secrets."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()

    def _exists(self) -> bool:
        try:
            return os.path.lexists(self.path)
        except OSError as exc:
            raise ServiceSecretError(
                "service_secret_path_inspection_failed",
                "Unable to inspect the service-secret path.",
            ) from exc

    def _validate_parent_directory(self) -> None:
        """Reject an untrusted directory containing the secret file."""

        directory = self.path.parent

        try:
            metadata = directory.lstat()
        except FileNotFoundError as exc:
            raise ServiceSecretError(
                "service_secret_directory_missing",
                "Service-secret directory is missing.",
            ) from exc
        except OSError as exc:
            raise ServiceSecretError(
                "service_secret_directory_inspection_failed",
                "Unable to inspect the service-secret directory.",
            ) from exc

        if stat.S_ISLNK(metadata.st_mode):
            raise ServiceSecretError(
                "service_secret_directory_symlink_not_allowed",
                "Service-secret directory cannot be a symbolic link.",
            )

        if not stat.S_ISDIR(metadata.st_mode):
            raise ServiceSecretError(
                "service_secret_directory_invalid",
                "Service-secret parent path must be a directory.",
            )

        # Directory write permission controls whether another account can
        # rename, replace, or delete the otherwise owner-only secret file.
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ServiceSecretError(
                "service_secret_directory_permissions_insecure",
                (
                    "Service-secret directory cannot be writable by "
                    "group or other users."
                ),
            )

        if os.name == "posix":
            trusted_owners = {
                0,
                os.geteuid(),
            }

            if metadata.st_uid not in trusted_owners:
                raise ServiceSecretError(
                    "service_secret_directory_owner_untrusted",
                    (
                        "Service-secret directory must be owned by "
                        "the service account or root."
                    ),
                )

    def _read_bytes(self) -> bytes:
        self._validate_parent_directory()
        try:
            metadata = self.path.lstat()
        except FileNotFoundError as exc:
            raise ServiceSecretError(
                "service_secret_file_missing",
                "Service-secret file is missing.",
            ) from exc
        except OSError as exc:
            raise ServiceSecretError(
                "service_secret_path_inspection_failed",
                "Unable to inspect the service-secret file.",
            ) from exc

        if stat.S_ISLNK(metadata.st_mode):
            raise ServiceSecretError(
                "service_secret_symlink_not_allowed",
                "Service-secret file cannot be a symbolic link.",
            )

        if not stat.S_ISREG(metadata.st_mode):
            raise ServiceSecretError(
                "service_secret_not_regular_file",
                "Service-secret path must be a regular file.",
            )

        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ServiceSecretError(
                "service_secret_permissions_insecure",
                "Service-secret file must use owner-only permissions.",
            )

        descriptor: int | None = None

        try:
            flags = os.O_RDONLY

            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC

            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            descriptor = os.open(self.path, flags)

            opened = os.fstat(descriptor)

            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
            ):
                raise ServiceSecretError(
                    "service_secret_file_changed_during_read",
                    (
                        "Service-secret file changed between "
                        "inspection and opening."
                    ),
                )

            if not stat.S_ISREG(opened.st_mode):
                raise ServiceSecretError(
                    "service_secret_not_regular_file",
                    "Service-secret path must be a regular file.",
                )

            if stat.S_IMODE(opened.st_mode) != 0o600:
                raise ServiceSecretError(
                    "service_secret_permissions_insecure",
                    "Service-secret file must use owner-only permissions.",
                )

            handle = os.fdopen(descriptor, "rb")
            descriptor = None

            with handle:
                data = handle.read(_MAXIMUM_SECRET_DOCUMENT_BYTES + 1)

        except ServiceSecretError:
            raise
        except OSError as exc:
            raise ServiceSecretError(
                "service_secret_file_read_failed",
                "Unable to read the service-secret file.",
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

        if len(data) > _MAXIMUM_SECRET_DOCUMENT_BYTES:
            raise ServiceSecretError(
                "service_secret_document_invalid",
                "Service-secret document exceeds its size limit.",
            )

        return data

    def load(self) -> ServiceSecrets:
        """Load and validate an existing secret document."""

        return _load_document(self._read_bytes())

    def load_if_exists(self) -> ServiceSecrets | None:
        """Load an existing document or return None when absent."""

        if not self._exists():
            return None

        return self.load()

    def create(self, material: ServiceSecrets) -> ServiceSecrets:
        """Atomically install a new owner-only secret document."""

        data = _document_bytes(material)

        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
                mode=0o700,
            )
        except OSError as exc:
            raise ServiceSecretError(
                "service_secret_directory_create_failed",
                "Unable to create the service-secret directory.",
            ) from exc

        self._validate_parent_directory()

        descriptor: int | None = None
        temporary_path: Path | None = None

        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
            )
            temporary_path = Path(temporary_name)

            os.fchmod(descriptor, 0o600)

            output = os.fdopen(descriptor, "wb")
            descriptor = None

            with output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())

            try:
                os.link(temporary_path, self.path)
            except FileExistsError:
                return self.load()

            directory_descriptor = os.open(
                self.path.parent,
                os.O_RDONLY
                | (
                    os.O_DIRECTORY
                    if hasattr(os, "O_DIRECTORY")
                    else 0
                ),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)

            return self.load()

        except ServiceSecretError:
            raise
        except OSError as exc:
            raise ServiceSecretError(
                "service_secret_file_write_failed",
                "Unable to persist the service-secret file.",
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass


__all__ = [
    "CURSOR_SECRET_NAME",
    "SERVICE_SECRET_DOCUMENT_TYPE",
    "SERVICE_SECRET_DOCUMENT_VERSION",
    "SERVICE_SECRET_FILENAME",
    "TRUSTSCAN_SECRET_NAME",
    "ServiceSecretError",
    "ServiceSecretFile",
    "ServiceSecrets",
    "default_service_secret_path",
    "service_secrets_from_encoded",
]
