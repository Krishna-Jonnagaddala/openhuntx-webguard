"""Production deployment configuration (Slice 12 requirement 15).

Deliberately a separate type from ``config.ServiceConfig``, not a
modification of it: ``ServiceConfig`` is the local/unit/lab
configuration (loopback-only, SQLite, local development signing) and
stays exactly as it is -- "do not remove SQLite simply because
PostgreSQL is being introduced. SQLite remains a supported
development/test backend" applies to configuration just as much as to
storage code.

``ProductionServiceConfig`` is typed and fail-closed: every field
required for a real production deployment must be present and valid,
or construction raises immediately. There is no default that silently
falls back to SQLite, an in-memory repository, or local development
signing -- a missing or malformed production setting is a startup
failure, never a quiet downgrade to a weaker backend. This is the
literal requirement ("Production must not silently fall back to:
SQLite, in-memory repositories, development signing if required
production configuration is missing"), enforced by construction rather
than by convention.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DATABASE_POOL_MINIMUM = 1
DEFAULT_DATABASE_POOL_MAXIMUM = 10
MAXIMUM_DATABASE_POOL_MAXIMUM = 100
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


class ProductionConfigError(ValueError):
    """Controlled invalid or missing production configuration."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise ProductionConfigError(
            "production_config_missing",
            f"{name} is required for a production deployment and was not set.",
        )
    return value.strip()


def _require_int_env(name: str, *, minimum: int, maximum: int) -> int:
    raw = _require_env(name)
    try:
        value = int(raw)
    except ValueError as exc:
        raise ProductionConfigError(
            "production_config_invalid",
            f"{name} must be an integer.",
        ) from exc
    if not minimum <= value <= maximum:
        raise ProductionConfigError(
            "production_config_invalid",
            f"{name} must be from {minimum} to {maximum}.",
        )
    return value


@dataclass(frozen=True, slots=True)
class ProductionServiceConfig:
    """Validated production configuration. Every field is required
    (no defaults that could silently activate a weaker backend) except
    the pool-size bounds, which have safe, explicitly-production-sized
    defaults rather than a dev-oriented one.

    ``database_backend`` and ``signing_provider`` are each constrained
    to exactly one accepted value -- not because more will never exist
    (a future provider is exactly what ``signing.py``'s
    ``SigningProvider`` protocol already anticipates), but because
    accepting an open-ended string here would let a typo (or a copied-
    from-dev config file) silently select "sqlite" or
    "local_development" in what is supposed to be a hard production
    gate. Widening this set is a deliberate future change, not
    something this type should permit by accident today.
    """

    environment: str
    service_identity: str
    database_backend: str
    database_url: str
    signing_provider: str
    kms_key_id: str
    callback_service_hostname: str
    migration_mode: str
    authorization_directory: str
    artifact_directory: str
    cursor_signing_secret: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    database_pool_minimum: int = DEFAULT_DATABASE_POOL_MINIMUM
    database_pool_maximum: int = DEFAULT_DATABASE_POOL_MAXIMUM
    # Slice 14 requirement 1: deliberately optional, unlike every field
    # above. Most production deployments never use authenticated
    # scanning at all; requiring a secret provider unconditionally would
    # fail closed on deployments that have no use for one. Instead,
    # resolution itself fails closed at the moment an authenticated scan
    # actually needs a secret and none is configured (see
    # `secret_provider.py`'s `LocalSecretProvider` -- the production
    # runtime's `authentication_contexts` repository has no local
    # secret storage to silently fall back to). When set, it is
    # constrained to one accepted value for the same typo-safety reason
    # `signing_provider` is.
    secret_provider: str | None = None

    def __post_init__(self) -> None:
        if self.environment != "production":
            raise ProductionConfigError(
                "production_config_environment_invalid",
                'environment must be exactly "production" to construct this config type.',
            )
        if not self.service_identity.strip():
            raise ProductionConfigError(
                "production_config_invalid",
                "service_identity must be a non-empty string.",
            )
        if self.database_backend != "postgresql":
            raise ProductionConfigError(
                "production_config_database_backend_invalid",
                'database_backend must be exactly "postgresql" in production.',
            )
        if not self.database_url.strip():
            raise ProductionConfigError(
                "production_config_missing",
                "database_url is required for a production deployment.",
            )
        if self.signing_provider != "kms":
            raise ProductionConfigError(
                "production_config_signing_provider_invalid",
                'signing_provider must be exactly "kms" in production.',
            )
        if not self.kms_key_id.strip():
            raise ProductionConfigError(
                "production_config_missing",
                "kms_key_id is required when signing_provider is kms.",
            )
        if not self.callback_service_hostname.strip():
            raise ProductionConfigError(
                "production_config_missing",
                "callback_service_hostname is required for a production deployment.",
            )
        if self.migration_mode not in ("apply_at_startup", "pre_applied"):
            raise ProductionConfigError(
                "production_config_migration_mode_invalid",
                'migration_mode must be "apply_at_startup" or "pre_applied".',
            )
        if not self.authorization_directory.strip():
            raise ProductionConfigError(
                "production_config_missing",
                "authorization_directory is required for a production deployment.",
            )
        if not self.artifact_directory.strip():
            raise ProductionConfigError(
                "production_config_missing",
                "artifact_directory is required for a production deployment.",
            )
        if self.secret_provider is not None and self.secret_provider != "aws_secrets_manager":  # noqa: S105 - a provider-selector enum value, not a credential
            raise ProductionConfigError(
                "production_config_secret_provider_invalid",
                'secret_provider must be unset or exactly "aws_secrets_manager".',
            )
        try:
            decoded_cursor_secret = base64.urlsafe_b64decode(
                self.cursor_signing_secret + "=" * (-len(self.cursor_signing_secret) % 4)
            )
        except (ValueError, TypeError) as exc:
            raise ProductionConfigError(
                "production_config_invalid",
                "cursor_signing_secret must be base64url-encoded.",
            ) from exc
        if len(decoded_cursor_secret) < 32:
            raise ProductionConfigError(
                "production_config_invalid",
                "cursor_signing_secret must decode to at least 32 bytes.",
            )
        if self.port != DEFAULT_PORT or self.host != DEFAULT_HOST:
            import ipaddress

            try:
                address = ipaddress.ip_address(self.host)
            except ValueError as exc:
                raise ProductionConfigError(
                    "production_config_invalid", "host must be a valid IP literal."
                ) from exc
            if not address.is_loopback:
                raise ProductionConfigError(
                    "production_config_non_loopback_binding_rejected",
                    "Production API binding is currently limited to loopback, matching "
                    "the pre-production API's own constraint -- public exposure requires "
                    "the reverse-proxy/TLS/WAF layer documented as not-yet-built in "
                    "docs/production/INFRASTRUCTURE_REQUIREMENTS.md.",
                )
        if (
            isinstance(self.database_pool_minimum, bool)
            or not isinstance(self.database_pool_minimum, int)
            or self.database_pool_minimum < 1
        ):
            raise ProductionConfigError(
                "production_config_invalid",
                "database_pool_minimum must be a positive integer.",
            )
        if (
            isinstance(self.database_pool_maximum, bool)
            or not isinstance(self.database_pool_maximum, int)
            or not self.database_pool_minimum
            <= self.database_pool_maximum
            <= MAXIMUM_DATABASE_POOL_MAXIMUM
        ):
            raise ProductionConfigError(
                "production_config_invalid",
                f"database_pool_maximum must be from database_pool_minimum to {MAXIMUM_DATABASE_POOL_MAXIMUM}.",
            )

    @property
    def cursor_signing_key_bytes(self) -> bytes:
        return base64.urlsafe_b64decode(
            self.cursor_signing_secret + "=" * (-len(self.cursor_signing_secret) % 4)
        )

    @classmethod
    def from_environment(cls) -> "ProductionServiceConfig":
        """Reads every field from an environment variable, none of
        them defaulted to a dev-safe value -- a missing
        ``WEBGUARD_*`` variable is a startup failure here, not a quiet
        fallback. Pool-size variables are the sole exception, since
        they have safe production-sized defaults rather than a
        dev-oriented one."""

        pool_minimum = int(
            os.environ.get("WEBGUARD_DATABASE_POOL_MINIMUM", str(DEFAULT_DATABASE_POOL_MINIMUM))
        )
        pool_maximum = int(
            os.environ.get("WEBGUARD_DATABASE_POOL_MAXIMUM", str(DEFAULT_DATABASE_POOL_MAXIMUM))
        )
        return cls(
            environment=_require_env("WEBGUARD_ENVIRONMENT"),
            service_identity=_require_env("WEBGUARD_SERVICE_IDENTITY"),
            database_backend=_require_env("WEBGUARD_DATABASE_BACKEND"),
            database_url=_require_env("WEBGUARD_DATABASE_URL"),
            signing_provider=_require_env("WEBGUARD_SIGNING_PROVIDER"),
            kms_key_id=_require_env("WEBGUARD_KMS_KEY_ID"),
            callback_service_hostname=_require_env("WEBGUARD_CALLBACK_SERVICE_HOSTNAME"),
            migration_mode=_require_env("WEBGUARD_MIGRATION_MODE"),
            authorization_directory=_require_env("WEBGUARD_AUTHORIZATION_DIRECTORY"),
            artifact_directory=_require_env("WEBGUARD_ARTIFACT_DIRECTORY"),
            cursor_signing_secret=_require_env("WEBGUARD_CURSOR_SIGNING_SECRET"),
            host=os.environ.get("WEBGUARD_HOST", DEFAULT_HOST),
            port=int(os.environ.get("WEBGUARD_PORT", str(DEFAULT_PORT))),
            database_pool_minimum=pool_minimum,
            database_pool_maximum=pool_maximum,
            secret_provider=os.environ.get("WEBGUARD_SECRET_PROVIDER") or None,
        )


__all__ = [
    "DEFAULT_DATABASE_POOL_MAXIMUM",
    "DEFAULT_DATABASE_POOL_MINIMUM",
    "MAXIMUM_DATABASE_POOL_MAXIMUM",
    "ProductionConfigError",
    "ProductionServiceConfig",
]
