"""Tests for the fail-closed production configuration (Slice 12
requirement 15): every required field must be present and exactly
valid, with no default that silently activates SQLite, in-memory
repositories, or local development signing.
"""

from __future__ import annotations

import unittest

from webguard_api.production_config import ProductionConfigError, ProductionServiceConfig

VALID_KWARGS = dict(
    environment="production",
    service_identity="webguard-api-1",
    database_backend="postgresql",
    database_url="postgresql://user:pass@db.internal:5432/webguard",
    signing_provider="kms",
    kms_key_id="arn:aws:kms:eu-west-2:111111111111:key/abc-123",
    callback_service_hostname="callback.openhuntx.example",
    migration_mode="pre_applied",
    authorization_directory="/var/webguard/authorizations",
    artifact_directory="/var/webguard/artifacts",
    cursor_signing_secret="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
)


class ProductionServiceConfigTests(unittest.TestCase):
    def test_valid_configuration_constructs(self) -> None:
        config = ProductionServiceConfig(**VALID_KWARGS)
        self.assertEqual(config.database_backend, "postgresql")
        self.assertEqual(config.signing_provider, "kms")

    def test_environment_must_be_exactly_production(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "environment": "staging"})
        self.assertEqual(caught.exception.code, "production_config_environment_invalid")

    def test_sqlite_database_backend_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "database_backend": "sqlite"})
        self.assertEqual(caught.exception.code, "production_config_database_backend_invalid")

    def test_empty_database_url_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "database_url": "   "})
        self.assertEqual(caught.exception.code, "production_config_missing")

    def test_local_development_signing_provider_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(
                **{**VALID_KWARGS, "signing_provider": "local_development"}
            )
        self.assertEqual(caught.exception.code, "production_config_signing_provider_invalid")

    def test_missing_kms_key_id_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "kms_key_id": ""})
        self.assertEqual(caught.exception.code, "production_config_missing")

    def test_missing_callback_hostname_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "callback_service_hostname": ""})
        self.assertEqual(caught.exception.code, "production_config_missing")

    def test_invalid_migration_mode_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "migration_mode": "yolo"})
        self.assertEqual(caught.exception.code, "production_config_migration_mode_invalid")

    def test_missing_authorization_directory_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "authorization_directory": ""})
        self.assertEqual(caught.exception.code, "production_config_missing")

    def test_cursor_signing_secret_too_short_is_rejected(self) -> None:
        import base64

        short = base64.urlsafe_b64encode(b"short").decode()
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "cursor_signing_secret": short})
        self.assertEqual(caught.exception.code, "production_config_invalid")

    def test_non_loopback_host_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(**{**VALID_KWARGS, "host": "0.0.0.0"})
        self.assertEqual(caught.exception.code, "production_config_non_loopback_binding_rejected")

    def test_pool_maximum_below_minimum_is_rejected(self) -> None:
        with self.assertRaises(ProductionConfigError) as caught:
            ProductionServiceConfig(
                **{
                    **VALID_KWARGS,
                    "database_pool_minimum": 5,
                    "database_pool_maximum": 2,
                }
            )
        self.assertEqual(caught.exception.code, "production_config_invalid")

    def test_from_environment_fails_closed_when_variables_are_missing(self) -> None:
        import os

        original = dict(os.environ)
        try:
            for key in list(os.environ):
                if key.startswith("WEBGUARD_"):
                    del os.environ[key]
            with self.assertRaises(ProductionConfigError) as caught:
                ProductionServiceConfig.from_environment()
            self.assertEqual(caught.exception.code, "production_config_missing")
        finally:
            os.environ.clear()
            os.environ.update(original)

    def test_from_environment_succeeds_with_every_variable_set(self) -> None:
        import os

        original = dict(os.environ)
        try:
            os.environ.update(
                {
                    "WEBGUARD_ENVIRONMENT": "production",
                    "WEBGUARD_SERVICE_IDENTITY": "webguard-api-1",
                    "WEBGUARD_DATABASE_BACKEND": "postgresql",
                    "WEBGUARD_DATABASE_URL": "postgresql://user:pass@db.internal:5432/webguard",
                    "WEBGUARD_SIGNING_PROVIDER": "kms",
                    "WEBGUARD_KMS_KEY_ID": "arn:aws:kms:eu-west-2:111111111111:key/abc-123",
                    "WEBGUARD_CALLBACK_SERVICE_HOSTNAME": "callback.openhuntx.example",
                    "WEBGUARD_MIGRATION_MODE": "pre_applied",
                    "WEBGUARD_AUTHORIZATION_DIRECTORY": "/var/webguard/authorizations",
                    "WEBGUARD_ARTIFACT_DIRECTORY": "/var/webguard/artifacts",
                    "WEBGUARD_CURSOR_SIGNING_SECRET": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
                }
            )
            config = ProductionServiceConfig.from_environment()
            self.assertEqual(config.service_identity, "webguard-api-1")
        finally:
            os.environ.clear()
            os.environ.update(original)


if __name__ == "__main__":
    unittest.main()
