"""Secret-resolution abstraction for authenticated scanning (Slice 14
requirement 1).

``PostgresAuthenticationContextRepository`` (Slice 13) deliberately has
no ``get_secret`` method and never will -- authentication-context
*metadata* lives in PostgreSQL, but the actual bearer token / session
cookies / basic-auth credentials never do. Something else must resolve
``secret_reference_id`` into real ``AuthenticationMaterial`` at scan
time. This module is that something else, mirroring ``signing.py``'s
own provider-neutral pattern exactly:

- ``LocalSecretProvider`` -- the local/dev/test/lab path. The in-memory
  ``AuthenticationContextRepository`` already holds secret material
  keyed by context ID (unchanged since Slice 7); this provider is a
  thin adapter so callers always go through one ``SecretProvider``
  interface regardless of environment, rather than branching on which
  concrete repository type is active.
- ``SecretsManagerSecretProvider`` -- signs through an injected,
  duck-typed client matching the shape of ``boto3``'s Secrets Manager
  client (``get_secret_value(SecretId=...) -> {"SecretString": ...}``)
  rather than importing ``boto3`` directly, for the identical reason
  ``KmsSigningProvider`` does not import it: this package's dependency
  footprint stays hash-locked and minimal, and a real
  ``boto3.client("secretsmanager")`` satisfies this protocol
  structurally without this package ever depending on it.

Fail-closed by construction, not by convention: if production is
running (``PostgresAuthenticationContextRepository`` is active, which
has no ``get_secret``) and no real ``SecretProvider`` was configured,
``LocalSecretProvider.resolve()`` -- the default every executor falls
back to when none is explicitly injected -- raises
``secret_provider_not_configured`` rather than silently returning
nothing or attempting local storage that does not exist in production.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Protocol

from webguard_scanner.authentication import AuthenticationMaterial, SessionCookie


class SecretProviderError(RuntimeError):
    """Controlled secret-resolution failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class SecretProvider(Protocol):
    def resolve(self, secret_reference_id: str) -> AuthenticationMaterial: ...


class LocalSecretProvider:
    """Adapter over an in-memory ``AuthenticationContextRepository``'s
    own ``get_secret`` method -- the local/dev/test/lab default, and
    the same object every executor falls back to when no explicit
    ``secret_provider`` is injected. When wrapping a repository that has
    no secret material of its own (``PostgresAuthenticationContextRepository``
    in production), this fails closed with a clear, fixed error instead
    of an ``AttributeError`` or a silent no-op."""

    def __init__(self, contexts: object) -> None:
        self._contexts = contexts

    def resolve(self, secret_reference_id: str) -> AuthenticationMaterial:
        get_secret = getattr(self._contexts, "get_secret", None)
        if get_secret is None:
            raise SecretProviderError(
                "secret_provider_not_configured",
                "No production-capable secret provider is configured, and the "
                "active authentication-context repository does not hold secret "
                "material directly. Production authenticated scanning requires "
                "an explicit secret provider (WEBGUARD_SECRET_PROVIDER).",
            )
        return get_secret(secret_reference_id)


class SecretsManagerClientProtocol(Protocol):
    """Structural shape of the subset of ``boto3``'s Secrets Manager
    client this module calls -- satisfied by a real
    ``boto3.client("secretsmanager")`` without this package importing
    ``boto3``, and by a plain fake in tests."""

    def get_secret_value(self, *, SecretId: str) -> dict: ...


class SecretsManagerSecretProvider:
    """Production-shaped secret provider. The secret's ``SecretString``
    is expected to be a JSON object matching
    ``AuthenticationMaterial``'s own field shape (``bearer_token``,
    ``cookies`` as a list of objects, ``basic_username``,
    ``basic_password``) -- this provider does not invent a new secret
    schema, it just deserializes the same shape the scanner already
    validates via ``AuthenticationMaterial.__post_init__``."""

    def __init__(self, client: SecretsManagerClientProtocol) -> None:
        self._client = client

    def resolve(self, secret_reference_id: str) -> AuthenticationMaterial:
        try:
            response = self._client.get_secret_value(SecretId=secret_reference_id)
            payload = json.loads(response["SecretString"])
        except SecretProviderError:
            raise
        except Exception as exc:
            raise SecretProviderError(
                "secret_provider_resolution_failed",
                "Unable to resolve authentication secret material from the "
                "configured secret provider.",
            ) from exc
        try:
            cookies = tuple(
                SessionCookie(
                    name=item["name"],
                    value=item["value"],
                    domain=item["domain"],
                    port=item["port"],
                    path=item.get("path", "/"),
                    secure=item.get("secure", False),
                    expires_at=(
                        datetime.fromisoformat(item["expires_at"])
                        if item.get("expires_at")
                        else None
                    ),
                )
                for item in payload.get("cookies", ())
            )
            return AuthenticationMaterial(
                bearer_token=payload.get("bearer_token"),
                cookies=cookies,
                basic_username=payload.get("basic_username"),
                basic_password=payload.get("basic_password"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SecretProviderError(
                "secret_provider_payload_invalid",
                "The resolved secret material does not match the expected "
                "authentication-material shape.",
            ) from exc


__all__ = [
    "LocalSecretProvider",
    "SecretProvider",
    "SecretProviderError",
    "SecretsManagerClientProtocol",
    "SecretsManagerSecretProvider",
]
