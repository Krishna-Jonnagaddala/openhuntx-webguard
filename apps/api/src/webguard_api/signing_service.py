"""TrustScan Signing Service (Slice 18 requirements 1-4).

A dedicated, narrow-interface internal service standing between every
WebGuard API/worker process and CloudHSM::

    WebGuard API / worker  -->  TrustScan Signing Service  -->  CloudHSM

No WebGuard API or worker process holds direct HSM credentials or a
PKCS#11 session of its own in the CloudHSM-backed production path --
only this service does. Its own HTTP surface deliberately mirrors
``signing.py``'s ``SigningProvider`` contract exactly and nothing more::

    POST /v1/sign             -- sign(message)
    GET  /v1/active-key-id    -- get_active_key_id()
    GET  /v1/public-key/{id}  -- get_public_key(key_id)

There is no encrypt/decrypt endpoint, no key-generation endpoint, and
no general PKCS#11-operation passthrough -- this service can only ever
do the three things TrustScan signing needs, nothing else, even though
the underlying HSM session it holds could technically do far more. See
``docs/production/TRUSTSCAN_SIGNING_SERVICE.md`` for the full
architecture, network-isolation model, and key-lifecycle operating
procedure (rotation/disable is a config-and-restart operation on this
service's own host, deliberately not a remotely-triggerable HTTP
mutation -- exposing one would need its own strong authorization model
this narrow interface is not trying to be).

Authentication is a single shared bearer secret, constant-time
compared, resolved through the existing ``SecretProvider`` architecture
in production (never hardcoded, never logged). This service is
internal-only -- never intended to be reachable from the public
Internet -- so the bearer secret is defense-in-depth, not the sole
boundary; real network isolation (a private subnet, a security group
scoped to the API/worker's own security group) is the primary one.

This module never imports a PKCS#11 binding (e.g. ``python-pkcs11``)
at package level, mirroring ``signing.py``'s own KMS/``boto3``
precedent exactly -- a real ``Pkcs11Ed25519KeyProtocol`` implementation
is constructed by ``build_cloudhsm_signing_provider_from_env()`` below,
the one function that actually imports the real binding, called only
from ``cli.py``'s ``signing-service`` subcommand in its
``--key-source cloudhsm`` mode.

**Honesty note (Slice 18 requirement 4's own instruction): the PKCS#11
adapter below has not been exercised against real CloudHSM hardware,
or even a real PKCS#11 driver library, anywhere in this repository's
test suite** -- no CloudHSM cluster and no PKCS#11 software module are
available in this environment. Only the ``Pkcs11Ed25519KeyProtocol``
boundary it implements is tested
(``tests/unit/test_cloudhsm_signing.py``), against a fake performing
real Ed25519 cryptography. ``docs/audit/production-platform-phase4-edge-signing.md``
states this gap explicitly; do not read the presence of this code as a
claim that real CloudHSM signing has been validated.
"""

from __future__ import annotations

import base64
import hmac
import http.client
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlsplit

from .signing import CloudHsmSigningProvider, SigningKeyRegistry, SigningProviderError
from .structured_logging import log_event

_MAXIMUM_MESSAGE_BYTES = 4096  # a TrustScan permit/receipt's signing_bytes is always small


class SigningServiceError(RuntimeError):
    def __init__(self, code: str, message: str, *, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _b64url_decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise SigningServiceError("signing_service_body_invalid", "Expected a base64url string.", status=400)
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded)
    except (ValueError, TypeError) as exc:
        raise SigningServiceError(
            "signing_service_body_invalid", "Field is not valid base64url.", status=400
        ) from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def build_signing_service_handler(
    registry: SigningKeyRegistry,
    *,
    bearer_token: str,
    clock: Callable[[], float] | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Constructs the request handler class. A factory (not a bare
    class) because the handler needs the registry/token closed over --
    the same pattern ``http_api.py``'s own ``build_handler`` and
    ``callback_server.py``'s ``_make_handler`` already use."""

    class _SigningServiceHandler(BaseHTTPRequestHandler):
        server_version = "OpenHuntX-TrustScan-Signing-Service"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _authenticated(self) -> bool:
            header = self.headers.get("Authorization") or ""
            if not header.startswith("Bearer "):
                return False
            presented = header[len("Bearer "):]
            # Constant-time comparison -- this is a credential check,
            # not a data-equality check (requirement 1's own spirit:
            # no shortcuts around a security boundary for convenience).
            return hmac.compare_digest(presented, bearer_token)

        def _send_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            # This service is never a browser target -- no CORS, no
            # CSP needed -- but these two cost nothing and are correct
            # for any HTTP responder handling internal service traffic.
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _error(self, exc: SigningServiceError) -> None:
            self._send_json(exc.status, {"error": {"code": exc.code, "message": exc.message}})

        def _require_auth(self) -> bool:
            if not self._authenticated():
                self._error(
                    SigningServiceError(
                        "signing_service_unauthorized", "A valid bearer token is required.", status=401
                    )
                )
                return False
            return True

        def do_POST(self) -> None:  # noqa: N802
            if not self._require_auth():
                return
            parsed = urlsplit(self.path)
            if parsed.path != "/v1/sign":
                self._error(SigningServiceError("signing_service_not_found", "Not found.", status=404))
                return
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length <= 0 or length > _MAXIMUM_MESSAGE_BYTES + 512:
                    raise SigningServiceError(
                        "signing_service_body_invalid", "Request body is missing or too large.", status=400
                    )
                raw = self.rfile.read(length)
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise SigningServiceError(
                        "signing_service_body_invalid", "Request body must be a JSON object.", status=400
                    )
                message = _b64url_decode(body.get("message"))
                if len(message) > _MAXIMUM_MESSAGE_BYTES:
                    raise SigningServiceError(
                        "signing_service_message_too_large", "message exceeds the maximum signing payload size.",
                        status=400,
                    )
                registry.ensure_active_key_signable()
                signature = registry.active.sign(message)
                self._send_json(
                    200, {"key_id": registry.active.key_id, "signature": _b64url_encode(signature)}
                )
                # P1-B1: key_id is permitted (an identifier, not
                # secret material); the message and signature bytes
                # are never logged, and no synthetic signing operation
                # is performed merely to produce this event.
                log_event(service="signing-service",
                    event="sign_request_completed", level="info", key_id=registry.active.key_id,
                )
            except SigningServiceError as exc:
                self._error(exc)
            except (ValueError, json.JSONDecodeError):
                self._error(
                    SigningServiceError("signing_service_body_invalid", "Request body is not valid JSON.", status=400)
                )
            except SigningProviderError as exc:
                self._error(SigningServiceError(exc.code, exc.message, status=500))
                if exc.code == "trustscan_signing_key_disabled":
                    log_event(service="signing-service", event="active_key_unavailable", level="error", error_code=exc.code)
                else:
                    log_event(service="signing-service", event="sign_request_failed", level="error", error_code=exc.code)

        def do_GET(self) -> None:  # noqa: N802
            if not self._require_auth():
                return
            parsed = urlsplit(self.path)
            if parsed.path == "/v1/active-key-id":
                self._send_json(200, {"key_id": registry.active.key_id})
                return
            if parsed.path.startswith("/v1/public-key/"):
                key_id = parsed.path[len("/v1/public-key/"):]
                key = registry.verification_key(key_id)
                if key is None:
                    self._error(
                        SigningServiceError(
                            "signing_service_key_not_found", "No signing key is registered under that key ID.",
                            status=404,
                        )
                    )
                    return
                self._send_json(
                    200,
                    {
                        "key_id": key.key_id,
                        "algorithm": key.algorithm,
                        "public_key": _b64url_encode(key.public_key_material),
                        "status": key.status,
                    },
                )
                return
            self._error(SigningServiceError("signing_service_not_found", "Not found.", status=404))

    return _SigningServiceHandler


class SigningServiceServer:
    """A real, bindable HTTP server for the signing service -- the
    same "genuine, runnable `ThreadingHTTPServer`, not a mock" pattern
    ``callback_server.py``'s ``CallbackHttpReceiver`` already
    establishes for a comparably narrow, independently-deployable
    component."""

    def __init__(
        self,
        registry: SigningKeyRegistry,
        *,
        bearer_token: str,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        handler = build_signing_service_handler(registry, bearer_token=bearer_token)
        self._server = ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def is_running(self) -> bool:
        """P1-B2: narrow liveness accessor for the internal health
        listener -- see callback_server.py::CallbackHttpReceiver's
        identical property for the reasoning. Exposes only a boolean,
        never the underlying `Thread` object."""

        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        log_event(service="signing-service", event="signing_service_started", level="info")

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        log_event(service="signing-service", event="signing_service_stopped", level="info")


def build_cloudhsm_signing_provider_from_env():
    """Constructs a real ``CloudHsmSigningProvider`` over a real
    PKCS#11 session, reading connection details from environment
    variables (``WEBGUARD_SIGNING_SERVICE_PKCS11_LIBRARY_PATH``,
    ``_TOKEN_LABEL``, ``_PIN``, ``_PRIVATE_KEY_LABEL``, and optionally
    ``_PUBLIC_KEY_LABEL`` -- defaults to the private key's own label,
    since CloudHSM key-pair provisioning commonly uses matching
    labels). ``python-pkcs11`` is imported here, at this one call
    site, never at package level -- mirroring ``cli.py``'s own lazy
    ``import boto3`` exactly, and for the identical reason: this
    package's hash-locked dependency set stays minimal regardless of
    which production signing path an operator chooses.

    See this module's own docstring for the explicit, honest
    statement that this function has not been executed against real
    CloudHSM hardware in this repository. The riskiest single
    assumption it makes -- documented inline below, not hidden -- is
    how a CloudHSM-reported ``EC_POINT`` attribute encodes an Ed25519
    public key; this must be verified against a real cluster before
    any production cutover.
    """

    import pkcs11  # noqa: PLC0415 - deliberately lazy; see module/function docstring
    from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

    library_path = _require_env_var("WEBGUARD_SIGNING_SERVICE_PKCS11_LIBRARY_PATH")
    token_label = _require_env_var("WEBGUARD_SIGNING_SERVICE_PKCS11_TOKEN_LABEL")
    pin = _require_env_var("WEBGUARD_SIGNING_SERVICE_PKCS11_PIN")
    private_key_label = _require_env_var("WEBGUARD_SIGNING_SERVICE_PKCS11_PRIVATE_KEY_LABEL")
    public_key_label = os.environ.get("WEBGUARD_SIGNING_SERVICE_PKCS11_PUBLIC_KEY_LABEL", private_key_label)

    library = pkcs11.lib(library_path)
    token = library.get_token(token_label=token_label)
    session = token.open(user_pin=pin)

    private_key = session.get_key(
        object_class=ObjectClass.PRIVATE_KEY, key_type=KeyType.EC_EDWARDS, label=private_key_label
    )
    public_key = session.get_key(
        object_class=ObjectClass.PUBLIC_KEY, key_type=KeyType.EC_EDWARDS, label=public_key_label
    )

    class _Pkcs11Ed25519Adapter:
        def sign(self, message: bytes) -> bytes:
            return private_key.sign(message, mechanism=Mechanism.EDDSA)

        def public_key_material(self) -> bytes:
            raw = public_key.get_attributes([Attribute.EC_POINT])[Attribute.EC_POINT]
            # UNVERIFIED against real CloudHSM (see this module's own
            # docstring): some PKCS#11 implementations return a bare
            # 32-byte Edwards point in EC_POINT; others wrap it as a
            # DER OCTET STRING (0x04 <length> <point>). This defensive
            # unwrap handles the documented common case for a 32-byte
            # Ed25519 point, but must be confirmed against a real
            # cluster's actual response before production use.
            if len(raw) == 34 and raw[0] == 0x04 and raw[1] == 0x20:
                return raw[2:]
            return raw

    return CloudHsmSigningProvider(_Pkcs11Ed25519Adapter())


def _require_env_var(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SigningServiceError(
            "signing_service_config_missing", f"{name} is required to start the signing service.", status=500
        )
    return value


class SigningServiceHttpClient:
    """Real HTTPS/HTTP transport satisfying ``signing.py``'s
    ``SigningServiceClientProtocol`` -- standard library only
    (``http.client``/``json``), matching this codebase's established
    outbound-HTTP convention (``mail.py``'s ``PostmarkHttpClient``,
    ``webguard_scanner.safe_http``). This is what
    ``SigningServiceClient`` is actually constructed with in
    production; a fake satisfying the same protocol is used in tests."""

    def __init__(self, *, base_url: str, bearer_token: str, timeout_seconds: float = 5.0) -> None:
        parsed = urlsplit(base_url)
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._use_tls = parsed.scheme == "https"
        self._bearer_token = bearer_token
        self._timeout_seconds = timeout_seconds

    def _connection(self) -> http.client.HTTPConnection:
        if self._use_tls:
            return http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout_seconds)
        return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout_seconds)

    def _request(self, method: str, path: str, *, body: bytes | None = None) -> dict:
        connection = self._connection()
        try:
            headers = {"Authorization": f"Bearer {self._bearer_token}"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            status = response.status
        except OSError as exc:
            raise SigningProviderError(
                "signing_service_unreachable", "Unable to reach the TrustScan signing service."
            ) from exc
        finally:
            connection.close()
        try:
            parsed_body = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError) as exc:
            raise SigningProviderError(
                "signing_service_response_invalid", "The signing service returned an unparseable response."
            ) from exc
        if status != 200:
            code = (parsed_body or {}).get("error", {}).get("code", "signing_service_request_failed")
            raise SigningProviderError(code, "The TrustScan signing service rejected this request.")
        return parsed_body

    def sign(self, message: bytes) -> dict:
        body = json.dumps({"message": _b64url_encode(message)}).encode("utf-8")
        response = self._request("POST", "/v1/sign", body=body)
        return {"key_id": response.get("key_id"), "signature": _b64url_decode(response.get("signature"))}

    def get_active_key_id(self) -> str:
        response = self._request("GET", "/v1/active-key-id")
        key_id = response.get("key_id")
        if not isinstance(key_id, str):
            raise SigningProviderError(
                "signing_service_response_invalid", "The signing service did not return a usable key_id."
            )
        return key_id

    def get_public_key(self, key_id: str) -> dict:
        response = self._request("GET", f"/v1/public-key/{key_id}")
        return {
            "key_id": response.get("key_id"),
            "algorithm": response.get("algorithm"),
            "public_key": _b64url_decode(response.get("public_key")),
            "status": response.get("status"),
        }


__all__ = [
    "SigningServiceError",
    "SigningServiceHttpClient",
    "SigningServiceServer",
    "build_cloudhsm_signing_provider_from_env",
    "build_signing_service_handler",
]
