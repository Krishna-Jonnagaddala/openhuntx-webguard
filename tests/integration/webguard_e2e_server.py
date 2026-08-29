#!/usr/bin/env python3
"""Real production-mode WebGuard API server for the Playwright browser
E2E suite (Slice 15 requirement 28).

Started as a subprocess by `apps/web/e2e/global-setup.ts`. Prints one
JSON line to stdout once ready (base URL, owner token, and the
controlled fixture's target URL for the browser test to add as an
asset), then blocks until SIGTERM.

Reuses `webguard_production_harness.run_production_stack` -- the same
real-Postgres, real-KMS-shaped-signing, real-HTTP-server startup
sequence already proven by `test_production_mode_e2e.py` -- plus one
new piece: a controlled fixture HTTP server that is both (a) a plain
page with no security headers, so a genuine PASSIVE `single_page` scan
(the only kind the web app's Start Scan workflow ever requests) trips
a real `webguard-passive` HTTP-header finding, and (b) able to answer
its own `.well-known/webguard-verification.txt` with the CURRENT real
pending token by reading it straight out of the running API's own
`target_verifications` repository -- so ownership verification is
exercised for real too, with no mocked token comparison.

The only thing patched is the "resolved address must be public"
SSRF gate, exactly as `test_production_mode_e2e.py` already does, so
that a loopback-bound fixture can stand in for a real public target
without a real public target having to exist. No other behavior is
altered; the token match itself is genuine.
"""

from __future__ import annotations

import ipaddress
import json
import os
import signal
import ssl
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _package in ("apps/api/src", "packages/contracts/python/src", "workers/scanner/src"):
    _candidate = _REPO_ROOT / _package
    if _candidate.is_dir():
        sys.path.insert(0, str(_candidate))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from webguard_contracts import (  # noqa: E402
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    write_owned_target_authorization_file,
)
from webguard_scanner import ValidatedTarget  # noqa: E402
from webguard_production_harness import run_production_stack  # noqa: E402

_STATE: dict[str, object] = {"components": None, "organization_id": None, "target_url": None}


def _generate_self_signed_certificate(directory: Path) -> Path:
    """Same pattern as `test_production_mode_e2e.py`: a real, locally-
    generated TLS certificate for the loopback fixture -- owned-target
    authorizations require HTTPS, so this is not optional."""

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e2e-fixture.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("e2e-fixture.test"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "e2e-fixture-cert.pem"
    with open(cert_path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    return cert_path


class _FixtureHandler(BaseHTTPRequestHandler):
    """A bare HTTP page with no security headers set (so a real passive
    header-analysis finding is genuinely detected) plus a dynamic
    `.well-known` responder that reads the live expected verification
    token straight out of the running API process it shares memory
    with -- no fixed/guessed token, no mocked comparison."""

    def log_message(self, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/.well-known/webguard-verification.txt":
            token = self._current_pending_token()
            if token is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = token.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = (
            b"<html><body><h1>Fixture asset</h1>"
            b"<p>A controlled Slice 15 E2E fixture with no security headers set.</p>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _current_pending_token() -> str | None:
        components = _STATE["components"]
        organization_id = _STATE["organization_id"]
        target_url = _STATE["target_url"]
        if components is None or organization_id is None or target_url is None:
            return None
        targets = components.targets.list_targets(organization_id)  # type: ignore[union-attr]
        match = next((t for t in targets if t.url == target_url), None)
        if match is None:
            return None
        record = components.target_verifications.get_current(  # type: ignore[union-attr]
            match.target_id, organization_id=organization_id
        )
        if record is None or record.status.value != "pending":
            return None
        try:
            return components.target_verifications.get_pending_token(  # type: ignore[union-attr]
                record.verification_id, organization_id=organization_id
            )
        except Exception:
            return None


def main() -> int:
    postgres_dsn = os.environ.get(
        "WEBGUARD_POSTGRES_TEST_DSN",
        "postgresql://webguard:webguard_dev_only_not_for_production@127.0.0.1:5433/webguard",
    )
    port = int(os.environ.get("WEBGUARD_E2E_API_PORT", "8765"))

    certificate_directory = TemporaryDirectory()
    certificate_path = _generate_self_signed_certificate(Path(certificate_directory.name))

    fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certfile=certificate_path)
    fixture_server.socket = tls_context.wrap_socket(fixture_server.socket, server_side=True)
    fixture_thread = threading.Thread(target=fixture_server.serve_forever, daemon=True)
    fixture_thread.start()
    fixture_port = fixture_server.server_address[1]
    target_url = f"https://e2e-fixture.test:{fixture_port}/"

    def _fake_validate_target_url(*args: object, **kwargs: object) -> ValidatedTarget:
        # A real `validate_target_url(url, policy)` call, with only the
        # "resolved address must be public" SSRF gate bypassed for our
        # loopback fixture -- everything else (scheme, hostname, port,
        # and critically the exact path being requested) is derived
        # from the real `url` argument, so a well-known-path fetch and
        # a root-page scan fetch each land on the right path.
        url = str(args[0]) if args else str(kwargs["url"])
        parsed = urlsplit(url)
        return ValidatedTarget(
            original_url=url,
            normalised_url=url,
            scheme=parsed.scheme or "https",
            hostname=parsed.hostname or "e2e-fixture.test",
            port=parsed.port or fixture_port,
            resolved_addresses=("127.0.0.1",),
        )

    real_create_default_context = ssl.create_default_context

    def _trusting_tls_context(*_args: object, **_kwargs: object) -> ssl.SSLContext:
        context = real_create_default_context()
        context.load_verify_locations(cafile=str(certificate_path))
        return context

    shutdown = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_args: shutdown.set())
    signal.signal(signal.SIGINT, lambda *_args: shutdown.set())

    with patch(
        "webguard_api.target_verification.validate_target_url", side_effect=_fake_validate_target_url
    ), patch(
        "webguard_api.executor.validate_target_url", side_effect=_fake_validate_target_url
    ), patch(
        "webguard_scanner.owned_target._public_addresses",
        side_effect=lambda target: target.resolved_addresses,
    ), patch(
        "webguard_scanner.safe_http.ssl.create_default_context", side_effect=_trusting_tls_context
    ), run_production_stack(postgres_dsn, port=port) as stack:
        _STATE["components"] = stack.components
        _STATE["organization_id"] = stack.organization_id
        _STATE["target_url"] = target_url

        now = datetime.now(timezone.utc)
        authorization_id = str(uuid4())
        write_owned_target_authorization_file(
            OwnedTargetAuthorization(
                authorization_id=authorization_id,
                organization="WebGuard E2E Org",
                authorized_by="E2E Harness",
                target=target_url,
                allowed_hosts=("e2e-fixture.test",),
                issued_at=now,
                expires_at=now.replace(year=now.year + 1),
                purpose="Slice 15 browser E2E: full product flow",
                limits=OwnedTargetLimits(),
            ),
            stack.authorization_directory / "e2e-fixture.json",
        )
        stack.components.identity.assign_authorization(
            stack.organization_id,
            authorization_id,
            assigned_by=stack.owner_principal_id,
            now=now,
        )

        ready = {
            "base_url": stack.base_url,
            "token": stack.owner_token,
            "target_url": target_url,
            "organization_id": stack.organization_id,
        }
        print(json.dumps(ready), flush=True)

        shutdown.wait()

    fixture_server.shutdown()
    fixture_server.server_close()
    fixture_thread.join(timeout=5)
    certificate_directory.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
