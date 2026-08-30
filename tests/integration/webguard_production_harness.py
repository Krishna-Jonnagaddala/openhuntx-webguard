"""Reusable production-mode WebGuard API startup harness (Slice 15;
extended in Slice 17 to fake the S3 and Postmark network boundaries the
same way KMS was already faked).

Extracts the exact "real production stack, no AWS" startup sequence
already proven by `test_production_mode_e2e.py` into an importable,
reusable form: a `FakeKmsClient` performing real ECDSA P-256/SHA-256
signing in-process (matching AWS KMS's own request/response shape, so
`KmsSigningProvider`'s verification path is exercised for real -- only
the network boundary to AWS is substituted), a `FakeS3Client` holding
objects in memory (so `ObjectStorageArtifactStore`'s real put/get/
checksum/tenant-key logic runs for real, only the network boundary to
S3 is substituted), and a `FakePostmarkTransport` capturing sent
messages in memory and optionally to a JSON Lines sink file (so
`ProductionMailProvider`'s real payload/retry/classification logic
runs for real, only the network boundary to Postmark is substituted --
mirroring `InMemoryMailProvider`'s own out-of-process-readable sink
mechanism from Slice 16, but sitting one layer lower so the real
production mail-provider code path is what actually executes). Plus a
context manager that builds `ProductionComponents` against a real
disposable PostgreSQL, starts the HTTP server and worker on real
threads, and tears everything down cleanly on exit.

Used by:
  - `scripts/dev/run_local_webguard_api.py` (manual frontend dev
    testing against a real backend)
  - `apps/web/e2e/global-setup.ts` (via a small subprocess wrapper)
    for the Playwright browser E2E suite (Slice 15 requirement 28;
    Slice 17 requirement 24's real report-download flow)

This harness does not itself constitute a new "test double" security
posture: the only thing it fakes is the AWS/Postmark network boundary,
exactly as `webguard_api.signing`'s own module docstring anticipates
for tests, and it always runs against a real PostgreSQL and the real,
unmodified `webguard_api` production code paths.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from webguard_contracts import OrganizationRole, PrincipalType
from webguard_api.http_api import create_server
from webguard_api.passwords import hash_password
from webguard_api.production_config import ProductionServiceConfig
from webguard_api.production_startup import ProductionComponents, build_production_components


class FakeKmsClient:
    """Duck-typed `KmsClientProtocol` performing real ECDSA P-256/
    SHA-256 signing in-process -- no AWS credentials, no network call.
    See `tests/integration/test_production_mode_e2e.py` for the
    original, proven copy of this pattern."""

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        assert MessageType == "RAW"
        assert SigningAlgorithm == "ECDSA_SHA_256"
        signature = self._private_key.sign(Message, ec.ECDSA(hashes.SHA256()))
        return {"Signature": signature, "KeyId": KeyId, "SigningAlgorithm": SigningAlgorithm}

    def get_public_key(self, *, KeyId):
        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {"KeyId": KeyId, "PublicKey": public_bytes}


class _FakeS3NotFoundError(Exception):
    """Structurally matches `botocore.exceptions.ClientError` (a
    `.response["Error"]["Code"]` attribute) without this module
    importing botocore -- `ObjectStorageArtifactStore` only ever
    inspects that shape, never the exception's real type."""

    def __init__(self) -> None:
        super().__init__("NoSuchKey")
        self.response = {"Error": {"Code": "NoSuchKey"}}


class FakeS3Client:
    """Duck-typed `S3ClientProtocol`, in-memory only -- no AWS
    credentials, no network call. Real put/get/head/delete semantics
    (including "missing key raises a NoSuchKey-shaped error"), so
    `ObjectStorageArtifactStore`'s own logic -- encryption parameters
    passed through, checksum-by-reading-back, path-safety rejection --
    all run for real against this fake, exactly like `FakeKmsClient`
    exercises `KmsSigningProvider`'s real signing/verification logic."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_object(self, *, Bucket, Key, Body, ServerSideEncryption, SSEKMSKeyId, ContentType):
        self.objects[Key] = Body
        return {}

    def get_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise _FakeS3NotFoundError()
        return {"Body": io.BytesIO(self.objects[Key])}

    def head_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise _FakeS3NotFoundError()
        return {}

    def delete_object(self, *, Bucket, Key):
        self.objects.pop(Key, None)
        return {}


class FakePostmarkTransport:
    """Duck-typed `PostmarkClientProtocol`, in-memory only -- no
    Postmark credentials, no network call. Always reports success, so
    `ProductionMailProvider`'s real payload-construction/retry/
    classification logic executes normally; only the actual HTTP call
    to Postmark is substituted. Optionally mirrors each captured
    message to a JSON Lines file (`sink_path`), exactly like
    `InMemoryMailProvider`'s own mechanism, so an out-of-process reader
    -- the Playwright browser E2E suite -- can observe a message sent
    by a server running in a different process."""

    def __init__(self, *, sink_path: Path | None = None) -> None:
        self._sink_path = sink_path
        self.sent: list[dict] = []

    def send_email(self, payload: dict) -> dict:
        self.sent.append(payload)
        if self._sink_path is not None:
            with open(self._sink_path, "a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "to": payload.get("To"),
                            "subject": payload.get("Subject"),
                            "body": payload.get("TextBody"),
                            "category": payload.get("Tag"),
                            "sent_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                    + "\n"
                )
        return {
            "status_code": 200,
            "body": {"ErrorCode": 0, "Message": "OK", "MessageID": f"fake-{secrets.token_hex(8)}"},
        }


DEFAULT_OWNER_PASSWORD = "dev-harness-owner-password-123"  # noqa: S105 - a disposable local test fixture credential


@dataclass(frozen=True)
class RunningStack:
    host: str
    port: int
    organization_id: str
    owner_principal_id: str
    owner_token: str
    owner_email: str
    owner_password: str
    components: ProductionComponents
    authorization_directory: Path
    s3_client: FakeS3Client
    mail_transport: FakePostmarkTransport

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@contextlib.contextmanager
def run_production_stack(
    postgres_dsn: str,
    *,
    port: int = 0,
    organization_name: str | None = None,
    owner_display_name: str = "Dev Owner",
    owner_email: str | None = None,
    owner_password: str = DEFAULT_OWNER_PASSWORD,
    allowed_origins: frozenset[str] = frozenset({"http://localhost:5173", "http://127.0.0.1:5173"}),
    web_app_base_url: str = "http://127.0.0.1:5173",
    mail_sink_path: Path | None = None,
) -> Iterator[RunningStack]:
    """Start a real production-mode WebGuard API + worker against
    `postgres_dsn`, with one bootstrapped organization/owner, and tear
    it down on exit. The owner gets both an API bearer token (for
    direct API testing/automation) and a real password credential (so
    the browser E2E suite can log in through the actual UI -- Slice 16
    requirement 24 -- rather than pasting a token). Slice 17: object
    storage and mail are both real production code (`ObjectStorageArtifactStore`,
    `ProductionMailProvider`) running against `FakeS3Client`/
    `FakePostmarkTransport` -- only the AWS/Postmark network boundary
    is substituted, exactly like KMS already was."""

    with TemporaryDirectory() as directory:
        root = Path(directory)
        auth_dir = root / "authorizations"
        artifacts = root / "artifacts"
        auth_dir.mkdir(parents=True, exist_ok=True)
        artifacts.mkdir(parents=True, exist_ok=True)

        config = ProductionServiceConfig(
            environment="production",
            service_identity="web-dev-1",
            database_backend="postgresql",
            database_url=postgres_dsn,
            signing_provider="kms",
            kms_key_id="fake-kms-key-dev",
            callback_service_hostname="callback.dev.invalid",
            migration_mode="pre_applied",
            authorization_directory=str(auth_dir),
            artifact_directory=str(artifacts),
            cursor_signing_secret=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            mail_provider="postmark",
            postmark_server_token="fake-postmark-server-token-dev",  # noqa: S105 - never reaches a real network call
            mail_from_address="alerts@webguard-dev.invalid",
            web_app_base_url=web_app_base_url,
            object_storage_provider="s3",
            object_storage_bucket="webguard-dev-fake-bucket",
            object_storage_region="eu-west-2",
            object_storage_kms_key_id="fake-kms-key-dev-s3",
        )
        s3_client = FakeS3Client()
        mail_transport = FakePostmarkTransport(sink_path=mail_sink_path)
        components = build_production_components(
            config, kms_client=FakeKmsClient(), s3_client=s3_client, mail_transport=mail_transport
        )
        try:
            now = datetime.now(timezone.utc)
            resolved_name = organization_name or f"WebGuard Dev Org {secrets.token_hex(4)}"
            # Email has a real, global unique constraint (one login
            # identity per address) -- unlike the pre-Slice-16 fields
            # here, a fixed default would collide the second time this
            # harness runs against a persistent (not freshly recreated)
            # database, exactly like the organization name already
            # avoids by suffixing itself.
            resolved_email = owner_email or f"owner-{secrets.token_hex(4)}@webguard-dev.invalid"
            organization = components.identity.create_organization(resolved_name, now=now)
            owner = components.identity.create_principal(
                organization.organization_id,
                owner_display_name,
                principal_type=PrincipalType.USER,
                role=OrganizationRole.OWNER,
                now=now,
                email=resolved_email,
            )
            issued_token = components.identity.create_token(owner.principal_id, label="dev-bootstrap", now=now)
            components.identity.set_password_hash(
                owner.principal_id, algorithm="argon2id", password_hash=hash_password(owner_password), now=now
            )
            components.identity.set_principal_email_verified(owner.principal_id, now=now)

            server = create_server(
                "127.0.0.1",
                port,
                components.service,
                authenticator=components.authenticator,
                session_authenticator=components.session_authenticator,
                rate_limiter=components.rate_limiter,
                maximum_request_bytes=8192,
                allowed_origins=allowed_origins,
                secure_cookies=False,
            )
            stop = threading.Event()
            worker_thread = threading.Thread(target=components.worker.run_forever, args=(stop,), daemon=True)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            worker_thread.start()
            server_thread.start()
            host, port = server.server_address[:2]
            try:
                yield RunningStack(
                    host=host,
                    port=port,
                    organization_id=organization.organization_id,
                    owner_principal_id=owner.principal_id,
                    owner_token=issued_token.token,
                    owner_email=resolved_email,
                    owner_password=owner_password,
                    components=components,
                    authorization_directory=auth_dir,
                    s3_client=s3_client,
                    mail_transport=mail_transport,
                )
            finally:
                stop.set()
                server.shutdown()
                server_thread.join(timeout=5)
                worker_thread.join(timeout=5)
                server.server_close()
        finally:
            components.pool.close()
