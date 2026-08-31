"""Production component assembly (Slice 13 requirement 1; extended to
schedules, authentication contexts, and authorization comparison plans
in Slice 14).

The production-mode counterpart to ``cli.py``'s ``_components()`` --
same return shape, same consumer classes (``WebGuardJobService``,
``ScanJobExecutor``, ``ScanJobWorker``, ``ScanScheduleCoordinator``,
``ApiTokenAuthenticator``, ``FixedWindowRateLimiter``), just backed by
PostgreSQL repositories instead of the SQLite
``ScanJobStore``/``IdentityStore``. This is deliberately not a second
service implementation -- it constructs the identical classes
``cli.py`` already uses, satisfying "refactor the existing
service/domain layer to depend on repository contracts" by injecting
different repository objects rather than writing a parallel API.

Live as of this slice: organizations/principals/memberships, targets,
authorizations, scans, jobs, findings, audit, schedules, authentication
contexts, authorization comparison plans, and report *metadata*.

Slice 17: report *bodies* are now real, too. ``ObjectStorageArtifactStore``
(S3-backed, SSE-KMS encrypted) replaces ``LocalArtifactStore`` in
production, reached through an injected ``s3_client`` -- structurally
duck-typed, never a ``boto3`` import in this module (see ``cli.py``'s
``_production_components()``, the one call site that imports it, for
why). Transactional email is likewise real: ``ProductionMailProvider``
(Postmark) replaces ``DevelopmentMailProvider`` -- this one needs no
lazy import at all, since it is built entirely on the standard library
(``http.client``), not a vendor SDK.

Authenticated-scanning secret resolution goes through
``secret_provider.py``'s ``SecretProvider`` abstraction:
``secrets_manager_client`` is injected exactly like ``kms_client``
(never a top-level ``import boto3`` here -- see that parameter's own
docstring) and is optional, because most production deployments never
use authenticated scanning at all; when omitted, the executor's own
default (``LocalSecretProvider`` wrapping
``PostgresAuthenticationContextRepository``, which has no secret
material) fails closed the moment an authenticated scan actually needs
one, not at startup.

SSRF-callback wiring fix (post-Slice-17, closes audit finding P0-1):
``ScanJobExecutor`` used to receive the raw
``PostgresCallbackRegistrationRepository`` directly as its
``callback_repository`` -- a durable *metadata* store, not the live
broker the executor actually needs (no ``.policy``, no
``wait_for_observation()``, and a ``register()`` returning a
``ScopedCallbackRegistration`` with no ``.url``). Every production scan
whose permit included ``active.ssrf.callback`` crashed with an
``AttributeError`` the moment it reached that detector. The executor
now receives a ``postgres_callback_broker.PostgresCallbackBroker``
instead: an adapter over the same durable repository that also polls
``callback_observations`` for a real-time wait (necessary because the
callback receiver, ``webguard-api callback-service``, is an
independently deployable process with no shared memory with the
worker) and finally consumes ``callback_service_hostname`` -- validated
by ``ProductionServiceConfig`` since it was introduced but, until now,
never read anywhere -- to build the actual public callback URL a probe
embeds. See ``postgres_callback_broker.py``'s module docstring for the
full design.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .artifact_store import ObjectStorageArtifactStore, S3ClientProtocol
from .auth import ApiTokenAuthenticator, BrowserSessionAuthenticator
from .auth_rate_limit import PostgresAuthRateLimiter
from .authorizations import AuthorizationRepository
from .callback_service import CallbackRepository
from .config import (
    DEFAULT_API_MAXIMUM_REQUEST_BYTES,
    DEFAULT_SCHEDULER_BATCH_SIZE,
    DEFAULT_SCHEDULER_POLL_SECONDS,
    DEFAULT_WORKER_HEARTBEAT_SECONDS,
    DEFAULT_WORKER_LEASE_SECONDS,
    DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
    DEFAULT_WORKER_POLL_SECONDS,
)
from .executor import ScanJobExecutor
from .mail import PostmarkClientProtocol, PostmarkHttpClient, ProductionMailProvider
from .pagination import SignedCursorCodec
from .postgres_authentication_contexts import PostgresAuthenticationContextRepository
from .postgres_authorization_comparison import PostgresAuthorizationComparisonPlanRepository
from .postgres_callback_broker import PostgresCallbackBroker
from .postgres_callback_service import PostgresCallbackRegistrationRepository
from .postgres_findings import PostgresFindingRepository
from .postgres_identity import PostgresIdentityRepository
from .postgres_jobs import PostgresJobRepository
from .postgres_pool import WebGuardPostgresPool
from .postgres_reports import PostgresReportRepository
from .postgres_scans import PostgresScanRepository
from .postgres_sessions import PostgresSessionRepository
from .postgres_target_verification import PostgresTargetVerificationRepository
from .postgres_targets import PostgresTargetRepository
from .production_config import ProductionServiceConfig
from .rate_limit import FixedWindowRateLimiter
from .scheduler import ScanScheduleCoordinator
from .secret_provider import SecretsManagerClientProtocol, SecretsManagerSecretProvider
from .service import WebGuardJobService
from .signing import KmsSigningProvider, SigningKeyRegistry, SigningServiceClient
from .signing_service import SigningServiceHttpClient
from .permits import TrustScanSigner
from .worker import ScanJobWorker


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ProductionComponents:
    pool: WebGuardPostgresPool
    identity: PostgresIdentityRepository
    targets: PostgresTargetRepository
    target_verifications: PostgresTargetVerificationRepository
    jobs: PostgresJobRepository
    scans: PostgresScanRepository
    findings: PostgresFindingRepository
    callback_repository: PostgresCallbackBroker
    authentication_contexts: PostgresAuthenticationContextRepository
    authorization_comparison_plans: PostgresAuthorizationComparisonPlanRepository
    reports: PostgresReportRepository
    authorizations: AuthorizationRepository
    trustscan_signer: TrustScanSigner
    service: WebGuardJobService
    executor: ScanJobExecutor
    worker: ScanJobWorker
    scheduler: ScanScheduleCoordinator
    authenticator: ApiTokenAuthenticator
    session_authenticator: BrowserSessionAuthenticator
    rate_limiter: FixedWindowRateLimiter

    def readiness_check(self) -> None:
        self.pool.check_connectivity()


def build_production_components(
    config: ProductionServiceConfig,
    *,
    kms_client=None,
    s3_client: S3ClientProtocol,
    secrets_manager_client: SecretsManagerClientProtocol | None = None,
    mail_transport: PostmarkClientProtocol | None = None,
) -> ProductionComponents:
    if config.environment != "production":
        raise ValueError("build_production_components requires a production config.")
    if config.signing_provider == "kms" and kms_client is None:
        raise ValueError("kms_client is required when signing_provider is kms.")

    pool = WebGuardPostgresPool(
        config.database_url,
        minimum_connections=config.database_pool_minimum,
        maximum_connections=config.database_pool_maximum,
    )
    identity = PostgresIdentityRepository(pool)
    targets = PostgresTargetRepository(pool)
    target_verifications = PostgresTargetVerificationRepository(pool)
    jobs = PostgresJobRepository(pool)
    scans = PostgresScanRepository(pool)
    findings = PostgresFindingRepository(pool)
    # Requirement (SSRF-callback wiring fix, closes audit finding
    # P0-1): the durable repository is still constructed directly here
    # (and still what `webguard-api callback-service` uses to record
    # inbound observations -- see `cli.py`), but `ScanJobExecutor`
    # needs the live broker adapter wrapping it, not the raw
    # repository -- see `PostgresCallbackBroker`'s module docstring
    # and this module's own docstring above for why.
    # `callback_service_hostname` is what finally makes this a real,
    # publicly-reachable callback URL rather than the loopback-only
    # `http://127.0.0.1:0/` every non-production caller defaults to.
    callback_registration_repository = PostgresCallbackRegistrationRepository(pool)
    callback_repository = PostgresCallbackBroker(
        callback_registration_repository,
        pool,
        base_url=f"https://{config.callback_service_hostname}/",
    )
    authentication_contexts = PostgresAuthenticationContextRepository(pool)
    authorization_comparison_plans = PostgresAuthorizationComparisonPlanRepository(pool)
    reports = PostgresReportRepository(pool)
    authorizations = AuthorizationRepository(Path(config.authorization_directory))
    sessions = PostgresSessionRepository(pool)
    # Slice 16 requirement 12: a real, distributed-safe counter (see
    # auth_rate_limit.py's own docstring on why Postgres is sufficient
    # here) shared by every auth-adjacent route's bucket key -- login,
    # registration, password reset, email verification, invitation
    # acceptance each get their own bucket key prefix, so one purpose
    # being hammered never exhausts another's quota, but all share one
    # threshold rather than needing a separately-tuned limiter per
    # route.
    auth_rate_limiter = PostgresAuthRateLimiter(pool, max_attempts=10, window_seconds=900)
    # Slice 17 requirement 1: real transactional delivery, always
    # through `ProductionMailProvider`'s own payload/retry/
    # classification logic. `mail_transport` is injectable (mirroring
    # `kms_client`/`s3_client`) purely so a test harness can fake the
    # actual Postmark network boundary -- e.g. the browser E2E suite's
    # `webguard_production_harness.py` -- while still exercising the
    # real production mail-provider code path end to end, not a
    # separate `InMemoryMailProvider` wholesale substitute. No lazy
    # import needed for the real default (unlike kms_client/s3_client
    # below): `PostmarkHttpClient` is built entirely on the standard
    # library, never a vendor SDK.
    mail_provider = ProductionMailProvider(
        mail_transport if mail_transport is not None else PostmarkHttpClient(server_token=config.postmark_server_token),
        from_address=config.mail_from_address,
    )

    # Slice 18: TrustScan production signing. "kms" (ECDSA_SHA_256,
    # unchanged since Slice 12) and "cloudhsm_signing_service"
    # (Ed25519, preserving the existing permit/receipt format
    # entirely -- docs/production/TRUSTSCAN_PRODUCTION_SIGNING.md's
    # Option A) are the only two accepted values
    # (ProductionServiceConfig fails closed on anything else). The
    # CloudHSM path never touches CloudHSM or a PKCS#11 binding from
    # this process -- it calls the dedicated, narrow-interface
    # TrustScan Signing Service over HTTP
    # (docs/production/TRUSTSCAN_SIGNING_SERVICE.md); only that
    # separate service process ever holds HSM credentials.
    if config.signing_provider == "kms":
        signing_provider = KmsSigningProvider(kms_client, key_id=config.kms_key_id)
    else:
        signing_service_transport = SigningServiceHttpClient(
            base_url=config.signing_service_url, bearer_token=config.signing_service_bearer_token
        )
        signing_provider = SigningServiceClient(signing_service_transport)
    registry = SigningKeyRegistry(signing_provider)
    trustscan_signer = TrustScanSigner.from_registry(registry)
    cursor_codec = SignedCursorCodec(config.cursor_signing_key_bytes)

    # Requirement 1: only construct a real secret provider when one was
    # actually configured -- most deployments never use authenticated
    # scanning, so requiring this unconditionally would fail closed for
    # no reason. `None` here means the executor's own default
    # (`LocalSecretProvider` wrapping `authentication_contexts`, which
    # has no secret material in production) is what actually enforces
    # the fail-closed behavior, at first use, not at startup.
    secret_provider = (
        SecretsManagerSecretProvider(secrets_manager_client)
        if secrets_manager_client is not None
        else None
    )

    # Slice 17 requirement 7: production never treats a local path as
    # durable cloud storage. Real S3, SSE-KMS encrypted with a specific
    # customer-managed key (never the AWS-managed SSE-S3 default -- see
    # docs/production/ARTIFACT_STORAGE.md §3). This same instance is
    # passed to both the service (report registration/download reads)
    # and the executor (report writes) below, so a report a worker
    # writes is immediately, durably readable via the API.
    artifact_store = ObjectStorageArtifactStore(
        bucket=config.object_storage_bucket, client=s3_client, kms_key_id=config.object_storage_kms_key_id
    )

    service = WebGuardJobService(
        store=jobs,
        authorizations=authorizations,
        identity=identity,
        trustscan_signer=trustscan_signer,
        cursor_codec=cursor_codec,
        readiness_check=lambda: pool.check_connectivity(),
        finding_repository=findings,
        scan_repository=scans,
        report_repository=reports,
        artifact_store=artifact_store,
        authentication_contexts=authentication_contexts,
        authorization_comparison_plans=authorization_comparison_plans,
        targets=targets,
        target_verifications=target_verifications,
        sessions=sessions,
        mail_provider=mail_provider,
        auth_rate_limiter=auth_rate_limiter,
        web_app_base_url=config.web_app_base_url,
    )
    executor = ScanJobExecutor(
        authorizations=authorizations,
        store=jobs,
        trustscan_signer=trustscan_signer,
        artifact_directory=Path(config.artifact_directory),
        organization_resolver=jobs.organization_id_for_job,
        authorization_assignment_checker=identity.authorization_is_assigned,
        callback_repository=callback_repository,
        scan_repository=scans,
        finding_repository=findings,
        authentication_contexts=authentication_contexts,
        authorization_comparison_plans=authorization_comparison_plans,
        secret_provider=secret_provider,
        artifact_store=artifact_store,
    )
    worker = ScanJobWorker(
        store=jobs,
        executor=executor,
        poll_seconds=DEFAULT_WORKER_POLL_SECONDS,
        worker_id=config.service_identity,
        lease_seconds=DEFAULT_WORKER_LEASE_SECONDS,
        heartbeat_seconds=DEFAULT_WORKER_HEARTBEAT_SECONDS,
        maximum_attempts=DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
    )
    scheduler = ScanScheduleCoordinator(
        store=jobs,
        authorizations=authorizations,
        identity=identity,
        trustscan_signer=trustscan_signer,
        poll_seconds=DEFAULT_SCHEDULER_POLL_SECONDS,
        batch_size=DEFAULT_SCHEDULER_BATCH_SIZE,
    )
    authenticator = ApiTokenAuthenticator(identity)
    session_authenticator = BrowserSessionAuthenticator(identity, sessions)
    rate_limiter = FixedWindowRateLimiter(requests=120, window_seconds=60)

    return ProductionComponents(
        pool=pool,
        identity=identity,
        targets=targets,
        target_verifications=target_verifications,
        jobs=jobs,
        scans=scans,
        findings=findings,
        callback_repository=callback_repository,
        authentication_contexts=authentication_contexts,
        authorization_comparison_plans=authorization_comparison_plans,
        reports=reports,
        authorizations=authorizations,
        trustscan_signer=trustscan_signer,
        service=service,
        executor=executor,
        worker=worker,
        scheduler=scheduler,
        authenticator=authenticator,
        session_authenticator=session_authenticator,
        rate_limiter=rate_limiter,
    )


__all__ = ["ProductionComponents", "build_production_components"]
