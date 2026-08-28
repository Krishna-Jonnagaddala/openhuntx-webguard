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
contexts, authorization comparison plans, and report *metadata*. Report
*bodies* remain local-artifact-only in every environment except
production, where ``ObjectStorageArtifactStore`` is used instead of
``LocalArtifactStore`` -- deliberately not implemented yet (Slice 15),
so every report-artifact operation fails closed with
``object_storage_not_implemented`` in production until object storage
is real, rather than silently treating a local path as durable cloud
storage (requirement 5's explicit instruction).

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
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .artifact_store import ObjectStorageArtifactStore
from .auth import ApiTokenAuthenticator
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
from .pagination import SignedCursorCodec
from .postgres_authentication_contexts import PostgresAuthenticationContextRepository
from .postgres_authorization_comparison import PostgresAuthorizationComparisonPlanRepository
from .postgres_callback_service import PostgresCallbackRegistrationRepository
from .postgres_findings import PostgresFindingRepository
from .postgres_identity import PostgresIdentityRepository
from .postgres_jobs import PostgresJobRepository
from .postgres_pool import WebGuardPostgresPool
from .postgres_reports import PostgresReportRepository
from .postgres_scans import PostgresScanRepository
from .postgres_targets import PostgresTargetRepository
from .production_config import ProductionServiceConfig
from .rate_limit import FixedWindowRateLimiter
from .scheduler import ScanScheduleCoordinator
from .secret_provider import SecretsManagerClientProtocol, SecretsManagerSecretProvider
from .service import WebGuardJobService
from .signing import KmsSigningProvider, SigningKeyRegistry
from .permits import TrustScanSigner
from .worker import ScanJobWorker


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ProductionComponents:
    pool: WebGuardPostgresPool
    identity: PostgresIdentityRepository
    targets: PostgresTargetRepository
    jobs: PostgresJobRepository
    scans: PostgresScanRepository
    findings: PostgresFindingRepository
    callback_repository: PostgresCallbackRegistrationRepository
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
    rate_limiter: FixedWindowRateLimiter

    def readiness_check(self) -> None:
        self.pool.check_connectivity()


def build_production_components(
    config: ProductionServiceConfig,
    *,
    kms_client,
    secrets_manager_client: SecretsManagerClientProtocol | None = None,
) -> ProductionComponents:
    if config.environment != "production":
        raise ValueError("build_production_components requires a production config.")

    pool = WebGuardPostgresPool(
        config.database_url,
        minimum_connections=config.database_pool_minimum,
        maximum_connections=config.database_pool_maximum,
    )
    identity = PostgresIdentityRepository(pool)
    targets = PostgresTargetRepository(pool)
    jobs = PostgresJobRepository(pool)
    scans = PostgresScanRepository(pool)
    findings = PostgresFindingRepository(pool)
    callback_repository = PostgresCallbackRegistrationRepository(pool)
    authentication_contexts = PostgresAuthenticationContextRepository(pool)
    authorization_comparison_plans = PostgresAuthorizationComparisonPlanRepository(pool)
    reports = PostgresReportRepository(pool)
    authorizations = AuthorizationRepository(Path(config.authorization_directory))

    signing_provider = KmsSigningProvider(kms_client, key_id=config.kms_key_id)
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

    # Requirement 5-6: production never treats a local path as durable
    # cloud storage. `ObjectStorageArtifactStore` is intentionally not
    # implemented yet (Slice 15) -- every report-artifact operation
    # fails closed with `object_storage_not_implemented` in production
    # until it is, rather than silently defaulting to
    # `LocalArtifactStore` the way every non-production environment
    # still does (see `service.py`'s own default).
    artifact_store = ObjectStorageArtifactStore(bucket="production-object-storage-not-yet-implemented")

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
    rate_limiter = FixedWindowRateLimiter(requests=120, window_seconds=60)

    return ProductionComponents(
        pool=pool,
        identity=identity,
        targets=targets,
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
        rate_limiter=rate_limiter,
    )


__all__ = ["ProductionComponents", "build_production_components"]
