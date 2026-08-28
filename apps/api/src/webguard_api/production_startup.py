"""Production component assembly (Slice 13 requirement 1).

The production-mode counterpart to ``cli.py``'s ``_components()`` --
same return shape, same consumer classes (``WebGuardJobService``,
``ScanJobExecutor``, ``ScanJobWorker``, ``ApiTokenAuthenticator``,
``FixedWindowRateLimiter``), just backed by PostgreSQL repositories
instead of the SQLite ``ScanJobStore``/``IdentityStore``. This is
deliberately not a second service implementation -- it constructs the
identical classes ``cli.py`` already uses, satisfying "refactor the
existing service/domain layer to depend on repository contracts" by
injecting different repository objects rather than writing a parallel
API.

Per the confirmed Slice 13 scope: organizations/principals/
memberships, targets, authorizations, scans, jobs, findings, and audit
events are live here. Schedules, authentication contexts, authorization
comparison plans, and report metadata are POSTGRES_REPOSITORY_READY
(built and contract-tested elsewhere) but LIVE_RUNTIME_WIRING_DEFERRED
-- ``PostgresJobRepository``'s schedule methods raise a controlled
error rather than being silently absent or falling back to SQLite.

The KMS client is always injected, never constructed here via a
top-level ``import boto3`` -- this package has no ``boto3`` dependency
(see ``signing.py``'s module docstring) and never will merely to run
this function. A real deployment's entry point constructs
``boto3.client("kms")`` and passes it in; tests inject a fake
satisfying ``KmsClientProtocol``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .auth import ApiTokenAuthenticator
from .authorizations import AuthorizationRepository
from .callback_service import CallbackRepository
from .config import (
    DEFAULT_API_MAXIMUM_REQUEST_BYTES,
    DEFAULT_WORKER_HEARTBEAT_SECONDS,
    DEFAULT_WORKER_LEASE_SECONDS,
    DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
    DEFAULT_WORKER_POLL_SECONDS,
)
from .executor import ScanJobExecutor
from .pagination import SignedCursorCodec
from .postgres_callback_service import PostgresCallbackRegistrationRepository
from .postgres_findings import PostgresFindingRepository
from .postgres_identity import PostgresIdentityRepository
from .postgres_jobs import PostgresJobRepository
from .postgres_pool import WebGuardPostgresPool
from .postgres_scans import PostgresScanRepository
from .postgres_targets import PostgresTargetRepository
from .production_config import ProductionServiceConfig
from .rate_limit import FixedWindowRateLimiter
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
    authorizations: AuthorizationRepository
    trustscan_signer: TrustScanSigner
    service: WebGuardJobService
    executor: ScanJobExecutor
    worker: ScanJobWorker
    authenticator: ApiTokenAuthenticator
    rate_limiter: FixedWindowRateLimiter

    def readiness_check(self) -> None:
        self.pool.check_connectivity()


def build_production_components(
    config: ProductionServiceConfig, *, kms_client
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
    authorizations = AuthorizationRepository(Path(config.authorization_directory))

    signing_provider = KmsSigningProvider(kms_client, key_id=config.kms_key_id)
    registry = SigningKeyRegistry(signing_provider)
    trustscan_signer = TrustScanSigner.from_registry(registry)
    cursor_codec = SignedCursorCodec(config.cursor_signing_key_bytes)

    service = WebGuardJobService(
        store=jobs,
        authorizations=authorizations,
        identity=identity,
        trustscan_signer=trustscan_signer,
        cursor_codec=cursor_codec,
        readiness_check=lambda: pool.check_connectivity(),
        finding_repository=findings,
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
        authorizations=authorizations,
        trustscan_signer=trustscan_signer,
        service=service,
        executor=executor,
        worker=worker,
        authenticator=authenticator,
        rate_limiter=rate_limiter,
    )


__all__ = ["ProductionComponents", "build_production_components"]
