"""Command-line entry point for the local authenticated WebGuard API."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence
from uuid import uuid4

from webguard_contracts import OrganizationRole, PrincipalType

from . import __version__
from .artifact_store import LocalArtifactStore
from .auth import ApiTokenAuthenticator, AuthenticationError, BrowserSessionAuthenticator
from .authorizations import AuthorizationRepository, AuthorizationRepositoryError
from .config import (
    DEFAULT_API_HOST,
    DEFAULT_API_MAXIMUM_REQUEST_BYTES,
    DEFAULT_API_PORT,
    DEFAULT_RATE_LIMIT_REQUESTS,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_SCHEDULER_BATCH_SIZE,
    DEFAULT_SCHEDULER_POLL_SECONDS,
    DEFAULT_WORKER_HEARTBEAT_SECONDS,
    DEFAULT_WORKER_LEASE_SECONDS,
    DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
    DEFAULT_WORKER_POLL_SECONDS,
    ServiceConfig,
    ServiceConfigError,
)
from .environment import Environment
from .executor import ScanJobExecutor
from .http_api import create_server
from .identity import (
    DEFAULT_TOKEN_VALIDITY_DAYS,
    IdentityStore,
    IdentityStoreError,
)
from .production_config import ProductionConfigError, ProductionServiceConfig
from .production_startup import ProductionComponents, build_production_components
from .rate_limit import FixedWindowRateLimiter
from .permits import TrustScanSigner
from .scheduler import ScanScheduleCoordinator
from .service import ApiServiceError, WebGuardJobService
from .store import JobStoreError, ScanJobStore
from .worker import ScanJobWorker


EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _config(args: argparse.Namespace) -> ServiceConfig:
    return ServiceConfig(
        host=args.host,
        port=args.port,
        database_path=args.database,
        service_secret_path=args.service_secrets,
        authorization_directory=args.authorizations,
        artifact_directory=args.artifacts,
        maximum_request_bytes=args.maximum_request_bytes,
        worker_poll_seconds=args.worker_poll_seconds,
        worker_id=args.worker_id,
        worker_lease_seconds=args.worker_lease_seconds,
        worker_heartbeat_seconds=args.worker_heartbeat_seconds,
        worker_maximum_attempts=args.worker_maximum_attempts,
        scheduler_poll_seconds=args.scheduler_poll_seconds,
        scheduler_batch_size=args.scheduler_batch_size,
        rate_limit_requests=args.rate_limit_requests,
        rate_limit_window_seconds=args.rate_limit_window_seconds,
    )


def _stores(config: ServiceConfig) -> tuple[ScanJobStore, IdentityStore]:
    jobs = ScanJobStore(
        config.database_path,
        service_secret_path=config.service_secret_path,
    )
    identity = IdentityStore(config.database_path)
    return jobs, identity


def _components(config: ServiceConfig):
    store, identity = _stores(config)
    authorizations = AuthorizationRepository(config.authorization_directory)
    trustscan_signer = TrustScanSigner(store.trustscan_signing_private_key())
    # One shared `LocalArtifactStore` over `config.artifact_directory`,
    # explicitly passed to both -- previously the executor wrote
    # reports under `config.artifact_directory` (via its own
    # `artifact_directory` parameter) while the service read them back
    # through its own separately-defaulted `LocalArtifactStore`
    # (hardcoded to `scan-results/service`). The two only ever agreed
    # by coincidence, since that hardcoded default equals
    # `ServiceConfig.artifact_directory`'s own default -- passing
    # `--artifacts <anything else>` to `serve`/`run` would have made
    # every report download silently fail with `artifact_not_found`.
    artifact_store = LocalArtifactStore(config.artifact_directory)
    executor = ScanJobExecutor(
        authorizations=authorizations,
        store=store,
        trustscan_signer=trustscan_signer,
        artifact_directory=config.artifact_directory,
        organization_resolver=store.organization_id_for_job,
        authorization_assignment_checker=(
            identity.authorization_is_assigned
        ),
        artifact_store=artifact_store,
    )
    web_app_base_url = os.environ.get("WEBGUARD_WEB_APP_BASE_URL", "http://127.0.0.1:5173")
    service = WebGuardJobService(
        store=store,
        authorizations=authorizations,
        identity=identity,
        trustscan_signer=trustscan_signer,
        artifact_store=artifact_store,
        web_app_base_url=web_app_base_url,
    )
    worker = ScanJobWorker(
        store=store,
        executor=executor,
        poll_seconds=config.worker_poll_seconds,
        worker_id=config.worker_id,
        lease_seconds=config.worker_lease_seconds,
        heartbeat_seconds=config.worker_heartbeat_seconds,
        maximum_attempts=config.worker_maximum_attempts,
    )
    scheduler = ScanScheduleCoordinator(
        store=store,
        authorizations=authorizations,
        identity=identity,
        trustscan_signer=trustscan_signer,
        poll_seconds=config.scheduler_poll_seconds,
        batch_size=config.scheduler_batch_size,
    )
    authenticator = ApiTokenAuthenticator(identity)
    limiter = FixedWindowRateLimiter(
        requests=config.rate_limit_requests,
        window_seconds=config.rate_limit_window_seconds,
    )
    return store, identity, service, worker, scheduler, authenticator, limiter


def _resolve_environment(args: argparse.Namespace) -> Environment:
    return Environment(args.environment)


def _production_components() -> tuple[ProductionServiceConfig, ProductionComponents]:
    """The production-mode counterpart to `_components()` (Slice 13
    requirement 1): selected explicitly via `--environment production`
    / `WEBGUARD_ENVIRONMENT=production`, never inferred. `boto3` is
    imported here, at the one call site that actually needs a real AWS
    KMS/Secrets-Manager/S3 client, and nowhere else in this package --
    see `production_startup.py`'s module docstring for why it is not a
    package-level dependency (Slice 17 requirement 22: no AWS SDK
    credential material of any kind is ever embedded in source -- the
    real `boto3.client(...)` calls below resolve credentials through
    boto3's own standard chain, i.e. a workload/service identity such
    as an ECS task role, exactly as `kms_client` already did). A
    Secrets Manager client is constructed only when `secret_provider`
    was actually configured (Slice 14 requirement 1) -- most
    deployments never use authenticated scanning and should not need
    AWS Secrets Manager credentials to start. The S3 client, unlike
    Secrets Manager, is unconditional: `ProductionServiceConfig`
    requires object-storage configuration for every production
    deployment (Slice 17 requirement 21)."""

    config = ProductionServiceConfig.from_environment()

    import boto3

    kms_client = boto3.client("kms")
    s3_client = boto3.client("s3", region_name=config.object_storage_region)
    secrets_manager_client = (
        boto3.client("secretsmanager")
        if config.secret_provider == "aws_secrets_manager"  # noqa: S105 - a provider-selector enum value, not a credential
        else None
    )
    components = build_production_components(
        config, kms_client=kms_client, s3_client=s3_client, secrets_manager_client=secrets_manager_client
    )
    return config, components


def _init_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _stores(config)
    print(f"Initialized service database: {config.database_path}")
    print(f"Authorization directory: {config.authorization_directory}")
    print(f"Artifact directory: {config.artifact_directory}")
    return EXIT_SUCCESS


def _bootstrap_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, identity = _stores(config)
    now = _utc_now()
    organization = identity.create_organization(args.organization, now=now)
    principal = identity.create_principal(
        organization.organization_id,
        args.principal,
        principal_type=PrincipalType.USER,
        role=OrganizationRole.OWNER,
        now=now,
    )
    issued = identity.create_token(
        principal.principal_id,
        label=args.token_label,
        validity_days=args.token_valid_days,
        now=now,
    )
    print(f"Organization ID: {organization.organization_id}")
    print(f"Owner principal ID: {principal.principal_id}")
    print(f"API token ID: {issued.metadata.token_id}")
    print(f"API token: {issued.token}")
    print("Store this token securely. It will not be displayed again.")
    return EXIT_SUCCESS


def _organization_create_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, identity = _stores(config)
    value = identity.create_organization(args.name, now=_utc_now())
    print(f"Organization ID: {value.organization_id}")
    print(f"Organization name: {value.name}")
    return EXIT_SUCCESS


def _principal_create_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, identity = _stores(config)
    value = identity.create_principal(
        args.organization_id,
        args.name,
        principal_type=PrincipalType(args.type),
        role=OrganizationRole(args.role),
        now=_utc_now(),
    )
    print(f"Principal ID: {value.principal_id}")
    print(f"Role: {value.role.value}")
    return EXIT_SUCCESS


def _token_create_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, identity = _stores(config)
    issued = identity.create_token(
        args.principal_id,
        label=args.label,
        validity_days=args.valid_days,
        now=_utc_now(),
    )
    print(f"API token ID: {issued.metadata.token_id}")
    print(f"API token: {issued.token}")
    print("Store this token securely. It will not be displayed again.")
    return EXIT_SUCCESS


def _token_revoke_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, identity = _stores(config)
    metadata = identity.revoke_token(args.token_id, now=_utc_now())
    print(f"Revoked API token: {metadata.token_id}")
    return EXIT_SUCCESS


def _authorization_assign_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, identity = _stores(config)
    repository = AuthorizationRepository(config.authorization_directory)
    repository.get(args.authorization_id)
    identity.assign_authorization(
        args.organization_id,
        args.authorization_id,
        assigned_by=args.principal_id,
        now=_utc_now(),
    )
    print(f"Assigned authorization: {args.authorization_id}")
    print(f"Organization ID: {args.organization_id}")
    return EXIT_SUCCESS


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _permit_issue_command(args: argparse.Namespace) -> int:
    """Issue a TrustScan permit through the same service path (RBAC,
    authorization binding, audit) the HTTP API uses -- never a shortcut
    that bypasses it. active_checks defaults to none (passive-only,
    fail closed); requesting any active check requires the caller's
    token to belong to an organization owner (see PERMIT_ISSUE_ACTIVE)."""

    config = _config(args)
    _, identity, service, _, _, authenticator, _ = _components(config)
    now = _utc_now()
    try:
        context = authenticator.authenticate([f"Bearer {args.token}"], now=now)
    except AuthenticationError as exc:
        print(f"webguard-api: [{exc.code}] {exc.message}", file=sys.stderr)
        return EXIT_FAILURE

    active_checks = sorted(set(args.active_check or []))
    if len(active_checks) != len(args.active_check or []):
        print(
            "webguard-api: [active_checks_duplicate] "
            "--active-check values must not repeat.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    body = json.dumps(
        {
            "target": args.target,
            "authorization_id": args.authorization_id,
            "confirm_authorization": args.authorization_id,
            "permitted_modes": sorted(set(args.mode)),
            "allowed_http_methods": sorted(
                {
                    method.upper()
                    for method in (args.allowed_http_method or ["GET", "HEAD"])
                }
            ),
            # A small buffer avoids a spurious trustscan_permit_start_in_past
            # rejection: the service independently re-reads its own clock a
            # moment after this timestamp is generated, and that read must
            # never land after not_before. Kept small so a freshly issued
            # permit is usable almost immediately.
            "not_before": _timestamp_text(now + timedelta(milliseconds=500)),
            "expires_at": _timestamp_text(now + timedelta(days=args.valid_days)),
            "maximum_request_attempts": args.maximum_request_attempts,
            "maximum_requests_per_second": args.maximum_requests_per_second,
            "maximum_concurrency": args.maximum_concurrency,
            "active_checks": active_checks,
            "authentication_context_id": args.authentication_context_id,
            "authorization_comparison_plan_id": args.authorization_comparison_plan_id,
        }
    ).encode("utf-8")

    try:
        record = service.issue_permit(context, body, request_id=str(uuid4()))
    except ApiServiceError as exc:
        print(f"webguard-api: [{exc.code}] {exc.message}", file=sys.stderr)
        return EXIT_FAILURE

    claims = record["permit"]["claims"]
    print(f"Permit ID: {claims['permit_id']}")
    print(f"Target: {claims['target']}")
    print(f"Permitted modes: {', '.join(claims['permitted_modes'])}")
    print(f"Expires at: {claims['expires_at']}")
    if claims["active_checks"]:
        print(f"Active checks authorized: {', '.join(claims['active_checks'])}")
    else:
        print("Active checks authorized: none (passive-only)")
    return EXIT_SUCCESS


def _authentication_context_register_command(args: argparse.Namespace) -> int:
    """Register a new authentication context through the same service
    path (RBAC, authorization binding, audit) the HTTP API uses.
    Owner-only. The secret is read from the flag once and never printed
    back -- only the resulting context's metadata is shown."""

    config = _config(args)
    _, identity, service, _, _, authenticator, _ = _components(config)
    now = _utc_now()
    try:
        context = authenticator.authenticate([f"Bearer {args.token}"], now=now)
    except AuthenticationError as exc:
        print(f"webguard-api: [{exc.code}] {exc.message}", file=sys.stderr)
        return EXIT_FAILURE

    body = {
        "target": args.target,
        "authorization_id": args.authorization_id,
        "identity_label": args.identity_label,
        "method": args.method,
        "expires_at": _timestamp_text(now + timedelta(days=args.valid_days)),
    }
    if args.bearer_token is not None:
        body["bearer_token"] = args.bearer_token
    if args.basic_username is not None:
        body["basic_username"] = args.basic_username
    if args.basic_password is not None:
        body["basic_password"] = args.basic_password

    try:
        record = service.register_authentication_context(
            context, body, request_id=str(uuid4())
        )
    except ApiServiceError as exc:
        print(f"webguard-api: [{exc.code}] {exc.message}", file=sys.stderr)
        return EXIT_FAILURE

    print(f"Authentication context ID: {record['authentication_context_id']}")
    print(f"Identity label: {record['identity_label']}")
    print(f"Method: {record['method']}")
    print(f"Expires at: {record['expires_at']}")
    return EXIT_SUCCESS


def _authorization_comparison_register_command(args: argparse.Namespace) -> int:
    """Register a new authorization-comparison plan (Slice 9) through the
    same service path (RBAC, binding validation, audit) the HTTP API
    uses. Owner-only. Closes the CLI/HTTP parity gap the phase 8 audit
    doc flagged: the CLI now uses the identical
    ``register_authorization_comparison_plan`` service method, not a
    hand-authored HTTP request."""

    config = _config(args)
    _, identity, service, _, _, authenticator, _ = _components(config)
    now = _utc_now()
    try:
        context = authenticator.authenticate([f"Bearer {args.token}"], now=now)
    except AuthenticationError as exc:
        print(f"webguard-api: [{exc.code}] {exc.message}", file=sys.stderr)
        return EXIT_FAILURE

    try:
        resource_scope = json.loads(args.resource_scope_json)
    except json.JSONDecodeError as exc:
        print(
            f"webguard-api: [resource_scope_json_invalid] {exc}",
            file=sys.stderr,
        )
        return EXIT_FAILURE
    if not isinstance(resource_scope, list):
        print(
            "webguard-api: [resource_scope_json_invalid] "
            "--resource-scope-json must be a JSON array.",
            file=sys.stderr,
        )
        return EXIT_FAILURE

    body = {
        "target": args.target,
        "authorization_id": args.authorization_id,
        "primary_context_id": args.primary_context_id,
        "secondary_context_id": args.secondary_context_id,
        "resource_scope": resource_scope,
        "expires_at": _timestamp_text(now + timedelta(days=args.valid_days)),
        "enable_discovery": args.enable_discovery,
    }
    if args.discovery_login_page_marker is not None:
        body["discovery_login_page_marker"] = args.discovery_login_page_marker

    try:
        record = service.register_authorization_comparison_plan(
            context, body, request_id=str(uuid4())
        )
    except ApiServiceError as exc:
        print(f"webguard-api: [{exc.code}] {exc.message}", file=sys.stderr)
        return EXIT_FAILURE

    print(f"Comparison plan ID: {record['comparison_plan_id']}")
    print(f"Permitted active check: {record['permitted_active_check']}")
    print(f"Resource pairs: {len(record['resource_scope'])}")
    print(f"Discovery enabled: {record['enable_discovery']}")
    print(f"Expires at: {record['expires_at']}")
    return EXIT_SUCCESS


def _authorization_comparison_revoke_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, identity, service, _, _, authenticator, _ = _components(config)
    now = _utc_now()
    try:
        context = authenticator.authenticate([f"Bearer {args.token}"], now=now)
    except AuthenticationError as exc:
        print(f"webguard-api: [{exc.code}] {exc.message}", file=sys.stderr)
        return EXIT_FAILURE

    try:
        record = service.revoke_authorization_comparison_plan(
            context, args.comparison_plan_id, request_id=str(uuid4())
        )
    except ApiServiceError as exc:
        print(f"webguard-api: [{exc.code}] {exc.message}", file=sys.stderr)
        return EXIT_FAILURE

    print(f"Comparison plan ID: {record['comparison_plan_id']}")
    print(f"Status: {record['status']}")
    return EXIT_SUCCESS


def _worker_command(args: argparse.Namespace) -> int:
    environment = _resolve_environment(args)
    pool = None
    if environment is Environment.PRODUCTION:
        _, components = _production_components()
        worker = components.worker
        pool = components.pool
    else:
        config = _config(args)
        _, _, _, worker, _, _, _ = _components(config)
    try:
        if args.once:
            processed = worker.run_once()
            recovery = worker.last_recovery_summary
            if recovery.total:
                print(
                    "Recovered expired leases: "
                    f"requeued={recovery.requeued}, "
                    f"cancelled={recovery.cancelled}, failed={recovery.failed}."
                )
            print("Processed one job." if processed else "No queued job was available.")
            return EXIT_SUCCESS
        stop_event = threading.Event()

        def request_stop(_signum: int, _frame: object) -> None:
            stop_event.set()

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        print(f"WebGuard worker started: {worker.worker_id} (environment={environment.value})")
        print(
            "Lease: "
            f"{worker.lease_seconds:g}s; heartbeat: "
            f"{worker.heartbeat_seconds:g}s; maximum attempts: "
            f"{worker.maximum_attempts}."
        )
        print("Press Ctrl+C to stop.")
        worker.run_forever(stop_event)
        print("WebGuard worker stopped.")
        return EXIT_SUCCESS
    finally:
        if pool is not None:
            pool.close()


def _scheduler_command(args: argparse.Namespace) -> int:
    environment = _resolve_environment(args)
    pool = None
    if environment is Environment.PRODUCTION:
        _, components = _production_components()
        scheduler = components.scheduler
        pool = components.pool
    else:
        config = _config(args)
        _, _, _, _, scheduler, _, _ = _components(config)
    try:
        if args.once:
            summary = scheduler.run_once()
            print(
                "Schedule pass: "
                f"inspected={summary.inspected}, enqueued={summary.enqueued}, "
                f"blocked={summary.blocked}, raced={summary.raced}."
            )
            return EXIT_SUCCESS
        stop_event = threading.Event()

        def request_stop(_signum: int, _frame: object) -> None:
            stop_event.set()

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        print(
            "WebGuard scheduler started "
            f"(environment={environment.value}): "
            f"poll={scheduler.poll_seconds:g}s; batch={scheduler.batch_size}."
        )
        print("Press Ctrl+C to stop.")
        scheduler.run_forever(stop_event)
        print("WebGuard scheduler stopped.")
        return EXIT_SUCCESS
    finally:
        if pool is not None:
            pool.close()


def _serve_command(args: argparse.Namespace) -> int:
    environment = _resolve_environment(args)
    pool = None
    scheduler = None
    if environment is Environment.PRODUCTION:
        # Requirement 1: production selection is explicit
        # (--environment / WEBGUARD_ENVIRONMENT), never inferred, and
        # fails closed via ProductionServiceConfig.from_environment()
        # if required settings are missing. Slice 14 requirement 3:
        # schedule materialization is now live against PostgreSQL, so
        # production starts a real scheduler thread here, the same way
        # local/lab mode always has.
        production_config, components = _production_components()
        host, port = production_config.host, production_config.port
        maximum_request_bytes = DEFAULT_API_MAXIMUM_REQUEST_BYTES
        service = components.service
        worker = components.worker
        scheduler = components.scheduler
        authenticator = components.authenticator
        session_authenticator = components.session_authenticator
        limiter = components.rate_limiter
        pool = components.pool
    else:
        config = _config(args)
        _, identity, service, worker, scheduler, authenticator, limiter = _components(config)
        session_authenticator = BrowserSessionAuthenticator(identity, service.sessions)
        host, port = config.host, config.port
        maximum_request_bytes = config.maximum_request_bytes
    stop_event = threading.Event()
    worker_thread = threading.Thread(
        target=worker.run_forever,
        args=(stop_event,),
        name="webguard-job-worker",
        daemon=True,
    )
    scheduler_thread = (
        threading.Thread(
            target=scheduler.run_forever,
            args=(stop_event,),
            name="webguard-scan-scheduler",
            daemon=True,
        )
        if scheduler is not None
        else None
    )
    allowed_origins = frozenset(
        origin.strip()
        for origin in os.environ.get("WEBGUARD_WEB_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    )
    # Slice 16: secure by default -- an operator must explicitly opt
    # out for plain-HTTP local/dev use (a browser will not store or
    # return a Secure cookie over plain HTTP at all, so getting this
    # wrong in dev doesn't fail insecurely, it just breaks login).
    # HSTS is readiness, not enforcement (see build_handler's
    # docstring): off by default, since this process itself only ever
    # binds to loopback.
    secure_cookies = os.environ.get("WEBGUARD_SECURE_COOKIES", "true").strip().lower() != "false"
    hsts_enabled = os.environ.get("WEBGUARD_HSTS_ENABLED", "false").strip().lower() == "true"
    server = create_server(
        host,
        port,
        service,
        authenticator=authenticator,
        session_authenticator=session_authenticator,
        rate_limiter=limiter,
        maximum_request_bytes=maximum_request_bytes,
        allowed_origins=allowed_origins,
        secure_cookies=secure_cookies,
        hsts_enabled=hsts_enabled,
    )

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    worker_thread.start()
    if scheduler_thread is not None:
        scheduler_thread.start()
    bound_host, bound_port = server.server_address[:2]
    print(f"WebGuard API listening on http://{bound_host}:{bound_port} (environment={environment.value})")
    print("Bearer authentication and organization RBAC are enabled.")
    print(
        f"Worker {worker.worker_id} uses renewable database leases "
        f"({worker.lease_seconds:g}s)."
    )
    if scheduler is not None:
        print(
            "Recurring scan scheduler is enabled "
            f"({scheduler.poll_seconds:g}s poll interval)."
        )
    else:
        print(
            "Recurring scan scheduler is not started: schedule execution is "
            "not yet wired to PostgreSQL (POSTGRES_REPOSITORY_READY, "
            "LIVE_RUNTIME_WIRING_DEFERRED)."
        )
    print("Binding is loopback-only. Press Ctrl+C to stop.")
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        stop_event.set()
        server.server_close()
        worker_thread.join(timeout=2.0)
        if scheduler_thread is not None:
            scheduler_thread.join(timeout=2.0)
        if pool is not None:
            pool.close()
    print("WebGuard API stopped.")
    return EXIT_SUCCESS


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default=DEFAULT_API_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_API_PORT)
    parser.add_argument("--database", type=Path, default=Path("var/webguard-api/jobs.sqlite3"))
    parser.add_argument(
        "--service-secrets",
        type=Path,
        default=None,
        help=(
            "Owner-only service signing secret file. "
            "Defaults beside the service database."
        ),
    )
    parser.add_argument("--authorizations", type=Path, default=Path("authorizations"))
    parser.add_argument("--artifacts", type=Path, default=Path("scan-results/service"))
    parser.add_argument(
        "--maximum-request-bytes", type=int, default=DEFAULT_API_MAXIMUM_REQUEST_BYTES
    )
    parser.add_argument(
        "--worker-poll-seconds", type=float, default=DEFAULT_WORKER_POLL_SECONDS
    )
    parser.add_argument("--worker-id")
    parser.add_argument(
        "--worker-lease-seconds",
        type=float,
        default=DEFAULT_WORKER_LEASE_SECONDS,
    )
    parser.add_argument(
        "--worker-heartbeat-seconds",
        type=float,
        default=DEFAULT_WORKER_HEARTBEAT_SECONDS,
    )
    parser.add_argument(
        "--worker-maximum-attempts",
        type=int,
        default=DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
    )
    parser.add_argument(
        "--scheduler-poll-seconds",
        type=float,
        default=DEFAULT_SCHEDULER_POLL_SECONDS,
    )
    parser.add_argument(
        "--scheduler-batch-size",
        type=int,
        default=DEFAULT_SCHEDULER_BATCH_SIZE,
    )
    parser.add_argument(
        "--rate-limit-requests", type=int, default=DEFAULT_RATE_LIMIT_REQUESTS
    )
    parser.add_argument(
        "--rate-limit-window-seconds", type=int, default=DEFAULT_RATE_LIMIT_WINDOW_SECONDS
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webguard-api",
        description="Authenticated local WebGuard control-plane API and scanner queue.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize service and identity tables.")
    _add_common_options(init_parser)
    init_parser.set_defaults(handler=_init_command)

    bootstrap = subparsers.add_parser(
        "bootstrap", help="Create the first organization, owner, and one-time API token."
    )
    _add_common_options(bootstrap)
    bootstrap.add_argument("--organization", required=True)
    bootstrap.add_argument("--principal", required=True)
    bootstrap.add_argument("--token-label", default="bootstrap-owner")
    bootstrap.add_argument(
        "--token-valid-days", type=int, default=DEFAULT_TOKEN_VALIDITY_DAYS
    )
    bootstrap.set_defaults(handler=_bootstrap_command)

    organization = subparsers.add_parser("organization", help="Manage organizations.")
    organization_commands = organization.add_subparsers(dest="organization_command", required=True)
    organization_create = organization_commands.add_parser("create")
    _add_common_options(organization_create)
    organization_create.add_argument("--name", required=True)
    organization_create.set_defaults(handler=_organization_create_command)

    principal = subparsers.add_parser("principal", help="Manage users and service accounts.")
    principal_commands = principal.add_subparsers(dest="principal_command", required=True)
    principal_create = principal_commands.add_parser("create")
    _add_common_options(principal_create)
    principal_create.add_argument("--organization-id", required=True)
    principal_create.add_argument("--name", required=True)
    principal_create.add_argument(
        "--type", choices=[item.value for item in PrincipalType], default=PrincipalType.USER.value
    )
    principal_create.add_argument(
        "--role", choices=[item.value for item in OrganizationRole], required=True
    )
    principal_create.set_defaults(handler=_principal_create_command)

    token = subparsers.add_parser("token", help="Manage API tokens.")
    token_commands = token.add_subparsers(dest="token_command", required=True)
    token_create = token_commands.add_parser("create")
    _add_common_options(token_create)
    token_create.add_argument("--principal-id", required=True)
    token_create.add_argument("--label", required=True)
    token_create.add_argument("--valid-days", type=int, default=DEFAULT_TOKEN_VALIDITY_DAYS)
    token_create.set_defaults(handler=_token_create_command)
    token_revoke = token_commands.add_parser("revoke")
    _add_common_options(token_revoke)
    token_revoke.add_argument("--token-id", required=True)
    token_revoke.set_defaults(handler=_token_revoke_command)

    assignment = subparsers.add_parser("authorization", help="Assign target authorizations.")
    assignment_commands = assignment.add_subparsers(dest="authorization_command", required=True)
    assignment_create = assignment_commands.add_parser("assign")
    _add_common_options(assignment_create)
    assignment_create.add_argument("--organization-id", required=True)
    assignment_create.add_argument("--principal-id", required=True)
    assignment_create.add_argument("--authorization-id", required=True)
    assignment_create.set_defaults(handler=_authorization_assign_command)

    permit = subparsers.add_parser("permit", help="Issue TrustScan scan permits.")
    permit_commands = permit.add_subparsers(dest="permit_command", required=True)
    permit_issue = permit_commands.add_parser(
        "issue",
        help=(
            "Issue a TrustScan permit. active_checks defaults to none "
            "(passive-only); requesting any active check requires an "
            "organization-owner token."
        ),
    )
    _add_common_options(permit_issue)
    permit_issue.add_argument(
        "--token", required=True, help="Bearer API token authenticating this request."
    )
    permit_issue.add_argument("--target", required=True)
    permit_issue.add_argument("--authorization-id", required=True)
    permit_issue.add_argument(
        "--mode",
        action="append",
        choices=["crawl", "single_page"],
        required=True,
        help="May be repeated. At least one permitted scan mode.",
    )
    permit_issue.add_argument(
        "--allowed-http-method",
        action="append",
        default=None,
        help="May be repeated. Defaults to GET and HEAD.",
    )
    permit_issue.add_argument("--valid-days", type=int, default=7)
    permit_issue.add_argument(
        "--maximum-request-attempts", type=int, default=15
    )
    permit_issue.add_argument(
        "--maximum-requests-per-second", type=float, default=1.0
    )
    permit_issue.add_argument("--maximum-concurrency", type=int, default=1)
    permit_issue.add_argument(
        "--active-check",
        action="append",
        default=None,
        help=(
            "May be repeated. Authorizes one active-detector ID (for "
            "example active.xss.reflected) for this permit. Omit entirely "
            "for a passive-only permit -- the default and the fail-closed "
            "behaviour for every permit that does not explicitly request "
            "one. Requesting any value here requires an organization-owner "
            "token."
        ),
    )
    permit_issue.add_argument(
        "--authentication-context-id",
        default=None,
        help=(
            "Bind this permit to a previously registered authentication "
            "context, authorizing authenticated scanning of the target "
            "under that context. Omit entirely for an unauthenticated "
            "permit -- the default and the fail-closed behaviour for "
            "every permit that does not explicitly request one. "
            "Requesting this requires an organization-owner token."
        ),
    )
    permit_issue.add_argument(
        "--authorization-comparison-plan-id",
        default=None,
        help=(
            "Bind this permit to a previously registered authorization-"
            "comparison plan, authorizing the IDOR/BOLA differential "
            "detector to compare the two identities that plan names. "
            "Omit entirely for a permit with no comparison capability -- "
            "the default and the fail-closed behaviour for every permit "
            "that does not explicitly request one. Requesting this "
            "requires an organization-owner token."
        ),
    )
    permit_issue.set_defaults(handler=_permit_issue_command)

    authentication_context = subparsers.add_parser(
        "authentication-context",
        help="Register authentication contexts for authenticated scanning.",
    )
    authentication_context_commands = authentication_context.add_subparsers(
        dest="authentication_context_command", required=True
    )
    authentication_context_register = authentication_context_commands.add_parser(
        "register",
        help=(
            "Register a bearer-token or basic-auth authentication context. "
            "Owner-only. The secret is never echoed back."
        ),
    )
    _add_common_options(authentication_context_register)
    authentication_context_register.add_argument(
        "--token", required=True, help="Bearer API token authenticating this request."
    )
    authentication_context_register.add_argument("--target", required=True)
    authentication_context_register.add_argument("--authorization-id", required=True)
    authentication_context_register.add_argument("--identity-label", required=True)
    authentication_context_register.add_argument(
        "--method",
        required=True,
        choices=["bearer_token", "cookie_session", "basic_auth", "login_workflow"],
    )
    authentication_context_register.add_argument("--valid-days", type=int, default=1)
    authentication_context_register.add_argument("--bearer-token", default=None)
    authentication_context_register.add_argument("--basic-username", default=None)
    authentication_context_register.add_argument("--basic-password", default=None)
    authentication_context_register.set_defaults(
        handler=_authentication_context_register_command
    )

    authorization_comparison = subparsers.add_parser(
        "authorization-comparison",
        help="Manage authorization-comparison plans for IDOR/BOLA scanning.",
    )
    authorization_comparison_commands = authorization_comparison.add_subparsers(
        dest="authorization_comparison_command", required=True
    )
    authorization_comparison_register = authorization_comparison_commands.add_parser(
        "register",
        help=(
            "Register an authorization-comparison plan referencing two "
            "already-registered, distinct authentication contexts. "
            "Owner-only."
        ),
    )
    _add_common_options(authorization_comparison_register)
    authorization_comparison_register.add_argument(
        "--token", required=True, help="Bearer API token authenticating this request."
    )
    authorization_comparison_register.add_argument("--target", required=True)
    authorization_comparison_register.add_argument("--authorization-id", required=True)
    authorization_comparison_register.add_argument(
        "--primary-context-id", required=True
    )
    authorization_comparison_register.add_argument(
        "--secondary-context-id", required=True
    )
    authorization_comparison_register.add_argument(
        "--resource-scope-json",
        default="[]",
        help=(
            "JSON array of explicit resource-pair objects (resource_type, "
            "method, primary_endpoint, secondary_endpoint, "
            "identifier_location, identifier_name, expected_access). "
            "May be empty (\"[]\") when --enable-discovery is set."
        ),
    )
    authorization_comparison_register.add_argument(
        "--enable-discovery",
        action="store_true",
        help=(
            "Also run an authenticated resource-discovery crawl for each "
            "identity at scan time (Slice 9), feeding structurally-"
            "eligible discovered resources into the same comparison "
            "alongside any explicit resource pairs above."
        ),
    )
    authorization_comparison_register.add_argument(
        "--discovery-login-page-marker",
        default=None,
        help=(
            "Optional string that, if present in a discovery-crawl "
            "page's body, marks that page as an expired-session login "
            "page rather than ordinary application content."
        ),
    )
    authorization_comparison_register.add_argument("--valid-days", type=int, default=1)
    authorization_comparison_register.set_defaults(
        handler=_authorization_comparison_register_command
    )

    authorization_comparison_revoke = authorization_comparison_commands.add_parser(
        "revoke", help="Revoke an authorization-comparison plan. Owner-only."
    )
    _add_common_options(authorization_comparison_revoke)
    authorization_comparison_revoke.add_argument(
        "--token", required=True, help="Bearer API token authenticating this request."
    )
    authorization_comparison_revoke.add_argument(
        "--comparison-plan-id", required=True
    )
    authorization_comparison_revoke.set_defaults(
        handler=_authorization_comparison_revoke_command
    )

    environment_choices = [item.value for item in Environment]
    environment_default = os.environ.get("WEBGUARD_ENVIRONMENT", Environment.DEVELOPMENT.value)
    environment_help = (
        "Explicit deployment environment (Slice 13 requirement 1) -- "
        "never inferred. \"production\" fails closed to "
        "ProductionServiceConfig.from_environment()'s own PostgreSQL/KMS "
        "requirements and ignores --database/--host/--port in favour of "
        "WEBGUARD_DATABASE_URL/WEBGUARD_HOST/WEBGUARD_PORT. Every other "
        "value runs the unchanged local SQLite/in-memory baseline. "
        f"Defaults to $WEBGUARD_ENVIRONMENT, or \"{Environment.DEVELOPMENT.value}\"."
    )

    serve_parser = subparsers.add_parser(
        "serve", help="Run the loopback HTTP API with one background worker."
    )
    _add_common_options(serve_parser)
    serve_parser.add_argument(
        "--environment", choices=environment_choices, default=environment_default, help=environment_help
    )
    serve_parser.set_defaults(handler=_serve_command)

    worker_parser = subparsers.add_parser(
        "worker", help="Run a scanner worker without the HTTP API."
    )
    _add_common_options(worker_parser)
    worker_parser.add_argument("--once", action="store_true")
    worker_parser.add_argument(
        "--environment", choices=environment_choices, default=environment_default, help=environment_help
    )
    worker_parser.set_defaults(handler=_worker_command)

    scheduler_parser = subparsers.add_parser(
        "scheduler", help="Materialize recurring schedules without the HTTP API."
    )
    _add_common_options(scheduler_parser)
    scheduler_parser.add_argument("--once", action="store_true")
    scheduler_parser.add_argument(
        "--environment", choices=environment_choices, default=environment_default, help=environment_help
    )
    scheduler_parser.set_defaults(handler=_scheduler_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (
        AuthorizationRepositoryError,
        IdentityStoreError,
        ServiceConfigError,
        JobStoreError,
        ProductionConfigError,
    ) as exc:
        print(f"ERROR [{exc.code}]: {exc.message}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:
        return 130


__all__ = ["build_parser", "main"]
