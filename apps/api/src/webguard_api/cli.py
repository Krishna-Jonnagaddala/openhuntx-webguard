"""Command-line entry point for the local authenticated WebGuard API."""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from webguard_contracts import OrganizationRole, PrincipalType

from .auth import ApiTokenAuthenticator
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
from .executor import ScanJobExecutor
from .http_api import create_server
from .identity import (
    DEFAULT_TOKEN_VALIDITY_DAYS,
    IdentityStore,
    IdentityStoreError,
)
from .rate_limit import FixedWindowRateLimiter
from .scheduler import ScanScheduleCoordinator
from .service import WebGuardJobService
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
    jobs = ScanJobStore(config.database_path)
    identity = IdentityStore(config.database_path)
    return jobs, identity


def _components(config: ServiceConfig):
    store, identity = _stores(config)
    authorizations = AuthorizationRepository(config.authorization_directory)
    executor = ScanJobExecutor(
        authorizations=authorizations,
        artifact_directory=config.artifact_directory,
        organization_resolver=store.organization_id_for_job,
    )
    service = WebGuardJobService(
        store=store,
        authorizations=authorizations,
        identity=identity,
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
        poll_seconds=config.scheduler_poll_seconds,
        batch_size=config.scheduler_batch_size,
    )
    authenticator = ApiTokenAuthenticator(identity)
    limiter = FixedWindowRateLimiter(
        requests=config.rate_limit_requests,
        window_seconds=config.rate_limit_window_seconds,
    )
    return store, identity, service, worker, scheduler, authenticator, limiter


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


def _worker_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, _, _, worker, _, _, _ = _components(config)
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
    print(f"WebGuard worker started: {worker.worker_id}")
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


def _scheduler_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, _, _, _, scheduler, _, _ = _components(config)
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
        "WebGuard scheduler started: "
        f"poll={scheduler.poll_seconds:g}s; batch={scheduler.batch_size}."
    )
    print("Press Ctrl+C to stop.")
    scheduler.run_forever(stop_event)
    print("WebGuard scheduler stopped.")
    return EXIT_SUCCESS


def _serve_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, _, service, worker, scheduler, authenticator, limiter = _components(config)
    stop_event = threading.Event()
    worker_thread = threading.Thread(
        target=worker.run_forever,
        args=(stop_event,),
        name="webguard-job-worker",
        daemon=True,
    )
    scheduler_thread = threading.Thread(
        target=scheduler.run_forever,
        args=(stop_event,),
        name="webguard-scan-scheduler",
        daemon=True,
    )
    server = create_server(
        config.host,
        config.port,
        service,
        authenticator=authenticator,
        rate_limiter=limiter,
        maximum_request_bytes=config.maximum_request_bytes,
    )

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    worker_thread.start()
    scheduler_thread.start()
    bound_host, bound_port = server.server_address[:2]
    print(f"WebGuard API listening on http://{bound_host}:{bound_port}")
    print("Bearer authentication and organization RBAC are enabled.")
    print(
        f"Worker {worker.worker_id} uses renewable database leases "
        f"({worker.lease_seconds:g}s)."
    )
    print(
        "Recurring scan scheduler is enabled "
        f"({scheduler.poll_seconds:g}s poll interval)."
    )
    print("Binding is loopback-only. Press Ctrl+C to stop.")
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        stop_event.set()
        server.server_close()
        worker_thread.join(timeout=2.0)
        scheduler_thread.join(timeout=2.0)
    print("WebGuard API stopped.")
    return EXIT_SUCCESS


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default=DEFAULT_API_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_API_PORT)
    parser.add_argument("--database", type=Path, default=Path("var/webguard-api/jobs.sqlite3"))
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
    parser.add_argument("--version", action="version", version="webguard-api 0.5.0")
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

    serve_parser = subparsers.add_parser(
        "serve", help="Run the loopback HTTP API with one background worker."
    )
    _add_common_options(serve_parser)
    serve_parser.set_defaults(handler=_serve_command)

    worker_parser = subparsers.add_parser(
        "worker", help="Run a scanner worker without the HTTP API."
    )
    _add_common_options(worker_parser)
    worker_parser.add_argument("--once", action="store_true")
    worker_parser.set_defaults(handler=_worker_command)

    scheduler_parser = subparsers.add_parser(
        "scheduler", help="Materialize recurring schedules without the HTTP API."
    )
    _add_common_options(scheduler_parser)
    scheduler_parser.add_argument("--once", action="store_true")
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
    ) as exc:
        print(f"ERROR [{exc.code}]: {exc.message}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:
        return 130


__all__ = ["build_parser", "main"]
