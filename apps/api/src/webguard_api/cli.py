"""Command-line entry point for the local WebGuard control-plane service."""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path
from typing import Sequence

from .authorizations import AuthorizationRepository
from .config import (
    DEFAULT_API_HOST,
    DEFAULT_API_MAXIMUM_REQUEST_BYTES,
    DEFAULT_API_PORT,
    DEFAULT_WORKER_POLL_SECONDS,
    ServiceConfig,
    ServiceConfigError,
)
from .executor import ScanJobExecutor
from .http_api import create_server
from .service import WebGuardJobService
from .store import JobStoreError, ScanJobStore
from .worker import ScanJobWorker


EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2


def _config(args: argparse.Namespace) -> ServiceConfig:
    return ServiceConfig(
        host=args.host,
        port=args.port,
        database_path=args.database,
        authorization_directory=args.authorizations,
        artifact_directory=args.artifacts,
        maximum_request_bytes=args.maximum_request_bytes,
        worker_poll_seconds=args.worker_poll_seconds,
    )


def _components(config: ServiceConfig):
    store = ScanJobStore(config.database_path)
    authorizations = AuthorizationRepository(config.authorization_directory)
    executor = ScanJobExecutor(
        authorizations=authorizations,
        artifact_directory=config.artifact_directory,
    )
    service = WebGuardJobService(store=store, authorizations=authorizations)
    worker = ScanJobWorker(
        store=store,
        executor=executor,
        poll_seconds=config.worker_poll_seconds,
    )
    return store, service, worker


def _init_command(args: argparse.Namespace) -> int:
    config = _config(args)
    ScanJobStore(config.database_path)
    print(f"Initialized job database: {config.database_path}")
    print(f"Authorization directory: {config.authorization_directory}")
    print(f"Artifact directory: {config.artifact_directory}")
    return EXIT_SUCCESS


def _worker_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, _, worker = _components(config)
    if args.once:
        processed = worker.run_once()
        print("Processed one job." if processed else "No queued job was available.")
        return EXIT_SUCCESS
    stop_event = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    print("WebGuard worker started. Press Ctrl+C to stop.")
    worker.run_forever(stop_event)
    print("WebGuard worker stopped.")
    return EXIT_SUCCESS


def _serve_command(args: argparse.Namespace) -> int:
    config = _config(args)
    _, service, worker = _components(config)
    stop_event = threading.Event()
    worker_thread = threading.Thread(
        target=worker.run_forever,
        args=(stop_event,),
        name="webguard-job-worker",
        daemon=True,
    )
    server = create_server(
        config.host,
        config.port,
        service,
        maximum_request_bytes=config.maximum_request_bytes,
    )

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    worker_thread.start()
    bound_host, bound_port = server.server_address[:2]
    print(f"WebGuard API listening on http://{bound_host}:{bound_port}")
    print("Binding is loopback-only. Press Ctrl+C to stop.")
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        stop_event.set()
        server.server_close()
        worker_thread.join(timeout=2.0)
    print("WebGuard API stopped.")
    return EXIT_SUCCESS


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default=DEFAULT_API_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_API_PORT)
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("var/webguard-api/jobs.sqlite3"),
    )
    parser.add_argument(
        "--authorizations",
        type=Path,
        default=Path("authorizations"),
    )
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=Path("scan-results/service"),
    )
    parser.add_argument(
        "--maximum-request-bytes",
        type=int,
        default=DEFAULT_API_MAXIMUM_REQUEST_BYTES,
    )
    parser.add_argument(
        "--worker-poll-seconds",
        type=float,
        default=DEFAULT_WORKER_POLL_SECONDS,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webguard-api",
        description="Local WebGuard control-plane API and scanner job queue.",
    )
    parser.add_argument("--version", action="version", version="webguard-api 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize the job database.")
    _add_common_options(init_parser)
    init_parser.set_defaults(handler=_init_command)

    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the loopback HTTP API with one background worker.",
    )
    _add_common_options(serve_parser)
    serve_parser.set_defaults(handler=_serve_command)

    worker_parser = subparsers.add_parser(
        "worker",
        help="Run a scanner worker without the HTTP API.",
    )
    _add_common_options(worker_parser)
    worker_parser.add_argument("--once", action="store_true")
    worker_parser.set_defaults(handler=_worker_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (ServiceConfigError, JobStoreError) as exc:
        print(f"ERROR [{exc.code}]: {exc.message}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:
        return 130


__all__ = ["build_parser", "main"]
