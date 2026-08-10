"""Configuration contract for the local WebGuard control-plane service."""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from pathlib import Path

from .service_secrets import default_service_secret_path


DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8765
DEFAULT_API_MAXIMUM_REQUEST_BYTES = 64 * 1024
DEFAULT_WORKER_POLL_SECONDS = 0.25
DEFAULT_WORKER_LEASE_SECONDS = 30.0
DEFAULT_WORKER_HEARTBEAT_SECONDS = 10.0
DEFAULT_WORKER_MAXIMUM_ATTEMPTS = 3
DEFAULT_SCHEDULER_POLL_SECONDS = 1.0
DEFAULT_SCHEDULER_BATCH_SIZE = 100
MAXIMUM_SCHEDULER_POLL_SECONDS = 60.0
MAXIMUM_SCHEDULER_BATCH_SIZE = 1000
MAXIMUM_API_REQUEST_BYTES = 128 * 1024
MAXIMUM_WORKER_POLL_SECONDS = 5.0
MINIMUM_WORKER_LEASE_SECONDS = 1.0
MAXIMUM_WORKER_LEASE_SECONDS = 3600.0
MINIMUM_WORKER_HEARTBEAT_SECONDS = 0.1
MAXIMUM_WORKER_MAXIMUM_ATTEMPTS = 100
DEFAULT_RATE_LIMIT_REQUESTS = 120
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60
MAXIMUM_RATE_LIMIT_REQUESTS = 10_000
MAXIMUM_RATE_LIMIT_WINDOW_SECONDS = 3_600


class ServiceConfigError(ValueError):
    """Controlled invalid service configuration."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _path(value: object, field_name: str) -> Path:
    try:
        result = Path(value).expanduser()
    except (TypeError, ValueError, RuntimeError) as exc:
        raise ServiceConfigError(
            "service_path_invalid",
            f"{field_name} is not a valid filesystem path.",
        ) from exc
    if not str(result):
        raise ServiceConfigError(
            "service_path_invalid",
            f"{field_name} cannot be empty.",
        )
    return result


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    """Validated local-only API, queue, and artifact configuration."""

    host: str = DEFAULT_API_HOST
    port: int = DEFAULT_API_PORT
    database_path: Path = Path("var/webguard-api/jobs.sqlite3")
    service_secret_path: Path | None = None
    authorization_directory: Path = Path("authorizations")
    artifact_directory: Path = Path("scan-results/service")
    maximum_request_bytes: int = DEFAULT_API_MAXIMUM_REQUEST_BYTES
    worker_poll_seconds: float = DEFAULT_WORKER_POLL_SECONDS
    worker_id: str | None = None
    worker_lease_seconds: float = DEFAULT_WORKER_LEASE_SECONDS
    worker_heartbeat_seconds: float = DEFAULT_WORKER_HEARTBEAT_SECONDS
    worker_maximum_attempts: int = DEFAULT_WORKER_MAXIMUM_ATTEMPTS
    scheduler_poll_seconds: float = DEFAULT_SCHEDULER_POLL_SECONDS
    scheduler_batch_size: int = DEFAULT_SCHEDULER_BATCH_SIZE
    rate_limit_requests: int = DEFAULT_RATE_LIMIT_REQUESTS
    rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS

    def __post_init__(self) -> None:
        if not isinstance(self.host, str):
            raise ServiceConfigError(
                "service_host_invalid",
                "host must be a loopback IP literal.",
            )
        host = self.host.strip()
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ServiceConfigError(
                "service_host_invalid",
                "host must be a loopback IP literal such as 127.0.0.1 or ::1.",
            ) from exc
        if not address.is_loopback:
            raise ServiceConfigError(
                "service_non_loopback_binding_rejected",
                "Milestone 1.30 permits loopback API binding only.",
            )
        object.__setattr__(self, "host", address.compressed)

        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 0 <= self.port <= 65535
        ):
            raise ServiceConfigError(
                "service_port_invalid",
                "port must be an integer from 0 to 65535.",
            )

        object.__setattr__(
            self,
            "database_path",
            _path(self.database_path, "database_path"),
        )
        if self.service_secret_path is None:
            service_secret_path = default_service_secret_path(
                self.database_path
            )
        else:
            service_secret_path = _path(
                self.service_secret_path,
                "service_secret_path",
            )

        object.__setattr__(
            self,
            "service_secret_path",
            service_secret_path,
        )

        object.__setattr__(
            self,
            "authorization_directory",
            _path(self.authorization_directory, "authorization_directory"),
        )
        object.__setattr__(
            self,
            "artifact_directory",
            _path(self.artifact_directory, "artifact_directory"),
        )

        if (
            isinstance(self.maximum_request_bytes, bool)
            or not isinstance(self.maximum_request_bytes, int)
            or not 1024 <= self.maximum_request_bytes <= MAXIMUM_API_REQUEST_BYTES
        ):
            raise ServiceConfigError(
                "service_request_limit_invalid",
                "maximum_request_bytes must be from 1024 to 131072.",
            )
        if (
            isinstance(self.worker_poll_seconds, bool)
            or not isinstance(self.worker_poll_seconds, (int, float))
        ):
            raise ServiceConfigError(
                "service_poll_interval_invalid",
                "worker_poll_seconds must be numeric.",
            )
        interval = float(self.worker_poll_seconds)
        if (
            not math.isfinite(interval)
            or not 0.01 <= interval <= MAXIMUM_WORKER_POLL_SECONDS
        ):
            raise ServiceConfigError(
                "service_poll_interval_invalid",
                "worker_poll_seconds must be from 0.01 to 5 seconds.",
            )
        object.__setattr__(self, "worker_poll_seconds", interval)

        if self.worker_id is not None:
            if not isinstance(self.worker_id, str):
                raise ServiceConfigError(
                    "service_worker_id_invalid",
                    "worker_id must be a non-empty string when supplied.",
                )
            worker_id = self.worker_id.strip()
            if (
                not worker_id
                or len(worker_id) > 128
                or any(ord(char) < 33 or ord(char) > 126 for char in worker_id)
            ):
                raise ServiceConfigError(
                    "service_worker_id_invalid",
                    "worker_id must contain 1 to 128 visible ASCII characters.",
                )
            object.__setattr__(self, "worker_id", worker_id)

        if (
            isinstance(self.worker_lease_seconds, bool)
            or not isinstance(self.worker_lease_seconds, (int, float))
        ):
            raise ServiceConfigError(
                "service_worker_lease_invalid",
                "worker_lease_seconds must be numeric.",
            )
        lease_seconds = float(self.worker_lease_seconds)
        if (
            not math.isfinite(lease_seconds)
            or not MINIMUM_WORKER_LEASE_SECONDS
            <= lease_seconds
            <= MAXIMUM_WORKER_LEASE_SECONDS
        ):
            raise ServiceConfigError(
                "service_worker_lease_invalid",
                "worker_lease_seconds must be from 1 to 3600 seconds.",
            )
        object.__setattr__(self, "worker_lease_seconds", lease_seconds)

        if (
            isinstance(self.worker_heartbeat_seconds, bool)
            or not isinstance(self.worker_heartbeat_seconds, (int, float))
        ):
            raise ServiceConfigError(
                "service_worker_heartbeat_invalid",
                "worker_heartbeat_seconds must be numeric.",
            )
        heartbeat_seconds = float(self.worker_heartbeat_seconds)
        if (
            not math.isfinite(heartbeat_seconds)
            or heartbeat_seconds < MINIMUM_WORKER_HEARTBEAT_SECONDS
            or heartbeat_seconds >= lease_seconds
        ):
            raise ServiceConfigError(
                "service_worker_heartbeat_invalid",
                "worker_heartbeat_seconds must be at least 0.1 and less than worker_lease_seconds.",
            )
        object.__setattr__(self, "worker_heartbeat_seconds", heartbeat_seconds)

        if (
            isinstance(self.worker_maximum_attempts, bool)
            or not isinstance(self.worker_maximum_attempts, int)
            or not 1
            <= self.worker_maximum_attempts
            <= MAXIMUM_WORKER_MAXIMUM_ATTEMPTS
        ):
            raise ServiceConfigError(
                "service_worker_attempts_invalid",
                "worker_maximum_attempts must be from 1 to 100.",
            )

        if (
            isinstance(self.scheduler_poll_seconds, bool)
            or not isinstance(self.scheduler_poll_seconds, (int, float))
        ):
            raise ServiceConfigError(
                "service_scheduler_poll_invalid",
                "scheduler_poll_seconds must be numeric.",
            )
        scheduler_poll = float(self.scheduler_poll_seconds)
        if (
            not math.isfinite(scheduler_poll)
            or not 0.1 <= scheduler_poll <= MAXIMUM_SCHEDULER_POLL_SECONDS
        ):
            raise ServiceConfigError(
                "service_scheduler_poll_invalid",
                "scheduler_poll_seconds must be from 0.1 to 60 seconds.",
            )
        object.__setattr__(self, "scheduler_poll_seconds", scheduler_poll)

        if (
            isinstance(self.scheduler_batch_size, bool)
            or not isinstance(self.scheduler_batch_size, int)
            or not 1 <= self.scheduler_batch_size <= MAXIMUM_SCHEDULER_BATCH_SIZE
        ):
            raise ServiceConfigError(
                "service_scheduler_batch_invalid",
                "scheduler_batch_size must be from 1 to 1000.",
            )

        if (
            isinstance(self.rate_limit_requests, bool)
            or not isinstance(self.rate_limit_requests, int)
            or not 1 <= self.rate_limit_requests <= MAXIMUM_RATE_LIMIT_REQUESTS
        ):
            raise ServiceConfigError(
                "service_rate_limit_invalid",
                "rate_limit_requests must be from 1 to 10000.",
            )
        if (
            isinstance(self.rate_limit_window_seconds, bool)
            or not isinstance(self.rate_limit_window_seconds, int)
            or not 1 <= self.rate_limit_window_seconds <= MAXIMUM_RATE_LIMIT_WINDOW_SECONDS
        ):
            raise ServiceConfigError(
                "service_rate_window_invalid",
                "rate_limit_window_seconds must be from 1 to 3600.",
            )

        resolved = [
            self.database_path.resolve(strict=False),
            self.service_secret_path.resolve(strict=False),
            self.authorization_directory.resolve(strict=False),
            self.artifact_directory.resolve(strict=False),
        ]
        if len(set(resolved)) != len(resolved):
            raise ServiceConfigError(
                "service_path_conflict",
                (
                    "Database, service-secret, authorization, and "
                    "artifact paths must be distinct."
                ),
            )


__all__ = [
    "DEFAULT_API_HOST",
    "DEFAULT_API_MAXIMUM_REQUEST_BYTES",
    "DEFAULT_API_PORT",
    "DEFAULT_SCHEDULER_BATCH_SIZE",
    "DEFAULT_SCHEDULER_POLL_SECONDS",
    "MAXIMUM_SCHEDULER_BATCH_SIZE",
    "MAXIMUM_SCHEDULER_POLL_SECONDS",
    "DEFAULT_WORKER_HEARTBEAT_SECONDS",
    "DEFAULT_WORKER_LEASE_SECONDS",
    "DEFAULT_WORKER_MAXIMUM_ATTEMPTS",
    "DEFAULT_WORKER_POLL_SECONDS",
    "DEFAULT_RATE_LIMIT_REQUESTS",
    "DEFAULT_RATE_LIMIT_WINDOW_SECONDS",
    "MAXIMUM_API_REQUEST_BYTES",
    "MAXIMUM_WORKER_LEASE_SECONDS",
    "MAXIMUM_WORKER_MAXIMUM_ATTEMPTS",
    "MAXIMUM_WORKER_POLL_SECONDS",
    "MINIMUM_WORKER_HEARTBEAT_SECONDS",
    "MINIMUM_WORKER_LEASE_SECONDS",
    "MAXIMUM_RATE_LIMIT_REQUESTS",
    "MAXIMUM_RATE_LIMIT_WINDOW_SECONDS",
    "ServiceConfig",
    "ServiceConfigError",
]
