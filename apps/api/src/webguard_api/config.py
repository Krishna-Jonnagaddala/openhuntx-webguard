"""Configuration contract for the local WebGuard control-plane service."""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from pathlib import Path


DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8765
DEFAULT_API_MAXIMUM_REQUEST_BYTES = 64 * 1024
DEFAULT_WORKER_POLL_SECONDS = 0.25
MAXIMUM_API_REQUEST_BYTES = 128 * 1024
MAXIMUM_WORKER_POLL_SECONDS = 5.0
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
    authorization_directory: Path = Path("authorizations")
    artifact_directory: Path = Path("scan-results/service")
    maximum_request_bytes: int = DEFAULT_API_MAXIMUM_REQUEST_BYTES
    worker_poll_seconds: float = DEFAULT_WORKER_POLL_SECONDS
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
                "Milestone 1.27 permits loopback API binding only.",
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
            self.authorization_directory.resolve(strict=False),
            self.artifact_directory.resolve(strict=False),
        ]
        if len(set(resolved)) != len(resolved):
            raise ServiceConfigError(
                "service_path_conflict",
                "Database, authorization, and artifact paths must be distinct.",
            )


__all__ = [
    "DEFAULT_API_HOST",
    "DEFAULT_API_MAXIMUM_REQUEST_BYTES",
    "DEFAULT_API_PORT",
    "DEFAULT_WORKER_POLL_SECONDS",
    "DEFAULT_RATE_LIMIT_REQUESTS",
    "DEFAULT_RATE_LIMIT_WINDOW_SECONDS",
    "MAXIMUM_API_REQUEST_BYTES",
    "MAXIMUM_WORKER_POLL_SECONDS",
    "MAXIMUM_RATE_LIMIT_REQUESTS",
    "MAXIMUM_RATE_LIMIT_WINDOW_SECONDS",
    "ServiceConfig",
    "ServiceConfigError",
]
