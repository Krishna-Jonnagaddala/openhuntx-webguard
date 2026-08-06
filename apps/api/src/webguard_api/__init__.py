"""OpenHuntX WebGuard local control-plane API."""

from .authorizations import (
    MAXIMUM_AUTHORIZATION_FILES,
    AuthorizationRepository,
    AuthorizationRepositoryError,
)
from .config import (
    DEFAULT_API_HOST,
    DEFAULT_API_MAXIMUM_REQUEST_BYTES,
    DEFAULT_API_PORT,
    DEFAULT_WORKER_POLL_SECONDS,
    MAXIMUM_API_REQUEST_BYTES,
    MAXIMUM_WORKER_POLL_SECONDS,
    ServiceConfig,
    ServiceConfigError,
)
from .executor import JobExecutionError, JobExecutionOutcome, ScanJobExecutor
from .http_api import ApiTransportError, build_handler, create_server
from .service import ApiServiceError, WebGuardJobService
from .store import DATABASE_SCHEMA_VERSION, JobStoreError, ScanJobStore
from .worker import ScanJobWorker

__version__ = "0.1.0"

__all__ = [
    "ApiServiceError",
    "ApiTransportError",
    "AuthorizationRepository",
    "AuthorizationRepositoryError",
    "DATABASE_SCHEMA_VERSION",
    "DEFAULT_API_HOST",
    "DEFAULT_API_MAXIMUM_REQUEST_BYTES",
    "DEFAULT_API_PORT",
    "DEFAULT_WORKER_POLL_SECONDS",
    "JobExecutionError",
    "JobExecutionOutcome",
    "JobStoreError",
    "MAXIMUM_API_REQUEST_BYTES",
    "MAXIMUM_AUTHORIZATION_FILES",
    "MAXIMUM_WORKER_POLL_SECONDS",
    "ScanJobExecutor",
    "ScanJobStore",
    "ScanJobWorker",
    "ServiceConfig",
    "ServiceConfigError",
    "WebGuardJobService",
    "__version__",
    "build_handler",
    "create_server",
]
