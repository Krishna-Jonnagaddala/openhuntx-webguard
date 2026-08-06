"""OpenHuntX WebGuard authenticated local control-plane API."""

from .auth import ApiPermission, ApiTokenAuthenticator, AuthContext, AuthenticationError
from .authorizations import (
    MAXIMUM_AUTHORIZATION_FILES,
    AuthorizationRepository,
    AuthorizationRepositoryError,
)
from .config import (
    DEFAULT_API_HOST,
    DEFAULT_API_MAXIMUM_REQUEST_BYTES,
    DEFAULT_API_PORT,
    DEFAULT_RATE_LIMIT_REQUESTS,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_WORKER_POLL_SECONDS,
    MAXIMUM_API_REQUEST_BYTES,
    MAXIMUM_RATE_LIMIT_REQUESTS,
    MAXIMUM_RATE_LIMIT_WINDOW_SECONDS,
    MAXIMUM_WORKER_POLL_SECONDS,
    ServiceConfig,
    ServiceConfigError,
)
from .executor import JobExecutionError, JobExecutionOutcome, ScanJobExecutor
from .http_api import ApiTransportError, build_handler, create_server
from .identity import (
    DEFAULT_TOKEN_VALIDITY_DAYS,
    IDENTITY_SCHEMA_VERSION,
    MAXIMUM_TOKEN_VALIDITY_DAYS,
    TOKEN_PREFIX,
    IdentityStore,
    IdentityStoreError,
    IssuedApiToken,
)
from .rate_limit import FixedWindowRateLimiter, RateLimitDecision, RateLimitError
from .service import ApiServiceError, WebGuardJobService
from .store import DATABASE_SCHEMA_VERSION, JobStoreError, ScanJobStore
from .worker import ScanJobWorker

__version__ = "0.2.0"

__all__ = [
    "ApiPermission",
    "ApiServiceError",
    "ApiTokenAuthenticator",
    "ApiTransportError",
    "AuthContext",
    "AuthenticationError",
    "AuthorizationRepository",
    "AuthorizationRepositoryError",
    "DATABASE_SCHEMA_VERSION",
    "DEFAULT_API_HOST",
    "DEFAULT_API_MAXIMUM_REQUEST_BYTES",
    "DEFAULT_API_PORT",
    "DEFAULT_RATE_LIMIT_REQUESTS",
    "DEFAULT_RATE_LIMIT_WINDOW_SECONDS",
    "DEFAULT_TOKEN_VALIDITY_DAYS",
    "DEFAULT_WORKER_POLL_SECONDS",
    "FixedWindowRateLimiter",
    "IDENTITY_SCHEMA_VERSION",
    "IdentityStore",
    "IdentityStoreError",
    "IssuedApiToken",
    "JobExecutionError",
    "JobExecutionOutcome",
    "JobStoreError",
    "MAXIMUM_API_REQUEST_BYTES",
    "MAXIMUM_AUTHORIZATION_FILES",
    "MAXIMUM_RATE_LIMIT_REQUESTS",
    "MAXIMUM_RATE_LIMIT_WINDOW_SECONDS",
    "MAXIMUM_TOKEN_VALIDITY_DAYS",
    "MAXIMUM_WORKER_POLL_SECONDS",
    "RateLimitDecision",
    "RateLimitError",
    "ScanJobExecutor",
    "ScanJobStore",
    "ScanJobWorker",
    "ServiceConfig",
    "ServiceConfigError",
    "TOKEN_PREFIX",
    "WebGuardJobService",
    "__version__",
    "build_handler",
    "create_server",
]
