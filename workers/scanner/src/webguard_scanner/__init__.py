"""OpenHuntX WebGuard scanner package."""

from .header_analyzer import (
    HeaderAnalysisError,
    analyze_security_headers,
)
from .safe_http import (
    FetchPolicy,
    SafeHttpResponse,
    SafeRequestError,
    fetch_once,
)
from .scope_validator import (
    TargetValidationError,
    ValidatedTarget,
    ValidationMode,
    ValidationPolicy,
    resolve_host,
    validate_target_url,
)

__version__ = "0.1.0"

__all__ = [
    "FetchPolicy",
    "HeaderAnalysisError",
    "SafeHttpResponse",
    "SafeRequestError",
    "TargetValidationError",
    "ValidatedTarget",
    "ValidationMode",
    "ValidationPolicy",
    "__version__",
    "analyze_security_headers",
    "fetch_once",
    "resolve_host",
    "validate_target_url",
]
