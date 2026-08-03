"""OpenHuntX WebGuard scanner package."""

from .error_taxonomy import (
    ErrorCategory,
    ErrorPolicy,
    classify_error,
    is_retryable_error,
    known_error_codes,
)
from .header_analyzer import (
    HeaderAnalysisError,
    analyze_security_headers,
)
from .passive_scan import (
    ENGINE_NAME,
    ENGINE_VERSION,
    PASSIVE_HEADER_CHECKS,
    run_passive_header_scan,
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
    "ENGINE_NAME",
    "ENGINE_VERSION",
    "ErrorCategory",
    "ErrorPolicy",
    "FetchPolicy",
    "HeaderAnalysisError",
    "PASSIVE_HEADER_CHECKS",
    "SafeHttpResponse",
    "SafeRequestError",
    "TargetValidationError",
    "ValidatedTarget",
    "ValidationMode",
    "ValidationPolicy",
    "__version__",
    "analyze_security_headers",
    "classify_error",
    "fetch_once",
    "is_retryable_error",
    "known_error_codes",
    "resolve_host",
    "run_passive_header_scan",
    "validate_target_url",
]
