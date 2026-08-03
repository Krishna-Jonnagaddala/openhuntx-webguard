"""OpenHuntX WebGuard scanner package."""

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
    "TargetValidationError",
    "ValidatedTarget",
    "ValidationMode",
    "ValidationPolicy",
    "__version__",
    "resolve_host",
    "validate_target_url",
]
