"""Shared OpenHuntX WebGuard data contracts."""

from .findings import (
    Confidence,
    ContractValidationError,
    Evidence,
    ExternalIdentifier,
    FindingIdentity,
    NormalizedFinding,
    Severity,
)

__version__ = "0.1.0"

__all__ = [
    "Confidence",
    "ContractValidationError",
    "Evidence",
    "ExternalIdentifier",
    "FindingIdentity",
    "NormalizedFinding",
    "Severity",
    "__version__",
]
