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
from .scans import (
    RequestAttempt,
    RequestAttemptOutcome,
    ScanContractValidationError,
    ScanCoverage,
    ScanError,
    ScanResult,
    ScanStatus,
    SkippedCheck,
)

__version__ = "0.1.0"

__all__ = [
    "Confidence",
    "ContractValidationError",
    "Evidence",
    "ExternalIdentifier",
    "FindingIdentity",
    "NormalizedFinding",
    "RequestAttempt",
    "RequestAttemptOutcome",
    "ScanContractValidationError",
    "ScanCoverage",
    "ScanError",
    "ScanResult",
    "ScanStatus",
    "Severity",
    "SkippedCheck",
    "__version__",
]
