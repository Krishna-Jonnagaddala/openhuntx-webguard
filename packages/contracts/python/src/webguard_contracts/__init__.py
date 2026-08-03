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
from .report_loader import (
    CURRENT_SCAN_SCHEMA_VERSION,
    MAXIMUM_SCAN_REPORT_BYTES,
    SUPPORTED_SCAN_SCHEMA_VERSIONS,
    MalformedScanReportError,
    ScanReportLoadError,
    UnsupportedSchemaVersionError,
    load_scan_result,
    load_scan_result_file,
    load_scan_result_json,
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
    "CURRENT_SCAN_SCHEMA_VERSION",
    "MAXIMUM_SCAN_REPORT_BYTES",
    "SUPPORTED_SCAN_SCHEMA_VERSIONS",
    "MalformedScanReportError",
    "NormalizedFinding",
    "RequestAttempt",
    "RequestAttemptOutcome",
    "ScanContractValidationError",
    "ScanReportLoadError",
    "ScanCoverage",
    "ScanError",
    "ScanResult",
    "ScanStatus",
    "Severity",
    "SkippedCheck",
    "UnsupportedSchemaVersionError",
    "load_scan_result",
    "load_scan_result_file",
    "load_scan_result_json",
    "__version__",
]
