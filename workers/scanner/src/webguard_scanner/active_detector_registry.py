"""Registry mapping active-detector IDs to their runner callables.

The set of keys here must exactly match
``webguard_contracts.KNOWN_TRUSTSCAN_ACTIVE_CHECKS`` -- a permit can only
authorize a detector ID that both sides recognize. A dedicated test
(tests/unit/test_active_detector_registry.py) asserts they stay in sync;
this module does not import the contracts package to check it directly,
since it is the scanner-side half of a boundary that intentionally has no
runtime coupling in either direction.
"""

from __future__ import annotations

from .sqli_error_detector import run_sqli_error_detector
from .xss_reflected_detector import run_reflected_xss_detector

ACTIVE_DETECTOR_REGISTRY = {
    "active.sqli.error": run_sqli_error_detector,
    "active.xss.reflected": run_reflected_xss_detector,
}

KNOWN_ACTIVE_DETECTOR_IDS = frozenset(ACTIVE_DETECTOR_REGISTRY)

__all__ = ["ACTIVE_DETECTOR_REGISTRY", "KNOWN_ACTIVE_DETECTOR_IDS"]
