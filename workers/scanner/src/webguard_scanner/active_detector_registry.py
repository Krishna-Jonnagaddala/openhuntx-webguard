"""Registry mapping active-detector IDs to their runner callables.

The union of keys here and ``COMPARISON_ACTIVE_CHECK_IDS`` must exactly
match ``webguard_contracts.KNOWN_TRUSTSCAN_ACTIVE_CHECKS`` -- a permit
can only authorize a detector ID that both sides recognize. A dedicated
test (tests/unit/test_active_detector_registry.py) asserts they stay in
sync; this module does not import the contracts package to check it
directly, since it is the scanner-side half of a boundary that
intentionally has no runtime coupling in either direction.

``active.authorization.idor`` is deliberately **not** in
``ACTIVE_DETECTOR_REGISTRY``. Every detector in that registry shares one
calling convention -- ``runner(target, candidates, context, policy=,
before_request=, after_request=, cancellation_check=,
authentication_material=)`` -- dispatched generically by the executor's
per-page detector loop. The IDOR/BOLA detector's actual signature is
fundamentally different (two identities' resolved authentication
material plus a bounded set of resource pairs, not a flat candidate
list), so it is authorized the same way through ``active_checks`` but
executed through its own dedicated orchestration path
(``executor._apply_authorization_comparison``), never through the
generic loop. ``COMPARISON_ACTIVE_CHECK_IDS`` exists so that split is
explicit and tested, not an accidental omission.

``active.ssrf.callback`` (Slice 10) is excluded from
``ACTIVE_DETECTOR_REGISTRY`` for the identical reason: it requires a
``CallbackBroker`` dependency and a bounded, asynchronous "wait for an
out-of-band callback" step that does not fit the generic synchronous
calling convention either. It is tracked in its own
``CALLBACK_ACTIVE_CHECK_IDS`` set and executed through
``executor._apply_ssrf_callback_detection``.
"""

from __future__ import annotations

from .sqli_error_detector import run_sqli_error_detector
from .xss_reflected_detector import run_reflected_xss_detector

ACTIVE_DETECTOR_REGISTRY = {
    "active.sqli.error": run_sqli_error_detector,
    "active.xss.reflected": run_reflected_xss_detector,
}

COMPARISON_ACTIVE_CHECK_IDS = frozenset({"active.authorization.idor"})
CALLBACK_ACTIVE_CHECK_IDS = frozenset({"active.ssrf.callback"})

KNOWN_ACTIVE_DETECTOR_IDS = (
    frozenset(ACTIVE_DETECTOR_REGISTRY)
    | COMPARISON_ACTIVE_CHECK_IDS
    | CALLBACK_ACTIVE_CHECK_IDS
)

__all__ = [
    "ACTIVE_DETECTOR_REGISTRY",
    "CALLBACK_ACTIVE_CHECK_IDS",
    "COMPARISON_ACTIVE_CHECK_IDS",
    "KNOWN_ACTIVE_DETECTOR_IDS",
]
