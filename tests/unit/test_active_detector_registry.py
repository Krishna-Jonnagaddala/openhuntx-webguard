"""The scanner-side active-detector registry and the contracts-side permit
catalog have no runtime import coupling by design (contracts must not
depend on the scanner package). This test is the only thing keeping them
from silently drifting apart."""

from __future__ import annotations

import unittest

from webguard_contracts import KNOWN_TRUSTSCAN_ACTIVE_CHECKS
from webguard_scanner import ACTIVE_DETECTOR_REGISTRY, KNOWN_ACTIVE_DETECTOR_IDS
from webguard_scanner.active_detector_registry import (
    CALLBACK_ACTIVE_CHECK_IDS,
    COMPARISON_ACTIVE_CHECK_IDS,
    FIXED_ENDPOINT_ACTIVE_CHECK_IDS,
)


class ActiveDetectorRegistryConsistencyTests(unittest.TestCase):
    def test_registry_matches_contracts_catalog(self) -> None:
        self.assertEqual(
            KNOWN_ACTIVE_DETECTOR_IDS,
            set(KNOWN_TRUSTSCAN_ACTIVE_CHECKS),
        )

    def test_registry_keys_plus_comparison_checks_match_known_ids(self) -> None:
        """active.authorization.idor is deliberately excluded from
        ACTIVE_DETECTOR_REGISTRY (see that module's docstring) -- it uses
        a separate orchestration path, not the generic per-candidate
        detector loop. This test asserts that split is complete and
        explicit, not an accidental gap: every known active-check ID is
        in exactly one of the generic registry, COMPARISON_ACTIVE_CHECK_IDS,
        CALLBACK_ACTIVE_CHECK_IDS, or FIXED_ENDPOINT_ACTIVE_CHECK_IDS,
        never neither, never more than one."""

        self.assertEqual(
            set(ACTIVE_DETECTOR_REGISTRY)
            | COMPARISON_ACTIVE_CHECK_IDS
            | CALLBACK_ACTIVE_CHECK_IDS
            | FIXED_ENDPOINT_ACTIVE_CHECK_IDS,
            KNOWN_ACTIVE_DETECTOR_IDS,
        )
        self.assertEqual(
            set(ACTIVE_DETECTOR_REGISTRY) & COMPARISON_ACTIVE_CHECK_IDS,
            set(),
        )
        self.assertEqual(
            set(ACTIVE_DETECTOR_REGISTRY) & CALLBACK_ACTIVE_CHECK_IDS,
            set(),
        )
        self.assertEqual(
            set(ACTIVE_DETECTOR_REGISTRY) & FIXED_ENDPOINT_ACTIVE_CHECK_IDS,
            set(),
        )
        self.assertEqual(
            COMPARISON_ACTIVE_CHECK_IDS & CALLBACK_ACTIVE_CHECK_IDS,
            set(),
        )
        self.assertEqual(
            COMPARISON_ACTIVE_CHECK_IDS & FIXED_ENDPOINT_ACTIVE_CHECK_IDS,
            set(),
        )
        self.assertEqual(
            CALLBACK_ACTIVE_CHECK_IDS & FIXED_ENDPOINT_ACTIVE_CHECK_IDS,
            set(),
        )

    def test_registry_values_are_callable(self) -> None:
        for detector_id, runner in ACTIVE_DETECTOR_REGISTRY.items():
            self.assertTrue(
                callable(runner),
                f"{detector_id} must map to a callable runner.",
            )


if __name__ == "__main__":
    unittest.main()
