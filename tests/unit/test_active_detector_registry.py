"""The scanner-side active-detector registry and the contracts-side permit
catalog have no runtime import coupling by design (contracts must not
depend on the scanner package). This test is the only thing keeping them
from silently drifting apart."""

from __future__ import annotations

import unittest

from webguard_contracts import KNOWN_TRUSTSCAN_ACTIVE_CHECKS
from webguard_scanner import ACTIVE_DETECTOR_REGISTRY, KNOWN_ACTIVE_DETECTOR_IDS


class ActiveDetectorRegistryConsistencyTests(unittest.TestCase):
    def test_registry_matches_contracts_catalog(self) -> None:
        self.assertEqual(
            KNOWN_ACTIVE_DETECTOR_IDS,
            set(KNOWN_TRUSTSCAN_ACTIVE_CHECKS),
        )

    def test_registry_keys_match_known_ids(self) -> None:
        self.assertEqual(
            set(ACTIVE_DETECTOR_REGISTRY),
            KNOWN_ACTIVE_DETECTOR_IDS,
        )

    def test_registry_values_are_callable(self) -> None:
        for detector_id, runner in ACTIVE_DETECTOR_REGISTRY.items():
            self.assertTrue(
                callable(runner),
                f"{detector_id} must map to a callable runner.",
            )


if __name__ == "__main__":
    unittest.main()
