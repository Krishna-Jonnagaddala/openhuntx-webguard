"""Explicit deployment environment (Slice 13 requirement 1).

Four values, chosen by the operator (a CLI flag or an environment
variable), never inferred from anything else -- no heuristic based on
hostname, an absent config file, a debug flag, or any other signal
that could be wrong. The whole point of this type existing is that
"which persistence/signing backend is this process using" is always a
deliberate, explicit choice, never a guess.
"""

from __future__ import annotations

from enum import Enum


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TEST = "test"
    LAB = "lab"
    PRODUCTION = "production"


__all__ = ["Environment"]
