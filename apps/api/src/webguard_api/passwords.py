"""Argon2id password hashing (Slice 16 requirement 3).

Uses `argon2-cffi` -- the standard, actively-maintained Python Argon2
binding -- rather than any hand-rolled cryptography. Parameters are the
RFC 9106 section 4 "second recommended option" (memory-constrained
environments without dedicated hardware): 64 MiB memory, 3 iterations,
4-way parallelism, a 16-byte salt, a 32-byte output. These are pinned
explicitly rather than left at the library's own defaults, so a future
argon2-cffi release changing its defaults cannot silently weaken (or
needlessly strengthen, causing a latency regression) every stored hash
in this database without a deliberate, reviewed change here.

`needs_rehash` lets a future parameter bump (a genuine security
improvement, not a routine change) be rolled out incrementally -- a
principal's hash is upgraded the next time they successfully
authenticate, rather than requiring a mass credential reset.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_TIME_COST = 3
_MEMORY_COST_KIB = 65536
_PARALLELISM = 4
_HASH_LENGTH = 32
_SALT_LENGTH = 16

_hasher = PasswordHasher(
    time_cost=_TIME_COST,
    memory_cost=_MEMORY_COST_KIB,
    parallelism=_PARALLELISM,
    hash_len=_HASH_LENGTH,
    salt_len=_SALT_LENGTH,
)

MINIMUM_PASSWORD_LENGTH = 12
MAXIMUM_PASSWORD_LENGTH = 256


class PasswordPolicyError(ValueError):
    """A candidate password fails the minimum acceptance policy."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def validate_password_policy(password: object) -> str:
    """Length-only policy, deliberately: composition rules (mandatory
    symbols/digits/etc.) are a well-documented anti-pattern -- they push
    users toward predictable substitutions without improving real
    entropy. A length floor is the single control with actual evidence
    behind it (NIST SP 800-63B)."""

    if not isinstance(password, str):
        raise PasswordPolicyError("password_invalid", "Password must be text.")
    if len(password) < MINIMUM_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            "password_too_short",
            f"Password must be at least {MINIMUM_PASSWORD_LENGTH} characters.",
        )
    if len(password) > MAXIMUM_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            "password_too_long",
            f"Password must be at most {MAXIMUM_PASSWORD_LENGTH} characters.",
        )
    return password


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        return _hasher.verify(encoded_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:  # noqa: BLE001 - a malformed stored hash must fail closed, not crash the request
        return False


def needs_rehash(encoded_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(encoded_hash)
    except InvalidHashError:
        return True


__all__ = [
    "MAXIMUM_PASSWORD_LENGTH",
    "MINIMUM_PASSWORD_LENGTH",
    "PasswordPolicyError",
    "hash_password",
    "needs_rehash",
    "validate_password_policy",
]
