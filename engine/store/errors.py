"""Store failures with a machine-readable reason (D28).

Every refusal in the sample store carries a stable ``reason`` code as well as a
human message, so an operator — and replay — can tell *why* a sample was not
usable: missing, expired, encrypted under a different key, tampered, truncated,
or written by a newer envelope version. Collapsing those into one "cannot read
sample" would make a replay INCONCLUSIVE for the wrong reason, which is the kind
of silent ambiguity D3 exists to forbid.

Messages never contain key material. A reason may name the *key id* (a one-way
hash prefix), never the key.
"""

from __future__ import annotations


class SampleStoreError(RuntimeError):
    """A sample-store operation failed closed, with a stable reason code."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        self.message = message
        super().__init__(f"{reason}: {message}" if message else reason)


# -- key handling -----------------------------------------------------------
NO_KEY = "no-key"
KEY_INVALID = "key-invalid"
KEY_FILE_MISSING = "key-file-missing"
KEY_FILE_PERMISSIONS = "key-file-permissions"
KEY_FILE_SYMLINK = "key-file-symlink"
KEY_FILE_EXISTS = "key-file-exists"

# -- addressing / storage ---------------------------------------------------
INVALID_SHA256 = "invalid-sha256"
NOT_FOUND = "not-found"
SYMLINK = "symlink"
NOT_A_FILE = "not-a-file"
EMPTY = "empty"
TOO_LARGE = "too-large"
WRITE_FAILED = "write-failed"
INDEX_ERROR = "index-error"

# -- envelope / decryption --------------------------------------------------
WRONG_KEY = "wrong-key"
UNKNOWN_VERSION = "unknown-version"
TRUNCATED = "truncated"
AUTH_FAILED = "auth-failed"
HASH_MISMATCH = "hash-mismatch"
LEGACY_HASH_MISMATCH = "legacy-hash-mismatch"

# -- retention --------------------------------------------------------------
REFERENCED = "referenced"
NOT_EXPIRED = "not-expired"
TTL_DISABLED = "ttl-disabled"
EXPIRED = "expired"
STORE_LOCKED = "store-locked"


__all__ = [
    "AUTH_FAILED",
    "EMPTY",
    "EXPIRED",
    "HASH_MISMATCH",
    "INDEX_ERROR",
    "INVALID_SHA256",
    "KEY_FILE_EXISTS",
    "KEY_FILE_MISSING",
    "KEY_FILE_PERMISSIONS",
    "KEY_FILE_SYMLINK",
    "KEY_INVALID",
    "LEGACY_HASH_MISMATCH",
    "NOT_A_FILE",
    "NOT_EXPIRED",
    "NOT_FOUND",
    "NO_KEY",
    "REFERENCED",
    "STORE_LOCKED",
    "SYMLINK",
    "SampleStoreError",
    "TOO_LARGE",
    "TRUNCATED",
    "TTL_DISABLED",
    "UNKNOWN_VERSION",
    "WRITE_FAILED",
    "WRONG_KEY",
]
