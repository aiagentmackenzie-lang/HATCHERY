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
KEY_RING_INVALID = "key-ring-invalid"
KEY_RING_NEWER = "key-ring-version"
KEY_NOT_FOUND = "key-not-found"
KEY_IS_ACTIVE = "key-is-active"
KEY_IN_USE = "key-in-use"

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
UNKNOWN_KEY_ID = "unknown-key-id"
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

# -- rotation ---------------------------------------------------------------
ROTATION_INCOMPLETE = "rotation-incomplete"

# -- backup / restore (D29) -------------------------------------------------
BACKUP_FAILED = "backup-failed"
BACKUP_EXISTS = "backup-exists"
MANIFEST_MISSING = "manifest-missing"
MANIFEST_INVALID = "manifest-invalid"
MANIFEST_NEWER = "manifest-version"
RESTORE_TARGET_NOT_EMPTY = "restore-target-not-empty"
RESTORE_PATH_REFUSED = "restore-path-refused"
RESTORE_BLOB_MISMATCH = "restore-blob-mismatch"
RESTORE_KEY_MISSING = "restore-key-missing"
RESTORE_SCHEMA_NEWER = "restore-schema-newer"


__all__ = [
    "AUTH_FAILED",
    "BACKUP_EXISTS",
    "BACKUP_FAILED",
    "EMPTY",
    "EXPIRED",
    "HASH_MISMATCH",
    "INDEX_ERROR",
    "INVALID_SHA256",
    "KEY_FILE_EXISTS",
    "KEY_FILE_MISSING",
    "KEY_FILE_PERMISSIONS",
    "KEY_FILE_SYMLINK",
    "KEY_IN_USE",
    "KEY_INVALID",
    "KEY_IS_ACTIVE",
    "KEY_NOT_FOUND",
    "KEY_RING_INVALID",
    "KEY_RING_NEWER",
    "LEGACY_HASH_MISMATCH",
    "MANIFEST_INVALID",
    "MANIFEST_MISSING",
    "MANIFEST_NEWER",
    "NOT_A_FILE",
    "NOT_EXPIRED",
    "NOT_FOUND",
    "NO_KEY",
    "REFERENCED",
    "RESTORE_BLOB_MISMATCH",
    "RESTORE_KEY_MISSING",
    "RESTORE_PATH_REFUSED",
    "RESTORE_SCHEMA_NEWER",
    "RESTORE_TARGET_NOT_EMPTY",
    "ROTATION_INCOMPLETE",
    "STORE_LOCKED",
    "SYMLINK",
    "SampleStoreError",
    "TOO_LARGE",
    "TRUNCATED",
    "TTL_DISABLED",
    "UNKNOWN_KEY_ID",
    "UNKNOWN_VERSION",
    "WRITE_FAILED",
    "WRONG_KEY",
]
