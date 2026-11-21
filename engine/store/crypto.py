"""Encryption at rest for the sample store (D28).

Design in one paragraph: a stored sample is an **AEAD envelope** — AES-256-GCM
from ``cryptography`` — whose header is authenticated as additional data, so a
tampered version byte, key id, nonce, length or ciphertext all fail the same
authentication check rather than being half-parsed. The envelope is versioned and
carries a key *id* (a truncated hash of the key, never the key), so a wrong key
is reported as a wrong key instead of as a corrupt file. Decryption verifies the
plaintext SHA-256 against the content address before a caller ever sees bytes.

Key material comes from ``HATCHERY_SAMPLE_KEY`` (hex or base64, 32 bytes) or a
``HATCHERY_SAMPLE_KEY_FILE`` — which must be a regular, non-symlink file with no
group/other permission bits. When nothing is configured, the store **generates**
a local key at ``<store>/.sample-key`` (0600) and says so loudly; it never falls
back to writing plaintext. A generated local key protects against plaintext at
rest (backups, snapshots, a copied directory); it does not protect against an
attacker who can read the store directory itself. That distinction is documented
rather than implied.

Nothing in this module writes key material to a log, an exception message, a
database row or a bundle. ``key_id`` is a one-way hash prefix and is safe to
print.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from engine.store.errors import (
    AUTH_FAILED,
    HASH_MISMATCH,
    KEY_FILE_EXISTS,
    KEY_FILE_MISSING,
    KEY_FILE_PERMISSIONS,
    KEY_FILE_SYMLINK,
    KEY_INVALID,
    TRUNCATED,
    UNKNOWN_VERSION,
    WRONG_KEY,
    SampleStoreError,
)

MAGIC = b"HATCHERY-SAMPLE\x00"
ENVELOPE_VERSION = 1
KEY_LEN = 32
KEY_ID_LEN = 8
NONCE_LEN = 12
LEN_LEN = 8
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 1 + KEY_ID_LEN + NONCE_LEN + LEN_LEN
ENVELOPE_ALGORITHM = "aes-256-gcm"
ENVELOPE_LABEL = f"{ENVELOPE_ALGORITHM}/v{ENVELOPE_VERSION}"
LEGACY_LABEL = "plaintext-legacy"

KEY_FILE_NAME = ".sample-key"
MAX_KEY_FILE_BYTES = 4096
# A hostile envelope may declare a 2**64 length; refuse to allocate before that.
MAX_DECLARED_PLAINTEXT = 1 << 32  # 4 GiB


@dataclass(frozen=True)
class SampleKey:
    """A loaded key. ``material`` must never be printed."""

    material: bytes
    source: str
    key_id: str
    generated: bool = False

    def __repr__(self) -> str:  # never leak the key through a repr/log line
        return f"SampleKey(source={self.source!r}, key_id={self.key_id!r})"

    def __str__(self) -> str:
        return f"key id {self.key_id} from {self.source}"


def key_id_for(material: bytes) -> str:
    """A stable, non-reversible id for a key (16 hex characters)."""
    return hashlib.sha256(b"hatchery-sample-key\x00" + material).hexdigest()[: KEY_ID_LEN * 2]


def parse_key_material(text: str) -> bytes:
    """Parse 32 bytes of key material from hex or base64 text."""
    cleaned = "".join(text.split())
    if not cleaned:
        raise SampleStoreError(KEY_INVALID, "the configured key is empty")
    material: Optional[bytes] = None
    if len(cleaned) == KEY_LEN * 2:
        try:
            material = bytes.fromhex(cleaned)
        except ValueError:
            material = None
    if material is None:
        try:
            padded = cleaned + "=" * (-len(cleaned) % 4)
            material = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            material = None
    if material is None or len(material) != KEY_LEN:
        raise SampleStoreError(
            KEY_INVALID,
            "the configured key must be exactly 32 bytes, encoded as 64 hex "
            "characters or base64 (44 characters); its value was not logged",
        )
    return material


def _read_key_file(path: Path) -> str:
    """Read a key file, refusing symlinks and loose permissions.

    The key file is a hostile-input surface: a symlink could point at a device
    or at a file the operator did not intend, and a world-readable key is not a
    key. Both are refusals, not warnings.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise SampleStoreError(KEY_FILE_MISSING, f"the key file {path} does not exist") from exc
    except OSError as exc:
        raise SampleStoreError(KEY_FILE_MISSING, f"the key file {path} is unreadable: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SampleStoreError(KEY_FILE_SYMLINK, f"the key file {path} is a symlink; refusing to follow it")
    if not stat.S_ISREG(info.st_mode):
        raise SampleStoreError(KEY_FILE_MISSING, f"the key file {path} is not a regular file")
    if info.st_mode & 0o077:
        raise SampleStoreError(
            KEY_FILE_PERMISSIONS,
            f"the key file {path} is accessible by group/other "
            f"(mode {oct(info.st_mode & 0o777)}); chmod 600 it",
        )
    if info.st_size > MAX_KEY_FILE_BYTES:
        raise SampleStoreError(KEY_INVALID, f"the key file {path} is implausibly large")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SampleStoreError(KEY_FILE_MISSING, f"the key file {path} could not be opened: {exc}") from exc
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read(MAX_KEY_FILE_BYTES)
    except OSError as exc:
        raise SampleStoreError(KEY_INVALID, f"the key file {path} could not be read: {exc}") from exc


def write_key_file(path: Path, material: bytes) -> None:
    """Create a key file (0600, no overwrite) for ``hatchery store keygen``."""
    if len(material) != KEY_LEN:  # pragma: no cover - generated internally
        raise SampleStoreError(KEY_INVALID, "generated key material has the wrong length")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SampleStoreError(
            KEY_FILE_EXISTS, f"{path} already exists; refusing to overwrite a key"
        ) from exc
    except OSError as exc:
        raise SampleStoreError(KEY_INVALID, f"could not create the key file {path}: {exc}") from exc
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, base64.b64encode(material) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        directory = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _generate_key_file(path: Path) -> SampleKey:
    material = secrets.token_bytes(KEY_LEN)
    try:
        write_key_file(path, material)
    except SampleStoreError as exc:
        # Two processes racing to create the first key: the loser must use the
        # winner's key, not fail. The file is read back and validated (regular
        # file, 0600, correct length) before it is trusted.
        if exc.reason != KEY_FILE_EXISTS:
            raise
        existing = parse_key_material(_read_key_file(path))
        return SampleKey(
            material=existing,
            source=f"file:{path}",
            key_id=key_id_for(existing),
        )
    return SampleKey(
        material=material,
        source=f"generated:{path}",
        key_id=key_id_for(material),
        generated=True,
    )


def key_file_path(store_root: Path) -> Path:
    return Path(store_root) / KEY_FILE_NAME


def resolve_key(store_root: Path, *, create: bool = False) -> Optional[SampleKey]:
    """Load the configured key, or generate a local one when ``create``.

    ``create=False`` returns ``None`` when nothing is configured, which lets a
    read-only consumer (``store verify``, ``store status``, replay of a legacy
    plaintext store) work without a key. A *misconfigured* key is always an
    error, never a silent "no key".
    """
    configured = os.environ.get("HATCHERY_SAMPLE_KEY", "").strip()
    if configured:
        material = parse_key_material(configured)
        return SampleKey(material, "env:HATCHERY_SAMPLE_KEY", key_id_for(material))

    configured_file = os.environ.get("HATCHERY_SAMPLE_KEY_FILE", "").strip()
    path = Path(configured_file).expanduser() if configured_file else key_file_path(store_root)
    explicit = bool(configured_file)
    if path.exists() or explicit:
        material = parse_key_material(_read_key_file(path))
        return SampleKey(material, f"file:{path}", key_id_for(material))

    if not create:
        return None
    return _generate_key_file(path)


def generate_key(path: Path) -> SampleKey:
    """Create a fresh key file at ``path``. Never prints the key.

    Unlike the automatic first-write key, this is an explicit operator action:
    an existing file is refused, never silently reused.
    """
    target = Path(path).expanduser()
    material = secrets.token_bytes(KEY_LEN)
    write_key_file(target, material)
    return SampleKey(
        material=material,
        source=f"file:{target}",
        key_id=key_id_for(material),
        generated=True,
    )


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def is_envelope(blob: bytes) -> bool:
    return blob.startswith(MAGIC)


def envelope_version(blob: bytes) -> Optional[int]:
    if not is_envelope(blob) or len(blob) <= len(MAGIC):
        return None
    return blob[len(MAGIC)]


def encrypt(plaintext: bytes, key: SampleKey, *, nonce: Optional[bytes] = None) -> bytes:
    """Encrypt bytes into a versioned envelope. The header is authenticated."""
    nonce = nonce if nonce is not None else secrets.token_bytes(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be 12 bytes")
    key_id = bytes.fromhex(key.key_id)
    header = (
        MAGIC
        + bytes([ENVELOPE_VERSION])
        + key_id
        + nonce
        + len(plaintext).to_bytes(LEN_LEN, "big")
    )
    ciphertext = AESGCM(key.material).encrypt(nonce, plaintext, header)
    return header + ciphertext


def decrypt(blob: bytes, key: SampleKey, *, max_bytes: int = MAX_DECLARED_PLAINTEXT) -> bytes:
    """Authenticate and decrypt an envelope.

    Every failure raises :class:`SampleStoreError` with a distinct reason:
    ``unknown-version``, ``truncated``, ``wrong-key``, ``auth-failed``. The
    caller is responsible for checking the plaintext hash against the content
    address (see :meth:`engine.store.store.SampleStore.read`).
    """
    if not is_envelope(blob):
        raise SampleStoreError(UNKNOWN_VERSION, "the stored file is not a HATCHERY envelope")
    if len(blob) < HEADER_LEN:
        raise SampleStoreError(
            TRUNCATED, f"the envelope is {len(blob)} bytes; a header alone needs {HEADER_LEN}"
        )
    version = blob[len(MAGIC)]
    if version != ENVELOPE_VERSION:
        raise SampleStoreError(
            UNKNOWN_VERSION,
            f"envelope version {version} is not supported by this build "
            f"(this build understands version {ENVELOPE_VERSION})",
        )
    offset = len(MAGIC) + 1
    stored_key_id = blob[offset : offset + KEY_ID_LEN].hex()
    offset += KEY_ID_LEN
    nonce = blob[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    declared = int.from_bytes(blob[offset : offset + LEN_LEN], "big")
    offset += LEN_LEN
    header = blob[:offset]
    ciphertext = blob[offset:]

    if stored_key_id != key.key_id:
        raise SampleStoreError(
            WRONG_KEY,
            f"the envelope was written with key id {stored_key_id}, but the configured "
            f"key is {key.key_id}",
        )
    if declared > max_bytes:
        raise SampleStoreError(
            TRUNCATED,
            f"the envelope declares {declared} plaintext bytes, above the "
            f"{max_bytes}-byte limit; refusing to allocate",
        )
    if len(ciphertext) != declared + TAG_LEN:
        raise SampleStoreError(
            TRUNCATED,
            f"the envelope declares {declared} plaintext bytes but carries "
            f"{len(ciphertext)} ciphertext bytes (expected {declared + TAG_LEN})",
        )
    try:
        plaintext = AESGCM(key.material).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise SampleStoreError(
            AUTH_FAILED,
            "the envelope failed authentication: the ciphertext or its header was "
            "modified, or the file was written with a different key that happens "
            "to share this key id",
        ) from exc
    if len(plaintext) != declared:  # pragma: no cover - AESGCM enforces this
        raise SampleStoreError(TRUNCATED, "the decrypted length disagrees with the header")
    return plaintext


def verify_plaintext_hash(plaintext: bytes, expected_sha256: str) -> str:
    """Return the plaintext SHA-256, refusing a content-address mismatch."""
    actual = hashlib.sha256(plaintext).hexdigest()
    if expected_sha256 and actual != expected_sha256:
        raise SampleStoreError(
            HASH_MISMATCH,
            f"the decrypted sample has sha256 {actual}, but the store address is "
            f"{expected_sha256}; refusing to use bytes that are not the sample",
        )
    return actual


__all__ = [
    "ENVELOPE_ALGORITHM",
    "ENVELOPE_LABEL",
    "ENVELOPE_VERSION",
    "HEADER_LEN",
    "KEY_FILE_NAME",
    "LEGACY_LABEL",
    "MAGIC",
    "MAX_DECLARED_PLAINTEXT",
    "SampleKey",
    "decrypt",
    "encrypt",
    "envelope_version",
    "generate_key",
    "is_envelope",
    "key_file_path",
    "key_id_for",
    "parse_key_material",
    "resolve_key",
    "verify_plaintext_hash",
    "write_key_file",
]
